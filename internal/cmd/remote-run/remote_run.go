package remote_run

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	"golang.org/x/term"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"code-intelligence.com/cifuzz/internal/access_tokens"
	"code-intelligence.com/cifuzz/internal/bundler"
	"code-intelligence.com/cifuzz/internal/cmd/remote-run/progress"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/sliceutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

var FeaturedProjectsOrganization = "organizations/1"

type artifact struct {
	DisplayName  string `json:"display-name"`
	ResourceName string `json:"resource-name"`
}

type remoteRunOpts struct {
	bundler.Opts `mapstructure:",squash"`
	Interactive  bool   `mapstructure:"interactive"`
	PrintJSON    bool   `mapstructure:"print-json"`
	ProjectName  string `mapstructure:"project"`
	Server       string `mapstructure:"server"`

	// Fields which are not configurable via viper (i.e. via cifuzz.yaml
	// and CIFUZZ_* environment variables), by setting
	// mapstructure:"-"
	BundlePath string `mapstructure:"-"`
}

func (opts *remoteRunOpts) Validate() error {
	if !sliceutil.Contains([]string{config.BuildSystemBazel, config.BuildSystemCMake, config.BuildSystemOther}, opts.BuildSystem) {
		err := errors.Errorf(`Starting a remote run is currently not supported for %[1]s projects. If you
are interested in using this feature with %[1]s, please file an issue at
https://github.com/CodeIntelligenceTesting/cifuzz/issues`, cases.Title(language.Und).String(opts.BuildSystem))
		log.Print(err.Error())
		return cmdutils.WrapSilentError(err)
	}

	if opts.BundlePath == "" {
		// We need to build a bundle, so we validate the bundler options
		// as well
		err := opts.Opts.Validate()
		if err != nil {
			return err
		}
	}

	if opts.Interactive {
		opts.Interactive = term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stdout.Fd()))
	}

	return nil
}

type runRemoteCmd struct {
	opts *remoteRunOpts
}

func New() *cobra.Command {
	return newWithOptions(&remoteRunOpts{})
}

func newWithOptions(opts *remoteRunOpts) *cobra.Command {
	var bindFlags func()

	cmd := &cobra.Command{
		Use:   "remote-run [flags] [<fuzz test>]...",
		Short: "Build fuzz tests and run them on a remote fuzzing server",
		Long: `This command builds fuzz tests, packages all runtime artifacts into a
bundle and uploads that to a remote fuzzing server to start a remote
fuzzing run.

If the --bundle flag is used, building and bundling is skipped and the
specified bundle is uploaded to start a remote fuzzing run instead.

This command needs a token to access the API of the remote fuzzing
server. You can specify this token via the CIFUZZ_API_TOKEN environment
variable. If no token is specified, you will be prompted to enter the
token. That token is then stored in ~/.config/cifuzz/access_tokens.json
and used the next time the remote-run command is used.
`,
		ValidArgsFunction: completion.ValidFuzzTests,
		Args:              cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			bindFlags()
			cmdutils.ViperMustBindPFlag("bundle", cmd.Flags().Lookup("bundle"))
			cmdutils.ViperMustBindPFlag("project", cmd.Flags().Lookup("project"))
			cmdutils.ViperMustBindPFlag("server", cmd.Flags().Lookup("server"))

			// Fail early if the platform is not supported
			if runtime.GOOS != "linux" {
				system := cases.Title(language.Und).String(runtime.GOOS)
				if runtime.GOOS == "darwin" {
					system = "macOS"
				}
				err := errors.Errorf(`Starting a remote run is currently only supported on Linux. If you are
interested in using this feature on %s, please file an issue at
https://github.com/CodeIntelligenceTesting/cifuzz/issues`, system)
				log.Print(err.Error())
				return cmdutils.WrapSilentError(err)
			}

			err := config.FindAndParseProjectConfig(opts)
			if err != nil {
				log.Errorf(err, "Failed to parse cifuzz.yaml: %v", err.Error())
				return cmdutils.WrapSilentError(err)
			}
			opts.FuzzTests = args

			if opts.ProjectName != "" && !strings.HasPrefix(opts.ProjectName, "projects/") {
				opts.ProjectName = "projects/" + opts.ProjectName
			}

			// If --json was specified, print all build output to stderr
			if opts.PrintJSON {
				opts.Stdout = cmd.ErrOrStderr()
			} else {
				opts.Stdout = cmd.OutOrStdout()
			}
			opts.Stderr = cmd.ErrOrStderr()

			// Check if the server option is a valid URL
			err = validateURL(opts.Server)
			if err != nil {
				// See if prefixing https:// makes it a valid URL
				err = validateURL("https://" + opts.Server)
				if err != nil {
					log.Error(err, fmt.Sprintf("server %q is not a valid URL", opts.Server))
				}
				opts.Server = "https://" + opts.Server
			}

			// Print warning that flags which only effect the build of
			// the bundle are ignored when an existing bundle is specified
			if opts.BundlePath != "" {
				for _, flag := range cmdutils.BundleFlags {
					if cmd.Flags().Lookup(flag).Changed {
						log.Warnf("Flag --%s is ignored when --bundle is used", flag)
					}
				}
			}

			return opts.Validate()
		},
		RunE: func(c *cobra.Command, args []string) error {
			cmd := runRemoteCmd{opts: opts}
			return cmd.run()
		},
	}

	bindFlags = cmdutils.AddFlags(cmd,
		cmdutils.AddBranchFlag,
		cmdutils.AddBuildCommandFlag,
		cmdutils.AddBuildJobsFlag,
		cmdutils.AddCommitFlag,
		cmdutils.AddDictFlag,
		cmdutils.AddDockerImageFlag,
		cmdutils.AddEngineArgFlag,
		cmdutils.AddEnvFlag,
		cmdutils.AddInteractiveFlag,
		cmdutils.AddPrintJSONFlag,
		cmdutils.AddProjectDirFlag,
		cmdutils.AddSeedCorpusFlag,
		cmdutils.AddTimeoutFlag,
	)
	cmd.Flags().StringVar(&opts.BundlePath, "bundle", "", "Path of an existing bundle to start a remote run with.")
	// TODO: Make the project name more accessible in the web app (currently
	//       it's only shown in the URL)
	cmd.Flags().StringP("project", "p", "", `The name of the CI Fuzz project you want to start a fuzzing run for,
e.g. "my-project-c170bc17".`)
	cmd.Flags().String("server", "https://app.code-intelligence.com", "Address of the fuzzing server")

	return cmd
}

func (c *runRemoteCmd) run() error {
	var err error

	// Obtain the API access token
	token := os.Getenv("CIFUZZ_API_TOKEN")
	if token == "" {
		token = access_tokens.Get(c.opts.Server)
	}

	if token == "" {
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			b, err := io.ReadAll(os.Stdin)
			if err != nil {
				return errors.WithStack(err)
			}
			token = strings.TrimSpace(string(b))
		} else if c.opts.Interactive {
			fmt.Printf(`Enter an API access token and press Enter. You can generate a token for
your account at %s/dashboard/settings/account.`+"\n", c.opts.Server)
			reader := bufio.NewReader(os.Stdin)
			token, err = reader.ReadString('\n')
			if err != nil {
				return errors.WithStack(err)
			}
			log.Print()
			token = strings.TrimSpace(token)
		} else {
			err := errors.New("An API token must be passed via stdin or CIFUZZ_API_TOKEN")
			return cmdutils.WrapIncorrectUsageError(err)
		}

		// Try to authenticate with the access token
		_, err = c.listProjects(token)
		if err != nil {
			return err
		}

		// Store the access token in the config file
		err = access_tokens.Set(c.opts.Server, token)
		if err != nil {
			return err
		}
	}

	if c.opts.ProjectName == "" {
		if c.opts.Interactive {
			c.opts.ProjectName, err = c.selectProject(token)
			if err != nil {
				return err
			}
		} else {
			projects, err := c.listProjects(token)
			if err != nil {
				log.Error(err)
				err = errors.New("Flag \"project\" must be set")
				return cmdutils.WrapIncorrectUsageError(err)
			}
			var projectNames []string
			for _, p := range projects {
				projectNames = append(projectNames, strings.TrimPrefix(p.Name, "projects/"))
			}
			if len(projectNames) == 0 {
				log.Warnf("No projects found. Please create a project first at %s.", c.opts.Server)
				err = errors.New("Flag \"project\" must be set")
				return cmdutils.WrapIncorrectUsageError(err)
			}
			err = errors.New("Flag \"project\" must be set. Valid projects:\n  " + strings.Join(projectNames, "\n  "))
			return cmdutils.WrapIncorrectUsageError(err)
		}
	}

	if c.opts.BundlePath == "" {
		tempDir, err := os.MkdirTemp("", "cifuzz-bundle-")
		if err != nil {
			return errors.WithStack(err)
		}
		defer fileutil.Cleanup(tempDir)
		bundlePath := filepath.Join(tempDir, "fuzz_tests.tar.gz")
		c.opts.BundlePath = bundlePath
		c.opts.Opts.OutputPath = bundlePath
		b := bundler.New(&c.opts.Opts)
		err = b.Bundle()
		if err != nil {
			return err
		}
	}

	artifact, err := c.uploadBundle(c.opts.BundlePath, token)
	if err != nil {
		return err
	}

	campaignRunName, err := c.startRemoteFuzzingRun(artifact, token)
	if err != nil {
		return err
	}

	if c.opts.PrintJSON {
		result := struct{ CampaignRun string }{campaignRunName}
		s, err := stringutil.ToJsonString(result)
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintln(os.Stdout, s)
	} else {
		// TODO: Would be nice to be able to link to a page which immediately
		//       shows details about the run, but currently details are only
		//       shown on the "<fuzz target>/edit" page, which lists all runs
		//       of the fuzz target.
		log.Successf(`Successfully started fuzzing run. To view findings and coverage, open:

    %s/dashboard/%s/overview

`, c.opts.Server, campaignRunName)
	}

	return nil
}

func (c *runRemoteCmd) selectProject(token string) (string, error) {
	// Get the list of projects from the server
	projects, err := c.listProjects(token)
	if err != nil {
		return "", err
	}

	// Let the user select a project
	var displayNames []string
	var names []string
	for _, p := range projects {
		displayNames = append(displayNames, p.DisplayName)
		names = append(names, p.Name)
	}
	maxLen := stringutil.MaxLen(displayNames)
	items := map[string]string{}
	for i := range displayNames {
		key := fmt.Sprintf("%-*s [%s]", maxLen, displayNames[i], strings.TrimPrefix(names[i], "projects/"))
		items[key] = names[i]
	}

	if len(items) == 0 {
		err := errors.Errorf("No projects found. Please create a project first at %s.", c.opts.Server)
		log.Error(err)
		return "", cmdutils.WrapSilentError(err)
	}

	projectName, err := dialog.Select("Select the project you want to start a fuzzing run for", items)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return projectName, nil
}

func (c *runRemoteCmd) uploadBundle(path string, token string) (*artifact, error) {
	signalHandlerCtx, cancelSignalHandler := context.WithCancel(context.Background())
	routines, routinesCtx := errgroup.WithContext(context.Background())

	// Cancel the routines context when receiving a termination signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT, syscall.SIGQUIT)
	routines.Go(func() error {
		select {
		case <-signalHandlerCtx.Done():
			return nil
		case s := <-sigs:
			log.Warnf("Received %s", s.String())
			return cmdutils.NewSignalError(s.(syscall.Signal))
		}
	})

	// Use a pipe to avoid reading the artifacts into memory at once
	r, w := io.Pipe()
	m := multipart.NewWriter(w)

	// Write the artifacts to the pipe
	routines.Go(func() error {
		defer w.Close()
		defer m.Close()

		part, err := m.CreateFormFile("fuzzing-artifacts", path)
		if err != nil {
			return errors.WithStack(err)
		}

		fileInfo, err := os.Stat(path)
		if err != nil {
			return errors.WithStack(err)
		}

		f, err := os.Open(path)
		if err != nil {
			return errors.WithStack(err)
		}
		defer f.Close()

		var reader io.Reader
		printProgress := term.IsTerminal(int(os.Stdout.Fd()))
		if printProgress {
			fmt.Println("Uploading...")
			reader = progress.NewReader(f, fileInfo.Size(), "Upload complete")
		} else {
			reader = f
		}

		_, err = io.Copy(part, reader)
		return errors.WithStack(err)
	})

	// Send a POST request with what we read from the pipe. The request
	// gets cancelled with the routines context is cancelled, which
	// happens if an error occurs in the io.Copy above or the user if
	// cancels the operation.
	var body []byte
	routines.Go(func() error {
		defer r.Close()
		defer cancelSignalHandler()
		url := fmt.Sprintf("%s/v2/%s/artifacts/import", c.opts.Server, c.opts.ProjectName)
		req, err := http.NewRequestWithContext(routinesCtx, "POST", url, r)
		if err != nil {
			return errors.WithStack(err)
		}
		req.Header.Set("Content-Type", m.FormDataContentType())
		req.Header.Add("Authorization", "Bearer "+token)

		client := &http.Client{}
		resp, err := client.Do(req)
		if err != nil {
			return errors.WithStack(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			msg := responseToErrMsg(resp)
			err := errors.Errorf("Failed to upload bundle: %s", msg)
			log.Error(err)
			return cmdutils.WrapSilentError(err)
		}

		body, err = io.ReadAll(resp.Body)
		if err != nil {
			return errors.WithStack(err)
		}

		return nil
	})

	err := routines.Wait()
	if err != nil {
		return nil, err
	}

	artifact := &artifact{}
	err = json.Unmarshal(body, artifact)
	if err != nil {
		err = errors.WithStack(err)
		log.Errorf(err, "Failed to parse response from upload bundle API call: %s", err.Error())
		return nil, cmdutils.WrapSilentError(err)
	}

	return artifact, nil
}

func (c *runRemoteCmd) startRemoteFuzzingRun(artifact *artifact, token string) (string, error) {
	resp, err := c.sendRequest("POST", fmt.Sprintf("v1/%s:run", artifact.ResourceName), token)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		msg := responseToErrMsg(resp)
		err = errors.Errorf("Failed to start fuzzing run: %s", msg)
		log.Error(err)
		return "", cmdutils.WrapSilentError(err)
	}

	// Get the campaign run name from the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithStack(err)
	}
	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return "", errors.WithStack(err)
	}
	campaignRunNameJSON, ok := objmap["name"]
	if !ok {
		err := errors.Errorf("Server response doesn't include run name: %v", stringutil.PrettyString(objmap))
		log.Error(err)
		return "", cmdutils.WrapSilentError(err)
	}
	var campaignRunName string
	err = json.Unmarshal(campaignRunNameJSON, &campaignRunName)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return campaignRunName, nil
}

func (c *runRemoteCmd) sendRequest(method, endpoint, token string) (*http.Response, error) {
	url := fmt.Sprintf("%s/%s", c.opts.Server, endpoint)
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	req.Header.Add("Authorization", "Bearer "+token)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return resp, nil
}

type project struct {
	Name                  string `json:"name"`
	DisplayName           string `json:"display_name"`
	OwnerOrganizationName string `json:"owner_organization_name"`
}

func (c *runRemoteCmd) listProjects(token string) ([]*project, error) {
	resp, err := c.sendRequest("GET", "v1/projects", token)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		msg := responseToErrMsg(resp)
		err := errors.Errorf("Failed to list projects: %s", msg)
		log.Error(err)
		return nil, cmdutils.WrapSilentError(err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var objmap map[string]json.RawMessage
	err = json.Unmarshal(body, &objmap)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var projects []*project
	err = json.Unmarshal(objmap["projects"], &projects)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// Filter out featured projects
	var filteredProjects []*project
	for _, p := range projects {
		if p.OwnerOrganizationName == FeaturedProjectsOrganization {
			continue
		}
		filteredProjects = append(filteredProjects, p)
	}

	return filteredProjects, nil
}

func responseToErrMsg(resp *http.Response) string {
	msg := resp.Status
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return msg
	}
	apiResp := struct {
		Code    int
		Message string
	}{}
	err = json.Unmarshal(body, &apiResp)
	if err != nil {
		return fmt.Sprintf("%s: %s", msg, string(body))
	}
	return fmt.Sprintf("%s: %s", msg, apiResp.Message)
}

func validateURL(s string) error {
	u, err := url.Parse(s)
	if err != nil {
		return errors.WithStack(err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.Errorf("unsupported protocol scheme %q", u.Scheme)
	}
	return nil
}
