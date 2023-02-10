package remote_run

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"code-intelligence.com/cifuzz/internal/api"
	"code-intelligence.com/cifuzz/internal/bundler"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	"code-intelligence.com/cifuzz/internal/cmdutils/login"
	"code-intelligence.com/cifuzz/internal/cmdutils/resolve"
	"code-intelligence.com/cifuzz/internal/completion"
	"code-intelligence.com/cifuzz/internal/config"
	"code-intelligence.com/cifuzz/pkg/dialog"
	"code-intelligence.com/cifuzz/pkg/log"
	"code-intelligence.com/cifuzz/util/fileutil"
	"code-intelligence.com/cifuzz/util/sliceutil"
	"code-intelligence.com/cifuzz/util/stringutil"
)

type remoteRunOpts struct {
	bundler.Opts `mapstructure:",squash"`
	Interactive  bool   `mapstructure:"interactive"`
	PrintJSON    bool   `mapstructure:"print-json"`
	ProjectName  string `mapstructure:"project"`
	Server       string `mapstructure:"server"`

	// Fields which are not configurable via viper (i.e. via cifuzz.yaml
	// and CIFUZZ_* environment variables), by setting
	// mapstructure:"-"
	BundlePath            string `mapstructure:"-"`
	ResolveSourceFilePath bool
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
		Short: "Build fuzz tests and run them on a CI Fuzz Server instance",
		Long: `This command builds fuzz tests, packages all runtime artifacts into a
bundle and uploads that to a CI Fuzz Server instance to start a remote
fuzzing run.

The inputs found in the inputs directory of the fuzz test are also added
to the bundle in addition to optional input directories specified with
the seed-corpus flag.
More details about the build system specific inputs directory location
can be found in the help message of the run command.

If the --bundle flag is used, building and bundling is skipped and the
specified bundle is uploaded to start a remote fuzzing run instead.

This command needs a token to access the API of the remote fuzzing
server. You can specify this token via the CIFUZZ_API_TOKEN environment
variable or by running 'cifuzz login' first.
`,
		ValidArgsFunction: completion.ValidFuzzTests,
		Args:              cobra.ArbitraryArgs,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			bindFlags()
			cmdutils.ViperMustBindPFlag("bundle", cmd.Flags().Lookup("bundle"))

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

			fuzzTests, err := resolve.FuzzTestArgument(opts.ResolveSourceFilePath, args, opts.BuildSystem, opts.ProjectDir)
			if err != nil {
				log.Error(err)
				return cmdutils.WrapSilentError(err)
			}
			opts.FuzzTests = fuzzTests

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
			err = api.ValidateURL(opts.Server)
			if err != nil {
				// See if prefixing https:// makes it a valid URL
				err = api.ValidateURL("https://" + opts.Server)
				if err != nil {
					log.Error(err, fmt.Sprintf("server %q is not a valid URL", opts.Server))
				}
				opts.Server = "https://" + opts.Server
			}

			// normalize server URL
			url, err := url.JoinPath(opts.Server)
			if err != nil {
				return err
			}
			opts.Server = url

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
		cmdutils.AddCleanCommandFlag,
		cmdutils.AddBuildJobsFlag,
		cmdutils.AddCommitFlag,
		cmdutils.AddDictFlag,
		cmdutils.AddDockerImageFlag,
		cmdutils.AddEngineArgFlag,
		cmdutils.AddEnvFlag,
		cmdutils.AddInteractiveFlag,
		cmdutils.AddPrintJSONFlag,
		cmdutils.AddProjectDirFlag,
		cmdutils.AddProjectFlag,
		cmdutils.AddSeedCorpusFlag,
		cmdutils.AddServerFlag,
		cmdutils.AddTimeoutFlag,
		cmdutils.AddResolveSourceFileFlag,
	)
	cmd.Flags().StringVar(&opts.BundlePath, "bundle", "", "Path of an existing bundle to start a remote run with.")

	return cmd
}

func (c *runRemoteCmd) run() error {
	var err error

	apiClient := &api.APIClient{
		Server: c.opts.Server,
	}

	token := login.GetToken(c.opts.Server)
	if token == "" {
		log.Print("You need to authenticate to a CI Fuzz Server instance to use this command.")

		if !c.opts.Interactive {
			log.Print("Please set CIFUZZ_API_TOKEN or run 'cifuzz login'.")
			return cmdutils.ErrSilent
		}

		yes, err := dialog.Confirm("Log in now?", true)
		if err != nil {
			return err
		}
		if !yes {
			log.Print("Please set CIFUZZ_API_TOKEN or run 'cifuzz login'.")
			return cmdutils.ErrSilent
		}
		token, err = login.ReadCheckAndStoreTokenInteractively(apiClient)
		if err != nil {
			return err
		}
	} else {
		err = login.CheckValidToken(apiClient, token)
		if err != nil {
			return err
		}
	}

	if c.opts.ProjectName == "" {
		projects, err := apiClient.ListProjects(token)
		if err != nil {
			log.Error(err)
			err = errors.New("Flag \"project\" must be set")
			return cmdutils.WrapIncorrectUsageError(err)
		}

		if c.opts.Interactive {
			c.opts.ProjectName, err = c.selectProject(projects)
			if err != nil {
				return err
			}
		} else {
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
		c.opts.OutputPath = bundlePath
		b := bundler.New(&c.opts.Opts)
		err = b.Bundle()
		if err != nil {
			return err
		}
	}

	artifact, err := apiClient.UploadBundle(c.opts.BundlePath, c.opts.ProjectName, token)
	if err != nil {
		var apiErr *api.APIError
		if !errors.As(err, &apiErr) {
			// API calls might fail due to network issues, invalid server
			// responses or similar. We don't want to print a stack trace
			// in those cases.
			log.Error(err)
			return cmdutils.WrapSilentError(err)
		}
		return err
	}

	campaignRunName, err := apiClient.StartRemoteFuzzingRun(artifact, token)
	if err != nil {
		// API calls might fail due to network issues, invalid server
		// responses or similar. We don't want to print a stack trace
		// in those cases.
		log.Error(err)
		return cmdutils.WrapSilentError(err)
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
		url, err := url.JoinPath(c.opts.Server, "dashboard", campaignRunName, "overview?origin=cli")
		if err != nil {
			return err
		}
		log.Successf(`Successfully started fuzzing run. To view findings and coverage, open:
    %s
`, url)
	}

	return nil
}

func (c *runRemoteCmd) selectProject(projects []*api.Project) (string, error) {
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

	projectName, err := dialog.Select("Select the project you want to start a fuzzing run for", items, true)
	if err != nil {
		return "", errors.WithStack(err)
	}

	return projectName, nil
}
