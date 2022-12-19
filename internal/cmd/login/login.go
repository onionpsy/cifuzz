package login

import (
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"code-intelligence.com/cifuzz/internal/api"
	"code-intelligence.com/cifuzz/internal/cmdutils"
	loginUtil "code-intelligence.com/cifuzz/internal/cmdutils/login"
	"code-intelligence.com/cifuzz/pkg/log"
)

func New() *cobra.Command {
	var bindFlags func()

	cmd := &cobra.Command{
		Use:   "login",
		Short: "Login to a remote fuzzing server",
		Long: `This command is used to authenticate with a CI remote fuzzing server.
To learn more, visit https://www.code-intelligence.com.`,
		Example: "$ cifuzz login",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			// Bind viper keys to flags. We can't do this in the New
			// function, because that would re-bind viper keys which
			// were bound to the flags of other commands before.
			bindFlags()
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := loginUtil.Opts{
				Interactive: viper.GetBool("interactive"),
				Server:      viper.GetString("server"),
			}

			// Check if the server option is a valid URL
			err := api.ValidateURL(opts.Server)
			if err != nil {
				// See if prefixing https:// makes it a valid URL
				err = api.ValidateURL("https://" + opts.Server)
				if err != nil {
					log.Error(err, fmt.Sprintf("server %q is not a valid URL", opts.Server))
				}
				opts.Server = "https://" + opts.Server
			}

			_, err = loginUtil.Login(opts)
			return err
		},
	}
	bindFlags = cmdutils.AddFlags(cmd,
		cmdutils.AddInteractiveFlag,
		cmdutils.AddServerFlag,
	)

	cmdutils.DisableConfigCheck(cmd)

	return cmd
}
