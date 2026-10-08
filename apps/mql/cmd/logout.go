// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"os"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/mql/cli/config"
	cli_errors "go.mondoo.com/mql/cli/errors"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	rangerUtils "go.mondoo.com/mql/utils/ranger"
)

func init() {
	rootCmd.AddCommand(LogoutCmd)
	LogoutCmd.Flags().Bool("force", false, "Force the logout without confirmation")
}

var LogoutCmd = &cobra.Command{
	Use:     "logout",
	Aliases: []string{"unregister"},
	Short:   "Log out from Mondoo Platform",
	Long: `
This process also revokes the Mondoo Platform service account to 
ensure the credentials cannot be used in the future.
`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("force", cmd.Flags().Lookup("force"))
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer providers.Coordinator.Shutdown()
		var err error

		// its perfectly fine not to have a config here, therefore we ignore errors
		opts, optsErr := config.Read()
		if optsErr != nil {
			return errors.Wrap(optsErr, "could not load configuration")
		}

		// print the used config to the user
		config.DisplayUsedConfig()

		// check valid client authentication
		serviceAccount := opts.GetServiceCredential()
		if serviceAccount == nil {
			return cli_errors.NewCommandError(errors.Wrap(err, "could not initialize client authentication"), ConfigurationErrorCode)
		}

		plugins := rangerUtils.DefaultRangerPlugins(opts.GetFeatures(), nil)
		certAuth, err := upstream.NewServiceAccountRangerPlugin(serviceAccount)
		if err != nil {
			log.Error().Err(err).Msg("could not initialize client authentication")
			return cli_errors.NewCommandError(nil, ConfigurationErrorCode)
		}
		plugins = append(plugins, certAuth)

		httpClient, err := opts.GetHttpClient()
		if err != nil {
			return cli_errors.NewCommandError(errors.Wrap(err, "error while creating Mondoo API client"), 1)
		}
		client, err := upstream.NewAgentManagerClient(opts.UpstreamApiEndpoint(), httpClient, plugins...)
		if err != nil {
			log.Error().Err(err).Msg("could not initialize connection to Mondoo Platform")
			return cli_errors.NewCommandError(nil, ConfigurationErrorCode)
		}

		if !viper.GetBool("force") {
			log.Info().Msg("are you sure you want to revoke client access to Mondoo Platform? Use --force if you are sure")
			return cli_errors.NewCommandError(errors.New("--force is required to logout"), ConfigurationErrorCode)
		}

		// try to load config into credentials struct
		credentials := opts.GetServiceCredential()

		// if we have credentials, we are going to self-destroy
		ctx := context.Background()
		if credentials != nil && len(credentials.Mrn) > 0 {
			_, err = client.PingPong(ctx, &upstream.Ping{})

			if err == nil {
				log.Info().Msgf("client %s authenticated successfully", credentials.Mrn)

				// un-register the agent
				_, err = client.UnRegisterAgent(ctx, &upstream.Mrn{
					Mrn: opts.AgentMrn,
				})
				if err != nil {
					log.Error().Err(err).Msg("failed to unregister client")
				}
			} else {
				log.Error().Err(err).Msg("communication with Mondoo Platform failed")
			}
		}

		// delete config if it exists
		path := viper.ConfigFileUsed()
		_, err = os.Stat(path)
		if err == nil {
			log.Debug().Str("path", path).Msg("remove client information from config")

			opts.AgentMrn = ""

			// Preserve the on-disk serialization format: a config loaded from
			// JSON must be written back as JSON, not silently converted to YAML.
			// The file holds credentials, so it is written with group and other
			// permissions removed and is never widened.
			data, marshalErr := config.MarshalConfig(path, opts)
			if marshalErr != nil {
				// Don't write on a marshal failure; a nil payload would truncate
				// the existing config file.
				log.Error().Err(marshalErr).Msg("could not update Mondoo config")
			} else if writeErr := config.WritePrivateFile(path, data); writeErr != nil {
				log.Error().Err(writeErr).Msg("could not update Mondoo config")
			}
		}

		log.Info().Msgf("Bye bye, space cat. Client %s unregistered successfully", credentials.Mrn)
		return nil
	},
}
