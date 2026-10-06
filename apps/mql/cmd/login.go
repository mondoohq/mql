// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/config"
	cli_errors "go.mondoo.com/mql/cli/errors"
	"go.mondoo.com/mql/cli/oauthlogin"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/sysinfo"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/health"
	rangerUtils "go.mondoo.com/mql/utils/ranger"
	"go.mondoo.com/ranger-rpc"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/plugins/authentication/statictoken"
	"go.mondoo.com/ranger-rpc/status"
	"golang.org/x/term"
)

var (
	tokenValidationErr = errors.New("The token is not a valid token to register this client with Mondoo Platform")
	tokenExpiredErr    = errors.New("The token is expired")
)

func init() {
	rootCmd.AddCommand(LoginCmd)
	LoginCmd.Flags().StringP("token", "t", "", "Set a client registration token")
	LoginCmd.Flags().StringToString("annotation", nil, "Set the client annotations")
	LoginCmd.Flags().String("updates-url", "", "Set the updates URL for mql and provider updates")
	LoginCmd.Flags().String("name", "", "Set asset name")
	LoginCmd.Flags().String("api-endpoint", "", "Set the Mondoo API endpoint")
	LoginCmd.Flags().Int("timer", 0, "Set the scan interval in minutes")
	LoginCmd.Flags().Int("splay", 0, "Randomize the timer by up to this many minutes")
	LoginCmd.Flags().Bool("device", false, "Log in with a one-time code entered in a browser on any device")
	LoginCmd.Flags().Bool("no-browser", false, "Do not open a browser on this machine; log in with a one-time code instead")
	LoginCmd.Flags().String("space", "", "Preselect this space MRN on the approval page")
	LoginCmd.Flags().Bool("insecure", false, "Allow browser login over unencrypted http to a non-loopback server")
}

// oauthLoginFlags are the options of the interactive (browser or device) login.
type oauthLoginFlags struct {
	device     bool
	noBrowser  bool
	spaceMrn   string
	insecure   bool
	binaryName string
}

var LoginCmd = &cobra.Command{
	Use:     "login",
	Aliases: []string{"register"},
	Short:   "Log in to Mondoo Platform",
	Long: `
Log in to Mondoo Platform.

Without arguments, login opens your browser and asks you to approve the login
and pick a space. The result is a short-lived credential for this machine; run
login again when it expires. On a machine without a browser (for example over
SSH), or with '--device' or '--no-browser', login prints a one-time code to
enter at a URL on any device instead.

To register this machine permanently, use a registration token instead and pass
it with '--token'. You can generate a registration token in the Mondoo Console:
Space -> Settings -> Registration Token. A registered client remains logged in
until you explicitly log out using the 'logout' subcommand.
	`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("api_endpoint", cmd.Flags().Lookup("api-endpoint"))
		_ = viper.BindPFlag("name", cmd.Flags().Lookup("name"))
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer providers.Coordinator.Shutdown()
		token, _ := cmd.Flags().GetString("token")
		annotations, _ := cmd.Flags().GetStringToString("annotation")
		updatesURL, _ := cmd.Flags().GetString("updates-url")
		timer, _ := cmd.Flags().GetInt("timer")
		splay, _ := cmd.Flags().GetInt("splay")
		apiEndpointOverride, _ := cmd.Flags().GetString("api-endpoint")
		var oauthFlags oauthLoginFlags
		oauthFlags.device, _ = cmd.Flags().GetBool("device")
		oauthFlags.noBrowser, _ = cmd.Flags().GetBool("no-browser")
		oauthFlags.spaceMrn, _ = cmd.Flags().GetString("space")
		oauthFlags.insecure, _ = cmd.Flags().GetBool("insecure")
		oauthFlags.binaryName = cmd.Root().Name()
		err := register(token, annotations, updatesURL, timer, splay, apiEndpointOverride, oauthFlags)
		if err != nil {
			// A login failure is not a usage error: don't print the help text,
			// and don't let cobra repeat an error we log ourselves.
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true

			if err == tokenValidationErr {
				log.Error().Msg(err.Error())
				return cli_errors.ExitCode1WithoutError
			}
			defer func() {
				opts, optsErr := config.Read()
				if optsErr != nil {
					log.Error().Err(optsErr).Msg("could not load configuration")
					return
				}

				httpClient, err := opts.GetHttpClient()
				if err != nil {
					log.Error().Err(optsErr).Msg("failed to set up Mondoo API client")
					return
				}

				upstreamStatus, err := health.CheckApiHealth(httpClient, opts.UpstreamApiEndpoint())
				if err != nil {
					log.Error().Err(err).Msg("could not check upstream health")
					return
				}

				for _, warn := range upstreamStatus.Warnings {
					log.Warn().Msg(warn)
				}
			}()

			if err == tokenExpiredErr {
				log.Error().Msg(err.Error())
				return cli_errors.ExitCode1WithoutError
			}
		}
		return err
	},
}

func register(token string, annotations map[string]string, updatesURL string, timer int, splay int, apiEndpointOverride string, oauthFlags oauthLoginFlags) error {
	var err error
	var credential *upstream.ServiceAccountCredentials
	var session *oauthlogin.Result

	// determine information about the client
	sysInfo, err := sysinfo.Get()
	if err != nil {
		return cli_errors.NewCommandError(errors.Wrap(err, "could not gather client information"), 1)
	}
	defaultPlugins := rangerUtils.DefaultRangerPlugins(mql.DefaultFeatures, nil)

	apiEndpoint := viper.GetString("api_endpoint")
	token = strings.TrimSpace(token)

	// NOTE: login is special because we do not have a config yet
	httpClient, err := config.NewHttpClient()
	if err != nil {
		return cli_errors.NewCommandError(errors.Wrap(err, "could not parse proxy URL"), 1)
	}

	// we handle these cases here:
	// 1. user has a token provided
	// 2. user has no token provided, but a registered client config is already there
	// 3. user has no token provided, but a service account config is already there
	// 4. user has no token provided and no usable credentials, or only an
	//    interactive login session: run the interactive (OAuth) login
	//
	if token != "" {
		// print token details
		claims, err := upstream.ExtractTokenClaims(token)
		if err != nil {
			log.Warn().Err(err).Msg("could not read the token")
			return tokenValidationErr
		} else {
			if len(claims.Description) > 0 {
				log.Info().Msg("token description: " + claims.Description)
			}
			if claims.IsExpired() {
				return tokenExpiredErr
			} else if claims.Expiry == nil {
				log.Warn().Msg("token does not contain an expiry date")
			} else {
				log.Info().Msg("token will expire at " + claims.Claims.Expiry.Time().Format(time.RFC1123))
			}
			if claims.Space == "" {
				log.Warn().
					Msg("token does not contain a space")
				return tokenValidationErr
			}

			// use the api endpoint from the token if not overridden via flag
			if apiEndpointOverride == "" {
				apiEndpoint = claims.ApiEndpoint
			}
		}

		// gather service account
		plugins := []ranger.ClientPlugin{}
		plugins = append(plugins, defaultPlugins...)
		plugins = append(plugins, statictoken.NewRangerPlugin(token))

		client, err := upstream.NewAgentManagerClient(apiEndpoint, httpClient, plugins...)
		if err != nil {
			return cli_errors.NewCommandError(errors.Wrap(err, "could not connect to mondoo platform"), 1)
		}

		name := viper.GetString("name")
		if name == "" {
			name = sysInfo.Hostname
		}

		confirmation, err := registerAgent(context.Background(), client, &upstream.AgentRegistrationRequest{
			Token: token,
			Name:  name,
			AgentInfo: &upstream.AgentInfo{
				Mrn:              "",
				Version:          sysInfo.Version,
				Build:            sysInfo.Build,
				PlatformName:     sysInfo.Platform.Name,
				PlatformRelease:  sysInfo.Platform.Version,
				PlatformArch:     sysInfo.Platform.Arch,
				PlatformIp:       sysInfo.IP,
				PlatformHostname: sysInfo.Hostname,
				Labels:           nil,
				PlatformId:       sysInfo.PlatformId,
			},
		})
		if err != nil {
			return cli_errors.NewCommandError(errors.Wrap(err, "failed to log in client"), 1)
		}

		log.Debug().Msg("store configuration")
		// update configuration file, api-endpoint is set automatically
		viper.Set("agent_mrn", confirmation.AgentMrn)
		viper.Set("api_endpoint", confirmation.Credential.ApiEndpoint)
		viper.Set("space_mrn", confirmation.Credential.GetParentMrn())
		viper.Set("mrn", confirmation.Credential.Mrn)
		viper.Set("private_key", confirmation.Credential.PrivateKey)
		viper.Set("certificate", confirmation.Credential.Certificate)
		viper.Set("annotations", annotations)
		if updatesURL != "" {
			viper.Set("updates_url", updatesURL)
		}
		if timer > 0 {
			viper.Set("scan_interval.timer", timer)
		}
		if splay > 0 {
			viper.Set("scan_interval.splay", splay)
		}
		credential = confirmation.Credential
	} else {
		// try to read local options
		opts, optsErr := config.Read()
		if optsErr != nil {
			log.Warn().Msg("could not load configuration, please use --token or --config with the appropriate values")
			return cli_errors.ExitCode1WithoutError
		}
		// print the used config to the user
		config.DisplayUsedConfig()

		httpClient, err = opts.GetHttpClient()
		if err != nil {
			log.Warn().Err(err).Msg("could not create http client")
			return cli_errors.ExitCode1WithoutError
		}

		if opts.IsOAuthSession() || !opts.HasCredentials() {
			if apiEndpoint == "" {
				apiEndpoint = opts.UpstreamApiEndpoint()
			}
			session, err = oauthLogin(apiEndpoint, httpClient, sysInfo, oauthFlags)
			if err != nil {
				return cli_errors.NewCommandError(err, 1)
			}
			credential = applySessionConfig(session)
			apiEndpoint = credential.ApiEndpoint
		} else if opts.AgentMrn != "" {
			// already authenticated
			log.Info().Msg("client is already logged in, skipping")
			credential = opts.GetServiceCredential()
		} else {
			credential = opts.GetServiceCredential()

			// run ping pong
			plugins := []ranger.ClientPlugin{}
			plugins = append(plugins, defaultPlugins...)
			certAuth, err := upstream.NewServiceAccountRangerPlugin(credential)
			if err != nil {
				log.Warn().Err(err).Msg("could not initialize certificate authentication")
				return cli_errors.ExitCode1WithoutError
			}
			plugins = append(plugins, certAuth)

			client, err := upstream.NewAgentManagerClient(apiEndpoint, httpClient, plugins...)
			if err != nil {
				log.Warn().Err(err).Msg("could not connect to Mondoo Platform")
				return cli_errors.ExitCode1WithoutError
			}

			name := viper.GetString("name")
			if name == "" {
				name = sysInfo.Hostname
			}

			confirmation, err := registerAgent(context.Background(), client, &upstream.AgentRegistrationRequest{
				Name: name,
				AgentInfo: &upstream.AgentInfo{
					Mrn:              opts.AgentMrn,
					Version:          sysInfo.Version,
					Build:            sysInfo.Build,
					PlatformName:     sysInfo.Platform.Name,
					PlatformRelease:  sysInfo.Platform.Version,
					PlatformArch:     sysInfo.Platform.Arch,
					PlatformIp:       sysInfo.IP,
					PlatformHostname: sysInfo.Hostname,
					Labels:           opts.Labels,
					PlatformId:       sysInfo.PlatformId,
				},
			})
			if err != nil {
				return cli_errors.NewCommandError(errors.Wrap(err, "failed to log in client"), 1)
			}

			// update configuration file, api-endpoint is set automatically
			// NOTE: we ignore the credentials from confirmation since the service never returns the credentials again
			viper.Set("agent_mrn", confirmation.AgentMrn)
		}
	}

	if session != nil {
		restrictConfigPermissions(viper.ConfigFileUsed())
	}
	err = config.StoreConfig()
	if err != nil {
		log.Warn().Err(err).Msg("could not write mondoo configuration")
		return cli_errors.ExitCode1WithoutError
	}

	// run ping pong to validate the service account
	plugins := []ranger.ClientPlugin{}
	plugins = append(plugins, defaultPlugins...)
	certAuth, err := upstream.NewServiceAccountRangerPlugin(credential)
	if err != nil {
		log.Warn().Err(err).Msg("could not initialize certificate authentication")
	}
	plugins = append(plugins, certAuth)
	client, err := upstream.NewAgentManagerClient(apiEndpoint, httpClient, plugins...)
	if err != nil {
		log.Warn().Err(err).Msg("could not connect to mondoo platform")
		return cli_errors.ExitCode1WithoutError
	}

	_, err = client.PingPong(context.Background(), &upstream.Ping{})
	if err != nil {
		log.Warn().Msg(err.Error())
		return cli_errors.ExitCode1WithoutError
	}

	if session != nil {
		fmt.Fprintln(os.Stderr, session.Summary(time.Now()))
		return nil
	}

	log.Info().Msgf("client %s has logged in successfully", viper.Get("agent_mrn"))
	return nil
}

// oauthLogin runs the interactive login against the server at apiEndpoint.
func oauthLogin(apiEndpoint string, httpClient *http.Client, sysInfo *sysinfo.SystemInfo, flags oauthLoginFlags) (*oauthlogin.Result, error) {
	mode := oauthlogin.ModeAuto
	if flags.device || flags.noBrowser {
		mode = oauthlogin.ModeDevice
	}
	version := config.RunningVersion()
	if version == "" {
		version = mql.GetVersion()
	}
	binaryName := flags.binaryName
	if binaryName == "" {
		binaryName = "mql"
	}
	deviceName := sysInfo.Hostname
	if deviceName == "" {
		deviceName, _ = os.Hostname()
	}

	res, err := oauthlogin.Login(context.Background(), oauthlogin.Options{
		Endpoint:    apiEndpoint,
		Insecure:    flags.insecure,
		Mode:        mode,
		SpaceMrn:    flags.spaceMrn,
		DeviceName:  deviceName,
		DeviceInfo:  fmt.Sprintf("%s %s %s/%s", binaryName, version, runtime.GOOS, runtime.GOARCH),
		HTTPClient:  httpClient,
		Interactive: term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd())),
	})
	if errors.Is(err, oauthlogin.ErrBrowserLoginDisabled) {
		return nil, fmt.Errorf("%w — use `%s login --token`", err, binaryName)
	}
	return res, err
}

// applySessionConfig stages an interactive login's credential in viper and
// returns it. Fields that would take precedence over the new credential are
// cleared.
func applySessionConfig(res *oauthlogin.Result) *upstream.ServiceAccountCredentials {
	for _, key := range []string{"agent_mrn", "token", "parent_mrn"} {
		if viper.IsSet(key) {
			viper.Set(key, nil)
		}
	}
	values := res.ConfigValues()
	for key, value := range values {
		viper.Set(key, value)
	}
	return &upstream.ServiceAccountCredentials{
		Mrn:         res.ServiceAccount.Mrn,
		ParentMrn:   res.ServiceAccount.ScopeMrn,
		ScopeMrn:    res.ServiceAccount.ScopeMrn,
		PrivateKey:  res.PrivateKeyPEM,
		Certificate: res.ServiceAccount.Certificate,
		ApiEndpoint: values["api_endpoint"].(string),
	}
}

// restrictConfigPermissions makes the config readable by its owner only before
// a private key is written to it. The writer keeps an existing file's mode, so
// the key is never readable by others, not even briefly. Best effort.
func restrictConfigPermissions(path string) {
	if path == "" || runtime.GOOS == "windows" {
		return
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			log.Debug().Err(err).Str("path", path).Msg("could not create config directory")
			return
		}
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			log.Debug().Err(err).Str("path", path).Msg("could not create config file")
			return
		}
		_ = f.Close()
		return
	}
	if err := os.Chmod(path, 0o600); err != nil {
		log.Debug().Err(err).Str("path", path).Msg("could not restrict config file permissions")
	}
}

func registerAgent(ctx context.Context, client *upstream.AgentManagerClient, req *upstream.AgentRegistrationRequest) (*upstream.AgentRegistrationConfirmation, error) {
	const maxRetries = 3
	try := 0
	for {
		confirmation, err := client.RegisterAgent(ctx, req)
		if err != nil {
			if status.Code(err) == codes.Aborted {
				jitter := time.Duration(rand.Intn(5000)) * time.Millisecond
				sleepTime := 5*(1<<try)*time.Second + jitter

				try++
				if try > maxRetries {
					return nil, errors.Wrap(err, "failed to log in client due to concurrent IAM changes")
				}

				log.Warn().Err(err).Msgf("failed to log in client due to concurrent IAM changes, retrying (%d/%d) in %dms", try, maxRetries, sleepTime.Milliseconds())
				time.Sleep(sleepTime)
			} else {
				return nil, errors.Wrap(err, "failed to log in client")
			}
		} else {
			return confirmation, nil
		}
	}
}
