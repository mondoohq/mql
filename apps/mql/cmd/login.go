// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
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
	"sigs.k8s.io/yaml"
)

var (
	tokenValidationErr = errors.New("The token is not a valid token to register this client with Mondoo Platform")
	tokenExpiredErr    = errors.New("The token is expired")
)

// registrationTokenEnv supplies the registration token when --token is not set.
const registrationTokenEnv = "MONDOO_REGISTRATION_TOKEN"

// errNoCredentials is returned when login has neither a registration token
// nor usable credentials and cannot ask the user, because it does not run in
// a terminal.
var errNoCredentials = errors.New("no credentials")

func init() {
	rootCmd.AddCommand(LoginCmd)
	LoginCmd.Flags().StringP("token", "t", "", "Set a client registration token (default $"+registrationTokenEnv+")")
	LoginCmd.Flags().StringToString("annotation", nil, "Set the client annotations")
	LoginCmd.Flags().String("updates-url", "", "Set the updates URL for mql and provider updates")
	LoginCmd.Flags().String("name", "", "Set asset name")
	LoginCmd.Flags().String("api-endpoint", "", "Set the Mondoo API endpoint")
	LoginCmd.Flags().Int("timer", 0, "Set the scan interval in minutes")
	LoginCmd.Flags().Int("splay", 0, "Randomize the timer by up to this many minutes")
	LoginCmd.Flags().Bool("no-browser", false, "Do not open a browser on this machine; log in with a one-time code instead")
	LoginCmd.Flags().String("space", "", "Preselect this space MRN on the approval page")
	LoginCmd.Flags().Bool("insecure", false, "Allow browser login over unencrypted http to a non-loopback server")
	LoginCmd.Flags().Bool("force", false, "Log in again even if a valid login session exists")
}

// oauthLoginFlags are the options of the interactive (browser or device) login.
type oauthLoginFlags struct {
	noBrowser  bool
	spaceMrn   string
	insecure   bool
	force      bool // log in again even if the config holds a valid session
	binaryName string
	// interactive reports whether stdin and stderr are terminals, so the
	// login can ask the user.
	interactive bool
}

var LoginCmd = &cobra.Command{
	Use:     "login",
	Aliases: []string{"register"},
	Short:   "Log in to Mondoo Platform",
	Long: `
Log in to Mondoo Platform.

Without arguments, login opens your browser and asks you to approve the login
and pick a space. The result is a short-lived credential for this machine; run
login again when it expires. While the credential is valid, login only
confirms it; use '--force' to log in again. If the browser does not open or
runs on another machine, open the URL login shows in any browser and paste the
code it displays. On a machine without a browser (for example over SSH), or
with '--no-browser', login prints a one-time code to enter at a URL on any
device instead. This interactive login needs a terminal.

To register this machine permanently, use a registration token instead and pass
it with '--token' or the MONDOO_REGISTRATION_TOKEN environment variable; '--token'
takes precedence. You can generate a registration token in the Mondoo Console:
Space -> Settings -> Registration Token. A registered client remains logged in
until you explicitly log out using the 'logout' subcommand.
	`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("api_endpoint", cmd.Flags().Lookup("api-endpoint"))
		_ = viper.BindPFlag("name", cmd.Flags().Lookup("name"))
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer providers.Coordinator.Shutdown()
		flagToken, _ := cmd.Flags().GetString("token")
		token, tokenSource := registrationToken(flagToken, os.Getenv)
		if tokenSource != "" {
			log.Debug().Str("source", tokenSource).Msg("using a registration token")
		}
		annotations, _ := cmd.Flags().GetStringToString("annotation")
		updatesURL, _ := cmd.Flags().GetString("updates-url")
		timer, _ := cmd.Flags().GetInt("timer")
		splay, _ := cmd.Flags().GetInt("splay")
		apiEndpointOverride, _ := cmd.Flags().GetString("api-endpoint")
		var oauthFlags oauthLoginFlags
		oauthFlags.noBrowser, _ = cmd.Flags().GetBool("no-browser")
		oauthFlags.spaceMrn, _ = cmd.Flags().GetString("space")
		oauthFlags.insecure, _ = cmd.Flags().GetBool("insecure")
		oauthFlags.force, _ = cmd.Flags().GetBool("force")
		oauthFlags.binaryName = cmd.Root().Name()
		oauthFlags.interactive = term.IsTerminal(int(os.Stdin.Fd())) && term.IsTerminal(int(os.Stderr.Fd()))
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
			if errors.Is(err, errNoCredentials) {
				return cli_errors.NewCommandError(err, 1)
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
	var replaced *replacedSession

	// Without a token or usable credentials, login has to ask the user; fail
	// before any other work when it cannot. An existing login session is
	// checked later: when it is still valid, login does not ask.
	if token == "" {
		if opts, optsErr := config.Read(); optsErr == nil && !opts.HasCredentials() {
			if err := checkCanLogInInteractively(oauthFlags); err != nil {
				return err
			}
		}
	}

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
		applyRegistrationConfig(confirmation.AgentMrn, confirmation.Credential)
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
		// print the used config to the user; login creates a missing file
		config.DisplayUsedConfigForLogin()

		httpClient, err = opts.GetHttpClient()
		if err != nil {
			log.Warn().Err(err).Msg("could not create http client")
			return cli_errors.ExitCode1WithoutError
		}

		if opts.IsOAuthSession() || !opts.HasCredentials() {
			now := time.Now()
			keep, err := existingSession(context.Background(), opts, apiEndpointOverride, oauthFlags.force, now, httpClient, pingSession)
			if err != nil {
				return cli_errors.NewCommandError(err, 1)
			}
			if keep {
				fmt.Fprintln(os.Stderr, alreadyLoggedInMessage(opts, oauthFlags.binaryName, now))
				return nil
			}
			if err := checkCanLogInInteractively(oauthFlags); err != nil {
				return err
			}
			replaced = sessionToReplace(opts, now)
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

	if session != nil || token != "" {
		// Both write a private key to the config.
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
		// The new credential is saved; the replaced session is no longer
		// needed and should not stay valid on the server.
		revokeReplaced(context.Background(), replaced, session.AccessToken, httpClient, revokeSession)
		return nil
	}

	log.Info().Msgf("client %s has logged in successfully", viper.Get("agent_mrn"))
	return nil
}

// registrationToken returns the registration token to log in with and where it
// came from: the --token flag, else the registrationTokenEnv environment
// variable. Both empty returns "", "".
func registrationToken(flagToken string, getenv func(string) string) (string, string) {
	if token := strings.TrimSpace(flagToken); token != "" {
		return token, "--token"
	}
	if token := strings.TrimSpace(getenv(registrationTokenEnv)); token != "" {
		return token, registrationTokenEnv
	}
	return "", ""
}

// checkCanLogInInteractively fails right away when login would have to ask
// the user but does not run in a terminal (CI, scripts, piped input), instead
// of waiting for an approval nobody can give.
func checkCanLogInInteractively(flags oauthLoginFlags) error {
	if flags.interactive {
		return nil
	}
	binaryName := flags.binaryName
	if binaryName == "" {
		binaryName = "mql"
	}
	return fmt.Errorf("%w: run `%s login` in a terminal, or pass a registration token with --token or %s", errNoCredentials, binaryName, registrationTokenEnv)
}

// oauthLogin runs the interactive login against the server at apiEndpoint.
func oauthLogin(apiEndpoint string, httpClient *http.Client, sysInfo *sysinfo.SystemInfo, flags oauthLoginFlags) (*oauthlogin.Result, error) {
	mode := oauthlogin.ModeAuto
	if flags.noBrowser {
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

	// Ctrl-C cancels the login instead of killing the process, so the
	// terminal settings changed while waiting are restored.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	res, err := oauthlogin.Login(ctx, oauthlogin.Options{
		Endpoint:    apiEndpoint,
		Insecure:    flags.insecure,
		Mode:        mode,
		SpaceMrn:    flags.spaceMrn,
		DeviceName:  deviceName,
		DeviceInfo:  fmt.Sprintf("%s %s %s/%s", binaryName, version, runtime.GOOS, runtime.GOARCH),
		HTTPClient:  httpClient,
		Interactive: flags.interactive,
	})
	if err != nil && ctx.Err() != nil {
		return nil, errors.New("login canceled")
	}
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

// applyRegistrationConfig stages a registered client's credential in viper.
// What an interactive login session left in the config is removed: scope_mrn
// would take precedence over the new space, and the auth block would make
// logout revoke a session that no longer applies.
func applyRegistrationConfig(agentMrn string, cred *upstream.ServiceAccountCredentials) {
	if viper.IsSet("auth") || viper.IsSet("scope_mrn") {
		if err := dropConfigKeys("auth", "scope_mrn"); err != nil {
			log.Debug().Err(err).Msg("could not remove the login session from the config")
			// At least keep the stale scope from overriding the new space.
			viper.Set("scope_mrn", cred.GetParentMrn())
		}
	}
	viper.Set("agent_mrn", agentMrn)
	viper.Set("api_endpoint", cred.ApiEndpoint)
	viper.Set("space_mrn", cred.GetParentMrn())
	viper.Set("mrn", cred.Mrn)
	viper.Set("private_key", cred.PrivateKey)
	viper.Set("certificate", cred.Certificate)
}

// dropConfigKeys removes top-level keys from the loaded configuration.
// viper.Set only overrides a key: a nil override does not hide what was read
// from the config file, so WriteConfig would write it back. The loaded
// settings are replaced by the current ones without those keys instead.
func dropConfigKeys(keys ...string) error {
	for _, key := range keys {
		if viper.IsSet(key) {
			viper.Set(key, nil)
		}
	}
	settings := viper.AllSettings()
	for _, key := range keys {
		delete(settings, key)
	}
	var data []byte
	var err error
	if strings.EqualFold(filepath.Ext(viper.ConfigFileUsed()), ".json") {
		data, err = json.Marshal(settings)
	} else {
		data, err = yaml.Marshal(settings)
	}
	if err != nil {
		return err
	}
	return viper.ReadConfig(bytes.NewReader(data))
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
