// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/mattn/go-isatty"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/cli/components"
	"go.mondoo.com/mql/cli/config"
	cli_errors "go.mondoo.com/mql/cli/errors"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/sysinfo"
	"go.mondoo.com/mql/providers-sdk/v1/upstream"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/health"
	"go.mondoo.com/ranger-rpc"
	"sigs.k8s.io/yaml"
)

func init() {
	StatusCmd.Flags().StringP("output", "o", "", "Set the output format: json, yaml")
	rootCmd.AddCommand(StatusCmd)
}

// statusTimeout bounds the total time the status command spends on network
// calls so it cannot hang indefinitely when the API is unreachable.
const statusTimeout = 30 * time.Second

// spinnerFrames and spinnerFPS are the braille frames and cadence used by the
// status loading indicator, matching the "Dot" spinner shown while scanning.
var (
	spinnerFrames = []string{"⣾ ", "⣽ ", "⣻ ", "⢿ ", "⡿ ", "⣟ ", "⣯ ", "⣷ "}
	spinnerFPS    = time.Second / 10
)

// statusSpinner animates a loading indicator on stderr while the status command
// performs its network calls. It writes to stderr (never stdout, which carries
// the rendered status) and is a no-op when stderr is not a terminal, keeping
// piped and redirected output clean.
type statusSpinner struct {
	stop chan struct{}
	done chan struct{}
}

// startStatusSpinner begins animating message on stderr. It returns nil when
// stderr is not a TTY; Stop tolerates a nil receiver so callers needn't check.
func startStatusSpinner(message string) *statusSpinner {
	if !isatty.IsTerminal(os.Stderr.Fd()) {
		return nil
	}

	s := &statusSpinner{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		ticker := time.NewTicker(spinnerFPS)
		defer ticker.Stop()

		frame := 0
		for {
			select {
			case <-s.stop:
				// erase the spinner line so the rendered status starts clean
				fmt.Fprint(os.Stderr, "\r\033[K")
				return
			case <-ticker.C:
				// Trail each frame with \r so the cursor returns to column 0.
				// Logs are left running: a log line printing over the spinner
				// overwrites it and its trailing newline moves output along,
				// while the next tick simply redraws the fixed-width frame.
				fmt.Fprintf(os.Stderr, "%s%s\r", spinnerFrames[frame%len(spinnerFrames)], message)
				frame++
			}
		}
	}()
	return s
}

// Stop halts the spinner and clears its line. Safe to call on a nil spinner.
func (s *statusSpinner) Stop() {
	if s == nil {
		return
	}
	close(s.stop)
	<-s.done
}

// StatusCmd represents the version command
var StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Verify access to Mondoo Platform",
	Long: `
Status sends a ping to Mondoo Platform to verify the credentials.
	`,
	PreRun: func(cmd *cobra.Command, args []string) {
		_ = viper.BindPFlag("output", cmd.Flags().Lookup("output"))
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		defer providers.Coordinator.Shutdown()

		config.DisplayUsedConfig()

		// Bound all network calls with a deadline so the command cannot hang
		// indefinitely when the API is unreachable.
		ctx, cancel := context.WithTimeout(cmd.Context(), statusTimeout)
		defer cancel()

		// Show a loading indicator while the (potentially slow) network calls
		// run. Skipped for json/yaml output so machine-readable streams stay
		// clean, and silent when stderr is not a terminal.
		var spin *statusSpinner
		if viper.GetString("output") == "" {
			spin = startStatusSpinner("Checking status…")
		}
		s, err := checkStatus(ctx)
		spin.Stop()
		if err != nil {
			return err
		}

		switch strings.ToLower(viper.GetString("output")) {
		case "yaml":
			s.RenderYaml()
		case "json":
			s.RenderJson()
		default:
			width, _ := components.TerminalWidth(os.Stdout)
			fmt.Fprint(os.Stdout, s.RenderCli(RenderOptions{Color: defaultRenderColor(), Binary: cmd.Root().Name(), Width: width}))
		}

		if !s.Client.Registered || s.Client.PingPongError != nil {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return cli_errors.ExitCode1WithoutError
		}
		return nil
	},
}

// reportedConfigFile returns the config file path to surface in `status`
// output. viper.ConfigFileUsed() returns the autodetected default path even
// when no file exists on disk, so a config file must have actually been loaded
// for the path to be meaningful. When nothing was loaded we report an empty
// string, keeping the output consistent with the "no configuration file
// provided" message emitted by config.DisplayUsedConfig.
func reportedConfigFile(loaded bool, configFileUsed string) string {
	if !loaded {
		return ""
	}
	return configFileUsed
}

func checkStatus(ctx context.Context) (Status, error) {
	s := Status{
		Client: ClientStatus{
			Timestamp:  time.Now().Format(time.RFC3339),
			Version:    mql.GetVersion(),
			APIVersion: mql.APIVersion(),
			Build:      mql.GetBuild(),
		},
	}

	opts, optsErr := config.Read()
	if optsErr != nil {
		return s, cli_errors.NewCommandError(errors.Wrap(optsErr, "could not load configuration"), 1)
	}

	// record which config file the credentials were loaded from, if any
	s.Client.ConfigFile = reportedConfigFile(config.LoadedConfig, viper.ConfigFileUsed())

	httpClient, err := opts.GetHttpClient()
	if err != nil {
		return s, cli_errors.NewCommandError(errors.Wrap(err, "failed to set up Mondoo API client"), 1)
	}

	// Probe the ingest endpoint alongside the checks below rather than in
	// series. Uploads go to a different host than the API on a different static
	// IP, so a firewall can allow the API and blackhole ingest — and a
	// blackholed host answers nothing until the probe's own deadline, which
	// would otherwise eat a third of this command's shared budget.
	ingest := probeIngestEndpoint(ctx, httpClient, opts.UpstreamIngestEndpoint())

	sysInfo, err := sysinfo.Get()
	if err == nil {
		s.Client.Platform = sysInfo.Platform
		s.Client.Hostname = sysInfo.Hostname
		s.Client.IP = sysInfo.IP
	}

	// check server health and clock skew
	upstreamStatus, err := health.CheckApiHealthContext(ctx, httpClient, opts.UpstreamApiEndpoint())
	if err != nil {
		log.Error().Err(err).Msg("could not check upstream health")
	}
	s.Upstream = upstreamStatus

	// Determine the updates URL (used for mql version checks)
	if opts.UpdatesURL != "" {
		s.Client.UpdatesURL = opts.UpdatesURL
	} else {
		s.Client.UpdatesURL = providers.DefaultUpdatesURL
	}

	// Fetch latest version using the configured updates URL
	releaseURL := s.Client.UpdatesURL + "/mql/latest.json?ignoreCache=1"
	latestVersion, err := mql.GetLatestReleaseNameContext(ctx, releaseURL, httpClient)
	if err != nil {
		log.Warn().Err(err).Msg("Failed to get latest version")
	}

	s.Client.LatestVersion = latestVersion

	// check valid agent authentication
	plugins := []ranger.ClientPlugin{}

	// try to load config into credentials struct
	credentials := opts.GetServiceCredential()
	if credentials != nil && len(credentials.Mrn) > 0 {
		s.Client.ParentMrn = credentials.GetParentMrn()
		s.Client.Registered = true
		s.Client.ServiceAccount = credentials.Mrn
		s.Client.Mrn = opts.AgentMrn
		if s.Client.Mrn == "" {
			s.Client.Mrn = "no managed client"
		}

		certAuth, err := upstream.NewServiceAccountRangerPlugin(credentials)
		if err != nil {
			return s, cli_errors.NewCommandError(errors.Wrap(err, "invalid credentials"), ConfigurationErrorCode)
		}
		plugins = append(plugins, certAuth)

		// try to ping the server
		client, err := upstream.NewAgentManagerClient(s.Upstream.API.Endpoint, httpClient, plugins...)
		if err == nil {
			_, err = client.PingPong(ctx, &upstream.Ping{})
			if err != nil {
				s.Client.PingPongError = err
			}
		} else {
			s.Client.PingPongError = err
		}
	}

	// The release track updates and providers resolve through. Shown even when
	// it is the default, so a support conversation can establish in one command
	// whether a machine is on pre-releases.
	s.Client.UpdateChannel = config.GetUpdateChannel()

	// Determine the providers URL:
	// 1. If updates_url is set, use updates_url + "/providers"
	// 2. Otherwise, use the default
	if opts.UpdatesURL != "" {
		s.Client.ProvidersURL = opts.UpdatesURL + "/providers"
	} else {
		s.Client.ProvidersURL = providers.DefaultProviderRegistryURL
	}

	// gather installed providers and their version drift up front, so rendering
	// stays a pure, side-effect-free transformation of the Status value
	providersList, err := getProviders(ctx)
	if err != nil {
		log.Warn().Err(err).Msg("failed to get provider info")
	}
	s.Client.Providers = providersList

	if ingest != nil {
		ingestStatus := <-ingest
		s.Ingest = &ingestStatus
	}

	return s, nil
}

// probeIngestEndpoint starts the ingest reachability probe in the background and
// returns the channel its single result arrives on, or nil when there is no
// endpoint to probe (see config.IngestEndpointFor: a self-hosted or otherwise
// non-hosted API endpoint derives none, and the check is skipped rather than
// reported as failing).
//
// The channel is buffered so the probe never blocks on a receiver: if
// checkStatus returns early, the goroutine parks its result and exits, and ctx
// — the command's overall deadline — bounds the request either way.
func probeIngestEndpoint(ctx context.Context, httpClient *http.Client, endpoint string) <-chan health.IngestStatus {
	if endpoint == "" {
		return nil
	}

	results := make(chan health.IngestStatus, 1)
	go func() {
		results <- health.CheckIngestReachable(ctx, httpClient, endpoint)
	}()
	return results
}

type Status struct {
	Client   ClientStatus  `json:"client"`
	Upstream health.Status `json:"upstream"`
	// Ingest is the reachability probe of the endpoint scan uploads are routed
	// through. nil when the check did not run: no ingest endpoint could be
	// derived from the configured API endpoint.
	Ingest *health.IngestStatus `json:"ingest,omitempty"`
}

type ClientStatus struct {
	Timestamp      string              `json:"timestamp,omitempty"`
	Mrn            string              `json:"mrn,omitempty"`
	ServiceAccount string              `json:"service_account,omitempty"`
	ParentMrn      string              `json:"parentMrn,omitempty"`
	Version        string              `json:"version,omitempty"`
	APIVersion     string              `json:"-"`
	LatestVersion  string              `json:"latest_version,omitempty"`
	Build          string              `json:"build,omitempty"`
	Labels         map[string]string   `json:"labels,omitempty"`
	Platform       *inventory.Platform `json:"platform,omitempty"`
	IP             string              `json:"ip,omitempty"`
	Hostname       string              `json:"hostname,omitempty"`
	Registered     bool                `json:"registered,omitempty"`
	PingPongError  error               `json:"pingPongError,omitempty"`
	UpdatesURL     string              `json:"updatesUrl,omitempty"`
	UpdateChannel  string              `json:"updateChannel,omitempty"`
	ProvidersURL   string              `json:"providersUrl,omitempty"`
	ConfigFile     string              `json:"configFile,omitempty"`
	Providers      []ProviderStatus    `json:"-"`
}

// ProviderStatus captures the installed and latest available version of a
// single provider, so the status renderer can show version drift without
// re-querying the registry. Latest is empty when the registry was unreachable.
type ProviderStatus struct {
	Name      string
	Installed string
	Latest    string
	Outdated  bool
}

func (s Status) RenderJson() {
	output, err := json.Marshal(s)
	if err != nil {
		log.Error().Err(err).Msg("could not generate json")
	}
	os.Stdout.Write(output)
}

func (s Status) RenderYaml() {
	output, err := yaml.Marshal(s)
	if err != nil {
		log.Error().Err(err).Msg("could not generate yaml")
	}
	os.Stdout.Write(output)
}

func getProviders(ctx context.Context) ([]ProviderStatus, error) {
	allProviders, err := providers.ListActive()
	if err != nil {
		return nil, err
	}

	result := make([]ProviderStatus, 0, len(allProviders))
	var errCircuitBreaker error
	for _, provider := range allProviders {
		ps := ProviderStatus{Name: provider.Name, Installed: provider.Version}
		if errCircuitBreaker == nil {
			latestVersion, err := providers.LatestVersion(ctx, provider.Name)
			if err != nil {
				// If we get a connection refused or the deadline expires, we assume
				// this will happen for all providers, so we stop checking versions.
				if errors.Is(err, syscall.ECONNREFUSED) ||
					errors.Is(err, context.DeadlineExceeded) ||
					errors.Is(err, context.Canceled) {
					errCircuitBreaker = err
				}
			} else {
				ps.Latest = latestVersion
				if provider.Name != "core" && newerAvailable(provider.Version, latestVersion) {
					ps.Outdated = true
				}
			}
		}
		result = append(result, ps)
	}

	return result, errCircuitBreaker
}
