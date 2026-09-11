// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package cmd

import (
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/health"
)

// update regenerates the golden files: go test ./apps/mql/cmd -run Golden -update
var update = flag.Bool("update", false, "update golden files")

// healthyRegisteredStatus returns a fully-populated Status representing a
// client that is registered, authenticated, on the latest version, and talking
// to a healthy Mondoo Platform. Individual tests mutate copies of it to cover
// the conditional branches (not registered, update available, etc.).
func healthyRegisteredStatus() Status {
	s := Status{
		Client: ClientStatus{
			Timestamp:      "2026-06-29T14:37:00-07:00",
			Version:        "13.25.0",
			APIVersion:     "13",
			LatestVersion:  "13.25.0",
			Platform:       &inventory.Platform{Name: "macos", Version: "26.5.1", Arch: "arm64"},
			Hostname:       "workstation.localdomain",
			IP:             "192.0.2.10",
			Registered:     true,
			Mrn:            "//agents.api.mondoo.app/spaces/test/agents/123",
			ServiceAccount: "//agents.api.mondoo.app/spaces/test/serviceaccounts/abc",
			ParentMrn:      "//captain.api.mondoo.app/spaces/test",
			UpdatesURL:     "https://releases.mondoo.com",
			ProvidersURL:   "https://releases.mondoo.com/providers",
			ConfigFile:     "",
			Providers: []ProviderStatus{
				{Name: "aws", Installed: "13.18.0", Latest: "13.30.0", Outdated: true},
				{Name: "core", Installed: "13.25.0", Latest: "13.25.0", Outdated: false},
				{Name: "os", Installed: "13.22.0", Latest: "13.25.2", Outdated: true},
			},
		},
	}
	s.Upstream.API.Endpoint = "https://us.api.mondoo.com"
	s.Upstream.API.Status = "SERVING"
	s.Upstream.API.Timestamp = "2026-06-29T21:37:00Z"
	s.Upstream.API.Version = "13"
	s.Ingest = &health.IngestStatus{
		Endpoint:   "https://ingest.us.mondoo.com",
		Reachable:  true,
		StatusCode: 404,
		LatencyMs:  41,
	}
	return s
}

func TestRenderCli_NoColorHasNoEscapes(t *testing.T) {
	s := healthyRegisteredStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	assert.NotContains(t, out, "\x1b[", "Color:false output must contain no ANSI escape sequences")
}

func TestRenderCli_HealthSummary_NotRegistered(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.Registered = false
	s.Client.Mrn = ""
	s.Client.ServiceAccount = ""

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "Client")
	assert.Contains(t, out, "not registered")
	assert.Contains(t, out, "action needed")
}

// registeredAuthFailedStatus mirrors a client whose config is present and
// registered, but whose service account was revoked or expired on the platform:
// the ping fails even though the API itself is reachable and SERVING.
func registeredAuthFailedStatus() Status {
	s := healthyRegisteredStatus()
	s.Client.PingPongError = errors.New("rpc error: code = Unauthenticated desc = invalid service account")
	// isolate the auth-failed path: everything else current
	for i := range s.Client.Providers {
		s.Client.Providers[i].Outdated = false
		s.Client.Providers[i].Latest = s.Client.Providers[i].Installed
	}
	return s
}

func TestRenderCli_HealthSummary_AuthFailed(t *testing.T) {
	s := registeredAuthFailedStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	// still registered, but the ping was rejected
	assert.Contains(t, out, "registered")
	assert.Contains(t, out, "authentication failed")
}

func TestRenderCli_Footer_AuthFailed(t *testing.T) {
	s := registeredAuthFailedStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	// footer must flag the error and give an actionable re-registration step
	// rather than the misleading "not registered" line.
	assert.Contains(t, out, "authentication failed")
	assert.Contains(t, out, "exit 1")
	assert.Contains(t, out, "next steps")
	assert.Contains(t, out, "mql login --token <token>")
	assert.Contains(t, out, "fresh token")
	assert.NotContains(t, out, "not registered")
}

func TestRenderCli_HealthSummary_RegisteredAndHealthy(t *testing.T) {
	s := healthyRegisteredStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	// Platform dot reflects a reachable, SERVING API.
	assert.Contains(t, out, "Platform")
	assert.Contains(t, out, "SERVING")
	assert.Contains(t, out, "healthy")
}

func TestRenderCli_HealthSummary_ProvidersStale(t *testing.T) {
	s := healthyRegisteredStatus() // fixture has 2 outdated providers, mql itself current

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "Updates")
	assert.Contains(t, out, "2 providers outdated")
}

func TestRenderCli_HealthSummary_FullyCurrent(t *testing.T) {
	s := healthyRegisteredStatus()
	// mark every provider current
	for i := range s.Client.Providers {
		s.Client.Providers[i].Outdated = false
		s.Client.Providers[i].Latest = s.Client.Providers[i].Installed
	}

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "up to date")
}

func TestRenderCli_SystemSection(t *testing.T) {
	s := healthyRegisteredStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "System")
	assert.Contains(t, out, "workstation.localdomain")
	assert.Contains(t, out, "192.0.2.10")
	assert.Contains(t, out, "macos")
	assert.Contains(t, out, "26.5.1")
	assert.Contains(t, out, "arm64")
}

func TestRenderCli_MqlSection_DefaultsAndCurrent(t *testing.T) {
	s := healthyRegisteredStatus() // version == latest, no config file

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "13.25.0")
	// API version surfaced
	assert.Contains(t, out, "API")
	// no config file loaded => communicates defaults
	assert.Contains(t, out, "defaults")
	assert.Contains(t, out, "https://releases.mondoo.com")
}

func TestRenderCli_MqlSection_ConfigFileShown(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.ConfigFile = "/home/user/.config/mondoo/mondoo.yml"

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "/home/user/.config/mondoo/mondoo.yml")
	assert.NotContains(t, out, "defaults — no config file")
}

func TestRenderCli_PlatformSection_Proxy(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.Proxy = "http://user:xxxxx@proxy.corp:3128"
	s.Client.ProxySource = "system"

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "http://user:xxxxx@proxy.corp:3128")
	assert.Contains(t, out, "(system)")
	assert.NotContains(t, out, "direct connection")

	s.Client.Proxy, s.Client.ProxySource = "", ""
	out = s.RenderCli(RenderOptions{Color: false})
	assert.Contains(t, out, "direct connection")
}

func TestRenderCli_MqlSection_UpdateAvailableShowsArrow(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.Version = "13.22.0"
	s.Client.LatestVersion = "13.25.0"

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "13.22.0")
	assert.Contains(t, out, "13.25.0")
	assert.Contains(t, out, "→")
}

func TestRenderCli_PlatformSection(t *testing.T) {
	s := healthyRegisteredStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "Mondoo Platform")
	assert.Contains(t, out, "https://us.api.mondoo.com")
	assert.Contains(t, out, "SERVING")
	assert.Contains(t, out, "2026-06-29T21:37:00Z")
}

func TestRenderCli_PlatformSection_ClientAheadIsNotAWarning(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.APIVersion = "14" // client updated ahead of the platform
	s.Upstream.API.Version = "13"

	out := s.RenderCli(RenderOptions{Color: false})

	assert.NotContains(t, out, "version mismatch")
	assert.Contains(t, out, "client ahead")
}

func TestRenderCli_PlatformSection_ClientBehindWarns(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.APIVersion = "12" // client trails the platform
	s.Upstream.API.Version = "13"

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "version mismatch")
}

func TestRenderCli_PlatformSection_UnstableClientIsNotAWarning(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.APIVersion = "unstable" // local dev build, no version stamped in
	s.Upstream.API.Version = "13"

	out := s.RenderCli(RenderOptions{Color: false})

	// A dev build is expected to run against any released platform, so it must
	// not be flagged as a mismatch; it's surfaced as a healthy dev build with
	// the same ✓ treatment as an in-sync production release.
	assert.NotContains(t, out, "version mismatch")
	assert.Contains(t, out, "✓ dev build")
}

func TestRenderCli_PlatformSection_NotRegisteredShowsLoginHint(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.Registered = false
	s.Client.Mrn = ""

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "mql login")
}

func TestRenderCli_ProvidersSection_Counts(t *testing.T) {
	s := healthyRegisteredStatus() // 3 installed, 2 outdated, 1 current

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "Providers")
	assert.Contains(t, out, "3 installed")
	assert.Contains(t, out, "2 outdated")
	assert.Contains(t, out, "1 current")
}

func TestRenderCli_ProvidersSection_DriftRows(t *testing.T) {
	s := healthyRegisteredStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "aws")
	assert.Contains(t, out, "13.18.0")
	assert.Contains(t, out, "13.30.0")
	assert.Contains(t, out, "os")
	assert.Contains(t, out, "13.25.2")
}

func TestRenderCli_ProvidersSection_RegistryUnreachable(t *testing.T) {
	s := healthyRegisteredStatus()
	for i := range s.Client.Providers {
		s.Client.Providers[i].Latest = ""
		s.Client.Providers[i].Outdated = false
	}

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "3 installed")
	assert.Contains(t, out, "registry unreachable")
}

func TestRenderCli_Footer_NotRegistered(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.Registered = false
	s.Client.Mrn = ""

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "exit 1")
	assert.Contains(t, out, "next steps")
	assert.Contains(t, out, "mql login")
}

func TestRenderCli_Footer_MultipleOutdatedRecommendsBulkUpdate(t *testing.T) {
	s := healthyRegisteredStatus() // fixture has 2 outdated providers

	out := s.RenderCli(RenderOptions{Color: false})

	// with 2+ outdated, the footer's next step recommends the bulk update
	// (the per-provider install hint still appears in the Providers section)
	assert.Contains(t, out, "next steps")
	assert.Contains(t, out, "mql providers update")
	assert.Contains(t, out, "update 2 outdated providers")
}

func TestRenderCli_Footer_SingleOutdatedKeepsInstallHint(t *testing.T) {
	s := healthyRegisteredStatus()
	// leave exactly one provider outdated
	firstOutdated := false
	for i := range s.Client.Providers {
		if s.Client.Providers[i].Outdated && !firstOutdated {
			firstOutdated = true
			continue
		}
		s.Client.Providers[i].Outdated = false
		s.Client.Providers[i].Latest = s.Client.Providers[i].Installed
	}

	out := s.RenderCli(RenderOptions{Color: false})

	// a single outdated provider keeps the targeted install hint
	assert.Contains(t, out, "mql providers install <name>")
	assert.NotContains(t, out, "mql providers update")
}

// manyCurrentProviders returns a registered status whose providers are all
// current, with long names, so the "✓ current" list is long enough to exercise
// the width budgeting.
func manyCurrentProviders() Status {
	s := healthyRegisteredStatus()
	s.Client.Providers = nil
	for _, name := range []string{
		"ansible", "arista", "atlassian", "aws", "azure", "cloudflare",
		"elasticsearch", "gcp", "github", "gitlab", "google-workspace", "k8s",
		"ms365", "network", "oci", "okta", "opcua", "os", "slack",
		"terraform", "vcd", "vsphere",
	} {
		s.Client.Providers = append(s.Client.Providers,
			ProviderStatus{Name: name, Installed: "13.25.0", Latest: "13.25.0", Outdated: false})
	}
	return s
}

// currentLine returns the "✓ current ..." row from a rendered status screen.
func currentLine(out string) string {
	for ln := range strings.SplitSeq(out, "\n") {
		if strings.Contains(ln, "✓ current") {
			return ln
		}
	}
	return ""
}

func TestRenderCli_CurrentProviders_NarrowWidthCollapses(t *testing.T) {
	s := manyCurrentProviders()

	out := s.RenderCli(RenderOptions{Color: false, Width: 60})

	line := currentLine(out)
	assert.NotEmpty(t, line)
	// the list must be trimmed to fit and the remainder folded into a "+N" marker
	assert.Contains(t, line, "+")
	// the provider list must fit inside the terminal so it doesn't wrap
	assert.LessOrEqual(t, len([]rune(line)), 60, "current-providers line exceeds width: %q", line)
}

func TestRenderCli_CurrentProviders_WideWidthShowsAll(t *testing.T) {
	s := manyCurrentProviders()

	out := s.RenderCli(RenderOptions{Color: false, Width: 500})

	line := currentLine(out)
	assert.NotEmpty(t, line)
	// with room to spare, no provider is dropped
	assert.NotContains(t, line, "+")
	assert.Contains(t, line, "vsphere")
}

func TestRenderCli_BinaryNameDrivesCommandHints(t *testing.T) {
	// stale + unregistered surfaces the login/update hints, so a single render
	// exercises several command strings at once.
	s := staleNotRegisteredStatus()

	out := s.RenderCli(RenderOptions{Color: false, Binary: "cnspec"})

	assert.Contains(t, out, "cnspec login")
	assert.Contains(t, out, "cnspec providers update")
	// no command hint should leak the other binary's name
	assert.NotContains(t, out, "mql login")
	assert.NotContains(t, out, "mql providers")
}

func TestRenderCli_BinaryNameDefaultsToMql(t *testing.T) {
	s := staleNotRegisteredStatus()

	// empty Binary (as the existing tests and goldens use) falls back to "mql"
	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "mql login")
	assert.NotContains(t, out, "cnspec")
}

func TestRenderCli_Footer_AllHealthyHasNoExitBanner(t *testing.T) {
	s := healthyRegisteredStatus()
	for i := range s.Client.Providers {
		s.Client.Providers[i].Outdated = false
		s.Client.Providers[i].Latest = s.Client.Providers[i].Installed
	}

	out := s.RenderCli(RenderOptions{Color: false})

	assert.NotContains(t, out, "exit 1")
	assert.Contains(t, out, "healthy")
}

// staleNotRegisteredStatus mirrors a fresh, unregistered install that is behind
// on both mql and its providers — the worst-case footer with every next step.
func staleNotRegisteredStatus() Status {
	s := healthyRegisteredStatus()
	s.Client.Registered = false
	s.Client.Mrn = ""
	s.Client.ServiceAccount = ""
	s.Client.ParentMrn = ""
	s.Client.Version = "13.22.0"
	s.Client.LatestVersion = "13.25.0"
	return s
}

// ingestUnreachableStatus mirrors the case this check exists for: the API is
// reachable and SERVING, the credentials are good, and the upload endpoint is
// blackholed — so every scan will run to completion and then fail to report.
func ingestUnreachableStatus() Status {
	s := healthyRegisteredStatus()
	// isolate the ingest failure: everything else current
	for i := range s.Client.Providers {
		s.Client.Providers[i].Outdated = false
		s.Client.Providers[i].Latest = s.Client.Providers[i].Installed
	}
	s.Ingest = &health.IngestStatus{
		Endpoint:  "https://ingest.us.mondoo.com",
		Reachable: false,
		LatencyMs: 10000,
		Reason:    health.IngestFailureTimeout,
		Error:     "Get \"https://ingest.us.mondoo.com\": context deadline exceeded",
	}
	return s
}

func TestRenderCli_PlatformSection_IngestReachable(t *testing.T) {
	s := healthyRegisteredStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "Ingest")
	assert.Contains(t, out, "https://ingest.us.mondoo.com")
	assert.Contains(t, out, "✓ reachable")
	assert.Contains(t, out, "41ms")
	// The endpoint answers an unauthenticated probe with 404 by design, so the
	// status code must not be rendered next to the green check.
	assert.NotContains(t, out, "404")
}

func TestRenderCli_PlatformSection_IngestOmittedWhenNotChecked(t *testing.T) {
	// A self-hosted API endpoint derives no ingest host, so the check does not
	// run and the row must not appear at all rather than render as a failure.
	s := healthyRegisteredStatus()
	s.Ingest = nil

	out := s.RenderCli(RenderOptions{Color: false})

	assert.NotContains(t, out, "Ingest")
	assert.NotContains(t, out, "unreachable")
}

func TestRenderCli_IngestUnreachable_RowNamesTheReason(t *testing.T) {
	s := ingestUnreachableStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "https://ingest.us.mondoo.com")
	assert.Contains(t, out, "✗ unreachable")
	assert.Contains(t, out, "timeout")
}

func TestRenderCli_IngestUnreachable_SummaryFlagsPlatform(t *testing.T) {
	s := ingestUnreachableStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	// The API is SERVING, so the summary still reports it reachable — but it
	// must not claim the platform is healthy when uploads cannot land.
	assert.Contains(t, out, "SERVING")
	assert.Contains(t, out, "⚠ ingest unreachable")
	assert.NotContains(t, out, "✓ healthy")
}

func TestRenderCli_IngestUnreachable_FooterNamesTheEgressRule(t *testing.T) {
	s := ingestUnreachableStatus()

	out := s.RenderCli(RenderOptions{Color: false})

	// Nothing about the client is broken, so the next step is the firewall rule
	// to open — as a host:port pair, which is how the rule is written.
	assert.Contains(t, out, "next steps")
	assert.Contains(t, out, "allow egress to ingest.us.mondoo.com:443")
	assert.NotContains(t, out, "all systems healthy")
	// ...but it is not an error state for the exit code, so no exit banner.
	assert.NotContains(t, out, "exit 1")
}

func TestIngestHostPort(t *testing.T) {
	tests := []struct {
		endpoint string
		expected string
	}{
		{"https://ingest.us.mondoo.com", "ingest.us.mondoo.com:443"},
		{"https://ingest.eu.mondoo.com/", "ingest.eu.mondoo.com:443"},
		{"https://ingest.us.mondoo.com:8443", "ingest.us.mondoo.com:8443"},
		{"http://localhost", "localhost:80"},
		// Unparseable input falls back to the raw endpoint rather than to an
		// empty hint.
		{"://nope", "://nope"},
		{"", ""},
	}

	for _, tt := range tests {
		assert.Equalf(t, tt.expected, ingestHostPort(tt.endpoint), "ingestHostPort(%q)", tt.endpoint)
	}
}

func TestRenderCli_Golden(t *testing.T) {
	cases := []struct {
		name   string
		status Status
	}{
		{"healthy_registered", healthyRegisteredStatus()},
		{"stale_not_registered", staleNotRegisteredStatus()},
		{"registered_auth_failed", registeredAuthFailedStatus()},
		{"ingest_unreachable", ingestUnreachableStatus()},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.status.RenderCli(RenderOptions{Color: false})
			golden := filepath.Join("testdata", "status_"+tc.name+".golden")

			if *update {
				require.NoError(t, os.MkdirAll("testdata", 0o755))
				require.NoError(t, os.WriteFile(golden, []byte(got), 0o644))
			}

			want, err := os.ReadFile(golden)
			require.NoError(t, err, "missing golden file; run: go test ./apps/mql/cmd -run Golden -update")
			assert.Equal(t, string(want), got)
		})
	}
}

func TestPadRight_CountsRunesNotBytes(t *testing.T) {
	// "café" is 5 bytes but 4 runes; padding to width 6 must add 2 spaces
	// (rune-based), not 1 (byte-based).
	assert.Equal(t, "café  ", padRight("café", 6))
}

func TestNewerAvailable(t *testing.T) {
	cases := []struct {
		current string
		latest  string
		want    bool
	}{
		// The build stamps a "v"-prefixed version while the release feed reports
		// it without the prefix; these are the same release, not an update.
		{"v13.27.0", "13.27.0", false},
		{"13.27.0", "v13.27.0", false},
		// A locally built binary ahead of the latest release is not outdated.
		{"13.30.0", "13.25.0", false},
		{"v13.30.0", "13.25.0", false},
		// A genuinely newer release is an available update.
		{"13.22.0", "13.25.0", true},
		{"v13.22.0", "13.25.0", true},
		// Equal versions never report an update.
		{"13.25.0", "13.25.0", false},
		// Unparseable versions fall back to an exact string comparison.
		{"unstable", "13.25.0", true},
		{"13.25.0", "13.25.0", false},
	}

	for _, tc := range cases {
		assert.Equalf(t, tc.want, newerAvailable(tc.current, tc.latest),
			"newerAvailable(%q, %q)", tc.current, tc.latest)
	}
}

func TestUpdateAvailable_IgnoresVPrefix(t *testing.T) {
	// v-prefixed running version vs. bare latest is the same release: no update.
	s := healthyRegisteredStatus()
	s.Client.Version = "v13.27.0"
	s.Client.LatestVersion = "13.27.0"

	assert.False(t, s.updateAvailable())

	out := s.RenderCli(RenderOptions{Color: false})
	assert.NotContains(t, out, "update recommended")
}

func TestUpdateAvailable_ClientAheadIsNotOutdated(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.Version = "13.30.0"
	s.Client.LatestVersion = "13.25.0"

	assert.False(t, s.updateAvailable())

	out := s.RenderCli(RenderOptions{Color: false})
	assert.NotContains(t, out, "update recommended")
}

func TestUpdateAvailable_UnstableDevBuildDoesNotNag(t *testing.T) {
	// A binary built locally from source stamps a "v"-prefixed git-describe
	// version that surfaces as an "unstable" API version; it must not suggest an
	// update even when a newer release exists.
	s := healthyRegisteredStatus()
	s.Client.APIVersion = "unstable"
	s.Client.Version = "v13.27.0+1234"
	s.Client.LatestVersion = "13.30.0"

	assert.False(t, s.updateAvailable())

	out := s.RenderCli(RenderOptions{Color: false})
	assert.NotContains(t, out, "update recommended")
}

func TestUpdateAvailable_NewerReleaseIsFlagged(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Client.Version = "v13.22.0"
	s.Client.LatestVersion = "13.25.0"

	assert.True(t, s.updateAvailable())

	out := s.RenderCli(RenderOptions{Color: false})
	assert.Contains(t, out, "update recommended")
}

func TestRenderCli_PlatformSection_WarningsAndFeatures(t *testing.T) {
	s := healthyRegisteredStatus()
	s.Upstream.Features = []string{"alpha", "beta"}
	s.Upstream.Warnings = []string{"possible clock skew detected: 45s"}

	out := s.RenderCli(RenderOptions{Color: false})

	assert.Contains(t, out, "alpha, beta")
	assert.Contains(t, out, "possible clock skew detected: 45s")
	assert.Contains(t, out, "⚠")
}
