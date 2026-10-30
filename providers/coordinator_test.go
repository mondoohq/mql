// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"fmt"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cockroachdb/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	pp "go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	gomock "go.uber.org/mock/gomock"
)

func TestShutdown(t *testing.T) {
	ctrl := gomock.NewController(t)
	c := &coordinator{
		runningByID: map[string]*RunningProvider{},
		runtimes:    map[string]*Runtime{},
	}

	for i := range 10 {
		c.runtimes[fmt.Sprintf("runtime-%d", i)] = &Runtime{}

		id := fmt.Sprintf("test-%d", i)

		// Make sure Shutdown is called for all running providers
		mockPlugin := NewMockProviderPlugin(ctrl)
		mockPlugin.EXPECT().Shutdown(gomock.Any()).Times(1).Return(nil, nil)
		c.runningByID[id] = &RunningProvider{
			ID:     id,
			Plugin: mockPlugin,
		}
	}

	c.Shutdown()

	// Make sure all running providers and runtimes are removed
	assert.Empty(t, c.runningByID)
	assert.Empty(t, c.runtimes)
}

func TestRemoveRuntime_AssetMrn(t *testing.T) {
	mrn := "mrn1"
	r := &Runtime{
		Provider: &ConnectedProvider{
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{Mrn: mrn},
			},
		},
	}

	c := &coordinator{
		runningByID: map[string]*RunningProvider{},
		runtimes: map[string]*Runtime{
			mrn:    r,
			"mrn2": r,
		},
	}

	c.RemoveRuntime(r)
	assert.NotContains(t, c.runtimes, mrn)
	assert.Contains(t, c.runtimes, "mrn2")
}

func TestRemoveRuntime_PlatformId(t *testing.T) {
	pId := "platformId1"
	r := &Runtime{
		Provider: &ConnectedProvider{
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{PlatformIds: []string{pId}},
			},
		},
	}

	c := &coordinator{
		runningByID: map[string]*RunningProvider{},
		runtimes: map[string]*Runtime{
			pId:           r,
			"platformId2": r,
		},
	}

	c.RemoveRuntime(r)
	assert.NotContains(t, c.runtimes, pId)
	assert.Contains(t, c.runtimes, "platformId2")
}

func TestRemoveRuntime_StopUnusedProvider(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Setup 1 provider with 1 runtime
	mockPlugin1 := NewMockProviderPlugin(ctrl)
	mockPlugin1.EXPECT().Shutdown(gomock.Any()).Times(1).Return(nil, nil)
	p1 := &RunningProvider{
		ID:     "provider1",
		Plugin: mockPlugin1,
	}
	r1 := &Runtime{
		providers: map[string]*ConnectedProvider{
			"provider1": {Instance: p1},
		},
		Provider: &ConnectedProvider{
			Instance: p1,
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{PlatformIds: []string{"platformId1"}},
			},
		},
	}

	// Setup another provider with another runtime
	mockPlugin2 := NewMockProviderPlugin(ctrl)
	mockPlugin2.EXPECT().Shutdown(gomock.Any()).Times(1).Return(nil, nil)
	p2 := &RunningProvider{
		ID:     "provider2",
		Plugin: mockPlugin2,
	}
	r2 := &Runtime{
		providers: map[string]*ConnectedProvider{
			"provider2": {Instance: p2},
		},
		Provider: &ConnectedProvider{
			Instance: p2,
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{PlatformIds: []string{"platformId2"}},
			},
		},
	}

	c := &coordinator{
		runningByID: map[string]*RunningProvider{
			"provider1": p1,
			"provider2": p2,
		},
		runtimes: map[string]*Runtime{
			"platformId1": r1,
			"platformId2": r2,
		},
		unprocessedRuntimes: []*Runtime{{}},
	}

	// Remove all runtimes
	c.RemoveRuntime(r1)
	c.RemoveRuntime(r2)

	// Verify that all provider are stopped
	assert.Empty(t, c.runningByID)
}

func TestUnprocessedProviders_RemoveClosed(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Setup 1 provider with 1 runtime
	mockPlugin1 := NewMockProviderPlugin(ctrl)
	p1 := &RunningProvider{
		ID:     "provider1",
		Plugin: mockPlugin1,
	}

	c := &coordinator{
		runtimes:    map[string]*Runtime{},
		runningByID: map[string]*RunningProvider{},
		unprocessedRuntimes: []*Runtime{
			{
				isClosed: true,
				providers: map[string]*ConnectedProvider{
					"provider2": {Instance: p1},
				},
				Provider: &ConnectedProvider{
					Instance:   p1,
					Connection: &pp.ConnectRes{},
				},
			},
			{
				providers: map[string]*ConnectedProvider{
					"provider2": {Instance: p1},
				},
				Provider: &ConnectedProvider{
					Instance:   p1,
					Connection: &pp.ConnectRes{},
				},
			},
		},
	}

	c.unsafeRefreshRuntimes()

	// The unprocessed runtimes should be 1 since one of them was closed
	assert.Len(t, c.unprocessedRuntimes, 1)
}

func TestRemoveRuntime_RemoveDeadProvider(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Setup 1 closed provider with 1 runtime
	mockPlugin1 := NewMockProviderPlugin(ctrl)
	p1 := &RunningProvider{
		ID:       "provider1",
		Plugin:   mockPlugin1,
		isClosed: true,
	}
	r1 := &Runtime{
		providers: map[string]*ConnectedProvider{
			"provider1": {Instance: p1},
		},
		Provider: &ConnectedProvider{
			Instance: p1,
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{PlatformIds: []string{"platformId1"}},
			},
		},
	}

	// Setup another provider with another runtime
	r2 := &Runtime{
		providers: map[string]*ConnectedProvider{
			"provider2": {Instance: p1},
		},
		Provider: &ConnectedProvider{
			Instance: p1,
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{PlatformIds: []string{"platformId2"}},
			},
		},
	}

	c := &coordinator{
		runningByID: map[string]*RunningProvider{
			"provider1": p1,
		},
		runtimes: map[string]*Runtime{
			"platformId1": r1,
			"platformId2": r2,
		},
	}

	// Remove 1 runtime
	c.RemoveRuntime(r1)

	// Verify that the provider has been removed because it crashed
	assert.Empty(t, c.runningByID)

	c.RemoveRuntime(r2)
}

func TestRemoveRuntime_UsedProvider(t *testing.T) {
	ctrl := gomock.NewController(t)

	// Setup 1 provider with 1 runtime
	mockPlugin1 := NewMockProviderPlugin(ctrl)
	p1 := &RunningProvider{
		ID:     "provider1",
		Plugin: mockPlugin1,
	}
	r1 := &Runtime{
		providers: map[string]*ConnectedProvider{
			"provider1": {Instance: p1},
		},
		Provider: &ConnectedProvider{
			Instance: p1,
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{PlatformIds: []string{"platformId1"}},
			},
		},
	}

	// Setup another runtime that also uses provider1
	r2 := &Runtime{
		providers: map[string]*ConnectedProvider{
			"provider1": {Instance: p1},
		},
		Provider: &ConnectedProvider{
			Instance: p1,
			Connection: &pp.ConnectRes{
				Asset: &inventory.Asset{PlatformIds: []string{"platformId2"}},
			},
		},
	}

	c := &coordinator{
		runningByID: map[string]*RunningProvider{
			"provider1": p1,
		},
		runtimes: map[string]*Runtime{
			"platformId1": r1,
			"platformId2": r2,
		},
	}

	// Remove the first runtime
	c.RemoveRuntime(r1)

	// Verify that the first provider is stopped
	assert.Contains(t, c.runningByID, "provider1")
}

func TestUnsafeStartProviderSchemaOnly(t *testing.T) {
	schemaOnlyProvider := func(path string) *Provider {
		return &Provider{
			Provider:  &pp.Provider{Name: "testp", ID: "testp", Version: "1.2.3"},
			Path:      path,
			HasBinary: false,
		}
	}

	newCoordinator := func(p *Provider) *coordinator {
		c := &coordinator{
			runningByID: map[string]*RunningProvider{},
			runtimes:    map[string]*Runtime{},
		}
		c.SetProviders(Providers{p.ID: p})
		return c
	}

	// Without these checks the exec below them fails with an obscure
	// "fork/exec ...: no such file or directory" instead of saying what is
	// actually wrong with the installation.
	t.Run("auto-update disabled", func(t *testing.T) {
		dir := useTestProviderPath(t, &fakeRegistry{latest: "1.2.3"})
		c := newCoordinator(schemaOnlyProvider(filepath.Join(dir, "testp")))

		_, err := c.unsafeStartProvider("testp", UpdateProvidersConfig{Enabled: false})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "installed schema-only and has no binary to run")
	})

	t.Run("auto-update on but the completing download fails", func(t *testing.T) {
		reg := &fakeRegistry{latest: "1.2.3", downloadErr: errors.New("registry is down")}
		dir := useTestProviderPath(t, reg)
		c := newCoordinator(schemaOnlyProvider(filepath.Join(dir, "testp")))

		_, err := c.unsafeStartProvider("testp", UpdateProvidersConfig{Enabled: true})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "completing its installation failed")
		assert.Equal(t, 1, reg.downloads, "it must have tried to complete the install")
	})
}

// TestClassifyProviderStartFailure pins the classification of real start
// failure shapes: the fork/exec errors come from os/exec, the handshake and
// timeout messages verbatim from hashicorp/go-plugin's client.go, the
// schema-only and not-found messages from this package.
func TestClassifyProviderStartFailure(t *testing.T) {
	cases := []struct {
		name string
		msg  string
		want string
	}{
		{
			// The shape from server#22011: binary killed before writing its
			// handshake line (security software, OOM), go-plugin reads nothing.
			name: "handshake failure",
			msg: "failed to initialize plugin client: Unrecognized remote plugin message: \n" +
				"Failed to read any lines from plugin's stdout\nThis usually means\n" +
				"  the plugin was not compiled for this architecture,\n" +
				"  the plugin is missing dynamic-link libraries necessary to run,\n" +
				"  the plugin is not executable by this process due to file permissions, or\n" +
				"  the plugin failed to negotiate the initial go-plugin protocol handshake\n",
			want: "handshake",
		},
		{
			name: "plugin start timeout",
			msg:  "failed to initialize plugin client: timeout while waiting for plugin to start",
			want: "timeout",
		},
		{
			name: "wrong architecture",
			msg:  "failed to initialize plugin client: fork/exec /opt/mondoo/providers/os/os: exec format error",
			want: "exec_format",
		},
		{
			name: "binary not executable",
			msg:  "failed to initialize plugin client: fork/exec /opt/mondoo/providers/os/os: permission denied",
			want: "permission",
		},
		{
			name: "binary missing",
			msg:  "failed to initialize plugin client: fork/exec /opt/mondoo/providers/os/os: no such file or directory",
			want: "missing_binary",
		},
		{
			name: "other exec failure",
			msg:  "failed to initialize plugin client: fork/exec /opt/mondoo/providers/os/os: too many open files",
			want: "exec",
		},
		{
			name: "schema-only install, auto-update off",
			msg:  "provider 'os' is installed schema-only and has no binary to run; install it fully or enable auto-update",
			want: "incomplete_install",
		},
		{
			name: "schema-only install, completing download failed",
			msg:  "provider 'os' is installed schema-only and completing its installation failed",
			want: "incomplete_install",
		},
		{
			name: "provider not installed",
			msg:  "cannot find provider os",
			want: "not_installed",
		},
		{
			// "permission denied" or "no such file or directory" outside a
			// fork/exec error (e.g. reading the resources json) must not be
			// classified as a binary problem.
			name: "unrelated file error stays unclassified",
			msg:  "failed to load provider os resources info: failed to read provider resources json from /x/os.resources.json: open /x/os.resources.json: no such file or directory",
			want: "",
		},
		{
			name: "unknown failure stays unclassified",
			msg:  "something else entirely",
			want: "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyProviderStartFailure(tc.msg))
		})
	}
}

func TestGetRunningProvider_ReportsStartFailureOnce(t *testing.T) {
	type report struct {
		msg  string
		tags map[string]string
	}
	var reports []report
	orig := sendProviderStartFailureFn
	sendProviderStartFailureFn = func(errMsg string, tags map[string]string) {
		reports = append(reports, report{msg: errMsg, tags: tags})
	}
	t.Cleanup(func() { sendProviderStartFailureFn = orig })

	// A provider that claims to have a binary but whose path doesn't exist:
	// the exec fails and GetRunningProvider surfaces a genuine start failure.
	providerPath := filepath.Join(t.TempDir(), "testp")
	p := &Provider{
		Provider:  &pp.Provider{Name: "testp", ID: "testp", Version: "1.2.3"},
		Path:      providerPath,
		HasBinary: true,
		Schema:    &resources.Schema{},
	}
	c := &coordinator{
		runningByID: map[string]*RunningProvider{},
		runtimes:    map[string]*Runtime{},
	}
	c.SetProviders(Providers{p.ID: p})

	_, err := c.GetRunningProvider("testp", UpdateProvidersConfig{Enabled: false})
	require.Error(t, err)

	require.Len(t, reports, 1)
	assert.Contains(t, reports[0].msg, "failed to initialize plugin client")
	// The report must not carry the host-local install path.
	assert.NotContains(t, reports[0].msg, providerPath)
	assert.Contains(t, reports[0].msg, "<providers>/testp")
	assert.Equal(t, "provider_start_failure", reports[0].tags["reportKind"])
	assert.Equal(t, "testp", reports[0].tags["provider"])
	assert.Equal(t, "1.2.3", reports[0].tags["providerVersion"])
	assert.Equal(t, "missing_binary", reports[0].tags["failureKind"])
	assert.Equal(t, runtime.GOOS, reports[0].tags["os"])
	assert.Equal(t, runtime.GOARCH, reports[0].tags["arch"])

	// A broken provider is retried on every asset of an inventory; the
	// repeat failure must not send a second report.
	_, err = c.GetRunningProvider("testp", UpdateProvidersConfig{Enabled: false})
	require.Error(t, err)
	assert.Len(t, reports, 1, "a repeated start failure for the same provider must not re-report")
}

// TestStartFailureDiagnostics covers the stderr-tail half of the start-failure
// diagnostics (the exit-disposition half is formatExitStatus, tested with the
// other exit-status helpers). The tail is what carries the dynamic linker's
// "cannot open shared object file" lines for the missing-libraries cause.
func TestStartFailureDiagnostics(t *testing.T) {
	t.Run("nothing observed, nothing appended", func(t *testing.T) {
		assert.Equal(t, "", startFailureDiagnostics(nil, nil))
	})

	t.Run("stderr tail is appended", func(t *testing.T) {
		got := startFailureDiagnostics(nil, []string{
			"error while loading shared libraries: libxyz.so.1",
			"cannot open shared object file: No such file or directory",
		})
		assert.Equal(t, "\nplugin stderr:\nerror while loading shared libraries: libxyz.so.1\ncannot open shared object file: No such file or directory", got)
	})

	t.Run("stderr tail is bounded", func(t *testing.T) {
		lines := make([]string, 30)
		for i := range lines {
			lines[i] = fmt.Sprintf("line-%d", i)
		}
		got := startFailureDiagnostics(nil, lines)
		// Keeps the LAST lines: with a line budget, the lines printed just
		// before the process died say more than the startup banner.
		assert.Contains(t, got, "line-29")
		assert.NotContains(t, got, "line-9\n")
		assert.Contains(t, got, "truncated")
	})
}

// TestScrubStartFailureReport pins the redaction of host-identifying detail
// from reports sent upstream: the provider install path (which on a user
// install sits under the home directory and names the user), the home
// directory anywhere else in the message (e.g. in linker stderr lines), and
// the local user/group names go-plugin prints in its "Additional notes"
// block. The local log line keeps the full detail; only the report is
// scrubbed. Message shapes are copied from real go-plugin output.
func TestScrubStartFailureReport(t *testing.T) {
	const home = "/Users/jsmith"
	const providerPath = "/Users/jsmith/.config/mondoo/providers/os"

	t.Run("fork-exec path and go-plugin notes", func(t *testing.T) {
		msg := "failed to initialize plugin client: fork/exec /Users/jsmith/.config/mondoo/providers/os/os: exec format error\n" +
			"\nAdditional notes about plugin:\n" +
			"  Path: /Users/jsmith/.config/mondoo/providers/os/os\n" +
			"  Mode: -rwxr-xr-x\n" +
			"  Owner: 501 [jsmith] (current: 501 [jsmith])\n" +
			"  Group: 0 [wheel] (current: 20 [staff])\n"
		got := scrubStartFailureReport(msg, providerPath, home)
		assert.NotContains(t, got, "jsmith")
		assert.NotContains(t, got, "wheel")
		assert.Contains(t, got, "fork/exec <providers>/os/os: exec format error")
		assert.Contains(t, got, "  Path: <providers>/os/os\n")
		assert.Contains(t, got, "  Owner: 501 (current: 501)\n")
		assert.Contains(t, got, "  Group: 0 (current: 20)\n")
	})

	t.Run("home directory in stderr lines", func(t *testing.T) {
		msg := "plugin stderr:\ndyld: Library not loaded: /Users/jsmith/lib/libtest.dylib"
		got := scrubStartFailureReport(msg, providerPath, home)
		assert.Equal(t, "plugin stderr:\ndyld: Library not loaded: ~/lib/libtest.dylib", got)
	})

	t.Run("negative uid keeps its id, drops the name", func(t *testing.T) {
		msg := "  Owner: -1 [nobody] (current: -1 [nobody])\n"
		got := scrubStartFailureReport(msg, providerPath, home)
		assert.Equal(t, "  Owner: -1 (current: -1)\n", got)
	})

	t.Run("empty inputs scrub nothing", func(t *testing.T) {
		msg := "failed to start provider 'os': cannot find provider os"
		assert.Equal(t, msg, scrubStartFailureReport(msg, "", ""))
	})
}

// TestEnrichStartFailure pins two properties of the diagnostics wrapper: the
// original error chain stays intact (errors.Is must keep working through the
// enrichment), and an error with nothing observed is returned unchanged.
func TestEnrichStartFailure(t *testing.T) {
	sentinel := errors.New("boom")
	wrapped := fmt.Errorf("failed to initialize plugin client: %w", sentinel)

	t.Run("preserves the error chain", func(t *testing.T) {
		got := enrichStartFailure(wrapped, nil, []string{"dyld: Library not loaded"})
		assert.ErrorIs(t, got, sentinel)
		assert.Contains(t, got.Error(), "failed to initialize plugin client: boom")
		assert.Contains(t, got.Error(), "plugin stderr:\ndyld: Library not loaded")
	})

	t.Run("nothing observed returns the error unchanged", func(t *testing.T) {
		got := enrichStartFailure(wrapped, nil, nil)
		assert.Same(t, wrapped, got)
	})
}
