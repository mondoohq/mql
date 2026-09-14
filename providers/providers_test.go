// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/cli/config"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// testPlugin answers heartbeats through a real plugin.Service, the way a
// provider binary does. The Service has to be a pointer built by NewService
// rather than an embedded zero value: an unconstructed Service has no watchdog
// stop channel, so once a heartbeat arms the watchdog nothing can retire it,
// and a few windows later it os.Exit()s the process it is running in - here
// the test binary itself, killing whichever unrelated test is running then.
type testPlugin struct {
	*plugin.Service
}

func (t *testPlugin) Connect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, nil
}

func (t *testPlugin) MockConnect(req *plugin.ConnectReq, callback plugin.ProviderCallback) (*plugin.ConnectRes, error) {
	return nil, nil
}

func (t *testPlugin) ParseCLI(req *plugin.ParseCLIReq) (*plugin.ParseCLIRes, error) {
	return nil, nil
}

func (t *testPlugin) Shutdown(req *plugin.ShutdownReq) (*plugin.ShutdownRes, error) {
	// sleep more than the heartbeat interval to ensure that even if shutting down
	// the provider can still respond to heartbeats
	time.Sleep(10 * time.Second)
	// hand off to the real Service: it retires the heartbeat watchdog, which
	// would otherwise reap this process once the parent stops beating.
	return t.Service.Shutdown(req)
}

func (t *testPlugin) GetData(req *plugin.DataReq) (*plugin.DataRes, error) {
	return nil, nil
}

func (t *testPlugin) StoreData(req *plugin.StoreReq) (*plugin.StoreRes, error) {
	return nil, nil
}

func TestProviderShutdown(t *testing.T) {
	s := &RunningProvider{
		Plugin:      &testPlugin{plugin.NewService()},
		interval:    500 * time.Millisecond,
		gracePeriod: 500 * time.Millisecond,
	}
	hbtCtx, hbtCancel := context.WithCancel(context.Background())
	s.hbCancelFunc = hbtCancel
	err := s.heartbeat(hbtCtx, hbtCancel)
	require.NoError(t, err)
	require.False(t, s.isCloseOrShutdown())
	// the shutdown here takes 10 seconds, whereas the heartbeat interval is every second.
	// this means that this provider gets multiple heartbeats while shutting down
	err = s.Shutdown()
	require.NoError(t, err)
	require.True(t, s.isCloseOrShutdown())
}

// TestProvider_LoadResources_ConcurrentIsRaceFree exercises the lazy
// schema load path that callers like installDependencies and the
// coordinator now share. Run with -race to verify the per-Provider mutex
// inside LoadResources serializes the write to p.Schema and the reads
// after the call observe a single consistent schema value.
func TestProvider_LoadResources_ConcurrentIsRaceFree(t *testing.T) {
	origFs := config.AppFs
	config.AppFs = afero.NewMemMapFs()
	t.Cleanup(func() { config.AppFs = origFs })

	const providerDir = "/providers/test"
	const providerName = "test"
	const resourcesJSON = `{"resources":{"test.foo":{"id":"test.foo","name":"test.foo","fields":{}}}}`
	require.NoError(t, afero.WriteFile(
		config.AppFs,
		providerDir+"/"+providerName+".resources.json",
		[]byte(resourcesJSON),
		0o644,
	))

	p := &Provider{
		Provider: &plugin.Provider{Name: providerName},
		Path:     providerDir,
	}

	const goroutines = 32
	var (
		wg       sync.WaitGroup
		start    = make(chan struct{})
		errCount atomic.Int32
	)
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			<-start
			if err := p.LoadResources(); err != nil {
				errCount.Add(1)
				t.Errorf("LoadResources: %v", err)
			}
		}()
	}
	close(start)
	wg.Wait()

	require.Zero(t, errCount.Load(), "no goroutine should fail")
	require.NotNil(t, p.Schema, "Schema must be populated after LoadResources")
	// AllResources is one of the methods callers invoke on the loaded
	// schema; calling it here lets the race detector flag any read that
	// isn't synchronized-after the (single) write inside the lock.
	require.NotEmpty(t, p.Schema.AllResources(), "schema resources must be parsed")
}

func TestOsRetry_RetryableError(t *testing.T) {
	funcCounter := 0
	testFunc := func() error {
		funcCounter++
		return syscall.EAGAIN
	}
	assert.NoError(t, osRetry(testFunc, 2))
	assert.Equal(t, 2, funcCounter)
}

func TestInstallIO(t *testing.T) {
	confJSON := []byte(`{"Name":"testp","Version":"1.2.3"}`)
	schemaJSON := []byte(`{"resources":{}}`)

	t.Run("schema-only archive", func(t *testing.T) {
		archive, err := buildTarXz(map[string][]byte{
			"testp.json":           confJSON,
			"testp.resources.json": schemaJSON,
		})
		require.NoError(t, err)

		installed, err := InstallIO(io.NopCloser(bytes.NewReader(archive)), InstallConf{Dst: t.TempDir()})
		require.NoError(t, err)
		require.Len(t, installed, 1)
		assert.Equal(t, "testp", installed[0].Name)
		assert.Equal(t, "1.2.3", installed[0].Version)
		assert.False(t, installed[0].HasBinary)
	})

	t.Run("archive with binary", func(t *testing.T) {
		archive, err := buildTarXz(map[string][]byte{
			"testp":                []byte(`fake-binary`),
			"testp.json":           confJSON,
			"testp.resources.json": schemaJSON,
		})
		require.NoError(t, err)

		installed, err := InstallIO(io.NopCloser(bytes.NewReader(archive)), InstallConf{Dst: t.TempDir()})
		require.NoError(t, err)
		require.Len(t, installed, 1)
		assert.Equal(t, "testp", installed[0].Name)
		assert.True(t, installed[0].HasBinary)
	})

	t.Run("archive without config errors", func(t *testing.T) {
		archive, err := buildTarXz(map[string][]byte{
			"testp.resources.json": schemaJSON,
		})
		require.NoError(t, err)

		_, err = InstallIO(io.NopCloser(bytes.NewReader(archive)), InstallConf{Dst: t.TempDir()})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot find testp.json")
	})
}

// fakeRegistry serves provider archives from memory so the install paths can
// be exercised without reaching releases.mondoo.com.
type fakeRegistry struct {
	latest      string
	archive     []byte
	confJSON    []byte
	schemaJSON  []byte
	downloadErr error
	downloads   int
}

func (r *fakeRegistry) GetLatestVersion(ctx context.Context, name string) (string, error) {
	return r.latest, nil
}

func (r *fakeRegistry) DownloadProvider(ctx context.Context, name, version, os, arch string) (io.ReadCloser, error) {
	r.downloads++
	if r.downloadErr != nil {
		return nil, r.downloadErr
	}
	return io.NopCloser(bytes.NewReader(r.archive)), nil
}

func (r *fakeRegistry) DownloadProviderMetadata(ctx context.Context, name, version string) ([]byte, []byte, error) {
	if r.downloadErr != nil {
		return nil, nil, r.downloadErr
	}
	return r.confJSON, r.schemaJSON, nil
}

// useTestProviderPath installs into a temp directory and serves downloads from
// the given registry, restoring the globals it swaps when the test ends.
func useTestProviderPath(t *testing.T, reg ProviderRegistry) string {
	t.Helper()
	dir := t.TempDir()

	origDefault, origCustom := DefaultPath, CustomProviderPath
	origRegistry, origCache := registry, CachedProviders

	// DefaultPath is where installs land; CustomProviderPath is what ListAll
	// reads, and setting it makes ListAll ignore the system and home paths, so
	// the test never sees the machine's real providers.
	DefaultPath = dir
	CustomProviderPath = dir
	SetProviderRegistry(reg)
	CachedProviders = nil

	t.Cleanup(func() {
		DefaultPath, CustomProviderPath = origDefault, origCustom
		SetProviderRegistry(origRegistry)
		CachedProviders = origCache
	})
	return dir
}

func TestTryProviderUpdateCompletesSchemaOnlyInstall(t *testing.T) {
	const name = "testp"
	const version = "1.2.3"
	confJSON := []byte(`{"Name":"testp","ID":"testp","Version":"1.2.3"}`)
	schemaJSON := []byte(`{"resources":{}}`)

	archive, err := buildTarXz(map[string][]byte{
		name:                     []byte(`fake-binary`),
		name + ".json":           confJSON,
		name + ".resources.json": schemaJSON,
	})
	require.NoError(t, err)

	reg := &fakeRegistry{latest: version, archive: archive, confJSON: confJSON, schemaJSON: schemaJSON}
	dir := useTestProviderPath(t, reg)
	binPath := filepath.Join(dir, name, name)

	schemaOnly, err := InstallSchemaOnly(name, version)
	require.NoError(t, err)
	require.False(t, schemaOnly.HasBinary, "a schema-only install has no binary")
	require.NoFileExists(t, binPath)

	// The schema is already current, so without the HasBinary check the
	// refresh logic would report the provider as up to date and return it
	// unchanged — still unusable.
	completed, err := TryProviderUpdate(schemaOnly, UpdateProvidersConfig{Enabled: true})
	require.NoError(t, err)

	assert.True(t, completed.HasBinary, "the install must be completed with its binary")
	assert.Equal(t, version, completed.Version, "the pinned version must be kept")
	assert.FileExists(t, binPath)
	assert.Equal(t, 1, reg.downloads)
}

func TestTryProviderUpdateSchemaOnlyDownloadFails(t *testing.T) {
	reg := &fakeRegistry{latest: "1.2.3", downloadErr: errors.New("registry is down")}
	dir := useTestProviderPath(t, reg)

	schemaOnly := &Provider{
		Provider:  &plugin.Provider{Name: "testp", ID: "testp", Version: "1.2.3"},
		Path:      filepath.Join(dir, "testp"),
		HasBinary: false,
	}

	_, err := TryProviderUpdate(schemaOnly, UpdateProvidersConfig{Enabled: true})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "registry is down")
}

func TestArchiveFileName(t *testing.T) {
	tests := []struct {
		name     string
		entry    string
		expected string
		wantErr  bool
	}{
		{"plain binary", "aws", "aws", false},
		{"windows binary", "aws.exe", "aws.exe", false},
		{"config", "aws.json", "aws.json", false},
		{"schema", "aws.resources.json", "aws.resources.json", false},
		{"leading dot slash", "./aws.json", "aws.json", false},
		{"parent directory", "../aws.json", "", true},
		{"nested parent directory", "../../etc/cron.d/mondoo", "", true},
		{"subdirectory", "nested/aws.json", "", true},
		{"absolute path", "/etc/cron.d/mondoo", "", true},
		{"parent only", "..", "", true},
		{"current directory", ".", "", true},
		{"empty", "", "", true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := archiveFileName(test.entry)
			if test.wantErr {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, test.expected, res)
		})
	}
}

func TestInstallIORejectsPathsOutsideDestination(t *testing.T) {
	// the unpack directory is created inside Dst, so an entry has to climb
	// two levels to land outside of it
	root := t.TempDir()
	dst := filepath.Join(root, "providers")
	escapee := filepath.Join(root, "escaped.json")

	archive, err := buildTarXz(map[string][]byte{
		"../../escaped.json": []byte(`{"name":"escaped"}`),
	})
	require.NoError(t, err)

	_, err = InstallIO(io.NopCloser(bytes.NewReader(archive)), InstallConf{Dst: dst})
	require.Error(t, err)

	_, err = os.Stat(escapee)
	assert.True(t, os.IsNotExist(err), "archive wrote outside the destination directory")
}

// A builtin provider ships inside the executor, so a dependency on one must
// never reach the installer. `os` and `vsphere` declare `import core`, which
// records core in Schema.Dependencies (ADR 042); before the guard in
// installDependencies that reached Install("core") and tried to download a
// provider that is compiled in.
func TestInstallDependenciesSkipsBuiltins(t *testing.T) {
	coreID := ""
	for id := range builtinProviders {
		if strings.HasSuffix(id, "/core") {
			coreID = id
			break
		}
	}
	require.NotEmpty(t, coreID, "core must be registered as a builtin")

	provider := &Provider{
		Provider: &plugin.Provider{Name: "os", ID: "go.mondoo.com/mql/providers/os"},
		Schema: &resources.Schema{
			Dependencies: map[string]*resources.ProviderInfo{
				"core": {Id: coreID, Name: "core"},
			},
		},
	}

	// deliberately empty: this is the embedder case, where ListAll returns
	// without builtins because no provider paths are configured. The guard has
	// to hold from the dependency's own identity, not from what is installed.
	existing := Providers{}

	require.NoError(t, installDependencies(provider, existing))
	assert.Empty(t, existing, "no provider should have been installed")
}

func TestValidateDeclaredPeers(t *testing.T) {
	caller := &Provider{
		Provider: &plugin.Provider{
			Name: "os", ID: "go.mondoo.com/mql/providers/os",
			Requires: []plugin.ProviderDep{
				{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "13.0.0"},
			},
		},
	}
	peer := func(v string) Providers {
		return Providers{"n": {Provider: &plugin.Provider{
			Name: "network", ID: "go.mondoo.com/mql/providers/network", Version: v,
		}}}
	}

	assert.NoError(t, validateDeclaredPeers(caller, peer("13.3.0")))
	assert.NoError(t, validateDeclaredPeers(caller, peer("13.0.0")))

	// An unstamped build reports its line with `rolling` as build metadata
	// (mql.GetVersion), which orders equal to the bare release. It used to be
	// spelled `-rolling`, which orders *behind* the release, so every developer
	// running from source hit "requires core >= 13.0.0, but v13.0.0-rolling is
	// installed" for a build of the very tree that declares the floor.
	assert.NoError(t, validateDeclaredPeers(caller, peer("v13.0.0+rolling")))
	assert.NoError(t, validateDeclaredPeers(caller, peer("v13.4.0+rolling")))
	// still an older line, marker or not
	assert.Error(t, validateDeclaredPeers(caller, peer("v12.9.9+rolling")))

	// The preview line stamps providers with a semver pre-release segment. It
	// clears a floor on an older major because the major dominates the
	// comparison: 14.0.0-rc.1 > 13.0.0. That is what lets preview providers
	// ship while the declared floors still name the stable line.
	assert.NoError(t, validateDeclaredPeers(caller, peer("14.0.0-rc.1")))

	// A pre-release orders behind its own release (SemVer 11), so raising a
	// floor to the major currently being previewed refuses every provider on
	// that line until it goes GA -- including the one it ships with. Floors
	// stay on the previous major for the duration of a preview.
	previewFloor := &Provider{
		Provider: &plugin.Provider{
			Name: "os", ID: "go.mondoo.com/mql/providers/os",
			Requires: []plugin.ProviderDep{
				{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "14.0.0"},
			},
		},
	}
	assert.Error(t, validateDeclaredPeers(previewFloor, peer("14.0.0-rc.1")),
		"a floor on the major being previewed refuses its own pre-releases")
	assert.NoError(t, validateDeclaredPeers(previewFloor, peer("14.0.0")))

	// not installed: not reported here, it fails later when something needs it
	assert.NoError(t, validateDeclaredPeers(caller, Providers{}))
	// unknown version is not evidence of a mismatch
	assert.NoError(t, validateDeclaredPeers(caller, peer("")))

	err := validateDeclaredPeers(caller, peer("12.4.0"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires network >= 13.0.0")
	assert.Contains(t, err.Error(), "12.4.0 is installed")
}
