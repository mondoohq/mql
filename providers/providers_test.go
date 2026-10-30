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
	for range goroutines {
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

// A provider update has to pull along the peers it declares a floor for.
// Before this, installDependencies only installed peers that were missing: a
// scan on a host whose providers had not been updated in a while installed
// the newer `os`, found the already-installed `network` below the floor the
// new `os` declares, and refused to start with "requires network >= 13.4.0,
// but 13.2.4 is installed" until the user ran `providers update` by hand.
func TestInstallDependenciesUpdatesOutdatedPeer(t *testing.T) {
	reg, dir, caller, stale := outdatedPeerFixture(t)
	const floor = "13.4.0"
	existing := Providers{caller.ID: caller, stale.ID: stale}

	require.NoError(t, installDependencies(caller, existing))

	assert.Equal(t, 1, reg.downloads, "the outdated peer is downloaded once")
	assert.FileExists(t, filepath.Join(dir, "network", "network.json"))
	peer := existing.Lookup(ProviderLookup{ProviderName: "network"})
	require.NotNil(t, peer)
	assert.Equal(t, floor, peer.Version)

	// The stale entry is keyed by its old ID, so adding the new one beside it
	// would leave two providers named network and a name lookup could still
	// return the old one.
	networks := 0
	for _, p := range existing {
		if p.Name == "network" {
			networks++
		}
	}
	assert.Equal(t, 1, networks, "the stale entry is replaced, not kept beside the new one")
}

// Runtime.AddConnection takes its provider list from the coordinator, as a
// clone of the published snapshot, once per connection. The snapshot was
// published before the peer was updated, so unless the update republishes
// it, every one of those callers finds the old version and installs the peer
// again: one scan downloaded network four times.
func TestInstallDependenciesPublishesUpdatedPeer(t *testing.T) {
	reg, _, caller, stale := outdatedPeerFixture(t)
	const floor = "13.4.0"

	orig := Coordinator.Providers()
	t.Cleanup(func() { Coordinator.SetProviders(orig) })
	Coordinator.SetProviders(Providers{caller.ID: caller, stale.ID: stale})

	require.NoError(t, installDependencies(caller, Coordinator.Providers()))

	published := Coordinator.Providers().Lookup(ProviderLookup{ProviderName: "network"})
	require.NotNil(t, published)
	assert.Equal(t, floor, published.Version, "the published list carries the update")

	require.NoError(t, installDependencies(caller, Coordinator.Providers()))
	assert.Equal(t, 1, reg.downloads, "a later caller with a fresh clone does not download again")
}

// outdatedPeerFixture is the reproduction in miniature: a registry serving
// network at the floor, and an os that declares that floor over a network
// installed below it. The installed network carries the ID that older
// releases had, which is what a host that has not updated in a while has on
// disk; it is found by name.
func outdatedPeerFixture(t *testing.T) (reg *fakeRegistry, dir string, caller, stale *Provider) {
	t.Helper()
	const floor = "13.4.0"
	confJSON := []byte(`{"Name":"network","ID":"go.mondoo.com/mql/providers/network","Version":"` + floor + `"}`)
	archive, err := buildTarXz(map[string][]byte{
		"network":                []byte(`fake-binary`),
		"network.json":           confJSON,
		"network.resources.json": []byte(`{"resources":{}}`),
	})
	require.NoError(t, err)
	reg = &fakeRegistry{latest: floor, archive: archive, confJSON: confJSON}
	dir = useTestProviderPath(t, reg)

	caller = &Provider{
		Provider: &plugin.Provider{
			Name: "os", ID: "go.mondoo.com/mql/providers/os", Version: "14.0.0",
			Requires: []plugin.ProviderDep{
				{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: floor},
			},
		},
		Schema: &resources.Schema{
			Dependencies: map[string]*resources.ProviderInfo{
				"network": {Id: "go.mondoo.com/mql/providers/network", Name: "network"},
			},
		},
	}
	stale = &Provider{Provider: &plugin.Provider{
		Name: "network", ID: "go.mondoo.com/cnquery/v9/providers/network", Version: "13.2.4",
	}}
	return reg, dir, caller, stale
}

// A peer that meets the floor is left alone: no download, same version.
func TestInstallDependenciesKeepsCurrentPeer(t *testing.T) {
	reg := &fakeRegistry{latest: "13.9.0"}
	useTestProviderPath(t, reg)

	caller := &Provider{
		Provider: &plugin.Provider{
			Name: "os", ID: "go.mondoo.com/mql/providers/os",
			Requires: []plugin.ProviderDep{
				{ID: "go.mondoo.com/mql/providers/network", Name: "network", MinVersion: "13.4.0"},
			},
		},
		Schema: &resources.Schema{
			Dependencies: map[string]*resources.ProviderInfo{
				"network": {Id: "go.mondoo.com/mql/providers/network", Name: "network"},
			},
		},
	}
	peer := &Provider{Provider: &plugin.Provider{
		Name: "network", ID: "go.mondoo.com/mql/providers/network", Version: "13.4.0",
	}}
	existing := Providers{caller.ID: caller, peer.ID: peer}

	require.NoError(t, installDependencies(caller, existing))
	assert.Equal(t, 0, reg.downloads, "a peer at the floor is not downloaded")
	assert.Equal(t, "13.4.0", existing.Lookup(ProviderLookup{ProviderName: "network"}).Version)
}

// When the registry's latest release is itself below the floor, downloading
// it cannot help: the peer is left alone and the floor check reports the
// mismatch as before.
func TestInstallDependenciesSkipsPeerUpdateWhenLatestIsBelowFloor(t *testing.T) {
	reg, _, caller, stale := outdatedPeerFixture(t)
	reg.latest = "13.3.0"
	existing := Providers{caller.ID: caller, stale.ID: stale}

	err := installDependencies(caller, existing)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires network >= 13.4.0, but 13.2.4 is installed")
	assert.Equal(t, 0, reg.downloads, "a release that cannot meet the floor is not downloaded")
}

// A builtin ships inside this executor, so an outdated one cannot be fixed by
// downloading a provider. It is reported by the floor check, never installed.
func TestInstallDependenciesNeverInstallsOutdatedBuiltin(t *testing.T) {
	coreID := ""
	for id := range builtinProviders {
		if strings.HasSuffix(id, "/core") {
			coreID = id
			break
		}
	}
	require.NotEmpty(t, coreID, "core must be registered as a builtin")

	reg := &fakeRegistry{latest: "14.0.0"}
	useTestProviderPath(t, reg)

	caller := &Provider{
		Provider: &plugin.Provider{
			Name: "os", ID: "go.mondoo.com/mql/providers/os",
			Requires: []plugin.ProviderDep{{ID: coreID, Name: "core", MinVersion: "14.0.0"}},
		},
		Schema: &resources.Schema{
			Dependencies: map[string]*resources.ProviderInfo{"core": {Id: coreID, Name: "core"}},
		},
	}
	core := &Provider{Provider: &plugin.Provider{Name: "core", ID: coreID, Version: "13.0.0"}}
	existing := Providers{caller.ID: caller, core.ID: core}

	err := installDependencies(caller, existing)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "requires core >= 14.0.0")
	assert.Equal(t, 0, reg.downloads, "a builtin is never downloaded")
}

func TestPeerBelowFloor(t *testing.T) {
	tests := []struct {
		name      string
		installed string
		floor     string
		below     bool
	}{
		{"below", "13.2.4", "13.4.0", true},
		{"at the floor", "13.4.0", "13.4.0", false},
		{"above", "14.0.6", "13.4.0", false},
		{"no floor is no constraint", "0.0.1", "", false},
		{"unknown installed version is not a mismatch", "", "13.4.0", false},
		{"unparseable installed version is not a mismatch", "unstable", "13.4.0", false},
		{"unparseable floor is not a mismatch", "1.0.0", "latest", false},
		{"build metadata orders equal to the release", "v13.4.0+rolling", "13.4.0", false},
		{"pre-release orders behind its own release", "14.0.0-rc.1", "14.0.0", true},
		{"pre-release of a newer major clears an older floor", "14.0.0-rc.1", "13.4.0", false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.below, peerBelowFloor(test.installed, test.floor))
		})
	}
}
