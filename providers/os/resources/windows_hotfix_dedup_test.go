// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/utils/syncx"
)

// hotfixDedupTestConnection is a minimal shared.Connection that answers
// Get-HotFix under both transports this codebase uses for it -- the Encode
// (-EncodedCommand) form windows.hotfixes runs, and the Wrap form
// WinPkgManager.List falls back to when nothing was injected -- from
// per-instance canned responses, counts exactly how many times each ran,
// and answers every other command (the installed-apps script, appx, ...) as
// an empty success so WinPkgManager.List() can run end to end without a
// full Windows package fixture.
type hotfixDedupTestConnection struct {
	plugin.Connection
	asset *inventory.Asset

	encodeCmd string
	wrapCmd   string

	encodeStdout string
	encodeExit   int
	wrapStdout   string
	wrapExit     int

	mu    sync.Mutex
	calls map[string]int
}

func newHotfixDedupTestConnection(id uint32) *hotfixDedupTestConnection {
	asset := &inventory.Asset{Platform: &inventory.Platform{
		Name: "windows", Arch: "amd64", Family: []string{"windows"},
		// build 9600 keeps getAppxPackages from issuing its own RunCommand:
		// appx packages only exist on build > 10240, so List() skips
		// straight past it and every command this test does not model is
		// the hotfix one.
		Version: "9600",
	}}
	return &hotfixDedupTestConnection{
		Connection: plugin.NewConnection(id, asset),
		asset:      asset,
		encodeCmd:  powershell.Encode(packages.WINDOWS_QUERY_HOTFIXES),
		wrapCmd:    powershell.Wrap(packages.WINDOWS_QUERY_HOTFIXES),
		calls:      map[string]int{},
	}
}

func (c *hotfixDedupTestConnection) RunCommand(command string) (*shared.Command, error) {
	c.mu.Lock()
	c.calls[command]++
	c.mu.Unlock()

	switch command {
	case c.encodeCmd:
		return &shared.Command{
			Command:    command,
			Stdout:     bytes.NewBufferString(c.encodeStdout),
			Stderr:     bytes.NewBufferString(""),
			ExitStatus: c.encodeExit,
		}, nil
	case c.wrapCmd:
		return &shared.Command{
			Command:    command,
			Stdout:     bytes.NewBufferString(c.wrapStdout),
			Stderr:     bytes.NewBufferString(""),
			ExitStatus: c.wrapExit,
		}, nil
	}

	// every other command (installed-apps enumeration, appx, ...) succeeds
	// with nothing to report, so WinPkgManager.List() completes without a
	// full package fixture.
	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(""),
		Stderr:     bytes.NewBufferString(""),
		ExitStatus: 0,
	}, nil
}

func (c *hotfixDedupTestConnection) callCount(command string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[command]
}

func (c *hotfixDedupTestConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, os.ErrNotExist
}
func (c *hotfixDedupTestConnection) FileSystem() afero.Fs { return afero.NewMemMapFs() }
func (c *hotfixDedupTestConnection) Name() string         { return "hotfix-dedup-test" }
func (c *hotfixDedupTestConnection) Type() shared.ConnectionType {
	return shared.Type_SSH
}
func (c *hotfixDedupTestConnection) Asset() *inventory.Asset            { return c.asset }
func (c *hotfixDedupTestConnection) UpdateAsset(asset *inventory.Asset) { c.asset = asset }
func (c *hotfixDedupTestConnection) Capabilities() shared.Capabilities {
	return shared.Capability_RunCommand
}

func newHotfixDedupRuntime(conn shared.Connection) *plugin.Runtime {
	return &plugin.Runtime{
		Connection: conn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}
}

const dedupHotfixJSON = `[{"Status":"Installed","Description":"Update","HotFixId":"KB5034441","Caption":"http://support.microsoft.com/?kbid=5034441","InstalledOn":{"value":"/Date(1705334400000)/","DateTime":"Wednesday, January 17, 2024 12:00:00 AM"},"InstalledBy":"NT AUTHORITY\\SYSTEM"}]`

// findHotfixPackage returns the "windows/hotfix" package named kbID from a
// packages.list() result, or nil.
func findHotfixPackage(list []any, kbID string) *mqlPackage {
	for _, p := range list {
		pkg, ok := p.(*mqlPackage)
		if !ok {
			continue
		}
		if pkg.Format.Data == "windows/hotfix" && pkg.Name.Data == kbID {
			return pkg
		}
	}
	return nil
}

// TestHotfixDedup_RunsGetHotfixOnceForPackagesAndWindowsHotfixes is the core
// guarantee this rework exists for: when both packages.list and
// windows.hotfixes are resolved on one runtime, Get-HotFix runs once, via
// the shared MQL resource/field cache, not once per resolver.
func TestHotfixDedup_RunsGetHotfixOnceForPackagesAndWindowsHotfixes(t *testing.T) {
	conn := newHotfixDedupTestConnection(100)
	conn.encodeStdout = dedupHotfixJSON
	runtime := newHotfixDedupRuntime(conn)

	// packages.list resolves first. Internally it goes through
	// windows.hotfixes' own field cache (see injectWindowsHotfixes in
	// packages.go), so this alone already runs Get-HotFix.
	pkgsRaw, err := CreateResource(runtime, "packages", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := pkgsRaw.(*mqlPackages).GetList()
	require.NoError(t, list.Error)
	require.NotNil(t, findHotfixPackage(list.Data, "KB5034441"), "packages.list should report the hotfix package")

	// windows.hotfixes resolves afterward and must hit the already-computed
	// field instead of running Get-HotFix again.
	winRaw, err := NewResource(runtime, "windows", nil)
	require.NoError(t, err)
	hf := winRaw.(*mqlWindows).GetHotfixes()
	require.NoError(t, hf.Error)
	require.Len(t, hf.Data, 1)

	assert.Equal(t, 1, conn.callCount(conn.encodeCmd), "Get-HotFix should run exactly once")
	assert.Equal(t, 0, conn.callCount(conn.wrapCmd), "packages.list must not fall back to its own query when injection succeeds")
}

// TestHotfixDedup_WindowsHotfixesFirstStillRunsOnce proves the sharing is
// order independent: resolving windows.hotfixes before packages.list must
// still leave Get-HotFix having run only once.
func TestHotfixDedup_WindowsHotfixesFirstStillRunsOnce(t *testing.T) {
	conn := newHotfixDedupTestConnection(101)
	conn.encodeStdout = dedupHotfixJSON
	runtime := newHotfixDedupRuntime(conn)

	winRaw, err := NewResource(runtime, "windows", nil)
	require.NoError(t, err)
	hf := winRaw.(*mqlWindows).GetHotfixes()
	require.NoError(t, hf.Error)
	require.Len(t, hf.Data, 1)

	pkgsRaw, err := CreateResource(runtime, "packages", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := pkgsRaw.(*mqlPackages).GetList()
	require.NoError(t, list.Error)
	require.NotNil(t, findHotfixPackage(list.Data, "KB5034441"))

	assert.Equal(t, 1, conn.callCount(conn.encodeCmd), "Get-HotFix should run exactly once")
	assert.Equal(t, 0, conn.callCount(conn.wrapCmd))
}

// TestHotfixDedup_WindowsHotfixesErrorsButPackagesListStillGetsHotfixes is
// the regression test for trap 1: windows.hotfixes treats a non-zero
// Get-HotFix exit as an error (unlike packages.list, which has always
// ignored exit status and parsed stdout regardless -- a single broken QFE
// entry must not fail the whole package inventory, since an empty or failed
// package list closes vulnerability findings upstream). packages.list must
// fall back to its own lenient direct query in that case, not propagate the
// error.
func TestHotfixDedup_WindowsHotfixesErrorsButPackagesListStillGetsHotfixes(t *testing.T) {
	conn := newHotfixDedupTestConnection(102)
	conn.encodeStdout = dedupHotfixJSON
	conn.encodeExit = 1 // windows.hotfixes must treat this as an error
	conn.wrapStdout = dedupHotfixJSON
	conn.wrapExit = 1 // WinPkgManager.List's own query must still ignore this

	runtime := newHotfixDedupRuntime(conn)

	pkgsRaw, err := CreateResource(runtime, "packages", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := pkgsRaw.(*mqlPackages).GetList()
	require.NoError(t, list.Error, "packages.list must not fail even though Get-HotFix exited non-zero")
	require.NotNil(t, findHotfixPackage(list.Data, "KB5034441"),
		"packages.list should still report the hotfix package from its own lenient fallback query")

	// windows.hotfixes on the same runtime must still report the error --
	// sharing the outcome must not make this resource lenient too.
	winRaw, err := NewResource(runtime, "windows", nil)
	require.NoError(t, err)
	hf := winRaw.(*mqlWindows).GetHotfixes()
	assert.Error(t, hf.Error)

	assert.Equal(t, 1, conn.callCount(conn.encodeCmd), "windows.hotfixes' failed attempt should not be retried")
	assert.Equal(t, 1, conn.callCount(conn.wrapCmd), "packages.list should have fallen back to its own direct query")
}

// TestHotfixDedup_InjectedPathMatchesDirectPathIncludingLocalInstallDate is
// the regression test for trap 2: packages.list must read the raw parsed
// slice windows.hotfixes() stashes, never round-trip through the
// windows.hotfix MQL resources. Those resources set installedOn from
// hf.InstalledOnTime() alone -- the raw, unadjusted epoch instant --
// whereas HotFixesToPackages applies installedOnDate's local-midnight
// adjustment (windows_packages.go). Round-tripping through the MQL
// resources would shift a package's install date by a day for any host
// east of UTC, which a UTC fixture can never show -- hence this uses a
// Berlin (UTC+2) example, mirroring TestHotFixInstalledOnCalendarDay in the
// packages package.
func TestHotfixDedup_InjectedPathMatchesDirectPathIncludingLocalInstallDate(t *testing.T) {
	// Berlin, UTC+2: Get-HotFix reports local midnight on September 9, 2020;
	// ConvertTo-Json serializes that as the UTC instant
	// 1599602400000 == 2020-09-08T22:00:00Z.
	const berlinJSON = `[{"Status":"Installed","Description":"Update","HotFixId":"KB5034441","Caption":"","InstalledOn":{"value":"/Date(1599602400000)/","DateTime":"Wednesday, September 9, 2020 12:00:00 AM"},"InstalledBy":""}]`
	wantInstalled := time.Date(2020, time.September, 9, 0, 0, 0, 0, time.UTC)

	conn := newHotfixDedupTestConnection(103)
	conn.encodeStdout = berlinJSON
	runtime := newHotfixDedupRuntime(conn)

	pkgsRaw, err := CreateResource(runtime, "packages", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := pkgsRaw.(*mqlPackages).GetList()
	require.NoError(t, list.Error)

	got := findHotfixPackage(list.Data, "KB5034441")
	require.NotNil(t, got)
	require.NotNil(t, got.InstallDate.Data)
	assert.True(t, got.InstallDate.Data.Equal(wantInstalled),
		"packages.list's injected path must apply the same local-midnight adjustment as its own direct path "+
			"(installedOnDate), not the raw unadjusted epoch instant windows.hotfix's installedOn field carries: "+
			"want %s, got %s", wantInstalled, got.InstallDate.Data)

	// Fixture sanity check: prove the raw unadjusted instant genuinely
	// differs from the calendar day above, so the assertion is exercising
	// the adjustment and not passing by coincidence.
	rawHotfixes, err := packages.ParseWindowsHotfixes(strings.NewReader(berlinJSON))
	require.NoError(t, err)
	require.Len(t, rawHotfixes, 1)
	unadjusted := rawHotfixes[0].InstalledOnTime()
	require.NotNil(t, unadjusted)
	assert.False(t, unadjusted.Equal(wantInstalled),
		"fixture sanity check: the raw epoch instant must differ from the local calendar day")
}

// TestHotfixDedup_ReplayUnpopulatedRawSliceFallsBackToDirectQuery is the
// regression test for the replay trap: when GetHotfixes()'s field is
// answered from a recording, hotfixes() never runs, so the raw internal
// slice mqlWindowsInternal carries is never populated. packages.list must
// detect that (rawHotfixes' second return being false) and fall back to its
// own query instead of treating the unpopulated slice as "zero hotfixes".
func TestHotfixDedup_ReplayUnpopulatedRawSliceFallsBackToDirectQuery(t *testing.T) {
	conn := newHotfixDedupTestConnection(104)
	conn.wrapStdout = dedupHotfixJSON // the fallback path's response
	runtime := newHotfixDedupRuntime(conn)

	// Simulate a runtime that replayed windows.hotfixes' field from a
	// recording (see createWindows's early return when runtime.HasRecording
	// is true): the Hotfixes field arrives already "set", so
	// plugin.GetOrCompute never calls hotfixes(), and
	// mqlWindowsInternal.hotfixesRawSet stays false. Pre-populating the
	// runtime's resource cache under the same key NewResource would look up
	// ("windows\x00", windows has no id() override) reproduces that outcome
	// without needing an actual recording fixture.
	preloaded := &mqlWindows{
		MqlRuntime: runtime,
		Hotfixes:   plugin.TValue[[]any]{State: plugin.StateIsSet, Data: []any{}},
	}
	runtime.Resources.Set("windows\x00", preloaded)

	pkgsRaw, err := CreateResource(runtime, "packages", map[string]*llx.RawData{})
	require.NoError(t, err)
	list := pkgsRaw.(*mqlPackages).GetList()
	require.NoError(t, list.Error)
	require.NotNil(t, findHotfixPackage(list.Data, "KB5034441"),
		"packages.list must fall back to its own query when the raw slice was never populated")

	assert.Equal(t, 0, conn.callCount(conn.encodeCmd), "hotfixes() must not have run: its field was already 'set' by the preloaded resource")
	assert.Equal(t, 1, conn.callCount(conn.wrapCmd), "packages.list should have fallen back to its own direct query")
}
