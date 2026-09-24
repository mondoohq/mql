// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"os"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// resetHotfixCache clears hotfixQueryCache so tests don't see state left
// behind by an earlier test (or leak state into a later one).
func resetHotfixCache() {
	hotfixQueryCache.Range(func(key, _ any) bool {
		hotfixQueryCache.Delete(key)
		return true
	})
}

// hotfixCacheTestConnection is a minimal shared.Connection that answers the
// Get-HotFix command from a per-instance canned response, counts how many
// times that exact command ran, and answers every other command (the
// installed-apps script, etc.) as an empty, successful result so
// WinPkgManager.List() can run end to end without needing a full Windows
// package fixture.
type hotfixCacheTestConnection struct {
	plugin.Connection
	asset *inventory.Asset

	hotfixCmd    string
	hotfixStdout string
	hotfixExit   int
	hotfixErr    error
	hotfixCalls  atomic.Int32

	// hotfixBlock, when non-nil, holds the hotfix RunCommand until it is
	// closed, so a test can get several callers in flight at once.
	hotfixBlock chan struct{}
}

func newHotfixCacheTestConnection(id uint32, hotfixStdout string) *hotfixCacheTestConnection {
	asset := &inventory.Asset{Platform: &inventory.Platform{Name: "windows", Arch: "amd64", Family: []string{"windows"}}}
	return &hotfixCacheTestConnection{
		Connection:   plugin.NewConnection(id, asset),
		asset:        asset,
		hotfixCmd:    powershell.Encode(WINDOWS_QUERY_HOTFIXES),
		hotfixStdout: hotfixStdout,
	}
}

func (c *hotfixCacheTestConnection) RunCommand(command string) (*shared.Command, error) {
	if command == c.hotfixCmd {
		c.hotfixCalls.Add(1)
		if c.hotfixBlock != nil {
			<-c.hotfixBlock
		}
		if c.hotfixErr != nil {
			return nil, c.hotfixErr
		}
		return &shared.Command{
			Command:    command,
			Stdout:     bytes.NewBufferString(c.hotfixStdout),
			Stderr:     bytes.NewBufferString(""),
			ExitStatus: c.hotfixExit,
		}, nil
	}

	// every other command (installed-apps enumeration, appx, ...) succeeds
	// with nothing to report, so WinPkgManager.List() completes without
	// needing a full package fixture
	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(""),
		Stderr:     bytes.NewBufferString(""),
		ExitStatus: 0,
	}, nil
}

func (c *hotfixCacheTestConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, os.ErrNotExist
}

func (c *hotfixCacheTestConnection) FileSystem() afero.Fs { return afero.NewMemMapFs() }
func (c *hotfixCacheTestConnection) Name() string         { return "hotfix-cache-test" }
func (c *hotfixCacheTestConnection) Type() shared.ConnectionType {
	return shared.Type_SSH
}
func (c *hotfixCacheTestConnection) Asset() *inventory.Asset            { return c.asset }
func (c *hotfixCacheTestConnection) UpdateAsset(asset *inventory.Asset) { c.asset = asset }
func (c *hotfixCacheTestConnection) Capabilities() shared.Capabilities {
	return shared.Capability_RunCommand
}

const oneHotfixJSON = `[{"Status":"Installed","Description":"Update","HotFixId":"KB5034441","Caption":"http://support.microsoft.com/?kbid=5034441","InstalledOn":{"value":"/Date(1705334400000)/","DateTime":"Wednesday, January 17, 2024 12:00:00 AM"},"InstalledBy":"NT AUTHORITY\\SYSTEM"}]`

// build 9600 keeps getAppxPackages from issuing its own RunCommand: appx
// packages only exist on build > 10240, so List() skips straight past it.
func hotfixCacheTestPlatform() *inventory.Platform {
	return &inventory.Platform{Name: "windows", Arch: "amd64", Family: []string{"windows"}, Version: "9600"}
}

// TestGetHotfixQueryResult_CachesPerConnection is the core guarantee:
// repeated callers on the same connection get the same answer for one
// Get-HotFix run.
func TestGetHotfixQueryResult_CachesPerConnection(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(1, oneHotfixJSON)

	for i := 0; i < 3; i++ {
		result, err := GetHotfixQueryResult(conn)
		require.NoError(t, err)
		require.NoError(t, result.ParseErr)
		require.Len(t, result.Hotfixes, 1)
		assert.Equal(t, "KB5034441", result.Hotfixes[0].HotFixId)
	}

	assert.Equal(t, int32(1), conn.hotfixCalls.Load(), "Get-HotFix ran more than once for the same connection")
}

// TestGetHotfixQueryResult_SharedByListAndWindowsHotfixes is the regression
// test for the point of this cache: packages.list (WinPkgManager.List) and
// windows.hotfixes both need the installed-hotfix outcome, and
// windows.hotfixes asks for it by calling this same GetHotfixQueryResult
// function. Resolving both on one connection must run Get-HotFix once, not
// twice.
func TestGetHotfixQueryResult_SharedByListAndWindowsHotfixes(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(2, oneHotfixJSON)
	mgr := &WinPkgManager{conn: conn, platform: hotfixCacheTestPlatform()}

	// packages.list's resolution path
	_, err := mgr.List()
	require.NoError(t, err)

	// windows.hotfixes' resolution path, post-refactor: it calls
	// GetHotfixQueryResult directly (see providers/os/resources/windows.go,
	// mqlWindows.hotfixes)
	result, err := GetHotfixQueryResult(conn)
	require.NoError(t, err)
	require.NoError(t, result.ParseErr)
	require.Len(t, result.Hotfixes, 1)

	assert.Equal(t, int32(1), conn.hotfixCalls.Load(),
		"Get-HotFix ran once per resolver instead of once for the connection")
}

// TestGetHotfixQueryResult_ScopedPerConnection guards against a cache that
// is global instead of per-connection: two different assets/scans must each
// get their own Get-HotFix answer and their own call count, never one
// served from the other's cache entry.
func TestGetHotfixQueryResult_ScopedPerConnection(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	connA := newHotfixCacheTestConnection(10, oneHotfixJSON)
	connB := newHotfixCacheTestConnection(11, `[{"Status":"Installed","Description":"Update","HotFixId":"KB9999999","Caption":"","InstalledOn":{},"InstalledBy":""}]`)

	resultA, err := GetHotfixQueryResult(connA)
	require.NoError(t, err)
	resultB, err := GetHotfixQueryResult(connB)
	require.NoError(t, err)

	require.Len(t, resultA.Hotfixes, 1)
	require.Len(t, resultB.Hotfixes, 1)
	assert.Equal(t, "KB5034441", resultA.Hotfixes[0].HotFixId)
	assert.Equal(t, "KB9999999", resultB.Hotfixes[0].HotFixId)

	// asking again on each connection must not cross-contaminate or re-fetch
	resultA2, err := GetHotfixQueryResult(connA)
	require.NoError(t, err)
	assert.Equal(t, resultA, resultA2)

	assert.Equal(t, int32(1), connA.hotfixCalls.Load())
	assert.Equal(t, int32(1), connB.hotfixCalls.Load())
}

// TestGetHotfixQueryResult_DoesNotCacheTransportFailures keeps a transient
// failure to even run the command (the agent busy, a momentary WMI hiccup,
// RunCommand itself erroring) from becoming a permanently empty hotfix list
// for the rest of the scan. This is distinct from a non-zero exit status:
// the command running and exiting non-zero IS memoized (see
// TestWinPkgManagerList_IgnoresNonZeroHotfixExitStatus and
// TestGetHotfixQueryResult_NonZeroExitIsMemoized below) because the outcome
// is deterministic within a scan; only a RunCommand transport error means we
// never captured a usable outcome to cache.
func TestGetHotfixQueryResult_DoesNotCacheTransportFailures(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(20, "")
	conn.hotfixErr = assert.AnError

	_, err := GetHotfixQueryResult(conn)
	require.Error(t, err)

	// the command now runs successfully; the cache must not be stuck on the
	// earlier transport failure
	conn.hotfixErr = nil
	conn.hotfixStdout = oneHotfixJSON

	result, err := GetHotfixQueryResult(conn)
	require.NoError(t, err)
	require.Len(t, result.Hotfixes, 1)
	assert.Equal(t, int32(2), conn.hotfixCalls.Load(), "a transport failure was cached instead of retried")
}

// TestGetHotfixQueryResult_NonZeroExitIsMemoized is the counterpart to
// TestGetHotfixQueryResult_DoesNotCacheTransportFailures: once RunCommand
// itself succeeds, the outcome (including a non-zero exit status) IS cached,
// so a second caller reading the same connection doesn't re-run Get-HotFix
// just because the first caller saw ExitStatus != 0.
func TestGetHotfixQueryResult_NonZeroExitIsMemoized(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(21, oneHotfixJSON)
	conn.hotfixExit = 1

	first, err := GetHotfixQueryResult(conn)
	require.NoError(t, err) // RunCommand succeeded; a non-zero exit is not a transport error
	assert.Equal(t, 1, first.ExitStatus)
	require.Len(t, first.Hotfixes, 1, "stdout still parses even though the exit status is non-zero")

	second, err := GetHotfixQueryResult(conn)
	require.NoError(t, err)
	assert.Equal(t, first, second)
	assert.Equal(t, int32(1), conn.hotfixCalls.Load(), "a non-zero-exit outcome was re-fetched instead of memoized")
}

// TestWinPkgManagerList_IgnoresNonZeroHotfixExitStatus is the regression
// test for the review finding on this cache: WinPkgManager.List has always
// parsed Get-HotFix's stdout regardless of exit status, because a single
// broken QFE entry that makes PowerShell exit non-zero while still printing
// valid JSON must not fail the whole package inventory -- an empty or
// failed package list closes vulnerability findings upstream. Sharing the
// command with windows.hotfixes (which IS strict about exit status, see
// TestWindowsHotfixes_NonZeroExitIsError in the resources package) must not
// change that.
func TestWinPkgManagerList_IgnoresNonZeroHotfixExitStatus(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(40, oneHotfixJSON)
	conn.hotfixExit = 1 // PowerShell exited non-zero, but stdout is still valid JSON

	mgr := &WinPkgManager{conn: conn, platform: hotfixCacheTestPlatform()}
	pkgs, err := mgr.List()
	require.NoError(t, err, "a non-zero hotfix exit status must not fail the whole package list")

	found := false
	for _, p := range pkgs {
		if p.Format == "windows/hotfix" && p.Name == "KB5034441" {
			found = true
		}
	}
	assert.True(t, found, "the hotfix parsed from stdout despite the non-zero exit status should still be reported")
}

// TestGetHotfixQueryResult_CollapsesConcurrentCallers covers the shape
// packages.list and windows.hotfixes actually have when a scan resolves
// both: they can arrive at GetHotfixQueryResult together, before either has
// a cached answer to read. Without the lock held across the command they
// would each start their own Get-HotFix.
func TestGetHotfixQueryResult_CollapsesConcurrentCallers(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	const callers = 6
	conn := newHotfixCacheTestConnection(30, oneHotfixJSON)
	conn.hotfixBlock = make(chan struct{})

	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			result, err := GetHotfixQueryResult(conn)
			assert.NoError(t, err)
			assert.Len(t, result.Hotfixes, 1)
		}()
	}

	// let the first query finish only once every caller has had a chance to
	// arrive, so this fails if they are not being collapsed
	close(conn.hotfixBlock)
	wg.Wait()

	assert.Equal(t, int32(1), conn.hotfixCalls.Load(), "concurrent callers each started their own Get-HotFix")
}
