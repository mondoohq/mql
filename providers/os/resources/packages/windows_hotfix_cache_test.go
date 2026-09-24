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

// TestGetHotfixes_CachesPerConnection is the core guarantee: repeated callers
// on the same connection get the same answer for one Get-HotFix run.
func TestGetHotfixes_CachesPerConnection(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(1, oneHotfixJSON)

	for i := 0; i < 3; i++ {
		hotfixes, err := GetHotfixes(conn)
		require.NoError(t, err)
		require.Len(t, hotfixes, 1)
		assert.Equal(t, "KB5034441", hotfixes[0].HotFixId)
	}

	assert.Equal(t, int32(1), conn.hotfixCalls.Load(), "Get-HotFix ran more than once for the same connection")
}

// TestGetHotfixes_SharedByListAndWindowsHotfixes is the regression test for
// the point of this cache: packages.list (WinPkgManager.List) and
// windows.hotfixes both need the installed-hotfix list, and windows.hotfixes
// asks for it by calling this same GetHotfixes function. Resolving both on
// one connection must run Get-HotFix once, not twice.
func TestGetHotfixes_SharedByListAndWindowsHotfixes(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(2, oneHotfixJSON)
	mgr := &WinPkgManager{conn: conn, platform: hotfixCacheTestPlatform()}

	// packages.list's resolution path
	_, err := mgr.List()
	require.NoError(t, err)

	// windows.hotfixes' resolution path, post-refactor: it calls GetHotfixes
	// directly (see providers/os/resources/windows.go, mqlWindows.hotfixes)
	hotfixes, err := GetHotfixes(conn)
	require.NoError(t, err)
	require.Len(t, hotfixes, 1)

	assert.Equal(t, int32(1), conn.hotfixCalls.Load(),
		"Get-HotFix ran once per resolver instead of once for the connection")
}

// TestGetHotfixes_ScopedPerConnection guards against a cache that is global
// instead of per-connection: two different assets/scans must each get their
// own Get-HotFix answer and their own call count, never one served from the
// other's cache entry.
func TestGetHotfixes_ScopedPerConnection(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	connA := newHotfixCacheTestConnection(10, oneHotfixJSON)
	connB := newHotfixCacheTestConnection(11, `[{"Status":"Installed","Description":"Update","HotFixId":"KB9999999","Caption":"","InstalledOn":{},"InstalledBy":""}]`)

	hfA, err := GetHotfixes(connA)
	require.NoError(t, err)
	hfB, err := GetHotfixes(connB)
	require.NoError(t, err)

	require.Len(t, hfA, 1)
	require.Len(t, hfB, 1)
	assert.Equal(t, "KB5034441", hfA[0].HotFixId)
	assert.Equal(t, "KB9999999", hfB[0].HotFixId)

	// asking again on each connection must not cross-contaminate or re-fetch
	hfA2, err := GetHotfixes(connA)
	require.NoError(t, err)
	assert.Equal(t, hfA, hfA2)

	assert.Equal(t, int32(1), connA.hotfixCalls.Load())
	assert.Equal(t, int32(1), connB.hotfixCalls.Load())
}

// TestGetHotfixes_DoesNotCacheFailures keeps a transient failure (the agent
// busy, a momentary WMI hiccup) from becoming a permanently empty hotfix list
// for the rest of the scan.
func TestGetHotfixes_DoesNotCacheFailures(t *testing.T) {
	resetHotfixCache()
	t.Cleanup(resetHotfixCache)

	conn := newHotfixCacheTestConnection(20, "")
	conn.hotfixExit = 1

	_, err := GetHotfixes(conn)
	require.Error(t, err)

	// the query now succeeds; the cache must not be stuck on the failure
	conn.hotfixExit = 0
	conn.hotfixStdout = oneHotfixJSON

	hotfixes, err := GetHotfixes(conn)
	require.NoError(t, err)
	require.Len(t, hotfixes, 1)
	assert.Equal(t, int32(2), conn.hotfixCalls.Load(), "a failed query was cached instead of retried")
}

// TestGetHotfixes_CollapsesConcurrentCallers covers the shape packages.list
// and windows.hotfixes actually have when a scan resolves both: they can
// arrive at GetHotfixes together, before either has a cached answer to read.
// Without the lock held across the command they would each start their own
// Get-HotFix.
func TestGetHotfixes_CollapsesConcurrentCallers(t *testing.T) {
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
			hotfixes, err := GetHotfixes(conn)
			assert.NoError(t, err)
			assert.Len(t, hotfixes, 1)
		}()
	}

	// let the first query finish only once every caller has had a chance to
	// arrive, so this fails if they are not being collapsed
	close(conn.hotfixBlock)
	wg.Wait()

	assert.Equal(t, int32(1), conn.hotfixCalls.Load(), "concurrent callers each started their own Get-HotFix")
}
