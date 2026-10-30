// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package packages

import (
	"bytes"
	"os"
	"sync"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/powershell"
)

// injectionTestConnection is a minimal shared.Connection that answers
// WinPkgManager's own (Wrap-transport) Get-HotFix query from a canned
// response, counts how many times that exact command ran, and answers every
// other command (the installed-apps script, etc.) as an empty, successful
// result so List() can run end to end without needing a full Windows
// package fixture.
type injectionTestConnection struct {
	plugin.Connection
	asset *inventory.Asset

	hotfixCmd    string
	hotfixStdout string
	hotfixExit   int

	mu    sync.Mutex
	calls int
}

func newInjectionTestConnection(id uint32, hotfixStdout string) *injectionTestConnection {
	asset := &inventory.Asset{Platform: &inventory.Platform{Name: "windows", Arch: "amd64", Family: []string{"windows"}}}
	return &injectionTestConnection{
		Connection:   plugin.NewConnection(id, asset),
		asset:        asset,
		hotfixCmd:    powershell.Wrap(WINDOWS_QUERY_HOTFIXES),
		hotfixStdout: hotfixStdout,
	}
}

func (c *injectionTestConnection) RunCommand(command string) (*shared.Command, error) {
	if command == c.hotfixCmd {
		c.mu.Lock()
		c.calls++
		c.mu.Unlock()
		return &shared.Command{
			Command:    command,
			Stdout:     bytes.NewBufferString(c.hotfixStdout),
			Stderr:     bytes.NewBufferString(""),
			ExitStatus: c.hotfixExit,
		}, nil
	}

	// every other command (installed-apps enumeration, appx, ...) succeeds
	// with nothing to report, so List() completes without needing a full
	// package fixture.
	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(""),
		Stderr:     bytes.NewBufferString(""),
		ExitStatus: 0,
	}, nil
}

func (c *injectionTestConnection) hotfixCalls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

func (c *injectionTestConnection) FileInfo(path string) (shared.FileInfoDetails, error) {
	return shared.FileInfoDetails{}, os.ErrNotExist
}

func (c *injectionTestConnection) FileSystem() afero.Fs { return afero.NewMemMapFs() }
func (c *injectionTestConnection) Name() string         { return "hotfix-injection-test" }
func (c *injectionTestConnection) Type() shared.ConnectionType {
	return shared.Type_SSH
}
func (c *injectionTestConnection) Asset() *inventory.Asset            { return c.asset }
func (c *injectionTestConnection) UpdateAsset(asset *inventory.Asset) { c.asset = asset }
func (c *injectionTestConnection) Capabilities() shared.Capabilities {
	return shared.Capability_RunCommand
}

const injectionTestHotfixJSON = `[{"Status":"Installed","Description":"Update","HotFixId":"KB5034441","Caption":"http://support.microsoft.com/?kbid=5034441","InstalledOn":{"value":"/Date(1705334400000)/","DateTime":"Wednesday, January 17, 2024 12:00:00 AM"},"InstalledBy":"NT AUTHORITY\\SYSTEM"}]`

// build 9600 keeps getAppxPackages from issuing its own RunCommand: appx
// packages only exist on build > 10240, so List() skips straight past it.
func injectionTestPlatform() *inventory.Platform {
	return &inventory.Platform{Name: "windows", Arch: "amd64", Family: []string{"windows"}, Version: "9600"}
}

// TestWinPkgManagerList_UsesInjectedHotfixesWithoutRunningGetHotfix is the
// core guarantee SetHotfixes exists for: when the resource layer has already
// resolved the hotfix outcome elsewhere and hands it down, List() must use
// it instead of running Get-HotFix itself.
func TestWinPkgManagerList_UsesInjectedHotfixesWithoutRunningGetHotfix(t *testing.T) {
	conn := newInjectionTestConnection(1, injectionTestHotfixJSON)
	mgr := &WinPkgManager{conn: conn, platform: injectionTestPlatform()}

	hotfixes, err := ParseWindowsHotfixes(bytes.NewBufferString(injectionTestHotfixJSON))
	require.NoError(t, err)
	require.Len(t, hotfixes, 1)
	mgr.SetHotfixes(hotfixes)

	pkgs, err := mgr.List()
	require.NoError(t, err)

	found := false
	for _, p := range pkgs {
		if p.Format == "windows/hotfix" && p.Name == "KB5034441" {
			found = true
		}
	}
	assert.True(t, found, "the injected hotfix should still be reported as a package")
	assert.Equal(t, 0, conn.hotfixCalls(), "List() must not run Get-HotFix itself when a result was injected")
}

// TestWinPkgManagerList_NoInjectionRunsGetHotfixItself is the counterpart:
// absent an injection (every WinPkgManager built outside the resource
// layer, including every other test in this package), List() must behave
// exactly as it always has and run its own query.
func TestWinPkgManagerList_NoInjectionRunsGetHotfixItself(t *testing.T) {
	conn := newInjectionTestConnection(2, injectionTestHotfixJSON)
	mgr := &WinPkgManager{conn: conn, platform: injectionTestPlatform()}

	pkgs, err := mgr.List()
	require.NoError(t, err)

	found := false
	for _, p := range pkgs {
		if p.Format == "windows/hotfix" && p.Name == "KB5034441" {
			found = true
		}
	}
	assert.True(t, found)
	assert.Equal(t, 1, conn.hotfixCalls(), "List() should have run Get-HotFix itself")
}

// TestWinPkgManagerList_IgnoresNonZeroHotfixExitStatus pins that
// WinPkgManager.List's own direct query -- the path taken whenever nothing
// was injected -- has always parsed Get-HotFix's stdout regardless of exit
// status: a single broken QFE entry that makes PowerShell exit non-zero
// while still printing valid JSON must not fail the whole package inventory,
// since an empty or failed package list closes vulnerability findings
// upstream. windows.hotfixes (providers/os/resources/windows.go) is strict
// about exit status instead -- see TestWindowsHotfixes_NonZeroExitIsError in
// the resources package -- and packages.list falls back to this lenient
// path exactly when that resource errors (see injectWindowsHotfixes in
// packages.go).
func TestWinPkgManagerList_IgnoresNonZeroHotfixExitStatus(t *testing.T) {
	conn := newInjectionTestConnection(3, injectionTestHotfixJSON)
	conn.hotfixExit = 1 // PowerShell exited non-zero, but stdout is still valid JSON

	mgr := &WinPkgManager{conn: conn, platform: injectionTestPlatform()}
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

// TestWinPkgManagerList_InjectedEmptyHotfixesIsNotNoInjection guards the
// pointer-to-slice shape of injectedHotfixes: an injected but genuinely
// empty hotfix list (a host with none installed) must not be mistaken for
// "nothing was injected" and trigger a redundant Get-HotFix run.
func TestWinPkgManagerList_InjectedEmptyHotfixesIsNotNoInjection(t *testing.T) {
	conn := newInjectionTestConnection(4, "")
	mgr := &WinPkgManager{conn: conn, platform: injectionTestPlatform()}
	mgr.SetHotfixes([]PowershellWinHotFix{})

	pkgs, err := mgr.List()
	require.NoError(t, err)

	for _, p := range pkgs {
		assert.NotEqual(t, "windows/hotfix", p.Format, "no hotfixes were injected, none should be reported")
	}
	assert.Equal(t, 0, conn.hotfixCalls(), "an injected empty result must not fall back to running Get-HotFix")
}
