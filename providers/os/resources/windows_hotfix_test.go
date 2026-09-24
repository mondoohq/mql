// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/resources/packages"
	"go.mondoo.com/mql/providers/os/resources/powershell"
	"go.mondoo.com/mql/utils/syncx"
)

// TestWindowsHotfixes_NonZeroExitIsError pins that windows.hotfixes always
// treats a non-zero Get-HotFix exit status as an error, even when stdout
// happens to contain valid JSON, unlike packages.list (WinPkgManager.List)
// which ignores exit status and parses stdout regardless (see
// TestWinPkgManagerList_IgnoresNonZeroHotfixExitStatus in the packages
// package). The two share Get-HotFix's outcome through windows.hotfixes'
// own MQL field cache (see injectWindowsHotfixes in packages.go) whenever
// packages.list can use it, but that sharing must not make this resource
// lenient too -- windows.hotfixes still needs to be able to tell "the agent
// errored" from "this host has no hotfixes", and packages.list falls back to
// its own query exactly when this resource errors.
func TestWindowsHotfixes_NonZeroExitIsError(t *testing.T) {
	hotfixCmd := powershell.Encode(packages.WINDOWS_QUERY_HOTFIXES)

	mockConn, err := mock.New(555001, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "windows",
			Family: []string{"windows"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			hotfixCmd: {
				Stdout:     `[{"Status":"Installed","Description":"Update","HotFixId":"KB5034441","Caption":"","InstalledOn":{},"InstalledBy":""}]`,
				Stderr:     "PowerShell exited non-zero",
				ExitStatus: 1,
			},
		},
	}))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Connection: mockConn,
		Resources:  &syncx.Map[plugin.Resource]{},
	}

	_, err = (&mqlWindows{MqlRuntime: runtime}).hotfixes()
	require.Error(t, err, "a non-zero exit status must fail windows.hotfixes even though stdout parsed")
	assert.Contains(t, err.Error(), "failed to retrieve hotfixes")
}
