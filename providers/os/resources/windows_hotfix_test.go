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

// TestWindowsHotfixes_NonZeroExitIsError is the regression test for one half
// of the review finding on packages.GetHotfixQueryResult's shared hotfix
// cache: windows.hotfixes has always treated a non-zero Get-HotFix exit
// status as an error, even when stdout happens to contain valid JSON,
// unlike packages.list (WinPkgManager.List) which ignores exit status and
// parses stdout regardless (see
// TestWinPkgManagerList_IgnoresNonZeroHotfixExitStatus in the packages
// package). Sharing the underlying command between the two must not make
// this resource lenient too -- windows.hotfixes still needs to be able to
// tell "the agent errored" from "this host has no hotfixes".
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
