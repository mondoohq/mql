// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package updates

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// SUSE OS updates
func TestZypperPatchParser(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "suse"},
	}, mock.WithPath("./testdata/updates_zypper.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("zypper --xmlout list-updates -t patch")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseZypperPatches(c.Stdout)
	assert.Nil(t, err)
	// 1 patch in <update-list> (the package manager patch) plus the 18 patches
	// zypper holds back in <blocked-update-list> until it is installed
	assert.Equal(t, 19, len(m), "detected the right amount of packages")

	assert.Equal(t, "openSUSE-2018-397", m[0].Name, "update name detected")
	assert.Equal(t, "moderate", m[0].Severity, "severity version detected")
	assert.Equal(t, "openSUSE-2018-361", m[1].Name, "first blocked patch detected")
	assert.Equal(t, "security", m[1].Category)
}

// zypper -n --xmlout list-updates -t patch on SLES 16.0 and Leap 15.6 while a
// package manager patch is pending: the libzypp/zypper patches stay in
// <update-list>, every other needed patch moves to <blocked-update-list>.
// Counts are zypper's own (descriptions, sources and issue lists trimmed).
func TestZypperPatchParserBlockedUpdates(t *testing.T) {
	tests := []struct {
		file              string
		total             int
		securityImportant int
		blockedName       string
		blockedRestart    bool
	}{
		{
			file:              "testdata/zypper_patches_blocked_sles16.xml",
			total:             125,
			securityImportant: 41,
			blockedName:       "SUSE-SLES-16.0-1784",
			blockedRestart:    false,
		},
		{
			file:              "testdata/zypper_patches_blocked_leap15.xml",
			total:             70,
			securityImportant: 29,
			blockedName:       "openSUSE-SLE-15.6-2026-1840",
			blockedRestart:    true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.file, func(t *testing.T) {
			f, err := os.Open(tc.file)
			require.NoError(t, err)
			defer f.Close()

			m, err := ParseZypperPatches(f)
			require.NoError(t, err)
			assert.Len(t, m, tc.total)

			secImp := 0
			var blocked *OperatingSystemUpdate
			for i := range m {
				if m[i].Category == "security" && m[i].Severity == "important" {
					secImp++
				}
				if m[i].Name == tc.blockedName {
					blocked = &m[i]
				}
			}
			assert.Equal(t, tc.securityImportant, secImp)
			require.NotNil(t, blocked, "patch from <blocked-update-list> is reported")
			assert.Equal(t, tc.blockedRestart, blocked.Restart)
			assert.Equal(t, SuseOSUpdateFormat, blocked.Format)
		})
	}
}
