// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func polkitInstalledOn(t *testing.T, paths ...string) bool {
	t.Helper()
	files := map[string]*mock.MockFileData{}
	for _, p := range paths {
		// a trailing slash marks a directory
		if dir, isDir := strings.CutSuffix(p, "/"); isDir {
			files[dir] = &mock.MockFileData{Path: dir, StatData: mock.FileInfo{IsDir: true, Mode: os.ModeDir | 0o755}}
			continue
		}
		files[p] = &mock.MockFileData{Path: p, Content: "x"}
	}
	conn, err := mock.New(0, &inventory.Asset{Platform: &inventory.Platform{
		Name:   "fedora",
		Family: []string{"redhat", "linux", "unix", "os"},
	}}, mock.WithData(&mock.TomlData{Files: files}))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	raw, err := CreateResource(runtime, "polkit", nil)
	require.NoError(t, err)
	installed := raw.(*mqlPolkit).GetInstalled()
	require.NoError(t, installed.Error)
	return installed.Data
}

func TestPolkitInstalled(t *testing.T) {
	// Fedora 44 cloud image without the polkit package: systemd and
	// NetworkManager still ship action and rule files.
	assert.False(t, polkitInstalledOn(t,
		"/usr/share/polkit-1/actions/",
		"/usr/share/polkit-1/rules.d/",
		"/usr/share/polkit-1/actions/org.freedesktop.login1.policy",
		"/usr/share/polkit-1/actions/io.systemd.credentials.policy",
		"/usr/share/polkit-1/rules.d/systemd-networkd.rules",
		"/usr/share/polkit-1/rules.d/org.freedesktop.NetworkManager.rules",
	))
	assert.False(t, polkitInstalledOn(t))

	// polkit 127 on Fedora / RHEL: polkitd in /usr/lib/polkit-1
	assert.True(t, polkitInstalledOn(t,
		"/usr/lib/polkit-1/polkitd",
		"/usr/share/polkit-1/actions/org.freedesktop.policykit.policy",
	))
	// policykit-1 0.105 on Debian and Ubuntu up to 22.04
	assert.True(t, polkitInstalledOn(t, "/usr/lib/policykit-1/polkitd"))
	// command-line tools alone
	assert.True(t, polkitInstalledOn(t, "/usr/bin/pkaction"))
	assert.True(t, polkitInstalledOn(t, "/usr/bin/pkexec"))
}
