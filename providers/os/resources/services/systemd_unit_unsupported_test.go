// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"os"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func readShowFixture(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile("testdata/systemd-show/" + name)
	require.NoError(t, err)
	return string(data)
}

// Debian 9 (systemd 232): the property list names settings 232 does not know,
// so systemctl show exits 1 and the --all retry answers. ProtectClock and the
// other later settings are not in that output and must read as unsupported,
// not as "no"; RestrictAddressFamilies is printed as "[unprintable]".
func TestSystemdUnitManager_GetOnSystemd232MarksUnsupported(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		buildSystemdUnitShowCommand([]string{"g04-hard"}): {
			Stdout:     readShowFixture(t, "debian9-232-show-g04-hard.txt"),
			ExitStatus: 1,
		},
		buildSystemdUnitShowAllCommand([]string{"g04-hard"}): {
			Stdout: readShowFixture(t, "debian9-232-show-all-g04-hard.txt"),
		},
	})

	u, err := (&SystemdUnitManager{conn: conn}).Get("g04-hard")
	require.NoError(t, err)
	assert.Equal(t, "active", u.ActiveState)
	assert.Equal(t, "strict", u.ProtectSystem)
	assert.True(t, u.ProtectKernelModules)
	assert.True(t, u.Supports("ProtectKernelModules"))

	for _, property := range []string{
		"ProtectKernelLogs", "ProtectClock", "ProtectHostname", "ProtectProc", "ProcSubset",
		"RestrictSUIDSGID", "RestrictNamespaces", "LockPersonality", "KeyringMode",
		"RestrictAddressFamilies",
	} {
		assert.Falsef(t, u.Supports(property), "%s on systemd 232", property)
	}
}

// Debian 10 (systemd 241) exits 0 for the property list and leaves out what it
// does not know. LockPersonality (235) is known and set; ProtectClock (245) is
// not known.
func TestSystemdUnitManager_GetOnSystemd241MarksUnsupported(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		buildSystemdUnitShowCommand([]string{"g04-hard"}): {
			Stdout: readShowFixture(t, "debian10-241-show-g04-hard.txt"),
		},
	})

	u, err := (&SystemdUnitManager{conn: conn}).Get("g04-hard")
	require.NoError(t, err)
	assert.True(t, u.LockPersonality)
	assert.True(t, u.Supports("LockPersonality"))
	assert.Equal(t, "private", u.KeyringMode)
	assert.False(t, u.Supports("ProtectClock"))
	assert.False(t, u.Supports("ProtectKernelLogs"))
	assert.False(t, u.Supports("RestrictAddressFamilies"))
}

// A unit without execution settings (a target) has none of the properties;
// that is not a gap in the release.
func TestMarkUnsupportedShowPropertiesSkipsUnitsWithoutExecSettings(t *testing.T) {
	record := map[string]string{"Id": "basic.target", "LoadState": "loaded"}
	markUnsupportedShowProperties(record)
	u := systemdUnitFromProperties(record)
	require.NotNil(t, u)
	assert.Nil(t, u.Unsupported)
	assert.True(t, u.Supports("ProtectClock"))
}

const hardUnitFile = `[Service]
ExecStart=/bin/sleep 1000000
NoNewPrivileges=yes
ProtectKernelModules=yes
ProtectClock=yes
LockPersonality=yes
`

// The unit-file fallback on a host whose systemd is older than a setting must
// not report the setting: systemd 232 ignores ProtectClock=yes.
func TestSystemdFSUnitManager_VersionHidesUnknownSettings(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/g04-hard.service", []byte(hardUnitFile), 0o644))

	u, err := (&SystemdFSUnitManager{Fs: fs, Version: 232}).Get("g04-hard")
	require.NoError(t, err)
	assert.True(t, u.NoNewPrivileges)
	assert.True(t, u.Supports("ProtectKernelModules"))
	assert.False(t, u.Supports("ProtectClock"))
	assert.False(t, u.Supports("LockPersonality"))

	u, err = (&SystemdFSUnitManager{Fs: fs, Version: 257}).Get("g04-hard")
	require.NoError(t, err)
	assert.True(t, u.ProtectClock)
	assert.True(t, u.Supports("ProtectClock"))

	// an image scan does not know the release and reads the file as written
	u, err = (&SystemdFSUnitManager{Fs: fs}).Get("g04-hard")
	require.NoError(t, err)
	assert.True(t, u.ProtectClock)
	assert.True(t, u.Supports("ProtectClock"))
}

func TestParseSystemctlVersion(t *testing.T) {
	assert.Equal(t, 232, parseSystemctlVersion("systemd 232\n+PAM +AUDIT +SELINUX\n"))
	assert.Equal(t, 252, parseSystemctlVersion("systemd 252 (252.39-1~deb12u2)\n+PAM\n"))
	assert.Equal(t, 0, parseSystemctlVersion(""))
	assert.Equal(t, 0, parseSystemctlVersion("bash: systemctl: command not found\n"))
}

// every property in the release table is one systemd.unit reports
func TestSystemdPropertySinceNamesShownProperties(t *testing.T) {
	shown := map[string]bool{}
	for _, p := range strings.Split(systemdUnitShowProperties, ",") {
		shown[p] = true
	}
	for p := range systemdPropertySince {
		assert.Truef(t, shown[p], "%s", p)
	}
}
