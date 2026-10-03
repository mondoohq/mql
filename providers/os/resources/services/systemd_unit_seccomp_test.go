// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// `systemctl --version` on RHEL 7.9: systemd 219 built without seccomp.
const rhel7SystemctlVersion = `systemd 219
+PAM +AUDIT +SELINUX +IMA -APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 -SECCOMP +BLKID +ELFUTILS +KMOD +IDN
`

// `systemctl --version` on RHEL 8.10: systemd 239 built with seccomp.
const rhel8SystemctlVersion = `systemd 239 (239-82.el8_10.17)
+PAM +AUDIT +SELINUX +IMA -APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD +IDN2 -IDN +PCRE2 default-hierarchy=legacy
`

// `systemctl show --all -- g04-raf.service` on RHEL 7.9 (excerpt). The unit
// file sets RestrictAddressFamilies=AF_UNIX, which 219 prints as
// "[unprintable]" and, built -SECCOMP, never enforces: the service opens an
// AF_INET socket.
const rhel7ShowAllRaf = `Type=oneshot
ExecStart={ path=/usr/bin/python3 ; argv[]=/usr/bin/python3 -c import socket ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
NoNewPrivileges=no
SystemCallFilter=~
SystemCallArchitectures=
RestrictAddressFamilies=[unprintable]
Id=g04-raf.service
Names=g04-raf.service
Description=g04 raf test
LoadState=loaded
ActiveState=inactive
SubState=dead
FragmentPath=/etc/systemd/system/g04-raf.service
UnitFileState=static
DropInPaths=
`

const rhel7RafUnitFile = `[Unit]
Description=g04 raf test
[Service]
Type=oneshot
RestrictAddressFamilies=AF_UNIX
ExecStart=/usr/bin/python3 -c "import socket"
`

func TestParseSystemctlSeccomp(t *testing.T) {
	assert.False(t, parseSystemctlSeccomp(rhel7SystemctlVersion))
	assert.True(t, parseSystemctlSeccomp(rhel8SystemctlVersion))
	// no feature line: nothing says seccomp is missing
	assert.True(t, parseSystemctlSeccomp("systemd 219\n"))
	assert.True(t, parseSystemctlSeccomp(""))
}

func seccompRafConn(t *testing.T, version string) *SystemdUnitManager {
	t.Helper()
	conn := unitFallbackConn(t, map[string]*mock.Command{
		"systemctl --version": {Stdout: version},
		buildSystemdUnitShowCommand([]string{"g04-raf"}): {
			Stdout:     rhel7ShowAllRaf,
			ExitStatus: 1,
		},
		buildSystemdUnitShowAllCommand([]string{"g04-raf"}): {
			Stdout: rhel7ShowAllRaf,
		},
	})
	require.NoError(t, afero.WriteFile(conn.FileSystem(), "/etc/systemd/system/g04-raf.service", []byte(rhel7RafUnitFile), 0o644))
	return &SystemdUnitManager{conn: conn}
}

// A systemd built -SECCOMP ignores every seccomp-backed setting, so the value
// the unit file holds must not be reported as a protection in effect.
func TestSystemdUnitManager_SeccompSettingsUnsupportedWithoutSeccomp(t *testing.T) {
	u, err := seccompRafConn(t, rhel7SystemctlVersion).Get("g04-raf")
	require.NoError(t, err)
	assert.Equal(t, "inactive", u.ActiveState)
	for _, property := range systemdSeccompProperties {
		assert.Falsef(t, u.Supports(property), "%s on a -SECCOMP systemd", property)
	}
	assert.True(t, u.Supports("NoNewPrivileges"))
}

// The same unit on a systemd built with seccomp still reads the setting from
// the unit file (#11372).
func TestSystemdUnitManager_SeccompSettingsReadWithSeccomp(t *testing.T) {
	u, err := seccompRafConn(t, rhel8SystemctlVersion).Get("g04-raf")
	require.NoError(t, err)
	assert.True(t, u.Supports("RestrictAddressFamilies"))
	assert.Equal(t, "AF_UNIX", u.RestrictAddressFamilies)
}

// The unit-file reader is told when the host's systemd has no seccomp.
func TestSystemdFSUnitManager_SeccompSettingsUnsupportedWithoutSeccomp(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/g04-raf.service", []byte(rhel7RafUnitFile), 0o644))

	u, err := (&SystemdFSUnitManager{Fs: fs, Version: 219, NoSeccomp: true}).Get("g04-raf")
	require.NoError(t, err)
	assert.False(t, u.Supports("RestrictAddressFamilies"))

	u, err = (&SystemdFSUnitManager{Fs: fs, Version: 219}).Get("g04-raf")
	require.NoError(t, err)
	assert.True(t, u.Supports("RestrictAddressFamilies"))
	assert.Equal(t, "AF_UNIX", u.RestrictAddressFamilies)
}
