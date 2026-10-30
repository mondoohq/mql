// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseSystemdShowRecords(t *testing.T) {
	out := `Id=sshd.service
Description=OpenSSH server daemon
LoadState=loaded
NoNewPrivileges=no

Id=chronyd.service
Description=NTP client/server
LoadState=loaded
NoNewPrivileges=yes
`

	records, err := parseSystemdShowRecords(strings.NewReader(out))
	require.NoError(t, err)
	require.Len(t, records, 2)

	assert.Equal(t, "sshd.service", records[0]["Id"])
	assert.Equal(t, "no", records[0]["NoNewPrivileges"])
	assert.Equal(t, "chronyd.service", records[1]["Id"])
	assert.Equal(t, "yes", records[1]["NoNewPrivileges"])
}

func TestParseSystemdShowRecords_RepeatedKeyIsJoined(t *testing.T) {
	records, err := parseSystemdShowRecords(strings.NewReader(`Id=multi.service
ExecStart={ path=/bin/one ; argv[]=/bin/one }
ExecStart={ path=/bin/two ; argv[]=/bin/two }
`))
	require.NoError(t, err)
	require.Len(t, records, 1)

	assert.Equal(t, "{ path=/bin/one ; argv[]=/bin/one }\n{ path=/bin/two ; argv[]=/bin/two }", records[0]["ExecStart"])
}

func TestParseSystemdShowRecords_SingleRecordNoTrailingBlankLine(t *testing.T) {
	records, err := parseSystemdShowRecords(strings.NewReader("Id=one.service\nLoadState=loaded"))
	require.NoError(t, err)
	require.Len(t, records, 1)
	assert.Equal(t, "one.service", records[0]["Id"])
}

func TestParseSystemdUnitFileNames(t *testing.T) {
	out := `UNIT FILE                    STATE    PRESET
sshd.service                 enabled  enabled
chronyd.service              enabled  enabled
sshd@.service                static   -
some.socket                  enabled  enabled
dbus.target                  static   -

5 unit files listed.
`

	names, err := parseSystemdUnitFileNames(strings.NewReader(out))
	require.NoError(t, err)

	// only service units, and the summary line is not one
	assert.Equal(t, []string{"sshd.service", "chronyd.service", "sshd@.service"}, names)
}

func TestParseSystemdUnitFileNames_Empty(t *testing.T) {
	names, err := parseSystemdUnitFileNames(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, names)
}

func TestParseSystemdBool(t *testing.T) {
	for _, value := range []string{"yes", "YES", "true", "on", "1", " yes "} {
		assert.True(t, parseSystemdBool(value), value)
	}
	for _, value := range []string{"no", "false", "off", "0", "", "garbage"} {
		assert.False(t, parseSystemdBool(value), value)
	}
}

func TestSplitSystemdList(t *testing.T) {
	tests := []struct {
		title    string
		value    string
		expected []string
	}{
		{"capability names", "cap_chown cap_dac_override", []string{"cap_chown", "cap_dac_override"}},
		{"braced value", "{ /var/lib/x /var/log/y }", []string{"/var/lib/x", "/var/log/y"}},
		{"deny list marker is kept", "~@clock @cpu-emulation", []string{"~@clock", "@cpu-emulation"}},
		{"empty", "", []string{}},
		{"whitespace only", "   ", []string{}},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.expected, splitSystemdList(test.value))
		})
	}
}

func TestParseSystemdExecStart(t *testing.T) {
	tests := []struct {
		title    string
		value    string
		expected string
	}{
		{
			"structured value",
			"{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D $OPTIONS ; ignore_errors=no }",
			"/usr/sbin/sshd -D $OPTIONS",
		},
		{
			"first of several",
			"{ path=/bin/one ; argv[]=/bin/one }\n{ path=/bin/two ; argv[]=/bin/two }",
			"/bin/one",
		},
		{"plain command", "/usr/bin/true", "/usr/bin/true"},
		{"empty", "", ""},
		{
			// Ubuntu 16.04 emergency.service: the shell command holds a bare ";"
			"semicolon inside the command",
			"{ path=/bin/sh ; argv[]=/bin/sh -c /sbin/sulogin; /bin/systemctl --job-mode=fail --no-block default ; ignore_errors=yes ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }",
			"/bin/sh -c /sbin/sulogin; /bin/systemctl --job-mode=fail --no-block default",
		},
		{
			// Ubuntu 24.04 cloud-init-hotplugd.service
			"several semicolons inside the command",
			`{ path=/bin/bash ; argv[]=/bin/bash -c read args <&3; echo "args=$args"; exec /usr/bin/cloud-init devel hotplug-hook $args; exit 0 ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }`,
			`/bin/bash -c read args <&3; echo "args=$args"; exec /usr/bin/cloud-init devel hotplug-hook $args; exit 0`,
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.expected, parseSystemdExecStart(test.value))
		})
	}
}

func TestSystemdUnitFromProperties(t *testing.T) {
	unit := systemdUnitFromProperties(map[string]string{
		"Id":                    "sshd.service",
		"Description":           "OpenSSH server daemon",
		"LoadState":             "loaded",
		"ActiveState":           "active",
		"UnitFileState":         "enabled",
		"FragmentPath":          "/usr/lib/systemd/system/sshd.service",
		"Type":                  "notify",
		"ExecStart":             "{ path=/usr/sbin/sshd ; argv[]=/usr/sbin/sshd -D ; ignore_errors=no }",
		"User":                  "",
		"NoNewPrivileges":       "yes",
		"ProtectSystem":         "full",
		"ProtectControlGroups":  "private",
		"PrivateTmp":            "yes",
		"RestrictNamespaces":    "cgroup ipc net",
		"CapabilityBoundingSet": "cap_chown cap_net_bind_service",
		"SystemCallFilter":      "~@clock @debug",
		"ReadWritePaths":        "{ /var/lib/sshd }",
	}, -1)

	require.NotNil(t, unit)
	assert.Equal(t, "sshd.service", unit.Name)
	assert.True(t, unit.Installed)
	assert.Equal(t, "/usr/sbin/sshd -D", unit.ExecStart)
	assert.True(t, unit.NoNewPrivileges)
	assert.Equal(t, "full", unit.ProtectSystem)
	// a value with more than two states stays a string
	assert.Equal(t, "private", unit.ProtectControlGroups)
	assert.Equal(t, "cgroup ipc net", unit.RestrictNamespaces)
	assert.Equal(t, []string{"cap_chown", "cap_net_bind_service"}, unit.CapabilityBoundingSet)
	assert.Equal(t, []string{"@clock", "@debug"}, unit.SystemCallFilter)
	assert.True(t, unit.SystemCallFilterIsDenylist)
	assert.Equal(t, []string{"/var/lib/sshd"}, unit.ReadWritePaths)
}

func TestSystemdUnitFromProperties_NotFound(t *testing.T) {
	unit := systemdUnitFromProperties(map[string]string{
		"Id":        "nope.service",
		"LoadState": "not-found",
	}, -1)

	require.NotNil(t, unit)
	assert.False(t, unit.Installed)
	// every setting reads as explicitly off, so an assertion over several of them
	// fails on a miss rather than passing on nulls
	assert.False(t, unit.NoNewPrivileges)
	assert.Empty(t, unit.ProtectSystem)
}

func TestSystemdUnitFromProperties_NoID(t *testing.T) {
	assert.Nil(t, systemdUnitFromProperties(map[string]string{"LoadState": "loaded"}, -1))
}

func TestSystemdFSUnitManager(t *testing.T) {
	fs := afero.NewMemMapFs()

	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service", []byte(`[Unit]
Description=Demo service

[Service]
Type=simple
ExecStart=/usr/bin/demo
User=demo
NoNewPrivileges=yes
ProtectSystem=full
CapabilityBoundingSet=cap_chown
CapabilityBoundingSet=cap_net_bind_service

[Install]
WantedBy=multi-user.target
`), 0o644))

	mgr := &SystemdFSUnitManager{Fs: fs}

	unit, err := mgr.Get("demo.service")
	require.NoError(t, err)

	assert.Equal(t, "demo.service", unit.Name)
	assert.Equal(t, "Demo service", unit.Description)
	assert.True(t, unit.Installed)
	assert.Equal(t, "/usr/lib/systemd/system/demo.service", unit.FragmentPath)
	assert.Equal(t, "simple", unit.Type)
	assert.Equal(t, "/usr/bin/demo", unit.ExecStart)
	assert.Equal(t, "demo", unit.User)
	assert.True(t, unit.NoNewPrivileges)
	assert.Equal(t, "full", unit.ProtectSystem)
	// a list setting accumulates across assignments rather than being replaced
	assert.Equal(t, []string{"cap_chown", "cap_net_bind_service"}, unit.CapabilityBoundingSet)
}

func TestSystemdFSUnitManager_DropInOverrides(t *testing.T) {
	fs := afero.NewMemMapFs()

	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service", []byte(`[Service]
User=demo
NoNewPrivileges=no
ProtectSystem=no
`), 0o644))

	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service.d/10-first.conf", []byte(`[Service]
NoNewPrivileges=yes
`), 0o644))

	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service.d/20-second.conf", []byte(`[Service]
ProtectSystem=strict
User=
`), 0o644))

	unit, err := (&SystemdFSUnitManager{Fs: fs}).Get("demo.service")
	require.NoError(t, err)

	// a drop-in overrides the unit file
	assert.True(t, unit.NoNewPrivileges)
	// and a later drop-in wins over an earlier one
	assert.Equal(t, "strict", unit.ProtectSystem)
	// an empty assignment resets the setting rather than appending to it
	assert.Empty(t, unit.User)
}

func TestSystemdFSUnitManager_SearchPathPrecedence(t *testing.T) {
	fs := afero.NewMemMapFs()

	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service", []byte("[Service]\nProtectSystem=no\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/demo.service", []byte("[Service]\nProtectSystem=strict\n"), 0o644))

	mgr := &SystemdFSUnitManager{Fs: fs}

	// /etc precedes /usr/lib in the unit search path
	unit, err := mgr.Get("demo.service")
	require.NoError(t, err)
	assert.Equal(t, "strict", unit.ProtectSystem)

	// and the shadowed copy is not listed a second time
	units, err := mgr.List()
	require.NoError(t, err)
	require.Len(t, units, 1)
	assert.Equal(t, "strict", units[0].ProtectSystem)
}

func TestSystemdFSUnitManager_MaskedUnit(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/masked.service", []byte(""), 0o644))

	unit, err := (&SystemdFSUnitManager{Fs: fs}).Get("masked.service")
	require.NoError(t, err)

	assert.Equal(t, "masked.service", unit.Name)
	// a filesystem that cannot read the /dev/null link still has to report the
	// unit as masked; reporting it as loaded would read like a service running
	// with no confinement at all
	assert.Equal(t, "masked", unit.LoadState)
	assert.Equal(t, "masked", unit.UnitFileState)
	// a masked unit is still installed: the name exists and carries a unit file,
	// it just cannot be started
	assert.True(t, unit.Installed)
	// and none of its settings are reported as configured: what it reports
	// is systemd's default, as systemctl show prints it for a masked unit
	assert.Equal(t, "no", unit.ProtectSystem)
	assert.False(t, unit.NoNewPrivileges)
	assert.Equal(t, "/etc/systemd/system/masked.service", unit.FragmentPath, "the mask link, as systemctl reports it")
}

func TestSystemdFSUnitManager_DropInOrderIsByFileNameAcrossDirectories(t *testing.T) {
	fs := afero.NewMemMapFs()

	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/demo.service",
		[]byte("[Service]\nProtectSystem=no\n"), 0o644))

	// the later-sorting file lives in the lower-precedence directory, so applying
	// drop-ins directory by directory would let /etc win when systemd would not
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/demo.service.d/05-early.conf",
		[]byte("[Service]\nProtectSystem=yes\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service.d/10-late.conf",
		[]byte("[Service]\nProtectSystem=strict\n"), 0o644))

	unit, err := (&SystemdFSUnitManager{Fs: fs}).Get("demo.service")
	require.NoError(t, err)

	// 10-late sorts after 05-early regardless of directory, so it wins
	assert.Equal(t, "strict", unit.ProtectSystem)
}

func TestSystemdFSUnitManager_DropInSameNameHigherPrecedenceDirWins(t *testing.T) {
	fs := afero.NewMemMapFs()

	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/demo.service",
		[]byte("[Service]\nProtectSystem=no\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/demo.service.d/10-over.conf",
		[]byte("[Service]\nProtectSystem=strict\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/demo.service.d/10-over.conf",
		[]byte("[Service]\nProtectSystem=yes\n"), 0o644))

	unit, err := (&SystemdFSUnitManager{Fs: fs}).Get("demo.service")
	require.NoError(t, err)

	// the same file name in both directories: /etc shadows /usr/lib entirely
	assert.Equal(t, "strict", unit.ProtectSystem)
}

func TestParseSystemdUnitFileNames_NoLegend(t *testing.T) {
	// with --no-legend there is no header line to skip, so the first unit must
	// not be swallowed
	names, err := parseSystemdUnitFileNames(strings.NewReader(
		"sshd.service                 enabled  enabled\nchronyd.service              enabled  enabled\n"))
	require.NoError(t, err)

	assert.Equal(t, []string{"sshd.service", "chronyd.service"}, names)
}

func TestSystemdFSUnitManager_NotFound(t *testing.T) {
	_, err := (&SystemdFSUnitManager{Fs: afero.NewMemMapFs()}).Get("absent.service")
	require.ErrorIs(t, err, ErrServiceNotFound)
}

func TestBuildSystemdUnitShowCommand(t *testing.T) {
	cmd := buildSystemdUnitShowCommand([]string{"sshd.service", "chronyd.service"})

	assert.Contains(t, cmd, "systemctl show --property=")
	assert.Contains(t, cmd, "NoNewPrivileges")
	assert.Contains(t, cmd, "sshd.service")
	assert.Contains(t, cmd, "chronyd.service")
}

func TestSystemdListProperty(t *testing.T) {
	assert.True(t, systemdListProperty("CapabilityBoundingSet"))
	assert.True(t, systemdListProperty("ReadWritePaths"))
	assert.False(t, systemdListProperty("ProtectSystem"))
	assert.False(t, systemdListProperty("User"))
}

func TestParseSystemdCapabilities(t *testing.T) {
	tests := []struct {
		title    string
		value    string
		lastCap  int
		expected []string
	}{
		{
			"names as current systemd prints them",
			"cap_chown cap_net_bind_service", 40,
			[]string{"cap_chown", "cap_net_bind_service"},
		},
		{
			// systemd 229, CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_CHOWN
			"decimal mask from systemd 229",
			"1025", 37,
			[]string{"cap_chown", "cap_net_bind_service"},
		},
		{
			// systemd 229, AmbientCapabilities=CAP_NET_BIND_SERVICE
			"single capability mask",
			"1024", 37,
			[]string{"cap_net_bind_service"},
		},
		{"zero mask is no capabilities", "0", 37, []string{}},
		{"empty", "", 37, []string{}},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			assert.Equal(t, test.expected, parseSystemdCapabilities(test.value, test.lastCap))
		})
	}
}

// systemd 229 prints a unit holding every capability as 18446744073709551615.
// Kept as written, none(_ == "cap_sys_admin") passed for it.
func TestParseSystemdCapabilities_FullMask(t *testing.T) {
	caps := parseSystemdCapabilities("18446744073709551615", 37)
	assert.Contains(t, caps, "cap_sys_admin")
	assert.Len(t, caps, 38)
	assert.Equal(t, "cap_audit_read", caps[len(caps)-1])
	// the kernel on that host stops at 37, so later capabilities are not listed
	assert.NotContains(t, caps, "cap_perfmon")
}

// CapabilityBoundingSet=~CAP_SYS_ADMIN on systemd 229 prints every bit but 21.
func TestParseSystemdCapabilities_MaskWithoutSysAdmin(t *testing.T) {
	caps := parseSystemdCapabilities("18446744073707454463", 37)
	assert.NotContains(t, caps, "cap_sys_admin")
	assert.Contains(t, caps, "cap_sys_module")
	assert.Len(t, caps, 37)
}

func TestParseSystemdCapabilities_UnknownLastCapDecodesEveryName(t *testing.T) {
	caps := parseSystemdCapabilities("18446744073709551615", -1)
	assert.Len(t, caps, len(systemdCapabilityNames))
	assert.Equal(t, "cap_checkpoint_restore", caps[len(caps)-1])
}

// systemd 245 on a newer kernel prints the capabilities it has no name for in
// hex (Ubuntu 20.04: "... cap_audit_read 0x26 0x27 0x28").
func TestParseSystemdCapabilities_HexEntries(t *testing.T) {
	caps := parseSystemdCapabilities("cap_block_suspend cap_audit_read 0x26 0x27 0x28", 40)
	assert.Equal(t, []string{"cap_block_suspend", "cap_audit_read", "cap_perfmon", "cap_bpf", "cap_checkpoint_restore"}, caps)
}

func TestParseSystemdSystemCallFilter(t *testing.T) {
	tests := []struct {
		title    string
		value    string
		expected []string
		deny     bool
	}{
		// every release prints a lone "~" for a unit without a filter
		{"no filter", "~", []string{}, false},
		{"unset", "", []string{}, false},
		{
			"deny list",
			"~chroot fsconfig fsmount kexec_load mount reboot umount2",
			[]string{"chroot", "fsconfig", "fsmount", "kexec_load", "mount", "reboot", "umount2"},
			true,
		},
		{"allow list", "execve exit exit_group read rt_sigreturn write", []string{"execve", "exit", "exit_group", "read", "rt_sigreturn", "write"}, false},
		{"unit file spelling", "~@mount @reboot", []string{"@mount", "@reboot"}, true},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			calls, deny := parseSystemdSystemCallFilter(test.value)
			assert.Equal(t, test.expected, calls)
			assert.Equal(t, test.deny, deny)
		})
	}
}

func TestNormalizeSystemdAddressFamilies(t *testing.T) {
	assert.Equal(t, "", normalizeSystemdAddressFamilies("~"))
	assert.Equal(t, "~AF_PACKET", normalizeSystemdAddressFamilies("~AF_PACKET"))
	assert.Equal(t, "AF_INET AF_UNIX", normalizeSystemdAddressFamilies("AF_INET AF_UNIX"))
}

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

// Units read from disk report what systemctl show reports for them. The
// expected values are systemd 252's (Debian 12) for these four unit files,
// which set none of the sandboxing settings, an inverted bounding set, two
// bounding set assignments, and BusName= with no Type=.
func TestSystemdFSUnitReportsSystemdDefaults(t *testing.T) {
	fs := afero.NewMemMapFs()
	for p, content := range map[string]string{
		"/etc/systemd/system/zz-noexec.service": "[Unit]\nDescription=zz no exec\n[Service]\nExecStop=/bin/true\n",
		"/etc/systemd/system/zz-bus.service":    "[Service]\nBusName=org.zz.Test\nExecStart=/bin/sleep 1\n",
		"/etc/systemd/system/zz-caps.service":   "[Service]\nExecStart=/bin/sleep 1\nCapabilityBoundingSet=~CAP_SYS_ADMIN CAP_NET_RAW\nAmbientCapabilities=CAP_NET_RAW CAP_CHOWN\nRestrictAddressFamilies=AF_UNIX AF_NETLINK AF_INET\n",
		"/etc/systemd/system/zz-caps2.service":  "[Service]\nExecStart=/bin/sleep 1\nCapabilityBoundingSet=CAP_NET_BIND_SERVICE\nCapabilityBoundingSet=CAP_CHOWN\nRestrictAddressFamilies=~AF_PACKET AF_INET6\n",
	} {
		require.NoError(t, afero.WriteFile(fs, p, []byte(content), 0o644))
	}
	m := &SystemdFSUnitManager{Fs: fs}
	get := func(name string) *SystemdUnit {
		u, err := m.Get(name)
		require.NoError(t, err)
		return u
	}

	noexec := get("zz-noexec.service")
	assert.Equal(t, "oneshot", noexec.Type)
	assert.Equal(t, "0022", noexec.UMask)
	assert.Equal(t, "no", noexec.ProtectSystem)
	assert.Equal(t, "no", noexec.ProtectHome)
	assert.Equal(t, "no", noexec.ProtectControlGroups)
	assert.Equal(t, "no", noexec.RestrictNamespaces)
	assert.Equal(t, "default", noexec.ProtectProc)
	assert.Equal(t, "all", noexec.ProcSubset)
	assert.Equal(t, "private", noexec.KeyringMode)
	assert.Equal(t, systemdCapabilityNames, noexec.CapabilityBoundingSet, "unset is every capability")
	assert.Empty(t, noexec.AmbientCapabilities)
	assert.Equal(t, "", noexec.RestrictAddressFamilies)
	assert.Equal(t, "zz no exec", noexec.Description)

	bus := get("zz-bus.service")
	assert.Equal(t, "dbus", bus.Type)
	assert.Equal(t, "zz-bus.service", bus.Description, "no Description= reads as the unit name")

	caps := get("zz-caps.service")
	assert.Equal(t, "simple", caps.Type)
	assert.Len(t, caps.CapabilityBoundingSet, len(systemdCapabilityNames)-2)
	assert.NotContains(t, caps.CapabilityBoundingSet, "cap_sys_admin")
	assert.NotContains(t, caps.CapabilityBoundingSet, "cap_net_raw")
	assert.Equal(t, []string{"cap_chown", "cap_net_raw"}, caps.AmbientCapabilities)
	assert.Equal(t, "AF_INET AF_NETLINK AF_UNIX", caps.RestrictAddressFamilies)

	caps2 := get("zz-caps2.service")
	assert.Equal(t, []string{"cap_chown", "cap_net_bind_service"}, caps2.CapabilityBoundingSet)
	assert.Equal(t, "~AF_INET6 AF_PACKET", caps2.RestrictAddressFamilies)
}

// systemd drops capabilities along with what a sandboxing setting protects,
// and prints a command line unquoted (console-getty.service on Debian 12).
func TestSystemdFSUnitImplicitCapabilitiesAndCommandLine(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/logrotate.service", []byte(
		"[Service]\nType=oneshot\nExecStart=/usr/sbin/logrotate /etc/logrotate.conf\nPrivateDevices=true\nProtectClock=true\nProtectKernelLogs=true\nProtectKernelModules=true\nProtectControlGroups=true\nReadWritePaths=/var/lib/logrotate/\n"), 0o644))
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/console-getty.service", []byte(
		"[Service]\nExecStart=-/sbin/agetty -o '-p -- \\\\u' --noclear --keep-baud - 115200,38400,9600 $TERM\n"), 0o644))
	m := &SystemdFSUnitManager{Fs: fs}

	u, err := m.Get("logrotate.service")
	require.NoError(t, err)
	for _, dropped := range []string{"cap_mknod", "cap_sys_rawio", "cap_sys_time", "cap_wake_alarm", "cap_syslog", "cap_sys_module"} {
		assert.NotContains(t, u.CapabilityBoundingSet, dropped)
	}
	assert.Len(t, u.CapabilityBoundingSet, len(systemdCapabilityNames)-6)
	assert.Equal(t, "yes", u.ProtectControlGroups)
	assert.Equal(t, []string{"/var/lib/logrotate"}, u.ReadWritePaths)

	u, err = m.Get("console-getty.service")
	require.NoError(t, err)
	// systemctl show console-getty -p ExecStart on Debian 12
	assert.Equal(t, `/sbin/agetty -o -p -- \u --noclear --keep-baud - 115200,38400,9600 $TERM`, u.ExecStart)

	// initrd-parse-etc.service: two commands, systemd reports the first,
	// whose "@" makes the second word argv[0]
	require.NoError(t, afero.WriteFile(fs, "/lib/systemd/system/initrd-parse-etc.service", []byte(
		"[Service]\nType=oneshot\nExecStart=@/lib/systemd/system-generators/systemd-fstab-generator systemd-sysroot-fstab-check\nExecStart=systemctl --no-block start initrd-cleanup.service\n"), 0o644))
	u, err = m.Get("initrd-parse-etc.service")
	require.NoError(t, err)
	assert.Equal(t, "systemd-sysroot-fstab-check", u.ExecStart)
}

// detect-part-label-duplicates.service on openSUSE Leap 15.6 continues its
// command over several lines
func TestSystemdFSUnitContinuedLines(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/cont.service", []byte(
		"[Service]\nExecStart=/bin/sh -c \" \\\n    if true; then \\\n      echo a; fi\"\n"), 0o644))
	u, err := (&SystemdFSUnitManager{Fs: fs}).Get("cont.service")
	require.NoError(t, err)
	assert.Equal(t, "/bin/sh -c       if true; then        echo a; fi", u.ExecStart)
}

func TestSystemdCommandLine(t *testing.T) {
	assert.Equal(t, "/bin/sh -c echo a; echo b", systemdCommandLine(`/bin/sh -c "echo a; echo b"`))
	assert.Equal(t, "argv0 --flag", systemdCommandLine("@/usr/bin/real argv0 --flag"))
	assert.Equal(t, "/usr/bin/x", systemdCommandLine("+!/usr/bin/x"))
	assert.Equal(t, "/bin/first", systemdCommandLine("/bin/first\n/bin/second"))
}

// A systemd that predates a sandboxing setting ignores it, and keeps the
// capabilities the setting would drop: ProtectClock= (245) on systemd 219.
func TestSystemdFSUnitImplicitDropsFollowTheRelease(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/usr/lib/systemd/system/clock.service", []byte(
		"[Service]\nExecStart=/bin/true\nProtectClock=yes\nPrivateDevices=yes\n"), 0o644))

	u, err := (&SystemdFSUnitManager{Fs: fs, Version: 219}).Get("clock.service")
	require.NoError(t, err)
	assert.Contains(t, u.CapabilityBoundingSet, "cap_sys_time")
	assert.NotContains(t, u.CapabilityBoundingSet, "cap_mknod", "PrivateDevices predates 219")

	u, err = (&SystemdFSUnitManager{Fs: fs, Version: 252}).Get("clock.service")
	require.NoError(t, err)
	assert.NotContains(t, u.CapabilityBoundingSet, "cap_sys_time")
}

// systemd reads a capability given by its number like one given by name.
func TestFoldSystemdCapabilitiesTakesNumbers(t *testing.T) {
	mask, err := strconv.ParseUint(foldSystemdCapabilities("", false, "21 cap_chown"), 10, 64)
	require.NoError(t, err)
	assert.Equal(t, []string{"cap_chown", "cap_sys_admin"}, decodeSystemdCapabilityMask(mask, -1))
}
