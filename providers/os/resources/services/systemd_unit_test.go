// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"strings"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	// and none of its settings are reported as configured
	assert.Empty(t, unit.ProtectSystem)
	assert.False(t, unit.NoNewPrivileges)
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
