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
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

const (
	unitListUnitsPlainCmd = "systemctl list-units --type service --all --plain --no-legend"
	unitListUnitFilesCmd  = "systemctl list-unit-files --type service --all --no-legend"
	systemdVersionCmd     = "systemctl --version"
	systemdAnsweringCmd   = "systemctl show --property=Version"
	accessDenied          = "Failed to get properties: Access denied\n"
)

// `systemctl --version` on Ubuntu 18.04 and RHEL 7.9.
const (
	ubuntu1804Version = "systemd 237\n+PAM +AUDIT +SELINUX +IMA +APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 +SECCOMP +BLKID +ELFUTILS +KMOD -IDN2 +IDN -PCRE2 default-hierarchy=hybrid\n"
	rhel7Version      = "systemd 219\n+PAM +AUDIT +SELINUX +IMA -APPARMOR +SMACK +SYSVINIT +UTMP +LIBCRYPTSETUP +GCRYPT +GNUTLS +ACL +XZ +LZ4 -SECCOMP +BLKID +ELFUTILS +KMOD +IDN\n"
)

// enumConn is a mock connection with commands and a filesystem holding the
// given files with their modes.
func enumConn(t *testing.T, cmds map[string]*mock.Command, files map[string]os.FileMode) *fsMockConn {
	t.Helper()
	conn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "redhat", Family: []string{"redhat", "linux"}},
	}, mock.WithData(&mock.TomlData{Commands: cmds}))
	require.NoError(t, err)

	fs := afero.NewMemMapFs()
	for name, mode := range files {
		require.NoError(t, afero.WriteFile(fs, name, []byte("#!/bin/sh\n"), mode))
	}
	return &fsMockConn{Connection: conn, fs: fs}
}

// fsMockConn records the commands it runs and serves its own filesystem.
type fsMockConn struct {
	*mock.Connection
	fs       afero.Fs
	commands []string
}

func (c *fsMockConn) FileSystem() afero.Fs { return c.fs }

func (c *fsMockConn) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	return c.Connection.RunCommand(command)
}

var _ shared.Connection = &fsMockConn{}

// `systemctl list-units --type service --all --plain --no-legend` on Ubuntu
// 18.04 (instances) and RHEL 7.9 (a SysV unit whose script was removed loads
// as not-found).
func TestParseSystemdLoadedUnitNames(t *testing.T) {
	names, err := parseSystemdLoadedUnitNames(strings.NewReader(strings.Join([]string{
		"g04-tpl@one.service                                   loaded    active   running g04 template one",
		"getty@tty1.service                                    loaded    active   running Getty on tty1",
		`systemd-fsck@dev-disk-by\x2dlabel-UEFI.service        loaded    active   exited  File System Check on /dev/disk/by-label/UEFI`,
		"user@1000.service                                     loaded    active   running User Manager for UID 1000",
		"choose_repo.service                                   not-found active   exited  choose_repo.service",
		"● g04-fail.service                                    loaded    failed   failed  g04 failing unit",
		"",
	}, "\n")))
	require.NoError(t, err)
	assert.Equal(t, []string{
		"g04-tpl@one.service",
		"getty@tty1.service",
		`systemd-fsck@dev-disk-by\x2dlabel-UEFI.service`,
		"user@1000.service",
		"g04-fail.service",
	}, names)
}

func TestIsSystemdInstanceName(t *testing.T) {
	assert.True(t, isSystemdInstanceName("g04-tpl@one"))
	assert.True(t, isSystemdInstanceName("getty@tty1.service"))
	assert.False(t, isSystemdInstanceName("getty@"))
	assert.False(t, isSystemdInstanceName("getty@.service"))
	assert.False(t, isSystemdInstanceName("sshd"))
}

// The RHEL 7 init script directory: `functions` and README are not
// executable and are no services.
func TestSysvInitScriptUnits(t *testing.T) {
	conn := enumConn(t, nil, map[string]os.FileMode{
		"/etc/rc.d/init.d/functions":  0o644,
		"/etc/rc.d/init.d/README":     0o644,
		"/etc/rc.d/init.d/netconsole": 0o755,
		"/etc/rc.d/init.d/network":    0o755,
	})
	assert.Equal(t, []string{"netconsole.service", "network.service"}, sysvInitScriptUnits(conn.FileSystem()))
	assert.Nil(t, sysvInitScriptUnits(afero.NewMemMapFs()))
}

// `systemctl show --all g04-olddir` on RHEL 7.9: systemd 219 knows only the
// *Directories names.
func TestFoldSystemdLegacyPathProperties(t *testing.T) {
	record := map[string]string{
		"Id":                      "g04-olddir.service",
		"NoNewPrivileges":         "no",
		"ReadWriteDirectories":    "/var/tmp",
		"ReadOnlyDirectories":     "/etc",
		"InaccessibleDirectories": "/root",
	}
	foldSystemdLegacyPathProperties(record)
	markUnsupportedShowProperties(record)
	u := systemdUnitFromProperties(record, -1)
	assert.Equal(t, []string{"/etc"}, u.ReadOnlyPaths)
	assert.Equal(t, []string{"/var/tmp"}, u.ReadWritePaths)
	assert.Equal(t, []string{"/root"}, u.InaccessiblePaths)
	assert.True(t, u.Supports("ReadOnlyPaths"))

	// the current name wins when a release prints both
	record = map[string]string{"ReadOnlyPaths": "/usr", "ReadOnlyDirectories": "/etc"}
	foldSystemdLegacyPathProperties(record)
	assert.Equal(t, "/usr", record["ReadOnlyPaths"])
}

func TestSystemdFSUnitManager_LegacyDirectoryNames(t *testing.T) {
	fs := afero.NewMemMapFs()
	require.NoError(t, afero.WriteFile(fs, "/etc/systemd/system/g04-olddir.service", []byte(`[Service]
ExecStart=/bin/sleep infinity
ReadOnlyDirectories=/etc
ReadOnlyPaths=/usr
`), 0o644))
	u, err := (&SystemdFSUnitManager{Fs: fs, Version: 252}).Get("g04-olddir")
	require.NoError(t, err)
	assert.Equal(t, []string{"/etc", "/usr"}, u.ReadOnlyPaths)
}

func unitShowRecord(id, active, fileState string) string {
	return strings.Join([]string{
		"Id=" + id,
		"Description=" + id,
		"LoadState=loaded",
		"ActiveState=" + active,
		"UnitFileState=" + fileState,
		"NoNewPrivileges=no",
		"",
	}, "\n")
}

// systemd.units on every release left out the running instances of a
// template (getty@tty1, g04-tpl@one): list-unit-files names only the
// template. A unit that list-units names but that does not load is dropped.
func TestSystemdUnitManager_ListIncludesInstances(t *testing.T) {
	conn := enumConn(t, map[string]*mock.Command{
		unitListUnitFilesCmd: {Stdout: "g04-tpl@.service  indirect\nsshd.service  enabled\n"},
		unitListUnitsPlainCmd: {Stdout: strings.Join([]string{
			"g04-tpl@one.service  loaded    active   running g04 template one",
			"getty@tty1.service   loaded    active   running Getty on tty1",
			"sshd.service         loaded    active   running OpenSSH server",
			"ghost.service        not-found inactive dead    ghost.service",
			"",
		}, "\n")},
		systemdVersionCmd: {Stdout: ubuntu1804Version},
		buildSystemdUnitShowCommand([]string{"sshd.service", "g04-tpl@one.service", "getty@tty1.service"}): {
			Stdout: unitShowRecord("sshd.service", "active", "enabled") + "\n" +
				unitShowRecord("g04-tpl@one.service", "active", "indirect") + "\n" +
				unitShowRecord("getty@tty1.service", "active", "enabled"),
		},
	}, map[string]os.FileMode{"/etc/systemd/system/g04-tpl@.service": 0o644})

	units, err := (&SystemdUnitManager{conn: conn}).List()
	require.NoError(t, err)
	names := []string{}
	for _, u := range units {
		names = append(names, u.Name)
	}
	assert.ElementsMatch(t, []string{"sshd.service", "g04-tpl@one.service", "getty@tty1.service", "g04-tpl@.service"}, names)
}

// On systemd 219 (RHEL 7) the SysV units are in neither listing unless
// loaded; the init scripts name them. A script that is no service loads as
// not-found and is not reported.
func TestSystemdUnitManager_ListIncludesSysVOn219(t *testing.T) {
	batch := []string{"sshd.service", "netconsole.service", "notaservice.service"}
	conn := enumConn(t, map[string]*mock.Command{
		unitListUnitFilesCmd:  {Stdout: "sshd.service  enabled\n"},
		unitListUnitsPlainCmd: {Stdout: "sshd.service  loaded active running OpenSSH server\n"},
		systemdVersionCmd:     {Stdout: rhel7Version},
		buildSystemdUnitShowCommand(batch): {
			Stdout: unitShowRecord("sshd.service", "active", "enabled") + "\n" +
				unitShowRecord("netconsole.service", "inactive", "bad") + "\n" +
				"Id=notaservice.service\nLoadState=not-found\nActiveState=inactive\nUnitFileState=\n",
		},
	}, map[string]os.FileMode{
		"/etc/rc.d/init.d/netconsole":  0o755,
		"/etc/rc.d/init.d/notaservice": 0o755,
		"/etc/rc.d/init.d/functions":   0o644,
	})

	units, err := (&SystemdUnitManager{conn: conn}).List()
	require.NoError(t, err)
	names := []string{}
	for _, u := range units {
		names = append(names, u.Name)
	}
	assert.ElementsMatch(t, []string{"sshd.service", "netconsole.service"}, names)
}

// systemd 219 fails a whole show batch with "Access denied" when a SysV
// service in it is running while its init script was deleted. Before, that
// made systemd.units drop to the unit files for every unit. The batch is split
// until the failing unit is on its own; it alone is left out.
func TestSystemdUnitManager_ListSplitsAFailingBatch(t *testing.T) {
	all := []string{"a.service", "b.service", "g04gone.service"}
	conn := enumConn(t, map[string]*mock.Command{
		unitListUnitFilesCmd:                               {Stdout: "a.service  enabled\nb.service  enabled\n"},
		unitListUnitsPlainCmd:                              {Stdout: "g04gone.service  loaded active running SYSV: g04 sysv service\n"},
		systemdVersionCmd:                                  {Stdout: ubuntu1804Version},
		systemdAnsweringCmd:                                {Stdout: "Version=237\n"},
		buildSystemdUnitShowCommand(all):                   {Stderr: accessDenied, ExitStatus: 1},
		buildSystemdUnitShowCommand([]string{"a.service"}): {Stdout: unitShowRecord("a.service", "active", "enabled")},
		buildSystemdUnitShowCommand([]string{"b.service", "g04gone.service"}): {Stderr: accessDenied, ExitStatus: 1},
		buildSystemdUnitShowCommand([]string{"b.service"}):                    {Stdout: unitShowRecord("b.service", "inactive", "disabled")},
		buildSystemdUnitShowCommand([]string{"g04gone.service"}):              {Stderr: accessDenied, ExitStatus: 1},
	}, nil)

	units, err := (&SystemdUnitManager{conn: conn}).List()
	require.NoError(t, err)
	require.Len(t, units, 2)
	assert.Equal(t, "a.service", units[0].Name)
	assert.Equal(t, "active", units[0].ActiveState)
	assert.Equal(t, "b.service", units[1].Name)
	assert.Equal(t, "disabled", units[1].UnitFileState)
}

// When systemd is not answering at all the batch is not split; the caller
// reads the unit files instead.
func TestBisectSystemdShowStopsWhenSystemdIsNotAnswering(t *testing.T) {
	calls := 0
	err := bisectSystemdShow([]string{"a", "b", "c", "d"},
		func([]string) (int, error) { calls++; return 0, assert.AnError },
		func(int) {},
		func(string, error) { t.Fatal("no unit is skipped") },
		func() bool { return false },
	)
	assert.ErrorIs(t, err, assert.AnError)
	assert.Equal(t, 1, calls)
}

// services.list on RHEL 7: a batch with the running SysV service whose
// script was deleted (g04gone) failed with "Access denied", and every other
// row in it lost its unit-file state: g04sysvon (chkconfig on) and the
// enabled getty@tty1 read enabled=false. netconsole, a SysV service neither
// running nor enabled, was missing altogether.
func TestSystemDServiceManagerListOn219(t *testing.T) {
	showCmd := func(units ...string) string { return buildSystemdServiceShowCommand(units) }
	svc := func(id, active, state, desc string) string {
		return strings.Join([]string{
			"Id=" + id, "Names=" + id, "Description=" + desc, "LoadState=loaded",
			"ActiveState=" + active, "UnitFileState=" + state, "",
		}, "\n")
	}
	conn := enumConn(t, map[string]*mock.Command{
		unitFilesCmd: {Stdout: strings.Join([]string{
			"UNIT FILE        STATE",
			"getty@.service   enabled",
			"sshd.service     enabled",
			"",
			"2 unit files listed.",
		}, "\n")},
		listUnitsCmd: {Stdout: strings.Join([]string{
			"g04gone.service       loaded    active   running SYSV: g04 sysv service",
			"g04sysvon.service     loaded    inactive dead    SYSV: g04 sysv service",
			"getty@tty1.service    loaded    active   running Getty on tty1",
			"sshd.service          loaded    active   running OpenSSH server daemon",
			"",
		}, "\n")},
		systemdVersionCmd:   {Stdout: rhel7Version},
		systemdAnsweringCmd: {Stdout: "Version=219\n"},
		showCmd("g04gone.service", "g04sysvon.service", "getty@tty1.service", "netconsole.service"): {Stderr: accessDenied, ExitStatus: 1},
		showCmd("g04gone.service", "g04sysvon.service"):                                             {Stderr: accessDenied, ExitStatus: 1},
		showCmd("g04gone.service"):   {Stderr: accessDenied, ExitStatus: 1},
		showCmd("g04sysvon.service"): {Stdout: svc("g04sysvon.service", "inactive", "bad", "SYSV: g04 sysv service")},
		showCmd("getty@tty1.service", "netconsole.service"): {Stdout: svc("getty@tty1.service", "active", "enabled", "Getty on tty1") + "\n" +
			svc("netconsole.service", "inactive", "bad", "LSB: Initializes network console logging")},
		"systemctl is-enabled -- g04sysvon.service":  {Stdout: "enabled\n"},
		"systemctl is-enabled -- netconsole.service": {Stdout: "disabled\n", ExitStatus: 1},
	}, map[string]os.FileMode{
		"/etc/rc.d/init.d/g04sysvon":  0o755,
		"/etc/rc.d/init.d/netconsole": 0o755,
		"/etc/rc.d/init.d/functions":  0o644,
	})

	services, err := (&SystemDServiceManager{conn: conn}).List()
	require.NoError(t, err)
	byName := servicesByName(services)

	require.Contains(t, byName, "g04sysvon")
	assert.True(t, byName["g04sysvon"].Enabled)
	require.Contains(t, byName, "getty@tty1")
	assert.True(t, byName["getty@tty1"].Enabled)
	assert.True(t, byName["getty@tty1"].Running)
	require.Contains(t, byName, "netconsole")
	assert.True(t, byName["netconsole"].Installed)
	assert.False(t, byName["netconsole"].Enabled)
	// the unit that fails on its own keeps what list-units said
	require.Contains(t, byName, "g04gone")
	assert.True(t, byName["g04gone"].Running)
}

// Ubuntu 24.04 after chrony was removed: list-unit-files still lists the
// dangling chronyd.service link as "bad", systemctl show says not-found.
func TestSystemDServiceManagerListDanglingUnitFileNotInstalled(t *testing.T) {
	conn := enumConn(t, map[string]*mock.Command{
		unitFilesCmd: {Stdout: strings.Join([]string{
			"UNIT FILE        STATE    VENDOR PRESET",
			"chronyd.service  bad      enabled",
			"sshd.service     enabled  enabled",
			"",
			"2 unit files listed.",
		}, "\n")},
		listUnitsCmd:      {Stdout: "  sshd.service  loaded active running OpenSSH server daemon\n"},
		systemdVersionCmd: {Stdout: "systemd 255 (255.4-1ubuntu8)\n"},
		buildSystemdServiceShowCommand([]string{"chronyd.service"}): {Stdout: strings.Join([]string{
			"Id=chronyd.service", "Names=chronyd.service", "Description=chronyd.service",
			"LoadState=not-found", "ActiveState=inactive", "UnitFileState=", "",
		}, "\n")},
	}, nil)

	services, err := (&SystemDServiceManager{conn: conn}).List()
	require.NoError(t, err)
	byName := servicesByName(services)
	require.Contains(t, byName, "chronyd")
	assert.False(t, byName["chronyd"].Installed)
	assert.False(t, byName["chronyd"].Enabled)
	for _, cmd := range conn.commands {
		assert.NotEqual(t, "systemctl is-enabled -- chronyd.service", cmd)
	}
}

// systemd 237 (Ubuntu 18.04) reports an enabled template instance as
// UnitFileState=indirect; is-enabled says enabled.
func TestSystemDServiceManagerIndirectInstanceAsksIsEnabled(t *testing.T) {
	conn := enumConn(t, map[string]*mock.Command{
		buildSystemdServiceShowCommand([]string{"g04-tpl@one.service"}): {Stdout: strings.Join([]string{
			"Id=g04-tpl@one.service", "Names=g04-tpl@one.service", "Description=g04 template one",
			"LoadState=loaded", "ActiveState=active", "UnitFileState=indirect", "",
		}, "\n")},
		"systemctl is-enabled -- g04-tpl@one.service": {Stdout: "enabled\n"},
	}, nil)

	service, err := (&SystemDServiceManager{conn: conn}).Get("g04-tpl@one")
	require.NoError(t, err)
	assert.True(t, service.Enabled)

	// a template's own indirect state is not asked about
	s := &Service{Name: "g04-tpl@", Installed: true}
	applySystemdUnitFileState(s, "indirect")
	assert.False(t, s.needsIsEnabled)
}

// systemd.unit("g04-olddir") on RHEL 7.9: the property list exits 1 after the
// first unit, and the --all retry prints 219's directive names.
func TestSystemdUnitManager_GetReadsLegacyDirectoriesOn219(t *testing.T) {
	conn := enumConn(t, map[string]*mock.Command{
		buildSystemdUnitShowCommand([]string{"g04-olddir"}): {
			Stdout:     "ReadWriteDirectories=/var/tmp\nReadOnlyDirectories=/etc\nInaccessibleDirectories=/root\nId=g04-olddir.service\n",
			ExitStatus: 1,
		},
		buildSystemdUnitShowAllCommand([]string{"g04-olddir"}): {Stdout: strings.Join([]string{
			"Type=simple",
			"NoNewPrivileges=no",
			"ReadWriteDirectories=/var/tmp",
			"ReadOnlyDirectories=/etc",
			"InaccessibleDirectories=/root",
			"Id=g04-olddir.service",
			"LoadState=loaded",
			"ActiveState=active",
			"",
		}, "\n")},
	}, nil)

	u, err := (&SystemdUnitManager{conn: conn}).Get("g04-olddir")
	require.NoError(t, err)
	assert.True(t, u.Supports("ReadOnlyPaths"))
	assert.Equal(t, []string{"/etc"}, u.ReadOnlyPaths)
	assert.Equal(t, []string{"/var/tmp"}, u.ReadWritePaths)
	assert.Equal(t, []string{"/root"}, u.InaccessiblePaths)
}
