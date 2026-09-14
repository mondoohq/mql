// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/mountedfs"
)

func TestParseServiceSystemDUnitFiles(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithPath("./testdata/ubuntu2204.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("systemctl list-unit-files --type service --all")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseServiceSystemDUnitFiles(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 263, len(m), "detected the right amount of services")

	// check first element
	assert.Equal(t, "accounts-daemon", m[0].Name, "service name detected")
	assert.Equal(t, "systemd", m[0].Type, "service type is added")

	// check last element
	assert.Equal(t, "x11-common", m[262].Name, "service name detected")
	assert.Equal(t, "systemd", m[262].Type, "service type is added")

	// check for masked element
	assert.Equal(t, "cryptdisks", m[30].Name, "service name detected")
	assert.Equal(t, true, m[30].Masked, "service is masked")
	assert.Equal(t, false, m[30].Static, "masked service is not static")

	// check for static element (alsa-restore is the third service, index 2)
	assert.Equal(t, "alsa-restore", m[2].Name, "service name detected")
	assert.Equal(t, true, m[2].Static, "service is static")
	assert.Equal(t, false, m[2].Enabled, "static service is not enabled")
	assert.Equal(t, false, m[2].Masked, "static service is not masked")

	// check that enabled service is not static
	assert.Equal(t, "accounts-daemon", m[0].Name, "service name detected")
	assert.Equal(t, false, m[0].Static, "enabled service is not static")
}

func TestParseServiceSystemDUnitFilesPhoton(t *testing.T) {
	mock, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "photon",
			Family: []string{"linux", "unix", "os"},
		},
	}, mock.WithPath("./testdata/photon.toml"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := mock.RunCommand("systemctl list-unit-files --type service --all")
	if err != nil {
		t.Fatal(err)
	}
	assert.Nil(t, err)

	m, err := ParseServiceSystemDUnitFiles(c.Stdout)
	assert.Nil(t, err)
	assert.Equal(t, 137, len(m), "detected the right amount of services")

	// check first element
	assert.Equal(t, "autovt@", m[0].Name, "service name detected")
	assert.Equal(t, "systemd", m[0].Type, "service type is added")

	// check last element
	assert.Equal(t, "vmtoolsd", m[136].Name, "service name detected")
	assert.Equal(t, "systemd", m[136].Type, "service type is added")

	// check for masked element
	assert.Equal(t, "dracut-pre-udev", m[30].Name, "service name detected")
	assert.Equal(t, false, m[30].Masked, "service is not masked")
}

func TestSystemdFS(t *testing.T) {
	s := SystemdFSServiceManager{
		Fs: mountedfs.NewMountedFs("testdata/systemd"),
	}

	services, err := s.List()
	require.NoError(t, err)
	servicesMap := map[string]*Service{}
	for _, svc := range services {
		servicesMap[svc.Name] = svc
	}

	assert.NotContains(t, servicesMap, "default")
	assert.NotContains(t, servicesMap, "default.target")
	assert.NotContains(t, servicesMap, "not-enabled")
	assert.Contains(t, servicesMap, "aliased")
	assert.Equal(t, &Service{
		Name:        "aliased",
		Type:        "service",
		Description: "Aliased Service",
		State:       ServiceUnknown,
		Installed:   true,
		Enabled:     true,
		Static:      true,
	}, servicesMap["aliased"])
	assert.Contains(t, servicesMap, "aliased-wants")
	assert.Contains(t, servicesMap, "aliased-requires")
	assert.Contains(t, servicesMap, "aliased-missing")
	assert.Equal(t, &Service{
		Name:      "aliased-missing",
		Type:      "service",
		State:     ServiceUnknown,
		Installed: false,
		Enabled:   false,
	}, servicesMap["aliased-missing"])
	assert.Contains(t, servicesMap, "intermediate-dep-want")
	assert.Contains(t, servicesMap, "intermediate-dep-require")
	assert.Contains(t, servicesMap, "masked")
	assert.Equal(t, &Service{
		Name:      "masked",
		Type:      "service",
		State:     ServiceUnknown,
		Installed: true,
		Enabled:   true,
		Masked:    true,
	}, servicesMap["masked"])
	assert.Contains(t, servicesMap, "implicit-socket")
	assert.Equal(t, &Service{
		Name:        "implicit-socket",
		Type:        "service",
		Description: "Implicit Socket Service",
		State:       ServiceUnknown,
		Installed:   true,
		Enabled:     true,
		Static:      true,
	}, servicesMap["implicit-socket"])
	assert.Contains(t, servicesMap, "explicit-socket-service")
	assert.Equal(t, &Service{
		Name:        "explicit-socket-service",
		Type:        "service",
		Description: "Explicit Socket Service",
		State:       ServiceUnknown,
		Installed:   true,
		Enabled:     true,
		Static:      true,
	}, servicesMap["explicit-socket-service"])

	// Relative path symlink
	assert.Contains(t, servicesMap, "display-manager")
	assert.Equal(t, &Service{
		Name:      "display-manager",
		Type:      "service",
		State:     ServiceUnknown,
		Installed: false,
		Enabled:   false,
		Masked:    false,
	}, servicesMap["display-manager"])

	// Absolute path symlink
	assert.Contains(t, servicesMap, "sshd")
	assert.Equal(t, &Service{
		Name:        "sshd",
		Description: "OpenBSD Secure Shell server",
		Type:        "service",
		State:       ServiceUnknown,
		Installed:   true,
		Enabled:     true,
		Masked:      false,
	}, servicesMap["sshd"])
}

type recordingConnection struct {
	*mock.Connection
	commands []string
}

func (c *recordingConnection) RunCommand(command string) (*shared.Command, error) {
	c.commands = append(c.commands, command)
	return c.Connection.RunCommand(command)
}

func TestParseServiceSystemDShow(t *testing.T) {
	services, err := ParseServiceSystemDShow(strings.NewReader(strings.Join([]string{
		"Id=ssh.service",
		"Description=OpenBSD Secure Shell server",
		"LoadState=loaded",
		"ActiveState=inactive",
		"UnitFileState=disabled",
		"",
		"Id=systemd-journald.service",
		"Description=Journal Service",
		"LoadState=loaded",
		"ActiveState=active",
		"UnitFileState=static",
		"",
	}, "\n")))
	require.NoError(t, err)
	require.Len(t, services, 2)

	assert.Equal(t, &Service{
		Name:        "ssh",
		Description: "OpenBSD Secure Shell server",
		Installed:   true,
		Running:     false,
		Enabled:     false,
		Masked:      false,
		Static:      false,
		Type:        "systemd",
	}, services["ssh"])
	assert.Equal(t, &Service{
		Name:        "systemd-journald",
		Description: "Journal Service",
		Installed:   true,
		Running:     true,
		Enabled:     false,
		Masked:      false,
		Static:      true,
		Type:        "systemd",
	}, services["systemd-journald"])
}

func TestParseServiceSystemDShowNotFoundIsNotEnabled(t *testing.T) {
	// A unit whose definition no longer exists (LoadState=not-found) can still
	// report a leftover UnitFileState such as "enabled" (e.g. a dangling
	// enablement symlink left behind by a removed package). It must not be
	// reported as enabled/masked/static, which would contradict installed=false.
	services, err := ParseServiceSystemDShow(strings.NewReader(strings.Join([]string{
		"Id=systemd-journal-upload.service",
		"Description=Journal Remote Upload Service",
		"LoadState=not-found",
		"ActiveState=inactive",
		"UnitFileState=enabled",
		"",
	}, "\n")))
	require.NoError(t, err)
	require.Len(t, services, 1)

	assert.Equal(t, &Service{
		Name:        "systemd-journal-upload",
		Description: "Journal Remote Upload Service",
		Installed:   false,
		Running:     false,
		Enabled:     false,
		Masked:      false,
		Static:      false,
		Type:        "systemd",
	}, services["systemd-journal-upload"])
}

func TestSystemDServiceManagerGetUsesTargetedShow(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description dbus.service"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Id=dbus.service",
					"Description=D-Bus System Message Bus",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=enabled",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	conn := &recordingConnection{Connection: mockConn}
	mgr := &SystemDServiceManager{conn: conn}

	service, err := mgr.Get("dbus")
	require.NoError(t, err)
	assert.Equal(t, &Service{
		Name:        "dbus",
		Description: "D-Bus System Message Bus",
		Installed:   true,
		Running:     true,
		Enabled:     true,
		Masked:      false,
		Static:      false,
		Type:        "systemd",
	}, service)
	assert.Equal(t, []string{showCmd}, conn.commands)
}

func TestSystemDServiceManagerGetReturnsNotFound(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description missing.service"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Id=missing.service",
					"Description=missing.service",
					"LoadState=not-found",
					"ActiveState=inactive",
					"UnitFileState=",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	conn := &recordingConnection{Connection: mockConn}
	mgr := &SystemDServiceManager{conn: conn}

	service, err := mgr.Get("missing")
	require.Nil(t, service)
	require.ErrorIs(t, err, ErrServiceNotFound)
	assert.Equal(t, []string{showCmd}, conn.commands)
}

func TestParseSystemdListUnits(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		"  UNIT                               LOAD      ACTIVE   SUB     DESCRIPTION",
		"  accounts-daemon.service            loaded    active   running Accounts Service",
		"  acpid.service                      loaded    inactive dead    ACPI Events Daemon",
		"  apparmor.service                   loaded    active   exited  Load AppArmor profiles",
		"● auditd.service                     not-found inactive dead    auditd.service",
		"  cron.service                       loaded    active   running Regular background program processing daemon",
		"  ssh.service                        loaded    inactive dead    OpenBSD Secure Shell server",
		"  dbus.target                        loaded    active   active  D-Bus",
		"",
		"LOAD   = Reflects whether the unit definition was properly loaded.",
		"ACTIVE = The high-level unit activation state, i.e. generalization of SUB.",
		"SUB    = The low-level unit activation state, values depend on unit type.",
		"",
		"7 loaded units listed.",
		"",
	}, "\n"))

	services, err := ParseSystemdListUnits(input)
	require.NoError(t, err)
	// 6 .service units (dbus.target is excluded)
	require.Len(t, services, 6)

	// Active running service
	assert.Equal(t, "accounts-daemon", services["accounts-daemon"].Name)
	assert.True(t, services["accounts-daemon"].Running)
	assert.True(t, services["accounts-daemon"].Installed)
	assert.Equal(t, "Accounts Service", services["accounts-daemon"].Description)

	// Inactive (dead) service
	assert.False(t, services["acpid"].Running)
	assert.True(t, services["acpid"].Installed)

	// Active but exited (oneshot that ran successfully)
	assert.True(t, services["apparmor"].Running)
	assert.Equal(t, "Load AppArmor profiles", services["apparmor"].Description)

	// Not-found unit (preceded by bullet)
	assert.False(t, services["auditd"].Running)
	assert.False(t, services["auditd"].Installed)

	// SSH - inactive
	assert.False(t, services["ssh"].Running)
	assert.Equal(t, "OpenBSD Secure Shell server", services["ssh"].Description)

	// Non-.service unit should be excluded
	assert.Nil(t, services["dbus"])
}

func TestParseServiceSystemDShowMergedRecords(t *testing.T) {
	// Simulates what happens when systemctl show skips a template unit and
	// doesn't output a blank-line separator between adjacent records.
	services, err := ParseServiceSystemDShow(strings.NewReader(strings.Join([]string{
		"Id=svc-before.service",
		"Description=Before Template",
		"LoadState=loaded",
		"ActiveState=active",
		"UnitFileState=enabled",
		// No blank line here — template was skipped by systemctl show
		"Id=svc-after.service",
		"Description=After Template",
		"LoadState=loaded",
		"ActiveState=inactive",
		"UnitFileState=disabled",
		"",
	}, "\n")))
	require.NoError(t, err)
	require.Len(t, services, 2)

	assert.Equal(t, &Service{
		Name:        "svc-before",
		Description: "Before Template",
		Installed:   true,
		Running:     true,
		Enabled:     true,
		Type:        "systemd",
	}, services["svc-before"])
	assert.Equal(t, &Service{
		Name:        "svc-after",
		Description: "After Template",
		Installed:   true,
		Running:     false,
		Enabled:     false,
		Type:        "systemd",
	}, services["svc-after"])
}

func TestSystemDServiceManagerListUsesListUnits(t *testing.T) {
	const listFilesCmd = "systemctl list-unit-files --type service --all"
	const listUnitsCmd = "systemctl list-units --type service --all"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			listFilesCmd: {
				Stdout: strings.Join([]string{
					"UNIT FILE STATE PRESET",
					"alpha.service enabled enabled",
					"beta.service static enabled",
					"gamma.service disabled enabled",
					"template@.service static enabled",
					"4 unit files listed.",
					"",
				}, "\n"),
			},
			listUnitsCmd: {
				Stdout: strings.Join([]string{
					"  UNIT              LOAD   ACTIVE   SUB     DESCRIPTION",
					"  alpha.service     loaded active   running Alpha Service",
					"  beta.service      loaded inactive dead    Beta Service",
					"",
					"LOAD   = ...",
					"ACTIVE = ...",
					"SUB    = ...",
					"",
					"2 loaded units listed.",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	conn := &recordingConnection{Connection: mockConn}
	mgr := &SystemDServiceManager{conn: conn}

	services, err := mgr.List()
	require.NoError(t, err)
	require.Len(t, services, 4)
	// Exactly 2 commands: list-unit-files + list-units
	assert.Equal(t, []string{listFilesCmd, listUnitsCmd}, conn.commands)

	servicesMap := map[string]*Service{}
	for _, service := range services {
		servicesMap[service.Name] = service
	}

	// alpha: in both list-unit-files (enabled) and list-units (active)
	assert.Equal(t, "Alpha Service", servicesMap["alpha"].Description)
	assert.True(t, servicesMap["alpha"].Running)
	assert.True(t, servicesMap["alpha"].Enabled)

	// beta: in both, but inactive
	assert.Equal(t, "Beta Service", servicesMap["beta"].Description)
	assert.False(t, servicesMap["beta"].Running)
	assert.True(t, servicesMap["beta"].Static)

	// gamma: only in list-unit-files (not loaded), Running stays false
	assert.False(t, servicesMap["gamma"].Running)
	assert.False(t, servicesMap["gamma"].Enabled)
	assert.Equal(t, "", servicesMap["gamma"].Description)

	// template@: only in list-unit-files, correctly not running
	assert.False(t, servicesMap["template@"].Running)
	assert.True(t, servicesMap["template@"].Static)
}

// failingReader stands in for a stdout pipe that breaks mid-read.
type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// TestParseServiceSystemDUnitFilesErrorKinds pins the distinction List() relies
// on: an unusable listing means systemd is not the running init and the caller
// should read the units off disk, while a broken stdout is an IO fault that has
// to surface. Both used to arrive as an undifferentiated error, so a failed read
// degraded into a filesystem listing that looked like a real answer.
func TestParseServiceSystemDUnitFilesErrorKinds(t *testing.T) {
	t.Run("empty output is a systemctl no-output error", func(t *testing.T) {
		_, err := ParseServiceSystemDUnitFiles(strings.NewReader(""))
		require.Error(t, err)
		assert.ErrorIs(t, err, errSystemctlNoOutput)
	})

	t.Run("read failure is not a systemctl no-output error", func(t *testing.T) {
		readErr := errors.New("connection reset by peer")
		_, err := ParseServiceSystemDUnitFiles(failingReader{err: readErr})
		require.Error(t, err)
		assert.NotErrorIs(t, err, errSystemctlNoOutput,
			"a broken stdout must not be mistaken for systemd being absent")
		assert.ErrorIs(t, err, readErr, "the underlying read error stays inspectable")
	})
}
