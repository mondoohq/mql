// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

func TestParseSystemdSocketUnitFiles(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		"UNIT FILE                    STATE    PRESET",
		"dbus.socket                  enabled  enabled",
		"dm-event.socket              enabled  enabled",
		"docker.socket                disabled enabled",
		"systemd-journald.socket      static   enabled",
		"uuidd.socket                 masked   enabled",
		"",
		"5 unit files listed.",
		"",
	}, "\n"))

	sockets, err := ParseSystemdSocketUnitFiles(input)
	require.NoError(t, err)
	require.Len(t, sockets, 5)

	// enabled socket
	assert.Equal(t, "dbus", sockets[0].Name)
	assert.True(t, sockets[0].Installed)
	assert.True(t, sockets[0].Enabled)
	assert.False(t, sockets[0].Masked)
	assert.False(t, sockets[0].Static)

	// disabled socket
	assert.Equal(t, "docker", sockets[2].Name)
	assert.False(t, sockets[2].Enabled)

	// static socket
	assert.Equal(t, "systemd-journald", sockets[3].Name)
	assert.True(t, sockets[3].Static)

	// masked socket
	assert.Equal(t, "uuidd", sockets[4].Name)
	assert.True(t, sockets[4].Masked)
}

func TestParseSystemdSocketListUnits(t *testing.T) {
	input := strings.NewReader(strings.Join([]string{
		"  UNIT                         LOAD      ACTIVE   SUB       DESCRIPTION",
		"  dbus.socket                  loaded    active   running   D-Bus System Message Bus Socket",
		"  docker.socket                loaded    inactive dead      Docker Socket for the API",
		"● missing.socket               not-found inactive dead      missing.socket",
		"",
		"LOAD   = ...",
		"ACTIVE = ...",
		"SUB    = ...",
		"",
		"3 loaded units listed.",
		"",
	}, "\n"))

	sockets, err := ParseSystemdSocketListUnits(input)
	require.NoError(t, err)
	require.Len(t, sockets, 3)

	assert.Equal(t, "dbus", sockets["dbus"].Name)
	assert.True(t, sockets["dbus"].Running)
	assert.True(t, sockets["dbus"].Installed)
	assert.Equal(t, "D-Bus System Message Bus Socket", sockets["dbus"].Description)

	assert.False(t, sockets["docker"].Running)
	assert.True(t, sockets["docker"].Installed)

	assert.False(t, sockets["missing"].Running)
	assert.False(t, sockets["missing"].Installed)
}

func TestSystemdSocketManagerList(t *testing.T) {
	const listFilesCmd = "systemctl list-unit-files --type socket --all"
	const listUnitsCmd = "systemctl list-units --type socket --all"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			listFilesCmd: {
				Stdout: strings.Join([]string{
					"UNIT FILE              STATE    PRESET",
					"dbus.socket            enabled  enabled",
					"docker.socket          disabled enabled",
					"",
					"2 unit files listed.",
					"",
				}, "\n"),
			},
			listUnitsCmd: {
				Stdout: strings.Join([]string{
					"  UNIT              LOAD   ACTIVE   SUB     DESCRIPTION",
					"  dbus.socket       loaded active   running D-Bus System Message Bus Socket",
					"",
					"LOAD   = ...",
					"",
					"1 loaded units listed.",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdSocketManager{conn: mockConn}
	sockets, err := mgr.List()
	require.NoError(t, err)
	require.Len(t, sockets, 2)

	socketMap := map[string]*SystemdSocket{}
	for _, s := range sockets {
		socketMap[s.Name] = s
	}

	assert.True(t, socketMap["dbus"].Enabled)
	assert.True(t, socketMap["dbus"].Running)
	assert.Equal(t, "D-Bus System Message Bus Socket", socketMap["dbus"].Description)

	assert.False(t, socketMap["docker"].Enabled)
	assert.False(t, socketMap["docker"].Running)
}

func TestSystemdSocketManagerGet(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description dbus.socket"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Id=dbus.socket",
					"Description=D-Bus System Message Bus Socket",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=enabled",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdSocketManager{conn: mockConn}
	socket, err := mgr.Get("dbus")
	require.NoError(t, err)

	assert.Equal(t, "dbus", socket.Name)
	assert.Equal(t, "D-Bus System Message Bus Socket", socket.Description)
	assert.True(t, socket.Installed)
	assert.True(t, socket.Running)
	assert.True(t, socket.Enabled)
	assert.False(t, socket.Masked)
	assert.False(t, socket.Static)
}

func TestSystemdSocketManagerGetNotFound(t *testing.T) {
	const showCmd = "systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description missing.socket"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Id=missing.socket",
					"Description=missing.socket",
					"LoadState=not-found",
					"ActiveState=inactive",
					"UnitFileState=",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdSocketManager{conn: mockConn}
	socket, err := mgr.Get("missing")
	require.Nil(t, socket)
	require.ErrorIs(t, err, ErrServiceNotFound)
}

func TestParseListenProperty(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected []string
	}{
		{
			name:     "empty",
			input:    "",
			expected: nil,
		},
		{
			name:     "simple stream",
			input:    "/run/dbus/system_bus_socket (Stream)",
			expected: []string{"/run/dbus/system_bus_socket"},
		},
		{
			name:     "ip address with port",
			input:    "[::]:22 (Stream)",
			expected: []string{"[::]:22"},
		},
		{
			name:     "structured format",
			input:    "{ path=/run/docker.sock ; type=Stream }",
			expected: []string{"/run/docker.sock"},
		},
		{
			name:     "bare path",
			input:    "/run/some.sock",
			expected: []string{"/run/some.sock"},
		},
		{
			name:     "multi-listen newline joined",
			input:    "/run/foo.sock (Stream)\n[::]:80 (Stream)",
			expected: []string{"/run/foo.sock", "[::]:80"},
		},
		{
			name:     "multi-listen structured",
			input:    "{ path=/run/a.sock ; type=Stream }\n{ path=/run/b.sock ; type=Stream }",
			expected: []string{"/run/a.sock", "/run/b.sock"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseListenProperty(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestShowSocketProperties(t *testing.T) {
	const showCmd = "systemctl show --property=Triggers,Accept,Listen dbus.socket"

	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{
			Name:   "ubuntu",
			Family: []string{"ubuntu", "linux"},
		},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			showCmd: {
				Stdout: strings.Join([]string{
					"Triggers=dbus.service",
					"Accept=no",
					"Listen=/run/dbus/system_bus_socket (Stream)",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	mgr := &SystemdSocketManager{conn: mockConn}
	props, err := mgr.ShowSocketProperties("dbus")
	require.NoError(t, err)

	assert.Equal(t, "dbus.service", props["Triggers"])
	assert.Equal(t, "no", props["Accept"])
	assert.Equal(t, "/run/dbus/system_bus_socket (Stream)", props["Listen"])

	// Verify ParseListenProperty works with the fetched value
	addrs := ParseListenProperty(props["Listen"])
	assert.Equal(t, []string{"/run/dbus/system_bus_socket"}, addrs)
}

// `systemctl show --property=Triggers,Accept,Listen g04.socket` on RHEL 7.9
// (systemd 219); Debian 9 (232) and Ubuntu 18.04 (237) print the same
// ListenStream= lines.
const rhel7ShowSocketListen = `Accept=yes
ListenStream=127.0.0.1:7777
ListenStream=/run/g04.sock
Triggers=
`

func TestShowSocketPropertiesFoldsListenTypes(t *testing.T) {
	conn := unitFallbackConn(t, map[string]*mock.Command{
		buildShowPropertyCommand("Triggers,Accept,Listen", "g04.socket"): {Stdout: rhel7ShowSocketListen},
	})
	props, err := NewSystemdSocketManager(conn).ShowSocketProperties("g04")
	require.NoError(t, err)
	assert.Equal(t, []string{"127.0.0.1:7777", "/run/g04.sock"}, ParseListenProperty(props["Listen"]))
}

func TestFoldListenTypeProperties(t *testing.T) {
	props := map[string]string{"ListenDatagram": "0.0.0.0:69", "ListenStream": "[::]:22"}
	foldListenTypeProperties(props)
	assert.Equal(t, "[::]:22 (Stream)\n0.0.0.0:69 (Datagram)", props["Listen"])

	// a current systemd's Listen= is kept as printed
	props = map[string]string{"Listen": "/run/dbus/system_bus_socket (Stream)", "ListenStream": "/other"}
	foldListenTypeProperties(props)
	assert.Equal(t, "/run/dbus/system_bus_socket (Stream)", props["Listen"])
}

func TestSystemdSocketManagerListAddsTemplateInstances(t *testing.T) {
	mockConn, err := mock.New(0, &inventory.Asset{
		Platform: &inventory.Platform{Name: "amazonlinux", Family: []string{"linux"}},
	}, mock.WithData(&mock.TomlData{
		Commands: map[string]*mock.Command{
			"systemctl list-unit-files --type socket --all": {
				Stdout: strings.Join([]string{
					"UNIT FILE                        STATE    PRESET",
					"g04-sk@.socket                   indirect disabled",
					"g04.socket                       enabled  disabled",
					"systemd-journald@.socket         static   -",
					"",
					"3 unit files listed.",
					"",
				}, "\n"),
			},
			"systemctl list-units --type socket --all": {
				Stdout: strings.Join([]string{
					"  UNIT                            LOAD   ACTIVE   SUB       DESCRIPTION",
					"  g04-sk@a.socket                 loaded active   listening g04 templated socket a",
					"  g04.socket                      loaded active   listening g04 socket",
					"  gone@b.socket                   not-found inactive dead   gone@b.socket",
					"",
					"LOAD   = Reflects whether the unit definition was properly loaded.",
					"3 loaded units listed.",
					"",
				}, "\n"),
			},
			"systemctl show --property=Id,LoadState,ActiveState,UnitFileState,Description g04-sk@a.socket": {
				Stdout: strings.Join([]string{
					"Id=g04-sk@a.socket",
					"Description=g04 templated socket a",
					"LoadState=loaded",
					"ActiveState=active",
					"UnitFileState=enabled",
					"",
				}, "\n"),
			},
		},
	}))
	require.NoError(t, err)

	sockets, err := (&SystemdSocketManager{conn: mockConn}).List()
	require.NoError(t, err)
	byName := map[string]*SystemdSocket{}
	for _, socket := range sockets {
		byName[socket.Name] = socket
	}
	require.Len(t, byName, 4)

	a := byName["g04-sk@a"]
	require.NotNil(t, a)
	assert.True(t, a.Installed)
	assert.True(t, a.Enabled)
	assert.True(t, a.Running)
	assert.Equal(t, "g04 templated socket a", a.Description)
	// an instance that does not load is not a socket on this host
	assert.Nil(t, byName["gone@b"])
}
