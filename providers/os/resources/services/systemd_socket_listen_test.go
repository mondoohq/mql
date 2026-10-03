// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package services

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

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
