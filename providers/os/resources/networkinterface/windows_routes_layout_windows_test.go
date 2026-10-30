// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

//go:build windows

package networkinterface

import (
	"sort"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// The declared structs must match netioapi.h (x64 and arm64 lay them out the
// same way): the reader takes every value from these fields.
func TestMibIpForwardRow2Layout(t *testing.T) {
	var row mibIpForwardRow2
	assert.EqualValues(t, 104, unsafe.Sizeof(row))
	assert.EqualValues(t, 0, unsafe.Offsetof(row.InterfaceLuid))
	assert.EqualValues(t, 8, unsafe.Offsetof(row.InterfaceIndex))
	assert.EqualValues(t, 12, unsafe.Offsetof(row.DestinationPrefix))
	assert.EqualValues(t, 44, unsafe.Offsetof(row.NextHop))
	assert.EqualValues(t, 72, unsafe.Offsetof(row.SitePrefixLength))
	assert.EqualValues(t, 76, unsafe.Offsetof(row.ValidLifetime))
	assert.EqualValues(t, 84, unsafe.Offsetof(row.Metric))
	assert.EqualValues(t, 88, unsafe.Offsetof(row.Protocol))
	assert.EqualValues(t, 92, unsafe.Offsetof(row.Loopback))
	assert.EqualValues(t, 96, unsafe.Offsetof(row.Age))
	assert.EqualValues(t, 100, unsafe.Offsetof(row.Origin))

	var prefix ipAddressPrefix
	assert.EqualValues(t, 32, unsafe.Sizeof(prefix))
	assert.EqualValues(t, 28, unsafe.Offsetof(prefix.PrefixLength))

	// The rows follow NumEntries at offset 8, not 4: NET_LUID is 8-byte aligned.
	var table mibIpForwardTable2
	assert.EqualValues(t, 8, unsafe.Offsetof(table.Table))
}

// windowsPlatform is how a scan sees a Windows target: runCommand encodes
// the route scripts for it.
var windowsPlatform = &inventory.Platform{Name: "windows", Family: []string{"windows"}}

// localTypeConn reports a local connection for the guard test.
type localTypeConn struct{ shared.Connection }

func (localTypeConn) Type() shared.ConnectionType { return shared.Type_Local }

type remoteTypeConn struct{ shared.Connection }

func (remoteTypeConn) Type() shared.ConnectionType { return shared.ConnectionType("ssh") }

// The native API reads the routing table of the machine the provider runs on,
// so it may answer only for a local connection.
func TestListUsesNativeRoutesOnlyLocally(t *testing.T) {
	orig := nativeRoutes
	t.Cleanup(func() { nativeRoutes = orig })
	called := false
	nativeRoutes = func(*windowsRouteDetector) ([]Route, error) {
		called = true
		return []Route{{Destination: "0.0.0.0/0", Gateway: "192.0.2.1"}}, nil
	}

	w := &windowsRouteDetector{conn: localTypeConn{}}
	routes, err := w.List()
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, "192.0.2.1", routes[0].Gateway)

	called = false
	w = &windowsRouteDetector{conn: remoteTypeConn{local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})}, platform: windowsPlatform}
	_, _ = w.List() // asks the (here: local) machine through PowerShell and netstat
	assert.False(t, called, "a remote connection must never read the scanner's own routing table")
}

// On a real Windows host the native reader and Get-NetRoute must report the
// same routes.
func TestNativeRoutesMatchGetNetRoute(t *testing.T) {
	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	w := &windowsRouteDetector{conn: conn, platform: windowsPlatform}

	native, err := w.detectWindowsRoutesViaGetIpForwardTable()
	require.NoError(t, err)
	require.NotEmpty(t, native)

	viaPowerShell, err := w.detectWindowsRoutesViaPowerShell()
	require.NoError(t, err)
	require.NotEmpty(t, viaPowerShell)

	key := func(rs []Route) []string {
		out := make([]string, 0, len(rs))
		for _, r := range rs {
			out = append(out, r.Destination+" via "+r.Gateway)
		}
		sort.Strings(out)
		return out
	}
	assert.Equal(t, key(viaPowerShell), key(native))
}

// GetAdaptersAddresses is judged by its return value alone: a stale thread
// error must not fail a successful call, and an ERROR_BUFFER_OVERFLOW is
// retried with the size the API asks for.
func TestAdapterAddressesBufferUsesReturnValue(t *testing.T) {
	orig := getAdaptersAddresses
	t.Cleanup(func() { getAdaptersAddresses = orig })

	calls := 0
	getAdaptersAddresses = func(buf *byte, size *uint32) uintptr {
		calls++
		if calls == 1 {
			*size = 40000
			return ERROR_BUFFER_OVERFLOW
		}
		return 0
	}
	buf, err := adapterAddressesBuffer()
	require.NoError(t, err)
	assert.Len(t, buf, 40000)
	assert.Equal(t, 2, calls)

	getAdaptersAddresses = func(*byte, *uint32) uintptr { return ERROR_NO_DATA }
	buf, err = adapterAddressesBuffer()
	require.NoError(t, err)
	assert.Nil(t, buf)

	getAdaptersAddresses = func(*byte, *uint32) uintptr { return 87 } // ERROR_INVALID_PARAMETER
	_, err = adapterAddressesBuffer()
	require.Error(t, err)

	getAdaptersAddresses = func(_ *byte, size *uint32) uintptr { *size += 16; return ERROR_BUFFER_OVERFLOW }
	_, err = adapterAddressesBuffer()
	require.Error(t, err)
}

// On a real host the adapters resolve to names.
func TestWindowsInterfaceMapLive(t *testing.T) {
	m, err := (&windowsRouteDetector{}).getWindowsInterfaceMap()
	require.NoError(t, err)
	assert.NotEmpty(t, m)
}
