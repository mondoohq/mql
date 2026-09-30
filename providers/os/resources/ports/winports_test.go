// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ports

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestParseWindowsTCP(t *testing.T) {
	data, err := os.Open("./testdata/windows_tcp.json")
	require.NoError(t, err)

	ports, err := ParseWindowsNetTCPConnections(data)
	require.NoError(t, err)
	assert.Equal(t, 1, len(ports))

	assert.Equal(t, int64(49672), ports[0].LocalPort)
	assert.Equal(t, "[::]", ports[0].LocalAddress)
	assert.Equal(t, int64(0), ports[0].RemotePort)
	assert.Equal(t, "[::]", ports[0].RemoteAddress)
}

// TestParseWindowsTCPSlim covers the projected output shape produced by
//
//	@(Get-NetTCPConnection | Select-Object LocalAddress, LocalPort,
//	  RemoteAddress, RemotePort, @{Name='State';Expression={[int]$_.State}},
//	  OwningProcess) | ConvertTo-Json
//
// i.e. only the six fields we read, State as an int, always an array. This is
// what listWindows now asks PowerShell for to keep the payload small.
func TestParseWindowsTCPSlim(t *testing.T) {
	data, err := os.Open("./testdata/windows_tcp_slim.json")
	require.NoError(t, err)
	defer data.Close()

	ports, err := ParseWindowsNetTCPConnections(data)
	require.NoError(t, err)
	require.Equal(t, 2, len(ports))

	// ipv6 listener — the address gets bracketed
	assert.Equal(t, "[::]", ports[0].LocalAddress)
	assert.Equal(t, int64(49672), ports[0].LocalPort)
	assert.Equal(t, "[::]", ports[0].RemoteAddress)
	assert.Equal(t, int64(0), ports[0].RemotePort)
	assert.Equal(t, State(Listen), ports[0].State)
	assert.Equal(t, int64(2136), ports[0].OwningProcess)

	// ipv4 established connection — the address is left as-is
	assert.Equal(t, "10.0.0.5", ports[1].LocalAddress)
	assert.Equal(t, int64(52014), ports[1].LocalPort)
	assert.Equal(t, "93.184.216.34", ports[1].RemoteAddress)
	assert.Equal(t, int64(443), ports[1].RemotePort)
	assert.Equal(t, State(Established), ports[1].State)
	assert.Equal(t, int64(4288), ports[1].OwningProcess)
}

// The Windows ports script returns TCP connections and UDP endpoints together,
// as captured from a Windows Server 2022 host.
func TestParseWindowsNetConnections(t *testing.T) {
	data, err := os.Open("./testdata/windows_connections.json")
	require.NoError(t, err)
	defer data.Close()

	conns, err := ParseWindowsNetConnections(data)
	require.NoError(t, err)
	require.Len(t, conns.TCP, 2)
	require.Len(t, conns.UDP, 2)

	assert.Equal(t, State(Listen), conns.TCP[0].State)
	// A socket that is bound but neither listening nor connected is 100 in the
	// MSFT_NetTCPConnection enum.
	assert.Equal(t, State(Bound), conns.TCP[1].State)
	assert.Equal(t, State(100), conns.TCP[1].State)

	assert.Equal(t, "[::]", conns.UDP[0].LocalAddress)
	assert.Equal(t, int64(61627), conns.UDP[0].LocalPort)
	assert.Equal(t, int64(1400), conns.UDP[0].OwningProcess)
	assert.Equal(t, "0.0.0.0", conns.UDP[1].LocalAddress)
}

func TestParseWindowsNetConnectionsShapes(t *testing.T) {
	// No UDP endpoints, and a single TCP connection flattened to an object.
	conns, err := ParseWindowsNetConnections(strings.NewReader(`{"tcp":{"LocalAddress":"::","LocalPort":135,"RemoteAddress":"::","RemotePort":0,"State":2,"OwningProcess":912},"udp":[]}`))
	require.NoError(t, err)
	require.Len(t, conns.TCP, 1)
	assert.Equal(t, "[::]", conns.TCP[0].LocalAddress)
	assert.Empty(t, conns.UDP)

	// A single TCP connection piped into ConvertTo-Json arrives as a bare
	// object, not a one-element array.
	tcp, err := ParseWindowsNetTCPConnections(strings.NewReader(`{"LocalAddress":"0.0.0.0","LocalPort":22,"RemoteAddress":"0.0.0.0","RemotePort":0,"State":2,"OwningProcess":3016}`))
	require.NoError(t, err)
	require.Len(t, tcp, 1)
}
