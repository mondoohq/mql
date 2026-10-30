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

func findSolarisPort(ports []SolarisPort, proto string, addr string, port int64) *SolarisPort {
	for i := range ports {
		p := ports[i]
		if p.Protocol == proto && p.LocalAddress == addr && p.LocalPort == port {
			return &p
		}
	}
	return nil
}

// Captured from `netstat -anu` as root on Oracle Solaris 11.4.86 (OCI).
func TestParseSolarisNetstatWithOwner(t *testing.T) {
	data, err := os.Open("./testdata/solaris114_netstat_anu.txt")
	require.NoError(t, err)
	defer data.Close()

	ports, err := ParseSolarisNetstat(data)
	require.NoError(t, err)

	// udp4 9, udp6 5, tcp4 5, tcp6 3. Never-bound `*.*` sockets, the second
	// copy of each duplicated row, and the Unix domain section are dropped.
	require.Len(t, ports, 22)
	counts := map[string]int{}
	for _, p := range ports {
		counts[p.Protocol]++
	}
	assert.Equal(t, map[string]int{"udp4": 9, "udp6": 5, "tcp4": 5, "tcp6": 3}, counts)

	t.Run("wildcard v4 listener binds every interface", func(t *testing.T) {
		p := findSolarisPort(ports, "tcp4", "0.0.0.0", 22)
		require.NotNil(t, p)
		assert.Equal(t, "LISTEN", p.State)
		assert.Equal(t, "root", p.User)
		assert.Equal(t, int64(771), p.Pid)
		assert.Equal(t, "", p.RemoteAddress)
		assert.Equal(t, int64(0), p.RemotePort)
	})

	t.Run("wildcard in the v6 section is the v6 wildcard", func(t *testing.T) {
		p := findSolarisPort(ports, "tcp6", "[::]", 22)
		require.NotNil(t, p)
		assert.Equal(t, int64(771), p.Pid)
	})

	t.Run("loopback listener keeps its address", func(t *testing.T) {
		p := findSolarisPort(ports, "tcp4", "127.0.0.1", 4999)
		require.NotNil(t, p)
		assert.Equal(t, "netadm", p.User)
		assert.Equal(t, int64(511), p.Pid)
	})

	t.Run("v6 literal is bracketed", func(t *testing.T) {
		p := findSolarisPort(ports, "tcp6", "[::1]", 5999)
		require.NotNil(t, p)
		assert.Equal(t, int64(105), p.Pid)
	})

	t.Run("established session carries both endpoints", func(t *testing.T) {
		p := findSolarisPort(ports, "tcp4", "10.77.1.190", 22)
		require.NotNil(t, p)
		assert.Equal(t, "ESTABLISHED", p.State)
		assert.Equal(t, "203.0.113.70", p.RemoteAddress)
		assert.Equal(t, int64(50937), p.RemotePort)
	})

	t.Run("unconnected udp has no remote and a user with an underscore", func(t *testing.T) {
		p := findSolarisPort(ports, "udp4", "127.0.0.1", 123)
		require.NotNil(t, p)
		assert.Equal(t, "Idle", p.State)
		assert.Equal(t, "_ntp", p.User)
		assert.Equal(t, int64(845), p.Pid)
		assert.Equal(t, "", p.RemoteAddress)
	})

	t.Run("udp v6 row with a blank interface column", func(t *testing.T) {
		p := findSolarisPort(ports, "udp6", "[::1]", 123)
		require.NotNil(t, p)
		assert.Equal(t, int64(845), p.Pid)
	})

	t.Run("no never-bound sockets", func(t *testing.T) {
		for _, p := range ports {
			assert.NotZero(t, p.LocalPort, "%+v", p)
		}
	})
}

// Captured from `netstat -an` as an unprivileged user on the same host: the
// listing Solaris releases before 11.2 produce, with no owner columns.
func TestParseSolarisNetstatWithoutOwner(t *testing.T) {
	data, err := os.Open("./testdata/solaris114_netstat_an.txt")
	require.NoError(t, err)
	defer data.Close()

	ports, err := ParseSolarisNetstat(data)
	require.NoError(t, err)
	require.NotEmpty(t, ports)

	for _, p := range ports {
		assert.Equal(t, "", p.User, "%+v", p)
		assert.Equal(t, int64(0), p.Pid, "%+v", p)
	}

	p := findSolarisPort(ports, "tcp4", "0.0.0.0", 22)
	require.NotNil(t, p)
	assert.Equal(t, "LISTEN", p.State)

	p = findSolarisPort(ports, "tcp4", "10.77.1.190", 22)
	require.NotNil(t, p)
	assert.Equal(t, "ESTABLISHED", p.State)
	assert.Equal(t, "203.0.113.70", p.RemoteAddress)

	p = findSolarisPort(ports, "udp4", "0.0.0.0", 68)
	require.NotNil(t, p)
	assert.Equal(t, "Idle", p.State)
}

// Rows no fixture captured: a connected UDP socket, whose remote column is
// filled in, and a TIME_WAIT socket no process holds any more.
func TestParseSolarisNetstatSparseRows(t *testing.T) {
	in := `UDP: IPv4
   Local Address        Remote Address      User    Pid      Command      State       Send Buf     TxOverflows     Recv Buf     RxOverflows
-------------------- -------------------- -------- ------ ------------- ----------  ------------ --------------- ------------ ---------------
10.0.0.5.40000       10.0.0.1.53          root        900 named          Connected         57344               0        57344               0

TCP: IPv4
   Local Address        Remote Address      User     Pid     Command     Swind  Send-Q  Rwind  Recv-Q    State
-------------------- -------------------- -------- ------ ------------- ------- ------ ------- ------ -----------
10.0.0.5.22          10.0.0.9.51000                                      131072      0  256000      0 TIME_WAIT
`
	ports, err := ParseSolarisNetstat(strings.NewReader(in))
	require.NoError(t, err)
	require.Len(t, ports, 2)

	assert.Equal(t, "udp4", ports[0].Protocol)
	assert.Equal(t, "Connected", ports[0].State)
	assert.Equal(t, "10.0.0.1", ports[0].RemoteAddress)
	assert.Equal(t, int64(53), ports[0].RemotePort)
	assert.Equal(t, "root", ports[0].User)
	assert.Equal(t, int64(900), ports[0].Pid)

	assert.Equal(t, "tcp4", ports[1].Protocol)
	assert.Equal(t, "TIME_WAIT", ports[1].State)
	assert.Equal(t, "", ports[1].User)
	assert.Equal(t, int64(0), ports[1].Pid)
	assert.Equal(t, int64(51000), ports[1].RemotePort)
}
