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

func TestParseAixNetstat(t *testing.T) {
	data, err := os.Open("./testdata/aix_netstat_an.txt")
	require.NoError(t, err)
	defer data.Close()

	ports, err := ParseAixNetstat(data)
	require.NoError(t, err)

	// 14 internet rows; the two Unix domain sockets below the second header
	// must not be picked up.
	require.Len(t, ports, 14)

	byIdx := func(i int) AixPort { return ports[i] }

	t.Run("wildcard listener binds every interface", func(t *testing.T) {
		p := byIdx(0)
		assert.Equal(t, "tcp4", p.Protocol)
		assert.Equal(t, "0.0.0.0", p.LocalAddress)
		assert.Equal(t, int64(22), p.LocalPort)
		assert.Equal(t, "LISTEN", p.State)
		// An unconnected socket has no peer.
		assert.Equal(t, "", p.RemoteAddress)
		assert.Equal(t, int64(0), p.RemotePort)
	})

	t.Run("bare tcp on the wildcard is a dual-stack v6 listener", func(t *testing.T) {
		p := byIdx(1)
		assert.Equal(t, "tcp6", p.Protocol)
		assert.Equal(t, "[::]", p.LocalAddress)
		assert.Equal(t, int64(23), p.LocalPort)
	})

	t.Run("loopback listener keeps its address", func(t *testing.T) {
		p := byIdx(2)
		assert.Equal(t, "127.0.0.1", p.LocalAddress)
		assert.Equal(t, int64(199), p.LocalPort)
	})

	t.Run("v6 literal is bracketed", func(t *testing.T) {
		p := byIdx(3)
		assert.Equal(t, "tcp6", p.Protocol)
		assert.Equal(t, "[::1]", p.LocalAddress)
		assert.Equal(t, int64(25), p.LocalPort)
	})

	t.Run("established session carries both endpoints", func(t *testing.T) {
		p := byIdx(4)
		assert.Equal(t, "10.10.20.15", p.LocalAddress)
		assert.Equal(t, int64(22), p.LocalPort)
		assert.Equal(t, "10.10.30.9", p.RemoteAddress)
		assert.Equal(t, int64(51544), p.RemotePort)
		assert.Equal(t, "ESTABLISHED", p.State)
	})

	t.Run("high local port is not confused with the address", func(t *testing.T) {
		// 10.10.20.15.32790 -> the LAST dot separates the port.
		p := byIdx(6)
		assert.Equal(t, "10.10.20.15", p.LocalAddress)
		assert.Equal(t, int64(32790), p.LocalPort)
		assert.Equal(t, int64(1521), p.RemotePort)
	})

	t.Run("non-listen states are preserved verbatim", func(t *testing.T) {
		assert.Equal(t, "TIME_WAIT", byIdx(7).State)
		assert.Equal(t, "CLOSE_WAIT", byIdx(8).State)
	})

	t.Run("v6 session splits on the dot, not the colons", func(t *testing.T) {
		p := byIdx(9)
		assert.Equal(t, "tcp6", p.Protocol)
		assert.Equal(t, "[2001:db8::15]", p.LocalAddress)
		assert.Equal(t, int64(443), p.LocalPort)
		assert.Equal(t, "[2001:db8::99]", p.RemoteAddress)
		assert.Equal(t, int64(51900), p.RemotePort)
	})

	t.Run("udp rows have no state", func(t *testing.T) {
		p := byIdx(10)
		assert.Equal(t, "udp4", p.Protocol)
		assert.Equal(t, "0.0.0.0", p.LocalAddress)
		assert.Equal(t, int64(123), p.LocalPort)
		// AIX prints no state column for UDP; it is stateless.
		assert.Equal(t, "", p.State)
	})

	t.Run("v6 udp wildcard resolves to the v6 wildcard", func(t *testing.T) {
		p := byIdx(12)
		assert.Equal(t, "udp6", p.Protocol)
		assert.Equal(t, "[::1]", p.LocalAddress)
		assert.Equal(t, int64(123), p.LocalPort)
	})

	t.Run("fully unbound socket yields no endpoint", func(t *testing.T) {
		p := byIdx(13)
		assert.Equal(t, "udp4", p.Protocol)
		assert.Equal(t, "", p.LocalAddress)
		assert.Equal(t, int64(0), p.LocalPort)
	})
}

// `netstat -Aan` prefixes every row with a PCB address, which shifts every
// column right by one. The protocol column is found by pattern, so both forms
// parse identically.
func TestParseAixNetstatWithPcbColumn(t *testing.T) {
	data, err := os.Open("./testdata/aix_netstat_aan.txt")
	require.NoError(t, err)
	defer data.Close()

	ports, err := ParseAixNetstat(data)
	require.NoError(t, err)
	require.Len(t, ports, 3)

	assert.Equal(t, "tcp4", ports[0].Protocol)
	assert.Equal(t, "0.0.0.0", ports[0].LocalAddress)
	assert.Equal(t, int64(22), ports[0].LocalPort)
	assert.Equal(t, "LISTEN", ports[0].State)

	assert.Equal(t, "10.10.20.15", ports[1].LocalAddress)
	assert.Equal(t, "10.10.30.9", ports[1].RemoteAddress)
	assert.Equal(t, int64(51544), ports[1].RemotePort)
	assert.Equal(t, "ESTABLISHED", ports[1].State)

	assert.Equal(t, "udp4", ports[2].Protocol)
	assert.Equal(t, int64(123), ports[2].LocalPort)
	assert.Equal(t, "", ports[2].State)
}

func TestParseAixNetstatEdgeCases(t *testing.T) {
	t.Run("empty input", func(t *testing.T) {
		p, err := ParseAixNetstat(strings.NewReader(""))
		require.NoError(t, err)
		assert.Empty(t, p)
	})

	t.Run("headers only", func(t *testing.T) {
		in := "Active Internet connections (including servers)\n" +
			"Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)\n"
		p, err := ParseAixNetstat(strings.NewReader(in))
		require.NoError(t, err)
		assert.Empty(t, p)
	})

	t.Run("truncated row is skipped rather than panicking", func(t *testing.T) {
		p, err := ParseAixNetstat(strings.NewReader("tcp4       0      0\n"))
		require.NoError(t, err)
		assert.Empty(t, p)
	})

	t.Run("unix-only output yields nothing", func(t *testing.T) {
		in := "Active UNIX domain sockets\n" +
			"f1000a0000000000  dgram  0  0  f1000b00  0  0  0  /dev/log\n"
		p, err := ParseAixNetstat(strings.NewReader(in))
		require.NoError(t, err)
		assert.Empty(t, p)
	})

	t.Run("a path containing tcp does not become a socket row", func(t *testing.T) {
		// Guards the protocol-by-pattern scan: the match is anchored, so
		// "/tmp/tcp4.sock" is not mistaken for the protocol column.
		in := "Active UNIX domain sockets\n" +
			"f1000a0000000000  stream  0  0  f1000b01  0  0  0  /tmp/tcp4.sock\n"
		p, err := ParseAixNetstat(strings.NewReader(in))
		require.NoError(t, err)
		assert.Empty(t, p)
	})
}

// testdata/aix73_netstat_an.txt is netstat -an on AIX 7.3 TL4 SP2. A bare tcp
// or udp row is an IPv6 socket that takes IPv4 too: httpd's *.80 and
// portmap's *.111 answered on both ::1 and 127.0.0.1 there, while the tcp4
// listeners on *.25 and *.47123 refused ::1.
func TestParseAixNetstatBareSockets(t *testing.T) {
	data, err := os.Open("./testdata/aix73_netstat_an.txt")
	require.NoError(t, err)
	defer data.Close()

	ports, err := ParseAixNetstat(data)
	require.NoError(t, err)

	find := func(proto string, port int64, addr string) *AixPort {
		for i := range ports {
			if ports[i].Protocol == proto && ports[i].LocalPort == port && ports[i].LocalAddress == addr {
				return &ports[i]
			}
		}
		return nil
	}

	// tcp *.111 LISTEN
	assert.NotNil(t, find("tcp6", 111, "[::]"))
	assert.Nil(t, find("tcp4", 111, "0.0.0.0"))
	// tcp4 *.25 LISTEN stays v4
	assert.NotNil(t, find("tcp4", 25, "0.0.0.0"))
	// udp *.2049
	assert.NotNil(t, find("udp6", 2049, "[::]"))
	// udp 192.168.234.39.123: bound to an IPv4 address, it takes IPv4 only
	assert.NotNil(t, find("udp4", 123, "192.168.234.39"))
	// sshd listens twice, v6 only and v4
	assert.NotNil(t, find("tcp6", 22, "[::]"))
	assert.NotNil(t, find("tcp4", 22, "0.0.0.0"))
}
