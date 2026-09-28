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

// Captured verbatim from `sockstat -46 -s` on FreeBSD 14.4-RELEASE.
const sockstatFreeBSD14 = `USER     COMMAND    PID   FD  PROTO     LOCAL ADDRESS         FOREIGN ADDRESS       CONN STATE
ec2-user sshd-sessi 10356 7   tcp4      10.45.1.14:22         97.115.90.143:61073   ESTABLISHED
root     sshd        1718 6   tcp6      *:22                  *:*                   LISTEN
root     sshd        1718 7   tcp4      *:22                  *:*                   LISTEN
ntpd     ntpd        1666 21  udp4      *:123                 *:*
ntpd     ntpd        1666 22  udp4      10.45.1.14:123        *:*
ntpd     ntpd        1666 23  udp6      [::1]:123             *:*
ntpd     ntpd        1666 24  udp6      [fe80::1%lo0]:123     *:*
`

func TestParseSockstatListeners(t *testing.T) {
	entries, err := ParseSockstat(strings.NewReader(sockstatFreeBSD14))
	require.NoError(t, err)
	require.Len(t, entries, 7, "the header must not become a row")

	// tcp6 listener on the wildcard address
	e := entries[1]
	assert.Equal(t, "root", e.User)
	assert.Equal(t, "sshd", e.Command)
	assert.Equal(t, int64(1718), e.Pid)
	assert.Equal(t, "tcp6", e.Protocol)
	assert.Equal(t, "*", e.LocalAddress)
	assert.Equal(t, int64(22), e.LocalPort)
	assert.Equal(t, "", e.RemoteAddress, "*:* is not a peer")
	assert.Equal(t, int64(0), e.RemotePort)
	assert.Equal(t, "LISTEN", e.State)
}

func TestParseSockstatEstablished(t *testing.T) {
	entries, err := ParseSockstat(strings.NewReader(sockstatFreeBSD14))
	require.NoError(t, err)

	e := entries[0]
	assert.Equal(t, "tcp4", e.Protocol)
	assert.Equal(t, "10.45.1.14", e.LocalAddress)
	assert.Equal(t, int64(22), e.LocalPort)
	assert.Equal(t, "97.115.90.143", e.RemoteAddress)
	assert.Equal(t, int64(61073), e.RemotePort)
	assert.Equal(t, "ESTABLISHED", e.State)
}

// udp rows carry no CONN STATE column, and IPv6 literals bring their own
// colons plus an optional zone.
func TestParseSockstatUDPAndIPv6(t *testing.T) {
	entries, err := ParseSockstat(strings.NewReader(sockstatFreeBSD14))
	require.NoError(t, err)

	udp6 := entries[5]
	assert.Equal(t, "udp6", udp6.Protocol)
	assert.Equal(t, "::1", udp6.LocalAddress, "brackets are stripped")
	assert.Equal(t, int64(123), udp6.LocalPort)
	assert.Equal(t, "", udp6.State, "udp has no connection state")

	zoned := entries[6]
	assert.Equal(t, "fe80::1%lo0", zoned.LocalAddress, "the zone is part of the address")
	assert.Equal(t, int64(123), zoned.LocalPort)
}

// Older releases have no -s flag, so the state column is simply absent.
func TestParseSockstatWithoutStateColumn(t *testing.T) {
	raw := `USER     COMMAND    PID   FD  PROTO     LOCAL ADDRESS         FOREIGN ADDRESS
root     sshd        1718 7   tcp4      *:22                  *:*
`
	entries, err := ParseSockstat(strings.NewReader(raw))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, int64(22), entries[0].LocalPort)
	assert.Equal(t, "", entries[0].State)
}

// Unix domain sockets and other non-inet rows are not ports.
func TestParseSockstatSkipsNonInet(t *testing.T) {
	raw := `USER     COMMAND    PID   FD  PROTO     LOCAL ADDRESS         FOREIGN ADDRESS
root     dbus        900  3   stream    /var/run/dbus/system_bus_socket  -
root     sshd        1718 7   tcp4      *:22                  *:*
`
	entries, err := ParseSockstat(strings.NewReader(raw))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "tcp4", entries[0].Protocol)
}

// A kernel socket has "?" where the pid goes; the row is still a real socket.
func TestParseSockstatKernelSocket(t *testing.T) {
	raw := `USER     COMMAND    PID   FD  PROTO     LOCAL ADDRESS         FOREIGN ADDRESS       CONN STATE
?        ?           ?    ?   tcp4      *:2049                *:*                   LISTEN
`
	entries, err := ParseSockstat(strings.NewReader(raw))
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, int64(0), entries[0].Pid)
	assert.Equal(t, int64(2049), entries[0].LocalPort)
}

func TestParseSockstatEmpty(t *testing.T) {
	entries, err := ParseSockstat(strings.NewReader(""))
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		in   string
		host string
		port int64
	}{
		{"*:22", "*", 22},
		{"10.0.0.1:443", "10.0.0.1", 443},
		{"[::1]:123", "::1", 123},
		{"[fe80::1%lo0]:123", "fe80::1%lo0", 123},
		{"fe80::4ff:faff:fec9:b7d3%ena0:123", "fe80::4ff:faff:fec9:b7d3%ena0", 123}, // FreeBSD 13.5 leaves it unbracketed
		{"::1:123", "::1", 123},
		{"*:*", "", 0},
		{"", "", 0},
		{"*:sunrpc", "*", 0},
	}
	for _, tc := range tests {
		t.Run(tc.in, func(t *testing.T) {
			h, p := splitHostPort(tc.in)
			assert.Equal(t, tc.host, h)
			assert.Equal(t, tc.port, p)
		})
	}
}

func parseSockstatFixture(t *testing.T, name string) []SockstatEntry {
	t.Helper()
	f, err := os.Open("testdata/" + name)
	require.NoError(t, err)
	defer f.Close()
	entries, err := ParseSockstat(f)
	require.NoError(t, err)
	return entries
}

func findSockstatEntry(entries []SockstatEntry, proto string, addr string, port int64) *SockstatEntry {
	for i := range entries {
		e := &entries[i]
		if e.Protocol == proto && e.LocalAddress == addr && e.LocalPort == port {
			return e
		}
	}
	return nil
}

// `sockstat -46 -s -w` from FreeBSD 13.5, 14.5 and 15.1 EC2 instances. Each
// release writes IPv6 addresses differently: 13.5 leaves them unbracketed, 14.5
// and 15.1 bracket them, and 15.1 prints ?? as the state of every udp socket.
// The ntpd socket on the ena0 link-local address is the one sockstat cut short
// without -w on 15.1.
func TestParseSockstatReleases(t *testing.T) {
	for _, tc := range []struct {
		file      string
		linkLocal string
	}{
		{"freebsd13_sockstat_46sw.txt", "fe80::4ff:faff:fec9:b7d3%ena0"},
		{"freebsd14_sockstat_46sw.txt", "fe80::4ff:d0ff:fee3:9f9f%ena0"},
		{"freebsd15_sockstat_46sw.txt", "fe80::4ff:daff:febe:3ed9%ena0"},
	} {
		t.Run(tc.file, func(t *testing.T) {
			entries := parseSockstatFixture(t, tc.file)

			ll := findSockstatEntry(entries, "udp6", tc.linkLocal, 123)
			require.NotNil(t, ll, "scoped link-local ntpd socket")
			assert.Equal(t, "ntpd", ll.Command)
			assert.Equal(t, "", ll.RemoteAddress)
			assert.Equal(t, "", ll.State, "udp has no connection state, ?? included")

			require.NotNil(t, findSockstatEntry(entries, "udp6", "::1", 123), "::1 loopback ntpd socket")

			sshd := findSockstatEntry(entries, "tcp6", "*", 22)
			require.NotNil(t, sshd)
			assert.Equal(t, "LISTEN", sshd.State)

			// nginx master and worker share one listening socket, and sockstat
			// lists it once per process holding it.
			nginx := 0
			for _, e := range entries {
				if e.Protocol == "tcp4" && e.LocalAddress == "*" && e.LocalPort == 80 {
					nginx++
				}
			}
			assert.Equal(t, 2, nginx)
		})
	}
}

// FreeBSD 14.5 with mysql-server running: mysqld opens dual-stack sockets that
// sockstat lists as tcp46. They were dropped, so neither 3306 nor 33060 showed.
func TestParseSockstatDualStack(t *testing.T) {
	entries := parseSockstatFixture(t, "freebsd14_sockstat_46sw.txt")

	mysql := findSockstatEntry(entries, "tcp6", "*", 3306)
	require.NotNil(t, mysql, "tcp46 socket reads as tcp6")
	assert.Equal(t, "mysqld", mysql.Command)
	assert.Equal(t, int64(29115), mysql.Pid)
	assert.Equal(t, "LISTEN", mysql.State)
	assert.NotNil(t, findSockstatEntry(entries, "tcp6", "*", 33060))

	p, ok := inetProtocol("udp46")
	assert.True(t, ok)
	assert.Equal(t, "udp6", p)
}

// sockstat on FreeBSD 13.5 lists the nginx worker (www, 2579) before the
// master (root, 2578) on the one *:80 socket they share.
func TestMergeSharedSockets(t *testing.T) {
	entries := parseSockstatFixture(t, "freebsd13_sockstat_46sw.txt")
	merged := MergeSharedSockets(entries)

	// the nginx listener, and the ssh session sshd-session holds in both its
	// privileged (root) and user (ec2-user) process
	assert.Len(t, merged, len(entries)-2)
	ssh := merged[0]
	assert.Equal(t, "ESTABLISHED", ssh.State)
	assert.Equal(t, int64(38846), ssh.Pid)
	assert.Equal(t, "root", ssh.User)

	var nginx []SockstatEntry
	for _, e := range merged {
		if e.Protocol == "tcp4" && e.LocalAddress == "*" && e.LocalPort == 80 {
			nginx = append(nginx, e)
		}
	}
	require.Len(t, nginx, 1)
	assert.Equal(t, int64(2578), nginx[0].Pid, "the master that bound the socket")
	assert.Equal(t, "root", nginx[0].User)

	// sshd's tcp4 and tcp6 listeners on port 22 are two sockets and stay two
	assert.NotNil(t, findSockstatEntry(merged, "tcp4", "*", 22))
	assert.NotNil(t, findSockstatEntry(merged, "tcp6", "*", 22))

	// a kernel row (pid 0) gives way to a process holding the same socket
	k := MergeSharedSockets([]SockstatEntry{
		{Protocol: "tcp4", LocalAddress: "*", LocalPort: 2049, State: "LISTEN"},
		{Protocol: "tcp4", LocalAddress: "*", LocalPort: 2049, State: "LISTEN", Pid: 900, Command: "nfsd"},
	})
	require.Len(t, k, 1)
	assert.Equal(t, "nfsd", k[0].Command)
}

// FreeBSD 15.1 prints ?? for the user, command and pid of a socket no process
// holds (TIME_WAIT); earlier releases print ?.
func TestParseSockstatOrphanFreeBSD15(t *testing.T) {
	entries := parseSockstatFixture(t, "freebsd15_sockstat_46sw.txt")
	last := entries[len(entries)-1]
	assert.Equal(t, int64(0), last.Pid)
	assert.Equal(t, "TIME_WAIT", last.State)
	assert.Equal(t, int64(27813), last.LocalPort)
}
