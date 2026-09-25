// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bufio"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/utils/syncx"
)

func TestParseLinuxProcNetIPv4(t *testing.T) {
	fi, err := os.Open("./ports/testdata/tcp4.txt")
	require.NoError(t, err)
	defer fi.Close()

	scanner := bufio.NewScanner(fi)
	scanner.Scan()
	line := scanner.Text()
	port, err := parseProcNetLine(line)
	require.NoError(t, err)
	require.Nil(t, port)

	scanner.Scan()
	line = scanner.Text()
	port, err = parseProcNetLine(line)
	require.NoError(t, err)
	require.NotNil(t, port)

	assert.Equal(t, int64(53), (*port).Port)
	assert.Equal(t, "127.0.0.53", port.Address)
	assert.Equal(t, int64(0), port.RemotePort)
	assert.Equal(t, "0.0.0.0", port.RemoteAddress)

	scanner.Scan()
	scanner.Scan()
	line = scanner.Text()
	port, err = parseProcNetLine(line)
	require.NoError(t, err)
	require.NotNil(t, port)

	assert.Equal(t, int64(37200), (*port).Port)
	assert.Equal(t, "10.0.2.15", port.Address)
	assert.Equal(t, int64(80), port.RemotePort)
	assert.Equal(t, "185.125.190.36", port.RemoteAddress)
}

func TestParseLinuxProcNetIPv6(t *testing.T) {
	fi, err := os.Open("./ports/testdata/tcp6.txt")
	require.NoError(t, err)
	defer fi.Close()

	scanner := bufio.NewScanner(fi)
	scanner.Scan()
	line := scanner.Text()
	port, err := parseProcNetLine(line)
	require.NoError(t, err)
	require.Nil(t, port)

	scanner.Scan()
	line = scanner.Text()
	port, err = parseProcNetLine(line)
	require.NoError(t, err)
	require.NotNil(t, port)

	assert.Equal(t, int64(22), (*port).Port)
	assert.Equal(t, "[::]", port.Address)
	assert.Equal(t, int64(0), port.RemotePort)
	assert.Equal(t, "[::]", port.RemoteAddress)

	// third line tests little-to-big endian
	// reading the hex ipv6 address 00000000000000000000000001000000
	// to be [::1]
	scanner.Scan()
	line = scanner.Text()
	port, err = parseProcNetLine(line)
	require.NoError(t, err)
	require.NotNil(t, port)

	assert.Equal(t, int64(631), (*port).Port)
	assert.Equal(t, "[::1]", port.Address)
	assert.Equal(t, int64(0), port.RemotePort)
	assert.Equal(t, "[::]", port.RemoteAddress)
}

// AIX netstat reports states in its own spelling; they have to land on the same
// vocabulary the other platforms use, or `ports.listening` (which filters on
// state == "listen") would silently return nothing on AIX.
func TestAixPortState(t *testing.T) {
	assert.Equal(t, "listen", aixPortState("LISTEN"))
	assert.Equal(t, "established", aixPortState("ESTABLISHED"))
	assert.Equal(t, "time wait", aixPortState("TIME_WAIT"))
	assert.Equal(t, "close wait", aixPortState("CLOSE_WAIT"))
	assert.Equal(t, "syn recv", aixPortState("SYN_RCVD"))
	assert.Equal(t, "syn recv", aixPortState("SYN_RECEIVED"))
	assert.Equal(t, "fin wait1", aixPortState("FIN_WAIT_1"))
	assert.Equal(t, "fin wait2", aixPortState("FIN_WAIT_2"))
	assert.Equal(t, "last ack", aixPortState("LAST_ACK"))
	assert.Equal(t, "closing", aixPortState("CLOSING"))
	assert.Equal(t, "close", aixPortState("CLOSED"))

	// UDP has no state on AIX; that must stay empty rather than become a state.
	assert.Equal(t, "", aixPortState(""))

	// Anything else is reported honestly as unknown, never guessed into a
	// canonical state.
	assert.Equal(t, "unknown", aixPortState("IDLE"))
	assert.Equal(t, "unknown", aixPortState("BOGUS"))
}

// Every mapped state must be a value the shared TCP_STATES table defines, so the
// two cannot drift apart.
func TestAixPortStatesAreCanonical(t *testing.T) {
	canonical := map[string]bool{}
	for _, v := range TCP_STATES {
		canonical[v] = true
	}
	for aix, mapped := range aixTcpStates {
		assert.True(t, canonical[mapped],
			"AIX state %q maps to %q which is not in TCP_STATES", aix, mapped)
	}
}

// A wildcard bind is reachable from the network. It used to be rewritten to
// loopback, which reported every exposed listener as local-only and quietly
// passed any check looking for internet-facing ports.
func TestExpandLsofWildcardAddress(t *testing.T) {
	for _, tt := range []struct {
		address  string
		protocol string
		want     string
	}{
		{"*", "tcp4", "0.0.0.0"},
		{"*", "udp4", "0.0.0.0"},
		{"*", "tcp6", "::"},
		{"*", "udp6", "::"},
		// concrete binds are passed through untouched
		{"127.0.0.1", "tcp4", "127.0.0.1"},
		{"::1", "tcp6", "::1"},
		{"172.16.1.129", "tcp4", "172.16.1.129"},
		{"", "tcp4", ""},
	} {
		t.Run(tt.protocol+"/"+tt.address, func(t *testing.T) {
			assert.Equal(t, tt.want, expandLsofWildcardAddress(tt.address, tt.protocol))
		})
	}
}

func TestFreebsdPortState(t *testing.T) {
	// mapped onto the same vocabulary the other platforms use
	assert.Equal(t, "listen", freebsdPortState("LISTEN"))
	assert.Equal(t, "established", freebsdPortState("ESTABLISHED"))
	assert.Equal(t, "time wait", freebsdPortState("TIME_WAIT"))
	assert.Equal(t, "close wait", freebsdPortState("CLOSE_WAIT"))

	// udp rows carry no state at all
	assert.Equal(t, "", freebsdPortState(""))

	// a state FreeBSD adds later must stay visible rather than read as "no
	// state", which is what a bare map lookup would have produced
	assert.Equal(t, "SOME_FUTURE_STATE", freebsdPortState("SOME_FUTURE_STATE"))
}

// A socket owned by a uid with no passwd entry leaves port.user null instead
// of failing the whole port list.
func TestParseProcNet_UnknownUid(t *testing.T) {
	fixturePath, err := filepath.Abs("testdata/port_unknown_uid.toml")
	require.NoError(t, err)
	asset := &inventory.Asset{
		Platform: &inventory.Platform{Name: "ubuntu", Family: []string{"linux", "unix"}},
	}
	conn, err := mock.New(0, asset, mock.WithPath(fixturePath))
	require.NoError(t, err)
	runtime := &plugin.Runtime{Connection: conn, Resources: &syncx.Map[plugin.Resource]{}}

	root, err := CreateResource(runtime, "user", map[string]*llx.RawData{
		"name": llx.StringData("root"),
		"uid":  llx.IntData(0),
	})
	require.NoError(t, err)
	raw, err := CreateResource(runtime, "ports", map[string]*llx.RawData{})
	require.NoError(t, err)

	ports, err := raw.(*mqlPorts).parseProcNet("/proc/net/tcp", "tcp4",
		map[int64]*mqlUser{0: root.(*mqlUser)})
	require.NoError(t, err, "an unknown uid must not fail the port list")
	require.Len(t, ports, 2)

	known := ports[0].(*mqlPort)
	assert.Equal(t, int64(53), known.Port.Data)
	require.NotNil(t, known.User.Data)
	assert.Equal(t, "root", known.User.Data.Name.Data)

	unknown := ports[1].(*mqlPort)
	assert.Equal(t, int64(8765), unknown.Port.Data)
	assert.Nil(t, unknown.User.Data, "port.user should be null for an unknown uid")
}
