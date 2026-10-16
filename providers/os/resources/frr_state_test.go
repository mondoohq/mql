// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"bytes"
	"errors"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/os/connection/shared"
)

// frrCmdConn answers a fixed set of commands, so the runtime accessors can
// be tested without a router.
type frrCmdConn struct {
	*mockConn
	out    map[string]string
	stderr map[string]string
	status map[string]int
	fail   map[string]bool
	// seen records every command in call order.
	seen []string
}

func (m *frrCmdConn) RunCommand(command string) (*shared.Command, error) {
	m.seen = append(m.seen, command)
	if m.fail[command] {
		return nil, errors.New("command not found")
	}
	return &shared.Command{
		Command:    command,
		Stdout:     bytes.NewBufferString(m.out[command]),
		Stderr:     bytes.NewBufferString(m.stderr[command]),
		ExitStatus: m.status[command],
	}, nil
}

func newFrrCmdConn() *frrCmdConn {
	return &frrCmdConn{
		mockConn: connWithPlatform("ubuntu"),
		out:      map[string]string{},
		stderr:   map[string]string{},
		status:   map[string]int{},
		fail:     map[string]bool{},
	}
}

func TestVtyshCommand(t *testing.T) {
	assert.Equal(t, `vtysh -c "show ip route json"`, vtyshCommand("show ip route json"))
	assert.Equal(t, `vtysh -c "show bgp vrf t-blue summary json"`,
		vtyshCommand("show bgp vrf t-blue summary json"))
}

func TestRunOutput(t *testing.T) {
	conn := newFrrCmdConn()
	conn.out["ip -j rule show"] = "[]"

	out, err := runOutput(conn, "ip -j rule show")
	require.NoError(t, err)
	assert.Equal(t, "[]", string(out))

	// A non-zero exit status is an error. A silent empty result would read
	// as a clean posture.
	conn.out["vtysh -c \"show vrf\""] = ""
	conn.stderr["vtysh -c \"show vrf\""] = "vtysh: not found"
	conn.status["vtysh -c \"show vrf\""] = 127
	_, err = runOutput(conn, "vtysh -c \"show vrf\"")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exit status 127")
	assert.Contains(t, err.Error(), "vtysh: not found")

	// A connection that cannot run commands at all is an error too.
	conn.fail["missing"] = true
	_, err = runOutput(conn, "missing")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot run")
}

func TestInitFrrRouteTable_Defaults(t *testing.T) {
	args, res, err := initFrrRouteTable(nil, map[string]*llx.RawData{})
	require.NoError(t, err)
	assert.Nil(t, res)
	assert.Equal(t, "", args["vrf"].Value)
	assert.Equal(t, "ipv4", args["afi"].Value)
	assert.Equal(t, int64(5000), args["limit"].Value)
	assert.Equal(t, "frr.routeTable/default/ipv4/limit/5000", args["__id"].Value)
}

func TestInitFrrRouteTable_Arguments(t *testing.T) {
	args, _, err := initFrrRouteTable(nil, map[string]*llx.RawData{
		"vrf":   llx.StringData("t-blue"),
		"afi":   llx.StringData("IPv6"),
		"limit": llx.IntData(10),
	})
	require.NoError(t, err)
	assert.Equal(t, "t-blue", args["vrf"].Value)
	assert.Equal(t, "ipv6", args["afi"].Value)
	assert.Equal(t, int64(10), args["limit"].Value)
	assert.Equal(t, "frr.routeTable/t-blue/ipv6/limit/10", args["__id"].Value)
}

// TestInitFrrRouteTable_Rejects covers the arguments that reach the vtysh
// command line. A VRF name from a query must not be able to change it.
func TestInitFrrRouteTable_Rejects(t *testing.T) {
	tests := []struct {
		name string
		args map[string]*llx.RawData
	}{
		{"command injection", map[string]*llx.RawData{"vrf": llx.StringData(`x"; reboot; "`)}},
		{"shell substitution", map[string]*llx.RawData{"vrf": llx.StringData("$(id)")}},
		{"space in name", map[string]*llx.RawData{"vrf": llx.StringData("a b")}},
		{"unknown address family", map[string]*llx.RawData{"afi": llx.StringData("ipv5")}},
		{"zero limit", map[string]*llx.RawData{"limit": llx.IntData(0)}},
		{"negative limit", map[string]*llx.RawData{"limit": llx.IntData(-1)}},
		{"wrong vrf type", map[string]*llx.RawData{"vrf": llx.IntData(1)}},
		{"wrong limit type", map[string]*llx.RawData{"limit": llx.StringData("many")}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := initFrrRouteTable(nil, tc.args)
			require.Error(t, err)
		})
	}
}

func TestFrrRouteTableID(t *testing.T) {
	assert.Equal(t, "frr.routeTable/default/ipv4/limit/5000", frrRouteTableID("", "ipv4", 5000))
	assert.Equal(t, "frr.routeTable/cluster/ipv6/limit/10", frrRouteTableID("cluster", "ipv6", 10))
	assert.Equal(t, "default", vrfKey(""))
	assert.Equal(t, "cluster", vrfKey("cluster"))
	assert.NotEqual(t, frrRouteTableID("cluster", "ipv4", 10), frrRouteTableID("cluster", "ipv4", 100))
}

func TestValidateFrrLimitMatchesPlatformInt(t *testing.T) {
	maxInt := int64(^uint(0) >> 1)
	assert.NoError(t, validateFrrLimit("frr.routeTable", maxInt))
	assert.Error(t, validateFrrLimit("frr.routeTable", 0))
	if strconv.IntSize == 32 {
		assert.Error(t, validateFrrLimit("frr.routeTable", maxInt+1))
	}
}

func TestRouteTableResourcesWithDifferentLimitsAreNotReused(t *testing.T) {
	runtime := plugin.NewRuntime(nil, nil, false, nil, nil, nil, nil, nil)
	first, err := NewResource(runtime, "frr.routeTable", map[string]*llx.RawData{
		"vrf": llx.StringData("cluster"), "afi": llx.StringData("ipv4"), "limit": llx.IntData(10),
	})
	require.NoError(t, err)
	second, err := NewResource(runtime, "frr.routeTable", map[string]*llx.RawData{
		"vrf": llx.StringData("cluster"), "afi": llx.StringData("ipv4"), "limit": llx.IntData(100),
	})
	require.NoError(t, err)
	assert.NotSame(t, first, second)
	assert.NotEqual(t, first.MqlID(), second.MqlID())
}
