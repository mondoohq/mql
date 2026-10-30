// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// absentMeansNull asserts that every named field of an args map is null rather
// than a zero value. RouterOS omits attributes it has no value for, so a
// fabricated false or 0 reports a setting as measured when nothing was read.
func absentMeansNull(t *testing.T, args map[string]*llx.RawData, fields ...string) {
	t.Helper()
	for _, f := range fields {
		v, ok := args[f]
		require.True(t, ok, "%s is not in the args map", f)
		assert.Nil(t, v.Value, "%s must be null when the device did not report it", f)
	}
}

// TestInterfaceArgsAbsentAttributes pins the case a real device produced: a
// vlan interface whose row carries l2mtu but no max-l2mtu at all. Before this,
// maxL2mtu read 0 — a layer-2 MTU of zero bytes reported as fact.
func TestInterfaceArgsAbsentAttributes(t *testing.T) {
	args := interfaceArgs(map[string]string{"name": "vlan10", "type": "vlan", "l2mtu": "65531"})

	assert.Equal(t, int64(65531), args["l2mtu"].Value, "a reported value still reads through")
	absentMeansNull(t, args, "maxL2mtu", "slave", "dynamic", "disabled", "running", "mtu")
}

// TestBridgeArgsAbsentAttributes covers the bridge hardening flags. RouterOS 6
// has no dhcp-snooping attribute at all, so a device that predates the feature
// reported "DHCP snooping is disabled" rather than "not measured".
func TestBridgeArgsAbsentAttributes(t *testing.T) {
	args := bridgeArgs(map[string]string{"name": "br-lab"})
	absentMeansNull(t, args, "vlanFiltering", "dhcpSnooping", "igmpSnooping", "fastForward")
}

// TestVlanArgsAbsentAttributes covers the vlan builder for the same reason.
func TestVlanArgsAbsentAttributes(t *testing.T) {
	args := vlanArgs(map[string]string{"name": "vlan10"})
	absentMeansNull(t, args, "disabled", "running", "mtu")
}

// TestFirewallTablesAgreeOnAbsentAttributes is the cross-path guard. The IPv4
// filter and NAT tables used to build their rows by hand, so on one device in
// one scan the same missing attribute read null on mangle and false on filter.
// Every table now shares one builder; this proves it.
func TestFirewallTablesAgreeOnAbsentAttributes(t *testing.T) {
	row := map[string]string{".id": "*1", "chain": "input", "action": "drop"}

	for _, prefix := range []string{
		"mikrotik.ip.firewall.filter/",
		"mikrotik.ip.firewall.nat/",
		"mikrotik.ip.firewall.mangle/",
		"mikrotik.ip.firewall.raw/",
	} {
		t.Run(prefix, func(t *testing.T) {
			args := firewallRuleArgs(prefix, row)
			assert.Equal(t, prefix+"*1", args["__id"].Value)
			assert.Equal(t, "input", args["chain"].Value)
			absentMeansNull(t, args, "log", "dynamic", "invalid", "disabled", "bytes", "packets")
		})
	}
}
