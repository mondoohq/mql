// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseInt(t *testing.T) {
	cases := map[string]int64{
		"":            0,
		"0":           0,
		"1500":        1500,
		"  42 ":       42,
		"abc":         0,
		"-5":          -5,
		"12345678901": 12345678901, // larger than int32
	}
	for in, want := range cases {
		assert.Equal(t, want, parseInt(in), "parseInt(%q)", in)
	}
}

func TestParseBool(t *testing.T) {
	// RouterOS reports flags as true/false and occasionally yes/no
	for _, s := range []string{"true", "TRUE", "yes", "Yes", " true "} {
		assert.True(t, parseBool(s), "parseBool(%q)", s)
	}
	for _, s := range []string{"", "false", "no", "0", "1", "enabled"} {
		assert.False(t, parseBool(s), "parseBool(%q)", s)
	}
}

// TestFirewallRuleID covers the identity every firewall table now shares.
// There used to be a second helper, firewallID, that composed exactly the same
// key; the two tables using it had drifted from the shared row builder and
// reported false where the others reported null for the same absent attribute.
func TestFirewallRuleID(t *testing.T) {
	// RouterOS supplies a stable internal .id
	assert.Equal(t, "p/*5",
		rowID("p/", map[string]string{".id": "*5", "chain": "input"}, "input", "", ""))
	// fallback composes a key from chain/action/comment when .id is absent
	row := map[string]string{"chain": "input", "action": "drop", "comment": "block ssh"}
	assert.Equal(t, "p/input/drop/block ssh",
		rowID("p/", row, row["chain"], row["action"], row["comment"]))
}

func TestInterfaceArgs(t *testing.T) {
	row := map[string]string{
		"name":         "ether1",
		"default-name": "ether1",
		"type":         "ether",
		"mtu":          "1500",
		"actual-mtu":   "1500",
		"l2mtu":        "1598",
		"mac-address":  "AA:BB:CC:DD:EE:FF",
		"link-downs":   "3",
		"rx-byte":      "1024",
		"tx-byte":      "2048",
		"running":      "true",
		"disabled":     "false",
		"slave":        "yes",
		"comment":      "uplink",
	}
	args := interfaceArgs(row)

	assert.Equal(t, "mikrotik.interface/ether1", args["__id"].Value)
	assert.Equal(t, "ether1", args["name"].Value)
	assert.Equal(t, "ether", args["type"].Value)
	assert.Equal(t, int64(1500), args["mtu"].Value)
	assert.Equal(t, int64(1598), args["l2mtu"].Value)
	assert.Equal(t, "AA:BB:CC:DD:EE:FF", args["macAddress"].Value)
	assert.Equal(t, int64(3), args["linkDowns"].Value)
	assert.Equal(t, int64(1024), args["rxByte"].Value)
	assert.Equal(t, int64(2048), args["txByte"].Value)
	assert.Equal(t, true, args["running"].Value)
	assert.Equal(t, false, args["disabled"].Value)
	assert.Equal(t, true, args["slave"].Value)
	assert.Equal(t, "uplink", args["comment"].Value)
}

func TestPoolArgs(t *testing.T) {
	row := map[string]string{
		"name":      "dhcp-pool",
		"ranges":    "192.168.88.10-192.168.88.254",
		"next-pool": "none",
	}
	args := poolArgs(row)

	assert.Equal(t, "mikrotik.ip.pool/dhcp-pool", args["__id"].Value)
	assert.Equal(t, "dhcp-pool", args["name"].Value)
	assert.Equal(t, []any{"192.168.88.10-192.168.88.254"}, args["ranges"].Value)
	assert.Equal(t, "none", args["nextPool"].Value)
}

func TestUserGroupArgs(t *testing.T) {
	row := map[string]string{
		"name":    "full",
		"policy":  "local, telnet, ssh,reboot,read,write,policy",
		"skin":    "default",
		"comment": "administrators",
	}
	args := userGroupArgs(row)

	assert.Equal(t, "mikrotik.userGroup/full", args["__id"].Value)
	assert.Equal(t, "full", args["name"].Value)
	// comma-separated policy is split into a list (whitespace trimmed)
	assert.Equal(t, []any{"local", "telnet", "ssh", "reboot", "read", "write", "policy"}, args["policy"].Value)
	assert.Equal(t, "default", args["skin"].Value)
	assert.Equal(t, "administrators", args["comment"].Value)
}

func TestSplitList(t *testing.T) {
	assert.Equal(t, []any{}, splitList(""))
	assert.Equal(t, []any{}, splitList("  "))
	assert.Equal(t, []any{"a"}, splitList("a"))
	assert.Equal(t, []any{"a", "b", "c"}, splitList("a, b ,c"))
	assert.Equal(t, []any{"a", "b"}, splitList("a,,b,"))
}

func TestMasterInterfaceName(t *testing.T) {
	// RouterOS reports "none" for physical radios with no parent interface;
	// that sentinel must normalize to empty so the masterInterface accessor
	// returns null instead of trying to resolve an interface named "none".
	assert.Equal(t, "", masterInterfaceName("none"))
	assert.Equal(t, "", masterInterfaceName(""))
	assert.Equal(t, "wifi1", masterInterfaceName("wifi1"))
}
