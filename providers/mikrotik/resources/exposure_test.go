// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOnAllInterfaces(t *testing.T) {
	all := onAllInterfaces("all")
	require.NotNil(t, all)
	assert.True(t, *all)

	upper := onAllInterfaces(" ALL ")
	require.NotNil(t, upper)
	assert.True(t, *upper)

	for _, list := range []string{"none", "LAN", "mgmt"} {
		got := onAllInterfaces(list)
		require.NotNil(t, got, "onAllInterfaces(%q)", list)
		assert.False(t, *got, "onAllInterfaces(%q)", list)
	}

	// an unread list is not proof that management is restricted
	assert.Nil(t, onAllInterfaces(""))
	assert.Nil(t, onAllInterfaces("   "))
}

func TestDiscoverySettingsArgs(t *testing.T) {
	args := discoverySettingsArgs(map[string]string{
		"discover-interface-list":  "all",
		"protocol":                 "cdp,lldp,mndp",
		"lldp-med-net-policy-vlan": "disabled",
		"lldp-mac-phy-config":      "no",
		"lldp-vlan-info":           "no",
	})

	assert.Equal(t, "mikrotik.ip.neighbor.settings", args["__id"].Value)
	assert.Equal(t, "all", args["discoverInterfaceList"].Value)
	// RouterOS names the attribute in the singular
	assert.Equal(t, []any{"cdp", "lldp", "mndp"}, args["protocols"].Value)
	assert.Equal(t, false, args["lldpMacPhyConfig"].Value)
	// the device did not report this one
	assert.Nil(t, args["lldpMaxFrameSize"].Value)
}

func TestDiscoverySettingsArgsAbsentMenu(t *testing.T) {
	args := discoverySettingsArgs(map[string]string{})

	assert.Nil(t, args["protocols"].Value)
	assert.Nil(t, args["lldpMacPhyConfig"].Value)
	assert.Equal(t, "", args["discoverInterfaceList"].Value)
}

func TestMacServerArgs(t *testing.T) {
	args := macServerArgs(
		map[string]string{"allowed-interface-list": "none"},
		map[string]string{"allowed-interface-list": "all"},
		map[string]string{"enabled": "yes"},
	)

	assert.Equal(t, "mikrotik.tool.macServer", args["__id"].Value)
	assert.Equal(t, "none", args["allowedInterfaceList"].Value)
	assert.Equal(t, false, args["macTelnetOnAllInterfaces"].Value)
	// MAC-Winbox on every interface is management reachable from any segment
	assert.Equal(t, "all", args["winboxAllowedInterfaceList"].Value)
	assert.Equal(t, true, args["macWinboxOnAllInterfaces"].Value)
	assert.Equal(t, true, args["pingEnabled"].Value)
}

func TestMacServerArgsAbsentMenus(t *testing.T) {
	// older RouterOS reports this menu in a different shape, and a build
	// without the submenus answers nothing at all; neither may read as
	// "management is restricted"
	args := macServerArgs(map[string]string{}, map[string]string{}, map[string]string{})

	assert.Nil(t, args["macTelnetOnAllInterfaces"].Value)
	assert.Nil(t, args["macWinboxOnAllInterfaces"].Value)
	assert.Nil(t, args["pingEnabled"].Value)
	assert.Equal(t, "", args["allowedInterfaceList"].Value)
}

func TestCloudArgs(t *testing.T) {
	args := cloudArgs(map[string]string{
		"ddns-enabled":         "yes",
		"ddns-update-interval": "none",
		"update-time":          "yes",
		"public-address":       "203.0.113.7",
		"dns-name":             "example.sn.mynetname.net",
		"status":               "updated",
	})

	assert.Equal(t, "mikrotik.ip.cloud", args["__id"].Value)
	assert.Equal(t, true, args["ddnsEnabled"].Value)
	assert.Equal(t, true, args["updateTime"].Value)
	assert.Equal(t, "203.0.113.7", args["publicAddress"].Value)
	assert.Equal(t, "example.sn.mynetname.net", args["dnsName"].Value)
	// the device reported no IPv6 address
	assert.Equal(t, "", args["publicAddress6"].Value)
}

func TestCloudArgsAbsentMenu(t *testing.T) {
	args := cloudArgs(map[string]string{})

	assert.Nil(t, args["ddnsEnabled"].Value)
	assert.Nil(t, args["updateTime"].Value)
	assert.Equal(t, "", args["dnsName"].Value)
}

func TestRomonArgs(t *testing.T) {
	on := romonArgs(map[string]string{
		"enabled": "yes",
		"id":      "00:00:00:00:00:01",
		"secrets": "not-a-real-secret",
	})

	assert.Equal(t, "mikrotik.tool.romon", on["__id"].Value)
	assert.Equal(t, true, on["enabled"].Value)
	assert.Equal(t, true, on["hasSecrets"].Value)
	// the RoMON secret never reaches the result
	assert.NotContains(t, on, "secrets")
	for field, v := range on {
		assert.NotEqual(t, "not-a-real-secret", v.Value, "field %q leaked the secret", field)
	}

	// enabled with no secret is a mesh anyone on the wire can join
	open := romonArgs(map[string]string{"enabled": "yes", "secrets": ""})
	assert.Equal(t, true, open["enabled"].Value)
	assert.Equal(t, false, open["hasSecrets"].Value)
}

func TestRomonArgsAbsentMenu(t *testing.T) {
	args := romonArgs(map[string]string{})

	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["hasSecrets"].Value)
}
