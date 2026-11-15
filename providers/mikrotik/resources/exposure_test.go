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

func TestBandwidthServerArgs(t *testing.T) {
	// RouterOS 7.25.1 default: enabled, open to every address
	def := bandwidthServerArgs(liveRows(t, "tool-bandwidth-server.json")[0])
	assert.Equal(t, "mikrotik.tool.bandwidthServer", def["__id"].Value)
	assert.Equal(t, true, def["enabled"].Value)
	assert.Equal(t, true, def["authenticate"].Value)
	// an empty allow-list is an empty list, not null: the device reported it
	assert.Equal(t, []any{}, def["allowedAddresses4"].Value)
	assert.Equal(t, []any{}, def["allowedAddresses6"].Value)
	assert.Equal(t, int64(100), def["maxSessions"].Value)
	assert.Equal(t, int64(2000), def["allocateUdpPortsFrom"].Value)

	restricted := bandwidthServerArgs(map[string]string{
		"enabled":            "false",
		"authenticate":       "false",
		"allowed-addresses4": "192.0.2.0/24,198.51.100.7/32",
		"allowed-addresses6": "2001:db8::/32",
	})
	assert.Equal(t, false, restricted["enabled"].Value)
	assert.Equal(t, false, restricted["authenticate"].Value)
	assert.Equal(t, []any{"192.0.2.0/24", "198.51.100.7/32"}, restricted["allowedAddresses4"].Value)
	assert.Equal(t, []any{"2001:db8::/32"}, restricted["allowedAddresses6"].Value)
}

func TestBandwidthServerArgsAbsentMenu(t *testing.T) {
	args := bandwidthServerArgs(map[string]string{})
	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["authenticate"].Value)
	assert.Nil(t, args["allowedAddresses4"].Value)
	assert.Nil(t, args["maxSessions"].Value)
}

func TestSocksArgs(t *testing.T) {
	// RouterOS 7.25.1 default: off, but SOCKS 4 with no authentication if
	// anyone turns it on
	def := socksArgs(liveRows(t, "ip-socks.json")[0])
	assert.Equal(t, "mikrotik.ip.socks", def["__id"].Value)
	assert.Equal(t, false, def["enabled"].Value)
	assert.Equal(t, "none", def["authMethod"].Value)
	assert.Equal(t, int64(1080), def["port"].Value)
	assert.Equal(t, int64(4), def["version"].Value)
	assert.Equal(t, int64(200), def["maxConnections"].Value)
	assert.Equal(t, "2m", def["connectionIdleTimeout"].Value)

	authenticated := socksArgs(map[string]string{
		"enabled":     "true",
		"auth-method": "password",
		"version":     "5",
	})
	assert.Equal(t, true, authenticated["enabled"].Value)
	assert.Equal(t, "password", authenticated["authMethod"].Value)
	assert.Equal(t, int64(5), authenticated["version"].Value)
}

func TestSocksArgsAbsentMenu(t *testing.T) {
	args := socksArgs(map[string]string{})
	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["port"].Value)
	assert.Nil(t, args["version"].Value)
}

func TestWebProxyArgs(t *testing.T) {
	// RouterOS 7.25.1 default: off, listening on 8080 if turned on
	def := webProxyArgs(liveRows(t, "ip-proxy.json")[0])
	assert.Equal(t, "mikrotik.ip.proxy", def["__id"].Value)
	assert.Equal(t, false, def["enabled"].Value)
	assert.Equal(t, []any{int64(8080)}, def["ports"].Value)
	assert.Equal(t, false, def["anonymous"].Value)
	assert.Equal(t, "::", def["parentProxy"].Value)
	assert.Equal(t, int64(0), def["parentProxyPort"].Value)
	assert.Equal(t, "::", def["srcAddress"].Value)
	assert.Equal(t, int64(600), def["maxClientConnections"].Value)

	// several ports and an upstream proxy, as RouterOS 7.25.1 reports them
	chained := webProxyArgs(map[string]string{
		"enabled":           "true",
		"anonymous":         "true",
		"port":              "8080,3128",
		"parent-proxy":      "192.0.2.10",
		"parent-proxy-port": "3128",
		"src-address":       "192.0.2.1",
	})
	assert.Equal(t, true, chained["enabled"].Value)
	assert.Equal(t, true, chained["anonymous"].Value)
	assert.Equal(t, []any{int64(8080), int64(3128)}, chained["ports"].Value)
	assert.Equal(t, "192.0.2.10", chained["parentProxy"].Value)
	assert.Equal(t, int64(3128), chained["parentProxyPort"].Value)
}

func TestWebProxyArgsAbsentMenu(t *testing.T) {
	args := webProxyArgs(map[string]string{})
	assert.Nil(t, args["enabled"].Value)
	assert.Nil(t, args["ports"].Value)
	assert.Nil(t, args["anonymous"].Value)
}
