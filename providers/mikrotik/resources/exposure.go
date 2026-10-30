// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// singletonAccessor reads a menu that holds a single settings record and
// creates the resource from it, or reports the menu as absent. Every RouterOS
// settings menu modelled here can be missing on some build or package, and an
// absent menu must leave the resource null rather than produce one whose flags
// all read false.
func singletonAccessor[T plugin.Resource](
	runtime *plugin.Runtime,
	menu string,
	name string,
	args func(map[string]string) map[string]*llx.RawData,
) (T, bool, error) {
	var zero T
	row, err := mikrotikConn(runtime).PrintOneOptional(menu)
	if err != nil {
		return zero, false, err
	}
	if len(row) == 0 {
		return zero, false, nil
	}
	res, err := CreateResource(runtime, name, args(row))
	if err != nil {
		return zero, false, err
	}
	return res.(T), true, nil
}

// singletonInit is the init counterpart of singletonAccessor, so a resource
// queried by its own name resolves the same way it does through the accessor.
func singletonInit(
	runtime *plugin.Runtime,
	menu string,
	args map[string]*llx.RawData,
	build func(map[string]string) map[string]*llx.RawData,
) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOneOptional(menu)
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu(menu)
	}
	return build(row), nil, nil
}

// --- ip.neighbor.settings ---

func discoverySettingsArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                  llx.StringData("mikrotik.ip.neighbor.settings"),
		"discoverInterfaceList": llx.StringData(row["discover-interface-list"]),
		"protocols":             listField(row, "protocol"),
		"lldpMedNetPolicyVlan":  llx.StringData(row["lldp-med-net-policy-vlan"]),
		"lldpMacPhyConfig":      boolField(row, "lldp-mac-phy-config"),
		"lldpVlanInfo":          boolField(row, "lldp-vlan-info"),
		"lldpMaxFrameSize":      boolField(row, "lldp-max-frame-size"),
	}
}

func (r *mqlMikrotik) discoverySettings() (*mqlMikrotikIpNeighborSettings, error) {
	res, ok, err := singletonAccessor[*mqlMikrotikIpNeighborSettings](
		r.MqlRuntime, "/ip/neighbor/discovery-settings", "mikrotik.ip.neighbor.settings", discoverySettingsArgs)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.DiscoverySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func initMikrotikIpNeighborSettings(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return singletonInit(runtime, "/ip/neighbor/discovery-settings", args, discoverySettingsArgs)
}

// --- tool.macServer ---

// onAllInterfaces reports whether a RouterOS interface list covers every
// interface. It is nil when the device did not report a list at all, since an
// unread list is not proof that management is restricted.
func onAllInterfaces(list string) *bool {
	list = strings.ToLower(strings.TrimSpace(list))
	if list == "" {
		return nil
	}
	all := list == "all"
	return &all
}

// macServerArgs folds the three MAC-layer management menus into one resource:
// MAC-Telnet's own interface list, MAC-Winbox's, and whether the device answers
// MAC-layer pings.
func macServerArgs(macServer, macWinbox, macPing map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                       llx.StringData("mikrotik.tool.macServer"),
		"allowedInterfaceList":       llx.StringData(macServer["allowed-interface-list"]),
		"macTelnetOnAllInterfaces":   llx.BoolDataPtr(onAllInterfaces(macServer["allowed-interface-list"])),
		"winboxAllowedInterfaceList": llx.StringData(macWinbox["allowed-interface-list"]),
		"macWinboxOnAllInterfaces":   llx.BoolDataPtr(onAllInterfaces(macWinbox["allowed-interface-list"])),
		"pingEnabled":                boolField(macPing, "enabled"),
	}
}

// readMacServer reads the three MAC-layer management menus. Each is optional
// on its own, and the resource exists as long as at least one answered.
func readMacServer(runtime *plugin.Runtime) (map[string]*llx.RawData, bool, error) {
	conn := mikrotikConn(runtime)
	macServer, err := conn.PrintOneOptional("/tool/mac-server")
	if err != nil {
		return nil, false, err
	}
	macWinbox, err := conn.PrintOneOptional("/tool/mac-server/mac-winbox")
	if err != nil {
		return nil, false, err
	}
	macPing, err := conn.PrintOneOptional("/tool/mac-server/ping")
	if err != nil {
		return nil, false, err
	}
	if len(macServer) == 0 && len(macWinbox) == 0 && len(macPing) == 0 {
		return nil, false, nil
	}
	return macServerArgs(macServer, macWinbox, macPing), true, nil
}

func (r *mqlMikrotik) macServer() (*mqlMikrotikToolMacServer, error) {
	args, ok, err := readMacServer(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.MacServer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.tool.macServer", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikToolMacServer), nil
}

func initMikrotikToolMacServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	built, ok, err := readMacServer(runtime)
	if err != nil {
		return nil, nil, err
	}
	if !ok {
		return nil, nil, errNoMenu("/tool/mac-server")
	}
	return built, nil, nil
}

// --- ip.cloud ---

func cloudArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":               llx.StringData("mikrotik.ip.cloud"),
		"ddnsEnabled":        boolField(row, "ddns-enabled"),
		"ddnsUpdateInterval": llx.StringData(row["ddns-update-interval"]),
		"updateTime":         boolField(row, "update-time"),
		"publicAddress":      llx.StringData(row["public-address"]),
		"publicAddress6":     llx.StringData(row["public-address-ipv6"]),
		"dnsName":            llx.StringData(row["dns-name"]),
		"status":             llx.StringData(row["status"]),
		"backToHomeVpn":      llx.StringData(row["back-to-home-vpn"]),
	}
}

func (r *mqlMikrotik) cloud() (*mqlMikrotikIpCloud, error) {
	res, ok, err := singletonAccessor[*mqlMikrotikIpCloud](
		r.MqlRuntime, "/ip/cloud", "mikrotik.ip.cloud", cloudArgs)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Cloud.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func initMikrotikIpCloud(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return singletonInit(runtime, "/ip/cloud", args, cloudArgs)
}

// --- tool.romon ---

func romonArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":    llx.StringData("mikrotik.tool.romon"),
		"enabled": boolField(row, "enabled"),
		"id":      llx.StringData(row["id"]),
		// the RoMON secret is never read; only whether one is configured
		"hasSecrets": presenceField(row, "secrets"),
	}
}

func (r *mqlMikrotik) romon() (*mqlMikrotikToolRomon, error) {
	res, ok, err := singletonAccessor[*mqlMikrotikToolRomon](
		r.MqlRuntime, "/tool/romon", "mikrotik.tool.romon", romonArgs)
	if err != nil {
		return nil, err
	}
	if !ok {
		r.Romon.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func initMikrotikToolRomon(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return singletonInit(runtime, "/tool/romon", args, romonArgs)
}
