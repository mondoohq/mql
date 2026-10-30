// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- interface ---

func interfaceArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":             llx.StringData("mikrotik.interface/" + row["name"]),
		"name":             llx.StringData(row["name"]),
		"defaultName":      llx.StringData(row["default-name"]),
		"type":             llx.StringData(row["type"]),
		"mtu":              intField(row, "mtu"),
		"actualMtu":        intField(row, "actual-mtu"),
		"l2mtu":            intField(row, "l2mtu"),
		"maxL2mtu":         intField(row, "max-l2mtu"),
		"macAddress":       llx.StringData(row["mac-address"]),
		"lastLinkUpTime":   llx.StringData(row["last-link-up-time"]),
		"lastLinkDownTime": llx.StringData(row["last-link-down-time"]),
		"linkDowns":        intField(row, "link-downs"),
		"rxByte":           intField(row, "rx-byte"),
		"txByte":           intField(row, "tx-byte"),
		"rxPacket":         intField(row, "rx-packet"),
		"txPacket":         intField(row, "tx-packet"),
		"rxDrop":           intField(row, "rx-drop"),
		"txDrop":           intField(row, "tx-drop"),
		"rxError":          intField(row, "rx-error"),
		"txError":          intField(row, "tx-error"),
		"running":          boolField(row, "running"),
		"slave":            boolField(row, "slave"),
		"dynamic":          boolField(row, "dynamic"),
		"disabled":         boolField(row, "disabled"),
		"comment":          llx.StringData(row["comment"]),
	}
}

func newMikrotikInterface(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.interface", interfaceArgs(row))
}

// initMikrotikInterface resolves a mikrotik.interface that was looked up by
// name only (e.g. from an ip.address or vlan cross-reference).
func initMikrotikInterface(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 || args["name"] == nil {
		return args, nil, nil
	}
	name, ok := args["name"].Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}

	rows, err := mikrotikConn(runtime).Print("/interface")
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if row["name"] == name {
			return interfaceArgs(row), nil, nil
		}
	}
	// interface no longer present — keep the bare reference rather than error
	return args, nil, nil
}

func (r *mqlMikrotikInterface) addresses() ([]any, error) {
	conn := mikrotikConn(r.MqlRuntime)
	rows, err := conn.Print("/ip/address")
	if err != nil {
		return nil, err
	}
	name := r.Name.Data
	res := []any{}
	for _, row := range rows {
		if row["interface"] != name && row["actual-interface"] != name {
			continue
		}
		addr, err := newMikrotikIpAddress(r.MqlRuntime, row)
		if err != nil {
			return nil, err
		}
		res = append(res, addr)
	}
	return res, nil
}

func (r *mqlMikrotikInterface) ipv6Addresses() ([]any, error) {
	conn := mikrotikConn(r.MqlRuntime)
	// see mikrotik.ipv6Addresses: the menu is gone without the ipv6 package
	rows, err := conn.PrintOptional("/ipv6/address")
	if err != nil {
		return nil, err
	}
	name := r.Name.Data
	res := []any{}
	for _, row := range rows {
		if row["interface"] != name && row["actual-interface"] != name {
			continue
		}
		addr, err := newMikrotikIpv6Address(r.MqlRuntime, row)
		if err != nil {
			return nil, err
		}
		res = append(res, addr)
	}
	return res, nil
}

// --- bridge ---

func newMikrotikBridge(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.interface.bridge", bridgeArgs(row))
}

func bridgeArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":          llx.StringData("mikrotik.interface.bridge/" + row["name"]),
		"name":          llx.StringData(row["name"]),
		"macAddress":    llx.StringData(row["mac-address"]),
		"protocolMode":  llx.StringData(row["protocol-mode"]),
		"vlanFiltering": boolField(row, "vlan-filtering"),
		"fastForward":   boolField(row, "fast-forward"),
		"igmpSnooping":  boolField(row, "igmp-snooping"),
		"dhcpSnooping":  boolField(row, "dhcp-snooping"),
		"mtu":           intField(row, "mtu"),
		"actualMtu":     intField(row, "actual-mtu"),
		"l2mtu":         intField(row, "l2mtu"),
		"ageingTime":    llx.StringData(row["ageing-time"]),
		"priority":      llx.StringData(row["priority"]),
		"arp":           llx.StringData(row["arp"]),
		"running":       boolField(row, "running"),
		"disabled":      boolField(row, "disabled"),
		"comment":       llx.StringData(row["comment"]),
	}
}

// --- vlan ---

type mqlMikrotikInterfaceVlanInternal struct {
	cacheInterface string
}

func newMikrotikVlan(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.interface.vlan", vlanArgs(row))
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikInterfaceVlan).cacheInterface = row["interface"]
	return res, nil
}

func vlanArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":          llx.StringData("mikrotik.interface.vlan/" + row["name"]),
		"name":          llx.StringData(row["name"]),
		"vlanId":        intField(row, "vlan-id"),
		"mtu":           intField(row, "mtu"),
		"l2mtu":         intField(row, "l2mtu"),
		"macAddress":    llx.StringData(row["mac-address"]),
		"useServiceTag": boolField(row, "use-service-tag"),
		"running":       boolField(row, "running"),
		"disabled":      boolField(row, "disabled"),
		"comment":       llx.StringData(row["comment"]),
	}
}

func (r *mqlMikrotikInterfaceVlan) compute_interface() (*mqlMikrotikInterface, error) {
	if r.cacheInterface == "" {
		r.Interface.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return interfaceByName(r.MqlRuntime, r.cacheInterface)
}
