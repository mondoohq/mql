// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- WiFi interface (RouterOS 7 /interface/wifi) ---

type mqlMikrotikInterfaceWifiInternal struct {
	cacheMasterInterface string
}

func newMikrotikWifiInterface(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	// the wifi subsystem reports nested attributes with dotted keys, e.g.
	// configuration.ssid, channel.band, security.authentication-types
	res, err := CreateResource(runtime, "mikrotik.interface.wifi", map[string]*llx.RawData{
		"__id":                llx.StringData("mikrotik.interface.wifi/" + row["name"]),
		"name":                llx.StringData(row["name"]),
		"defaultName":         llx.StringData(row["default-name"]),
		"macAddress":          llx.StringData(row["mac-address"]),
		"ssid":                llx.StringData(row["configuration.ssid"]),
		"mode":                llx.StringData(row["configuration.mode"]),
		"channelBand":         llx.StringData(row["channel.band"]),
		"channelFrequency":    llx.StringData(row["channel.frequency"]),
		"channelWidth":        llx.StringData(row["channel.width"]),
		"authenticationTypes": listField(row, "security.authentication-types"),
		"running":             boolField(row, "running"),
		"disabled":            boolField(row, "disabled"),
		"comment":             llx.StringData(row["comment"]),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikInterfaceWifi).cacheMasterInterface = masterInterfaceName(row["master-interface"])
	return res, nil
}

func (r *mqlMikrotik) wifiInterfaces() ([]any, error) {
	// /interface/wifi only exists on RouterOS 7 with the wifi package; on older
	// or non-WiFi devices PrintOptional returns an empty list instead of erroring.
	rows, err := mikrotikConn(r.MqlRuntime).PrintOptional("/interface/wifi")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikWifiInterface)
}

func (r *mqlMikrotikInterfaceWifi) masterInterface() (*mqlMikrotikInterface, error) {
	if r.cacheMasterInterface == "" {
		r.MasterInterface.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return interfaceByName(r.MqlRuntime, r.cacheMasterInterface)
}

// masterInterfaceName normalizes RouterOS's "none" sentinel (used by physical
// radios that have no parent interface) to an empty string.
func masterInterfaceName(v string) string {
	if v == "none" {
		return ""
	}
	return v
}
