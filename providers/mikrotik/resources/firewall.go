// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// firewallRuleArgs maps the chain, action, match conditions, counters, and
// state flags that every RouterOS firewall table shares onto resource fields.
// Table-specific attributes (marks, NAT targets, ICMPv6 options) are merged in
// by the individual creators.
func firewallRuleArgs(prefix string, row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":           llx.StringData(rowID(prefix, row, row["chain"], row["action"], row["comment"])),
		"chain":          llx.StringData(row["chain"]),
		"action":         llx.StringData(row["action"]),
		"protocol":       llx.StringData(row["protocol"]),
		"srcAddress":     llx.StringData(row["src-address"]),
		"dstAddress":     llx.StringData(row["dst-address"]),
		"srcAddressList": llx.StringData(row["src-address-list"]),
		"dstAddressList": llx.StringData(row["dst-address-list"]),
		"srcPort":        llx.StringData(row["src-port"]),
		"dstPort":        llx.StringData(row["dst-port"]),
		"inInterface":    llx.StringData(row["in-interface"]),
		"outInterface":   llx.StringData(row["out-interface"]),
		"log":            boolField(row, "log"),
		"logPrefix":      llx.StringData(row["log-prefix"]),
		"bytes":          intField(row, "bytes"),
		"packets":        intField(row, "packets"),
		"disabled":       boolField(row, "disabled"),
		"dynamic":        boolField(row, "dynamic"),
		"invalid":        boolField(row, "invalid"),
		"comment":        llx.StringData(row["comment"]),
	}
}

// --- ip.firewall.mangle ---

func newMikrotikFirewallMangle(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	args := firewallRuleArgs("mikrotik.ip.firewall.mangle/", row)
	args["newPacketMark"] = llx.StringData(row["new-packet-mark"])
	args["newConnectionMark"] = llx.StringData(row["new-connection-mark"])
	args["newRoutingMark"] = llx.StringData(row["new-routing-mark"])
	args["passthrough"] = boolField(row, "passthrough")
	args["connectionState"] = llx.StringData(row["connection-state"])
	args["connectionMark"] = llx.StringData(row["connection-mark"])
	args["packetMark"] = llx.StringData(row["packet-mark"])
	args["routingMark"] = llx.StringData(row["routing-mark"])
	return CreateResource(runtime, "mikrotik.ip.firewall.mangle", args)
}

func (r *mqlMikrotik) mangleRules() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/firewall/mangle")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikFirewallMangle)
}

// --- ip.firewall.raw ---

func newMikrotikFirewallRaw(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.ip.firewall.raw",
		firewallRuleArgs("mikrotik.ip.firewall.raw/", row))
}

func (r *mqlMikrotik) rawRules() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/firewall/raw")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikFirewallRaw)
}

// --- ipv6.firewall.filter ---

func newMikrotikIpv6FirewallFilter(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	args := firewallRuleArgs("mikrotik.ipv6.firewall.filter/", row)
	args["connectionState"] = llx.StringData(row["connection-state"])
	args["icmpOptions"] = llx.StringData(row["icmp-options"])
	return CreateResource(runtime, "mikrotik.ipv6.firewall.filter", args)
}

func (r *mqlMikrotik) ipv6FirewallRules() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).PrintOptional("/ipv6/firewall/filter")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpv6FirewallFilter)
}

// --- ipv6.firewall.nat ---

func newMikrotikIpv6FirewallNat(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	args := firewallRuleArgs("mikrotik.ipv6.firewall.nat/", row)
	args["toAddresses"] = llx.StringData(row["to-addresses"])
	args["toPorts"] = llx.StringData(row["to-ports"])
	return CreateResource(runtime, "mikrotik.ipv6.firewall.nat", args)
}

func (r *mqlMikrotik) ipv6NatRules() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).PrintOptional("/ipv6/firewall/nat")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpv6FirewallNat)
}

// --- firewall address lists ---

func addressListArgs(prefix string, row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":         llx.StringData(rowID(prefix, row, row["list"], row["address"])),
		"list":         llx.StringData(row["list"]),
		"address":      llx.StringData(row["address"]),
		"creationTime": llx.StringData(row["creation-time"]),
		"timeout":      llx.StringData(row["timeout"]),
		"dynamic":      boolField(row, "dynamic"),
		"disabled":     boolField(row, "disabled"),
		"comment":      llx.StringData(row["comment"]),
	}
}

func newMikrotikFirewallAddressList(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.ip.firewall.addressList",
		addressListArgs("mikrotik.ip.firewall.addressList/", row))
}

func (r *mqlMikrotik) firewallAddressLists() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/firewall/address-list")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikFirewallAddressList)
}

func newMikrotikIpv6FirewallAddressList(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.ipv6.firewall.addressList",
		addressListArgs("mikrotik.ipv6.firewall.addressList/", row))
}

func (r *mqlMikrotik) ipv6AddressLists() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).PrintOptional("/ipv6/firewall/address-list")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikIpv6FirewallAddressList)
}

// --- ip.firewall.connectionTracking ---

func connectionTrackingArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":                  llx.StringData("mikrotik.ip.firewall.connectionTracking"),
		"enabled":               llx.StringData(row["enabled"]),
		"looseTcpTracking":      boolField(row, "loose-tcp-tracking"),
		"totalEntries":          intField(row, "total-entries"),
		"maxEntries":            intField(row, "max-entries"),
		"tcpSynSentTimeout":     llx.StringData(row["tcp-syn-sent-timeout"]),
		"tcpSynReceivedTimeout": llx.StringData(row["tcp-syn-received-timeout"]),
		"tcpEstablishedTimeout": llx.StringData(row["tcp-established-timeout"]),
		"tcpFinWaitTimeout":     llx.StringData(row["tcp-fin-wait-timeout"]),
		"tcpCloseWaitTimeout":   llx.StringData(row["tcp-close-wait-timeout"]),
		"tcpLastAckTimeout":     llx.StringData(row["tcp-last-ack-timeout"]),
		"tcpTimeWaitTimeout":    llx.StringData(row["tcp-time-wait-timeout"]),
		"tcpCloseTimeout":       llx.StringData(row["tcp-close-timeout"]),
		"tcpMaxRetransTimeout":  llx.StringData(row["tcp-max-retrans-timeout"]),
		"tcpUnackedTimeout":     llx.StringData(row["tcp-unacked-timeout"]),
		"udpTimeout":            llx.StringData(row["udp-timeout"]),
		"udpStreamTimeout":      llx.StringData(row["udp-stream-timeout"]),
		"icmpTimeout":           llx.StringData(row["icmp-timeout"]),
		"genericTimeout":        llx.StringData(row["generic-timeout"]),
	}
}

func (r *mqlMikrotik) connectionTracking() (*mqlMikrotikIpFirewallConnectionTracking, error) {
	row, err := mikrotikConn(r.MqlRuntime).PrintOne("/ip/firewall/connection-tracking")
	if err != nil {
		return nil, err
	}
	if len(row) == 0 {
		r.ConnectionTracking.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := CreateResource(r.MqlRuntime, "mikrotik.ip.firewall.connectionTracking", connectionTrackingArgs(row))
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikIpFirewallConnectionTracking), nil
}

func initMikrotikIpFirewallConnectionTracking(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	row, err := mikrotikConn(runtime).PrintOne("/ip/firewall/connection-tracking")
	if err != nil {
		return nil, nil, err
	}
	if len(row) == 0 {
		return nil, nil, errNoMenu("/ip/firewall/connection-tracking")
	}
	return connectionTrackingArgs(row), nil, nil
}

// --- ip.firewall.servicePort ---

func newMikrotikServicePort(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.ip.firewall.servicePort", map[string]*llx.RawData{
		"__id":     llx.StringData("mikrotik.ip.firewall.servicePort/" + row["name"]),
		"name":     llx.StringData(row["name"]),
		"ports":    llx.StringData(row["ports"]),
		"disabled": boolField(row, "disabled"),
		"invalid":  boolField(row, "invalid"),
	})
}

func (r *mqlMikrotik) servicePorts() ([]any, error) {
	rows, err := mikrotikConn(r.MqlRuntime).Print("/ip/firewall/service-port")
	if err != nil {
		return nil, err
	}
	return buildList(r.MqlRuntime, rows, newMikrotikServicePort)
}
