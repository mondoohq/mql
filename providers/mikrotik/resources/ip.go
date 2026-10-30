// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- ip.address ---

type mqlMikrotikIpAddressInternal struct {
	cacheInterface string
}

func newMikrotikIpAddress(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	id := row[".id"]
	if id == "" {
		id = row["address"] + "/" + row["interface"]
	}
	res, err := CreateResource(runtime, "mikrotik.ip.address", map[string]*llx.RawData{
		"__id":            llx.StringData("mikrotik.ip.address/" + id),
		"address":         llx.StringData(row["address"]),
		"network":         llx.StringData(row["network"]),
		"actualInterface": llx.StringData(row["actual-interface"]),
		"disabled":        boolField(row, "disabled"),
		"dynamic":         boolField(row, "dynamic"),
		"invalid":         boolField(row, "invalid"),
		"comment":         llx.StringData(row["comment"]),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikIpAddress).cacheInterface = row["interface"]
	return res, nil
}

func (r *mqlMikrotikIpAddress) compute_interface() (*mqlMikrotikInterface, error) {
	if r.cacheInterface == "" {
		r.Interface.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return interfaceByName(r.MqlRuntime, r.cacheInterface)
}

// --- ipv6.address ---

type mqlMikrotikIpv6AddressInternal struct {
	cacheInterface string
}

func newMikrotikIpv6Address(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	id := row[".id"]
	if id == "" {
		id = row["address"] + "/" + row["interface"]
	}
	res, err := CreateResource(runtime, "mikrotik.ipv6.address", map[string]*llx.RawData{
		"__id":            llx.StringData("mikrotik.ipv6.address/" + id),
		"address":         llx.StringData(row["address"]),
		"fromPool":        llx.StringData(row["from-pool"]),
		"actualInterface": llx.StringData(row["actual-interface"]),
		"advertise":       boolField(row, "advertise"),
		"eui64":           boolField(row, "eui-64"),
		"noDad":           boolField(row, "no-dad"),
		"linkLocal":       boolField(row, "link-local"),
		"disabled":        boolField(row, "disabled"),
		"dynamic":         boolField(row, "dynamic"),
		"invalid":         boolField(row, "invalid"),
		"comment":         llx.StringData(row["comment"]),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikIpv6Address).cacheInterface = row["interface"]
	return res, nil
}

func (r *mqlMikrotikIpv6Address) compute_interface() (*mqlMikrotikInterface, error) {
	if r.cacheInterface == "" {
		r.Interface.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return interfaceByName(r.MqlRuntime, r.cacheInterface)
}

// --- ip.route ---

func newMikrotikRoute(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	id := row[".id"]
	if id == "" {
		id = row["dst-address"] + "/" + row["gateway"]
	}
	return CreateResource(runtime, "mikrotik.ip.route", map[string]*llx.RawData{
		"__id":         llx.StringData("mikrotik.ip.route/" + id),
		"dstAddress":   llx.StringData(row["dst-address"]),
		"gateway":      llx.StringData(row["gateway"]),
		"immediateGw":  llx.StringData(row["immediate-gw"]),
		"distance":     intField(row, "distance"),
		"scope":        intField(row, "scope"),
		"targetScope":  intField(row, "target-scope"),
		"routingTable": llx.StringData(row["routing-table"]),
		"prefSrc":      llx.StringData(row["pref-src"]),
		"vrfInterface": llx.StringData(row["vrf-interface"]),
		"blackhole":    boolField(row, "blackhole"),
		"active":       boolField(row, "active"),
		"dynamic":      boolField(row, "dynamic"),
		"static":       boolField(row, "static"),
		"connect":      boolField(row, "connect"),
		"ecmp":         boolField(row, "ecmp"),
		"disabled":     boolField(row, "disabled"),
		"comment":      llx.StringData(row["comment"]),
	})
}

// --- ip.pool ---

func poolArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":     llx.StringData("mikrotik.ip.pool/" + row["name"]),
		"name":     llx.StringData(row["name"]),
		"ranges":   listField(row, "ranges"),
		"nextPool": llx.StringData(row["next-pool"]),
	}
}

func newMikrotikIpPool(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.ip.pool", poolArgs(row))
}

func initMikrotikIpPool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 || args["name"] == nil {
		return args, nil, nil
	}
	name, ok := args["name"].Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}
	rows, err := mikrotikConn(runtime).Print("/ip/pool")
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if row["name"] == name {
			return poolArgs(row), nil, nil
		}
	}
	// The listing completed and named no such pool. Falling through would build
	// a resource carrying only the name, leaving every other field unset, so a
	// query would read empty data rather than an error.
	return nil, nil, fmt.Errorf("mikrotik.ip.pool %q not found", name)
}

// --- ip.service ---

func newMikrotikService(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.ip.service", map[string]*llx.RawData{
		"__id":        llx.StringData("mikrotik.ip.service/" + row["name"]),
		"name":        llx.StringData(row["name"]),
		"port":        intField(row, "port"),
		"address":     llx.StringData(row["address"]),
		"certificate": llx.StringData(row["certificate"]),
		"tlsVersion":  llx.StringData(row["tls-version"]),
		"vrf":         llx.StringData(row["vrf"]),
		"maxSessions": intField(row, "max-sessions"),
		"disabled":    boolField(row, "disabled"),
		"invalid":     boolField(row, "invalid"),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikIpService).cacheCertificate = certificateRefName(row["certificate"])
	return res, nil
}

// --- ip.firewall.filter ---

func newMikrotikFirewallFilter(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	args := firewallRuleArgs("mikrotik.ip.firewall.filter/", row)
	args["connectionState"] = llx.StringData(row["connection-state"])
	return CreateResource(runtime, "mikrotik.ip.firewall.filter", args)
}

// --- ip.firewall.nat ---

func newMikrotikFirewallNat(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	args := firewallRuleArgs("mikrotik.ip.firewall.nat/", row)
	args["toAddresses"] = llx.StringData(row["to-addresses"])
	args["toPorts"] = llx.StringData(row["to-ports"])
	return CreateResource(runtime, "mikrotik.ip.firewall.nat", args)
}

// --- ip.dhcp.server ---

type mqlMikrotikIpDhcpServerInternal struct {
	cacheInterface   string
	cacheAddressPool string
}

func newMikrotikDhcpServer(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.ip.dhcp.server", map[string]*llx.RawData{
		"__id":          llx.StringData("mikrotik.ip.dhcp.server/" + row["name"]),
		"name":          llx.StringData(row["name"]),
		"leaseTime":     llx.StringData(row["lease-time"]),
		"authoritative": llx.StringData(row["authoritative"]),
		"addArp":        boolField(row, "add-arp"),
		"dynamic":       boolField(row, "dynamic"),
		"disabled":      boolField(row, "disabled"),
		"invalid":       boolField(row, "invalid"),
		"comment":       llx.StringData(row["comment"]),
	})
	if err != nil {
		return nil, err
	}
	srv := res.(*mqlMikrotikIpDhcpServer)
	srv.cacheInterface = row["interface"]
	srv.cacheAddressPool = row["address-pool"]
	return res, nil
}

func initMikrotikIpDhcpServer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 || args["name"] == nil {
		return args, nil, nil
	}
	name, ok := args["name"].Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}
	rows, err := mikrotikConn(runtime).Print("/ip/dhcp-server")
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if row["name"] == name {
			res, err := newMikrotikDhcpServer(runtime, row)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("mikrotik.ip.dhcp.server %q not found", name)
}

func (r *mqlMikrotikIpDhcpServer) compute_interface() (*mqlMikrotikInterface, error) {
	if r.cacheInterface == "" {
		r.Interface.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return interfaceByName(r.MqlRuntime, r.cacheInterface)
}

func (r *mqlMikrotikIpDhcpServer) addressPool() (*mqlMikrotikIpPool, error) {
	if r.cacheAddressPool == "" || r.cacheAddressPool == "static-only" {
		r.AddressPool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "mikrotik.ip.pool", map[string]*llx.RawData{
		"name": llx.StringData(r.cacheAddressPool),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikIpPool), nil
}

func (r *mqlMikrotikIpDhcpServer) leases() ([]any, error) {
	conn := mikrotikConn(r.MqlRuntime)
	rows, err := conn.Print("/ip/dhcp-server/lease")
	if err != nil {
		return nil, err
	}
	name := r.Name.Data
	res := []any{}
	for _, row := range rows {
		if row["server"] != name {
			continue
		}
		lease, err := newMikrotikDhcpLease(r.MqlRuntime, row)
		if err != nil {
			return nil, err
		}
		res = append(res, lease)
	}
	return res, nil
}

// --- ip.dhcp.lease ---

type mqlMikrotikIpDhcpLeaseInternal struct {
	cacheServer string
}

func newMikrotikDhcpLease(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	id := row[".id"]
	if id == "" {
		id = row["address"] + "/" + row["mac-address"]
	}
	res, err := CreateResource(runtime, "mikrotik.ip.dhcp.lease", map[string]*llx.RawData{
		"__id":             llx.StringData("mikrotik.ip.dhcp.lease/" + id),
		"address":          llx.StringData(row["address"]),
		"macAddress":       llx.StringData(row["mac-address"]),
		"clientId":         llx.StringData(row["client-id"]),
		"hostName":         llx.StringData(row["host-name"]),
		"status":           llx.StringData(row["status"]),
		"expiresAfter":     llx.StringData(row["expires-after"]),
		"lastSeen":         llx.StringData(row["last-seen"]),
		"activeAddress":    llx.StringData(row["active-address"]),
		"activeMacAddress": llx.StringData(row["active-mac-address"]),
		"dynamic":          boolField(row, "dynamic"),
		"blocked":          boolField(row, "blocked"),
		"disabled":         boolField(row, "disabled"),
		"comment":          llx.StringData(row["comment"]),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikIpDhcpLease).cacheServer = row["server"]
	return res, nil
}

func (r *mqlMikrotikIpDhcpLease) server() (*mqlMikrotikIpDhcpServer, error) {
	if r.cacheServer == "" {
		r.Server.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "mikrotik.ip.dhcp.server", map[string]*llx.RawData{
		"name": llx.StringData(r.cacheServer),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikIpDhcpServer), nil
}

// --- ip.neighbor ---

type mqlMikrotikIpNeighborInternal struct {
	cacheInterface string
}

func newMikrotikNeighbor(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	id := row[".id"]
	if id == "" {
		id = row["mac-address"] + "/" + row["interface"]
	}
	res, err := CreateResource(runtime, "mikrotik.ip.neighbor", map[string]*llx.RawData{
		"__id":       llx.StringData("mikrotik.ip.neighbor/" + id),
		"address":    llx.StringData(row["address"]),
		"address4":   llx.StringData(row["address4"]),
		"address6":   llx.StringData(row["address6"]),
		"macAddress": llx.StringData(row["mac-address"]),
		"identity":   llx.StringData(row["identity"]),
		"platform":   llx.StringData(row["platform"]),
		"version":    llx.StringData(row["version"]),
		"board":      llx.StringData(row["board"]),
	})
	if err != nil {
		return nil, err
	}
	// RouterOS reports the local interface as either "interface" or
	// "interface-name" depending on version
	iface := row["interface"]
	if iface == "" {
		iface = row["interface-name"]
	}
	res.(*mqlMikrotikIpNeighbor).cacheInterface = iface
	return res, nil
}

func (r *mqlMikrotikIpNeighbor) compute_interface() (*mqlMikrotikInterface, error) {
	if r.cacheInterface == "" {
		r.Interface.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return interfaceByName(r.MqlRuntime, r.cacheInterface)
}

// --- user ---

type mqlMikrotikUserInternal struct {
	cacheGroup string
}

func newMikrotikUser(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "mikrotik.user", map[string]*llx.RawData{
		"__id":         llx.StringData("mikrotik.user/" + row["name"]),
		"name":         llx.StringData(row["name"]),
		"group":        llx.StringData(row["group"]),
		"address":      llx.StringData(row["address"]),
		"lastLoggedIn": llx.StringData(row["last-logged-in"]),
		"disabled":     boolField(row, "disabled"),
		"comment":      llx.StringData(row["comment"]),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlMikrotikUser).cacheGroup = row["group"]
	return res, nil
}

func (r *mqlMikrotikUser) userGroup() (*mqlMikrotikUserGroup, error) {
	if r.cacheGroup == "" {
		r.UserGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "mikrotik.userGroup", map[string]*llx.RawData{
		"name": llx.StringData(r.cacheGroup),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMikrotikUserGroup), nil
}

// --- user.group ---

func userGroupArgs(row map[string]string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":    llx.StringData("mikrotik.userGroup/" + row["name"]),
		"name":    llx.StringData(row["name"]),
		"policy":  listField(row, "policy"),
		"skin":    llx.StringData(row["skin"]),
		"comment": llx.StringData(row["comment"]),
	}
}

func newMikrotikUserGroup(runtime *plugin.Runtime, row map[string]string) (plugin.Resource, error) {
	return CreateResource(runtime, "mikrotik.userGroup", userGroupArgs(row))
}

func initMikrotikUserGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 || args["name"] == nil {
		return args, nil, nil
	}
	name, ok := args["name"].Value.(string)
	if !ok || name == "" {
		return args, nil, nil
	}
	rows, err := mikrotikConn(runtime).Print("/user/group")
	if err != nil {
		return nil, nil, err
	}
	for _, row := range rows {
		if row["name"] == name {
			return userGroupArgs(row), nil, nil
		}
	}
	return nil, nil, fmt.Errorf("mikrotik.userGroup %q not found", name)
}
