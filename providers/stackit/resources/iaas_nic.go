// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"

	iaas "github.com/stackitcloud/stackit-sdk-go/services/iaas/v2api"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ------------------------- network interfaces (NICs) -------------------------

// nics lists the network interfaces attached to a network.
func (r *mqlStackitNetwork) nics() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListNics(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	return buildNics(r.MqlRuntime, items)
}

// networkInterfaces lists the network interfaces attached to a server.
func (r *mqlStackitServer) networkInterfaces() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IaaS()
	if err != nil {
		return nil, err
	}
	resp, err := client.DefaultAPI.ListServerNICs(bgctx(), c.ProjectID(), c.Region(), r.Id.Data).Execute()
	if err != nil {
		if isAccessDenied(err) {
			return deniedList(err)
		}
		return nil, err
	}
	items, _ := resp.GetItemsOk()
	return buildNics(r.MqlRuntime, items)
}

func buildNics(runtime *plugin.Runtime, items []iaas.NIC) ([]any, error) {
	out := make([]any, 0, len(items))
	for i := range items {
		res, err := buildNic(runtime, &items[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func buildNic(runtime *plugin.Runtime, n *iaas.NIC) (plugin.Resource, error) {
	allowed := []string{}
	for _, a := range n.GetAllowedAddresses() {
		if a.String != nil {
			allowed = append(allowed, *a.String)
		}
	}
	args := map[string]*llx.RawData{
		"id":               llx.StringData(n.GetId()),
		"name":             llx.StringData(n.GetName()),
		"networkId":        llx.StringData(n.GetNetworkId()),
		"ipv4":             llx.StringData(n.GetIpv4()),
		"ipv6":             llx.StringData(n.GetIpv6()),
		"mac":              llx.StringData(n.GetMac()),
		"device":           llx.StringData(n.GetDevice()),
		"nicType":          llx.StringData(n.GetType()),
		"nicSecurity":      llx.BoolData(n.GetNicSecurity()),
		"securityGroupIds": strSliceData(n.GetSecurityGroups()),
		"allowedAddresses": strSliceData(allowed),
		"status":           llx.StringData(n.GetStatus()),
		"labels":           labelData(n.GetLabels()),
	}
	return CreateResource(runtime, "stackit.nic", args)
}

// id keys the NIC by its owning network and its own UUID. The GET endpoint
// requires both the network ID and the NIC ID, so both are part of the cache
// key to keep instances distinct and re-fetchable.
func (r *mqlStackitNic) id() (string, error) {
	return "stackit.nic/" + r.NetworkId.Data + "/" + r.Id.Data, nil
}

func (r *mqlStackitNic) network() (*mqlStackitNetwork, error) {
	if r.NetworkId.Data == "" {
		return markNull[mqlStackitNetwork](&r.Network)
	}
	res, err := NewResource(r.MqlRuntime, "stackit.network", map[string]*llx.RawData{
		"id": llx.StringData(r.NetworkId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitNetwork), nil
}

func (r *mqlStackitNic) securityGroups() ([]any, error) {
	out := make([]any, 0, len(r.SecurityGroupIds.Data))
	for _, raw := range r.SecurityGroupIds.Data {
		id, ok := raw.(string)
		if !ok || id == "" {
			continue
		}
		sg, err := NewResource(r.MqlRuntime, "stackit.securityGroup", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, sg)
	}
	return out, nil
}

// projectNICs returns the project's network interfaces from the connection's
// shared list, classifying a refused list call.
func projectNICs(runtime *plugin.Runtime) ([]iaas.NIC, error) {
	nics, err := conn(runtime).ProjectNICs(bgctx())
	if err != nil {
		if isAccessDenied(err) {
			return nil, refusal(err)
		}
		return nil, err
	}
	return nics, nil
}

// findNIC returns the interface with the given ID, or nil when the list holds
// none.
func findNIC(nics []iaas.NIC, id string) *iaas.NIC {
	if id == "" {
		return nil
	}
	for i := range nics {
		if nics[i].GetId() == id {
			return &nics[i]
		}
	}
	return nil
}

// nicsWithSecurityGroup returns the interfaces the security group is applied
// to.
func nicsWithSecurityGroup(nics []iaas.NIC, securityGroupID string) []*iaas.NIC {
	out := []*iaas.NIC{}
	if securityGroupID == "" {
		return out
	}
	for i := range nics {
		if slices.Contains(nics[i].GetSecurityGroups(), securityGroupID) {
			out = append(out, &nics[i])
		}
	}
	return out
}

// nicTypeServer is the interface type of a server's network interface. Only
// on such an interface does the device field name a server; a gateway or
// metadata port carries the ID of something else, or nothing.
const nicTypeServer = "server"

// nicServerID returns the ID of the server the interface belongs to, or ""
// when it is not a server interface.
func nicServerID(n *iaas.NIC) string {
	if n == nil || n.GetType() != nicTypeServer {
		return ""
	}
	return n.GetDevice()
}

// networkInterface resolves the interface the address is bound to against the
// project's interface list. The public IP record carries no network ID, which
// the single-interface lookup requires.
func (r *mqlStackitPublicIp) networkInterface() (*mqlStackitNic, error) {
	if r.NetworkInterfaceId.Data == "" {
		return markNull(&r.NetworkInterface)
	}
	nics, err := projectNICs(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	n := findNIC(nics, r.NetworkInterfaceId.Data)
	if n == nil {
		return markNull(&r.NetworkInterface)
	}
	res, err := buildNic(r.MqlRuntime, n)
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitNic), nil
}

// server resolves the server behind the interface the address is bound to,
// against the project's server list.
func (r *mqlStackitPublicIp) server() (*mqlStackitServer, error) {
	if r.NetworkInterfaceId.Data == "" {
		return markNull(&r.Server)
	}
	nics, err := projectNICs(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	serverID := nicServerID(findNIC(nics, r.NetworkInterfaceId.Data))
	if serverID == "" {
		return markNull(&r.Server)
	}
	root, err := CreateResource(r.MqlRuntime, "stackit", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	servers := root.(*mqlStackit).GetServers()
	if servers.Error != nil {
		return nil, servers.Error
	}
	for _, s := range servers.Data {
		if srv, ok := s.(*mqlStackitServer); ok && srv.Id.Data == serverID {
			return srv, nil
		}
	}
	return markNull(&r.Server)
}

// networkInterfaces lists the interfaces the group is applied to, read off the
// project's interface list.
func (r *mqlStackitSecurityGroup) networkInterfaces() ([]any, error) {
	nics, err := projectNICs(r.MqlRuntime)
	if err != nil {
		return nil, err
	}
	matched := nicsWithSecurityGroup(nics, r.Id.Data)
	out := make([]any, 0, len(matched))
	for _, n := range matched {
		res, err := buildNic(r.MqlRuntime, n)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// remoteSecurityGroup resolves the group a rule admits traffic from against
// the project's security group list. Null when the rule's remote is an IP
// range, or when the group is gone.
func (r *mqlStackitSecurityGroupRule) remoteSecurityGroup() (*mqlStackitSecurityGroup, error) {
	id := r.RemoteSecurityGroupId.Data
	if id == "" {
		return markNull(&r.RemoteSecurityGroup)
	}
	groups, err := conn(r.MqlRuntime).SecurityGroups(bgctx())
	if err != nil {
		if isAccessDenied(err) {
			return nil, refusal(err)
		}
		return nil, err
	}
	sg, ok := groups[id]
	if !ok {
		return markNull(&r.RemoteSecurityGroup)
	}
	res, err := buildSecurityGroup(r.MqlRuntime, &sg)
	if err != nil {
		return nil, err
	}
	return res.(*mqlStackitSecurityGroup), nil
}
