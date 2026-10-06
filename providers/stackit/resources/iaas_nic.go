// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
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
