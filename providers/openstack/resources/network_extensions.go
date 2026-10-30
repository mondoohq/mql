// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/qos/policies"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/subnetpools"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/trunks"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.subnetPool ----

type mqlOpenstackSubnetPoolInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackSubnetPool) addressScope() (*mqlOpenstackNetworkAddressScope, error) {
	if r.AddressScopeId.Data == "" {
		r.AddressScope.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.network.addressScope", map[string]*llx.RawData{
		"id": llx.StringData(r.AddressScopeId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackNetworkAddressScope), nil
}

func (r *mqlOpenstackSubnetPool) id() (string, error) {
	return "openstack.subnetPool/" + r.Id.Data, nil
}

func initOpenstackSubnetPool(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetSubnetPools()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		sp := raw.(*mqlOpenstackSubnetPool)
		if sp.Id.Data == id {
			return args, sp, nil
		}
	}
	initSyntheticID("openstack.subnetPool", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) subnetPools() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := subnetpools.List(client, subnetpools.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := subnetpools.ExtractSubnetPools(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		sp := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.subnetPool", map[string]*llx.RawData{
			"__id":             llx.StringData("openstack.subnetPool/" + sp.ID),
			"id":               llx.StringData(sp.ID),
			"name":             llx.StringData(sp.Name),
			"description":      llx.StringData(sp.Description),
			"prefixes":         stringSliceData(sp.Prefixes),
			"defaultPrefixLen": llx.IntData(int64(sp.DefaultPrefixLen)),
			"minPrefixLen":     llx.IntData(int64(sp.MinPrefixLen)),
			"maxPrefixLen":     llx.IntData(int64(sp.MaxPrefixLen)),
			"defaultQuota":     llx.IntData(int64(sp.DefaultQuota)),
			"addressScopeId":   llx.StringData(sp.AddressScopeID),
			"ipVersion":        llx.IntData(int64(sp.IPversion)),
			"shared":           llx.BoolData(sp.Shared),
			"isDefault":        llx.BoolData(sp.IsDefault),
			"tags":             stringSliceData(sp.Tags),
			"createdAt":        llx.TimeDataPtr(timePtr(sp.CreatedAt)),
			"updatedAt":        llx.TimeDataPtr(timePtr(sp.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlSp := res.(*mqlOpenstackSubnetPool)
		mqlSp.cacheProjectID = sp.ProjectID
		out = append(out, mqlSp)
	}
	return out, nil
}

func (r *mqlOpenstackSubnetPool) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

// ---- openstack.qosPolicy ----

type mqlOpenstackQosPolicyInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackQosPolicy) id() (string, error) {
	return "openstack.qosPolicy/" + r.Id.Data, nil
}

func initOpenstackQosPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetQosPolicies()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		q := raw.(*mqlOpenstackQosPolicy)
		if q.Id.Data == id {
			return args, q, nil
		}
	}
	initSyntheticID("openstack.qosPolicy", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) qosPolicies() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := policies.List(client, policies.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := policies.ExtractPolicies(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		p := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.qosPolicy", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.qosPolicy/" + p.ID),
			"id":          llx.StringData(p.ID),
			"name":        llx.StringData(p.Name),
			"description": llx.StringData(p.Description),
			"shared":      llx.BoolData(p.Shared),
			"isDefault":   llx.BoolData(p.IsDefault),
			"rules":       dictSliceData(qosRulesToDict(p.Rules)),
			"tags":        stringSliceData(p.Tags),
			"createdAt":   llx.TimeDataPtr(timePtr(p.CreatedAt)),
			"updatedAt":   llx.TimeDataPtr(timePtr(p.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlP := res.(*mqlOpenstackQosPolicy)
		mqlP.cacheProjectID = p.ProjectID
		out = append(out, mqlP)
	}
	return out, nil
}

func (r *mqlOpenstackQosPolicy) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func qosRulesToDict(in []map[string]any) []any {
	out := make([]any, 0, len(in))
	for _, rule := range in {
		out = append(out, rule)
	}
	return out
}

// ---- openstack.trunk ----

type mqlOpenstackTrunkInternal struct {
	cacheProjectID    string
	cacheParentPortID string
	cacheSubportPorts []string
}

func (r *mqlOpenstackTrunk) id() (string, error) {
	return "openstack.trunk/" + r.Id.Data, nil
}

func initOpenstackTrunk(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetTrunks()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		t := raw.(*mqlOpenstackTrunk)
		if t.Id.Data == id {
			return args, t, nil
		}
	}
	initSyntheticID("openstack.trunk", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) trunks() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := trunks.List(client, trunks.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := trunks.ExtractTrunks(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		t := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.trunk", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.trunk/" + t.ID),
			"id":           llx.StringData(t.ID),
			"name":         llx.StringData(t.Name),
			"description":  llx.StringData(t.Description),
			"adminStateUp": llx.BoolData(t.AdminStateUp),
			"status":       llx.StringData(t.Status),
			"subports":     dictSliceData(subportsToDict(t.Subports)),
			"tags":         stringSliceData(t.Tags),
			"createdAt":    llx.TimeDataPtr(timePtr(t.CreatedAt)),
			"updatedAt":    llx.TimeDataPtr(timePtr(t.UpdatedAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlT := res.(*mqlOpenstackTrunk)
		mqlT.cacheProjectID = t.ProjectID
		mqlT.cacheParentPortID = t.PortID
		mqlT.cacheSubportPorts = subportPortIDs(t.Subports)
		out = append(out, mqlT)
	}
	return out, nil
}

func (r *mqlOpenstackTrunk) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackTrunk) parentPort() (*mqlOpenstackPort, error) {
	if r.cacheParentPortID == "" {
		r.ParentPort.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.port", map[string]*llx.RawData{"id": llx.StringData(r.cacheParentPortID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackPort), nil
}

func (r *mqlOpenstackTrunk) subportPorts() ([]any, error) {
	out := make([]any, 0, len(r.cacheSubportPorts))
	for _, id := range r.cacheSubportPorts {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.port", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func subportsToDict(in []trunks.Subport) []any {
	out := make([]any, 0, len(in))
	for _, sp := range in {
		out = append(out, map[string]any{
			"port_id":           sp.PortID,
			"segmentation_type": sp.SegmentationType,
			"segmentation_id":   sp.SegmentationID,
		})
	}
	return out
}

func subportPortIDs(in []trunks.Subport) []string {
	out := make([]string, 0, len(in))
	for _, sp := range in {
		if sp.PortID != "" {
			out = append(out, sp.PortID)
		}
	}
	return out
}
