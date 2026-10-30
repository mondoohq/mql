// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/vpnaas/endpointgroups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/vpnaas/ikepolicies"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/vpnaas/ipsecpolicies"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/vpnaas/services"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/vpnaas/siteconnections"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.vpn.service ----

type mqlOpenstackVpnServiceInternal struct {
	cacheProjectID string
	cacheSubnetID  string
	cacheRouterID  string
}

func (r *mqlOpenstackVpnService) id() (string, error) {
	return "openstack.vpn.service/" + r.Id.Data, nil
}

func initOpenstackVpnService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetVpnServices()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackVpnService)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.vpn.service", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) vpnServices() ([]any, error) {
	client, err := conn(o.MqlRuntime).NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := services.List(client, services.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := services.ExtractServices(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		s := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.vpn.service", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.vpn.service/" + s.ID),
			"id":           llx.StringData(s.ID),
			"name":         llx.StringData(s.Name),
			"description":  llx.StringData(s.Description),
			"status":       llx.StringData(s.Status),
			"adminStateUp": llx.BoolData(s.AdminStateUp),
			"externalV4Ip": llx.StringData(s.ExternalV4IP),
			"externalV6Ip": llx.StringData(s.ExternalV6IP),
			"flavorId":     llx.StringData(s.FlavorID),
		})
		if err != nil {
			return nil, err
		}
		mqlS := res.(*mqlOpenstackVpnService)
		mqlS.cacheProjectID = s.ProjectID
		mqlS.cacheSubnetID = s.SubnetID
		mqlS.cacheRouterID = s.RouterID
		out = append(out, mqlS)
	}
	return out, nil
}

func (r *mqlOpenstackVpnService) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackVpnService) subnet() (*mqlOpenstackSubnet, error) {
	if r.cacheSubnetID == "" {
		r.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.subnet", map[string]*llx.RawData{"id": llx.StringData(r.cacheSubnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackSubnet), nil
}

func (r *mqlOpenstackVpnService) router() (*mqlOpenstackRouter, error) {
	if r.cacheRouterID == "" {
		r.Router.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.router", map[string]*llx.RawData{"id": llx.StringData(r.cacheRouterID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackRouter), nil
}

// ---- openstack.vpn.ikePolicy ----

type mqlOpenstackVpnIkePolicyInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackVpnIkePolicy) id() (string, error) {
	return "openstack.vpn.ikePolicy/" + r.Id.Data, nil
}

func initOpenstackVpnIkePolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetVpnIkePolicies()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		p := raw.(*mqlOpenstackVpnIkePolicy)
		if p.Id.Data == id {
			return args, p, nil
		}
	}
	initSyntheticID("openstack.vpn.ikePolicy", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) vpnIkePolicies() ([]any, error) {
	client, err := conn(o.MqlRuntime).NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := ikepolicies.List(client, ikepolicies.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := ikepolicies.ExtractPolicies(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		p := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.vpn.ikePolicy", map[string]*llx.RawData{
			"__id":                  llx.StringData("openstack.vpn.ikePolicy/" + p.ID),
			"id":                    llx.StringData(p.ID),
			"name":                  llx.StringData(p.Name),
			"description":           llx.StringData(p.Description),
			"authAlgorithm":         llx.StringData(p.AuthAlgorithm),
			"encryptionAlgorithm":   llx.StringData(p.EncryptionAlgorithm),
			"pfs":                   llx.StringData(p.PFS),
			"phase1NegotiationMode": llx.StringData(p.Phase1NegotiationMode),
			"ikeVersion":            llx.StringData(p.IKEVersion),
			"lifetimeUnits":         llx.StringData(p.Lifetime.Units),
			"lifetimeValue":         llx.IntData(int64(p.Lifetime.Value)),
		})
		if err != nil {
			return nil, err
		}
		mqlP := res.(*mqlOpenstackVpnIkePolicy)
		mqlP.cacheProjectID = p.ProjectID
		out = append(out, mqlP)
	}
	return out, nil
}

func (r *mqlOpenstackVpnIkePolicy) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

// ---- openstack.vpn.ipsecPolicy ----

type mqlOpenstackVpnIpsecPolicyInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackVpnIpsecPolicy) id() (string, error) {
	return "openstack.vpn.ipsecPolicy/" + r.Id.Data, nil
}

func initOpenstackVpnIpsecPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetVpnIpsecPolicies()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		p := raw.(*mqlOpenstackVpnIpsecPolicy)
		if p.Id.Data == id {
			return args, p, nil
		}
	}
	initSyntheticID("openstack.vpn.ipsecPolicy", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) vpnIpsecPolicies() ([]any, error) {
	client, err := conn(o.MqlRuntime).NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := ipsecpolicies.List(client, ipsecpolicies.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := ipsecpolicies.ExtractPolicies(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		p := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.vpn.ipsecPolicy", map[string]*llx.RawData{
			"__id":                llx.StringData("openstack.vpn.ipsecPolicy/" + p.ID),
			"id":                  llx.StringData(p.ID),
			"name":                llx.StringData(p.Name),
			"description":         llx.StringData(p.Description),
			"authAlgorithm":       llx.StringData(p.AuthAlgorithm),
			"encryptionAlgorithm": llx.StringData(p.EncryptionAlgorithm),
			"pfs":                 llx.StringData(p.PFS),
			"encapsulationMode":   llx.StringData(p.EncapsulationMode),
			"transformProtocol":   llx.StringData(p.TransformProtocol),
			"lifetimeUnits":       llx.StringData(p.Lifetime.Units),
			"lifetimeValue":       llx.IntData(int64(p.Lifetime.Value)),
		})
		if err != nil {
			return nil, err
		}
		mqlP := res.(*mqlOpenstackVpnIpsecPolicy)
		mqlP.cacheProjectID = p.ProjectID
		out = append(out, mqlP)
	}
	return out, nil
}

func (r *mqlOpenstackVpnIpsecPolicy) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

// ---- openstack.vpn.endpointGroup ----

type mqlOpenstackVpnEndpointGroupInternal struct {
	cacheProjectID string
}

func (r *mqlOpenstackVpnEndpointGroup) id() (string, error) {
	return "openstack.vpn.endpointGroup/" + r.Id.Data, nil
}

func initOpenstackVpnEndpointGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetVpnEndpointGroups()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		g := raw.(*mqlOpenstackVpnEndpointGroup)
		if g.Id.Data == id {
			return args, g, nil
		}
	}
	initSyntheticID("openstack.vpn.endpointGroup", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) vpnEndpointGroups() ([]any, error) {
	client, err := conn(o.MqlRuntime).NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := endpointgroups.List(client, endpointgroups.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := endpointgroups.ExtractEndpointGroups(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		g := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.vpn.endpointGroup", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.vpn.endpointGroup/" + g.ID),
			"id":          llx.StringData(g.ID),
			"name":        llx.StringData(g.Name),
			"description": llx.StringData(g.Description),
			"type":        llx.StringData(g.Type),
			"endpoints":   stringSliceData(g.Endpoints),
		})
		if err != nil {
			return nil, err
		}
		mqlG := res.(*mqlOpenstackVpnEndpointGroup)
		mqlG.cacheProjectID = g.ProjectID
		out = append(out, mqlG)
	}
	return out, nil
}

func (r *mqlOpenstackVpnEndpointGroup) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

// ---- openstack.vpn.siteConnection ----

type mqlOpenstackVpnSiteConnectionInternal struct {
	cacheProjectID      string
	cacheServiceID      string
	cacheIkePolicyID    string
	cacheIpsecPolicyID  string
	cacheLocalEpGroupID string
	cachePeerEpGroupID  string
}

func (r *mqlOpenstackVpnSiteConnection) id() (string, error) {
	return "openstack.vpn.siteConnection/" + r.Id.Data, nil
}

func initOpenstackVpnSiteConnection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetVpnSiteConnections()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		c := raw.(*mqlOpenstackVpnSiteConnection)
		if c.Id.Data == id {
			return args, c, nil
		}
	}
	initSyntheticID("openstack.vpn.siteConnection", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) vpnSiteConnections() ([]any, error) {
	client, err := conn(o.MqlRuntime).NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := siteconnections.List(client, siteconnections.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := siteconnections.ExtractConnections(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		c := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.vpn.siteConnection", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.vpn.siteConnection/" + c.ID),
			"id":           llx.StringData(c.ID),
			"name":         llx.StringData(c.Name),
			"description":  llx.StringData(c.Description),
			"status":       llx.StringData(c.Status),
			"adminStateUp": llx.BoolData(c.AdminStateUp),
			"peerAddress":  llx.StringData(c.PeerAddress),
			"peerId":       llx.StringData(c.PeerID),
			"localId":      llx.StringData(c.LocalID),
			"peerCidrs":    stringSliceData(c.PeerCIDRs),
			"routeMode":    llx.StringData(c.RouteMode),
			"initiator":    llx.StringData(c.Initiator),
			"authMode":     llx.StringData(c.AuthMode),
			"mtu":          llx.IntData(int64(c.MTU)),
			"dpdAction":    llx.StringData(c.DPD.Action),
			"dpdTimeout":   llx.IntData(int64(c.DPD.Timeout)),
			"dpdInterval":  llx.IntData(int64(c.DPD.Interval)),
		})
		if err != nil {
			return nil, err
		}
		mqlC := res.(*mqlOpenstackVpnSiteConnection)
		mqlC.cacheProjectID = c.ProjectID
		mqlC.cacheServiceID = c.VPNServiceID
		mqlC.cacheIkePolicyID = c.IKEPolicyID
		mqlC.cacheIpsecPolicyID = c.IPSecPolicyID
		mqlC.cacheLocalEpGroupID = c.LocalEPGroupID
		mqlC.cachePeerEpGroupID = c.PeerEPGroupID
		out = append(out, mqlC)
	}
	return out, nil
}

func (r *mqlOpenstackVpnSiteConnection) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackVpnSiteConnection) service() (*mqlOpenstackVpnService, error) {
	if r.cacheServiceID == "" {
		r.Service.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.vpn.service", map[string]*llx.RawData{"id": llx.StringData(r.cacheServiceID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackVpnService), nil
}

func (r *mqlOpenstackVpnSiteConnection) ikePolicy() (*mqlOpenstackVpnIkePolicy, error) {
	if r.cacheIkePolicyID == "" {
		r.IkePolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.vpn.ikePolicy", map[string]*llx.RawData{"id": llx.StringData(r.cacheIkePolicyID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackVpnIkePolicy), nil
}

func (r *mqlOpenstackVpnSiteConnection) ipsecPolicy() (*mqlOpenstackVpnIpsecPolicy, error) {
	if r.cacheIpsecPolicyID == "" {
		r.IpsecPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.vpn.ipsecPolicy", map[string]*llx.RawData{"id": llx.StringData(r.cacheIpsecPolicyID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackVpnIpsecPolicy), nil
}

func (r *mqlOpenstackVpnSiteConnection) localEndpointGroup() (*mqlOpenstackVpnEndpointGroup, error) {
	if r.cacheLocalEpGroupID == "" {
		r.LocalEndpointGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.vpn.endpointGroup", map[string]*llx.RawData{"id": llx.StringData(r.cacheLocalEpGroupID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackVpnEndpointGroup), nil
}

func (r *mqlOpenstackVpnSiteConnection) peerEndpointGroup() (*mqlOpenstackVpnEndpointGroup, error) {
	if r.cachePeerEpGroupID == "" {
		r.PeerEndpointGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.vpn.endpointGroup", map[string]*llx.RawData{"id": llx.StringData(r.cachePeerEpGroupID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackVpnEndpointGroup), nil
}
