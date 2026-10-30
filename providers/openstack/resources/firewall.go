// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/fwaas_v2/groups"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/fwaas_v2/policies"
	"github.com/gophercloud/gophercloud/v2/openstack/networking/v2/extensions/fwaas_v2/rules"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- openstack.firewall.group ----

type mqlOpenstackFirewallGroupInternal struct {
	cacheProjectID       string
	cachePortIDs         []string
	cacheIngressPolicyID string
	cacheEgressPolicyID  string
}

func (r *mqlOpenstackFirewallGroup) id() (string, error) {
	return "openstack.firewall.group/" + r.Id.Data, nil
}

func initOpenstackFirewallGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetFirewallGroups()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		g := raw.(*mqlOpenstackFirewallGroup)
		if g.Id.Data == id {
			return args, g, nil
		}
	}
	initSyntheticID("openstack.firewall.group", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) firewallGroups() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := groups.List(client, groups.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := groups.ExtractGroups(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		g := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.firewall.group", map[string]*llx.RawData{
			"__id":         llx.StringData("openstack.firewall.group/" + g.ID),
			"id":           llx.StringData(g.ID),
			"name":         llx.StringData(g.Name),
			"description":  llx.StringData(g.Description),
			"adminStateUp": llx.BoolData(g.AdminStateUp),
			"status":       llx.StringData(g.Status),
			"shared":       llx.BoolData(g.Shared),
		})
		if err != nil {
			return nil, err
		}
		mqlG := res.(*mqlOpenstackFirewallGroup)
		mqlG.cacheProjectID = g.ProjectID
		mqlG.cachePortIDs = g.Ports
		mqlG.cacheIngressPolicyID = g.IngressFirewallPolicyID
		mqlG.cacheEgressPolicyID = g.EgressFirewallPolicyID
		out = append(out, mqlG)
	}
	return out, nil
}

func (r *mqlOpenstackFirewallGroup) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackFirewallGroup) ports() ([]any, error) {
	out := make([]any, 0, len(r.cachePortIDs))
	for _, id := range r.cachePortIDs {
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

func (r *mqlOpenstackFirewallGroup) ingressPolicy() (*mqlOpenstackFirewallPolicy, error) {
	return resolveFirewallPolicy(r.MqlRuntime, r.cacheIngressPolicyID, &r.IngressPolicy)
}

func (r *mqlOpenstackFirewallGroup) egressPolicy() (*mqlOpenstackFirewallPolicy, error) {
	return resolveFirewallPolicy(r.MqlRuntime, r.cacheEgressPolicyID, &r.EgressPolicy)
}

func resolveFirewallPolicy(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOpenstackFirewallPolicy]) (*mqlOpenstackFirewallPolicy, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.firewall.policy", map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackFirewallPolicy), nil
}

// ---- openstack.firewall.policy ----

type mqlOpenstackFirewallPolicyInternal struct {
	cacheProjectID string
	cacheRuleIDs   []string
}

func (r *mqlOpenstackFirewallPolicy) id() (string, error) {
	return "openstack.firewall.policy/" + r.Id.Data, nil
}

func initOpenstackFirewallPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetFirewallPolicies()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		p := raw.(*mqlOpenstackFirewallPolicy)
		if p.Id.Data == id {
			return args, p, nil
		}
	}
	initSyntheticID("openstack.firewall.policy", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) firewallPolicies() ([]any, error) {
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
		res, err := CreateResource(o.MqlRuntime, "openstack.firewall.policy", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.firewall.policy/" + p.ID),
			"id":          llx.StringData(p.ID),
			"name":        llx.StringData(p.Name),
			"description": llx.StringData(p.Description),
			"audited":     llx.BoolData(p.Audited),
			"shared":      llx.BoolData(p.Shared),
		})
		if err != nil {
			return nil, err
		}
		mqlP := res.(*mqlOpenstackFirewallPolicy)
		mqlP.cacheProjectID = p.ProjectID
		mqlP.cacheRuleIDs = p.Rules
		out = append(out, mqlP)
	}
	return out, nil
}

func (r *mqlOpenstackFirewallPolicy) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackFirewallPolicy) rules() ([]any, error) {
	if len(r.cacheRuleIDs) == 0 {
		return []any{}, nil
	}

	// Index the global rule list once. Without the index, each rule ID
	// triggers a NewResource + init function that linearly scans the
	// full rules list, producing O(N*M) per policy. The index folds that
	// to O(N+M) total when openstack.firewallRules has been resolved.
	root, err := CreateResource(r.MqlRuntime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	list := root.(*mqlOpenstack).GetFirewallRules()
	var byID map[string]*mqlOpenstackFirewallRule
	if list.Error == nil {
		byID = make(map[string]*mqlOpenstackFirewallRule, len(list.Data))
		for _, raw := range list.Data {
			fr := raw.(*mqlOpenstackFirewallRule)
			byID[fr.Id.Data] = fr
		}
	}

	out := make([]any, 0, len(r.cacheRuleIDs))
	for _, id := range r.cacheRuleIDs {
		if id == "" {
			continue
		}
		if fr, ok := byID[id]; ok {
			out = append(out, fr)
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.firewall.rule", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.firewall.rule ----

type mqlOpenstackFirewallRuleInternal struct {
	cacheProjectID string
	cachePolicyIDs []string
}

func (r *mqlOpenstackFirewallRule) id() (string, error) {
	return "openstack.firewall.rule/" + r.Id.Data, nil
}

func initOpenstackFirewallRule(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetFirewallRules()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		r := raw.(*mqlOpenstackFirewallRule)
		if r.Id.Data == id {
			return args, r, nil
		}
	}
	initSyntheticID("openstack.firewall.rule", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) firewallRules() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.NetworkClient()
	if err != nil {
		return nil, err
	}
	pages, err := rules.List(client, rules.ListOpts{}).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := rules.ExtractRules(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for i := range items {
		fr := &items[i]
		res, err := CreateResource(o.MqlRuntime, "openstack.firewall.rule", map[string]*llx.RawData{
			"__id":                 llx.StringData("openstack.firewall.rule/" + fr.ID),
			"id":                   llx.StringData(fr.ID),
			"name":                 llx.StringData(fr.Name),
			"description":          llx.StringData(fr.Description),
			"protocol":             llx.StringData(fr.Protocol),
			"action":               llx.StringData(fr.Action),
			"ipVersion":            llx.IntData(int64(fr.IPVersion)),
			"sourceIpAddress":      llx.StringData(fr.SourceIPAddress),
			"destinationIpAddress": llx.StringData(fr.DestinationIPAddress),
			"sourcePort":           llx.StringData(fr.SourcePort),
			"destinationPort":      llx.StringData(fr.DestinationPort),
			"shared":               llx.BoolData(fr.Shared),
			"enabled":              llx.BoolData(fr.Enabled),
		})
		if err != nil {
			return nil, err
		}
		mqlR := res.(*mqlOpenstackFirewallRule)
		mqlR.cacheProjectID = fr.ProjectID
		mqlR.cachePolicyIDs = fr.FirewallPolicyID
		out = append(out, mqlR)
	}
	return out, nil
}

func (r *mqlOpenstackFirewallRule) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackFirewallRule) policies() ([]any, error) {
	out := make([]any, 0, len(r.cachePolicyIDs))
	for _, id := range r.cachePolicyIDs {
		if id == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "openstack.firewall.policy", map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
