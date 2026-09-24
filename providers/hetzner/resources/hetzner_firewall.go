// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"github.com/hetznercloud/hcloud-go/v2/hcloud"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/hetzner/connection"
)

type mqlHetznerFirewallInternal struct {
	cacheServerIDs []int64
	// cacheLabelSelectorServerIDs holds the servers the firewall's
	// label_selector bindings currently resolve to (from each binding's
	// AppliedToResources), so labelSelectorTargets() can surface the
	// effective blast radius without a refetch.
	cacheLabelSelectorServerIDs []int64
}

func (r *mqlHetznerFirewall) id() (string, error) {
	return fmt.Sprintf("hetzner.firewall/%d", r.Id.Data), nil
}

func (h *mqlHetzner) firewalls() ([]any, error) {
	c := conn(h.MqlRuntime)
	items, err := paginate(func(opts hcloud.ListOpts) ([]*hcloud.Firewall, *hcloud.Response, error) {
		return c.Client().Firewall.List(ctx(), hcloud.FirewallListOpts{ListOpts: opts})
	})
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(items))
	for _, fw := range items {
		res, err := newMqlHetznerFirewall(h.MqlRuntime, fw)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// firewallRuleDicts renders a firewall's rules as the dicts the rules field
// carries.
//
// Every value has to be JSON-native, because the dict-to-primitive converter
// accepts only bool/int64/float64/string/[]any/map. The port and description
// are *string in the SDK and are dereferenced only when set, so an absent one
// stays out of the dict rather than becoming an empty string that reads as a
// configured value.
//
// These dicts feed firewallRuleOpenToInternet and through it the exposure
// verdict, so a serialization failure here would take the reachability answer
// with it.
func firewallRuleDicts(rules []hcloud.FirewallRule) []any {
	out := make([]any, 0, len(rules))
	for _, r := range rules {
		srcs := make([]any, 0, len(r.SourceIPs))
		for _, ip := range r.SourceIPs {
			srcs = append(srcs, ip.String())
		}
		dsts := make([]any, 0, len(r.DestinationIPs))
		for _, ip := range r.DestinationIPs {
			dsts = append(dsts, ip.String())
		}
		entry := map[string]any{
			"direction":      string(r.Direction),
			"protocol":       string(r.Protocol),
			"sourceIps":      srcs,
			"destinationIps": dsts,
		}
		if r.Port != nil {
			entry["port"] = *r.Port
		}
		if r.Description != nil {
			entry["description"] = *r.Description
		}
		out = append(out, entry)
	}
	return out
}

func newMqlHetznerFirewall(runtime *plugin.Runtime, fw *hcloud.Firewall) (*mqlHetznerFirewall, error) {
	rules := firewallRuleDicts(fw.Rules)

	var serverIDs []int64
	var labelSelectors []string
	var labelSelectorServerIDs []int64
	seenLabelServer := map[int64]struct{}{}
	for _, a := range fw.AppliedTo {
		if a.Server != nil {
			serverIDs = append(serverIDs, a.Server.ID)
		}
		if a.LabelSelector != nil {
			labelSelectors = append(labelSelectors, a.LabelSelector.Selector)
		}
		// AppliedToResources carries the servers a label_selector binding
		// currently expands to. Dedupe across selectors so a server matched
		// by multiple selectors is only listed once.
		for _, applied := range a.AppliedToResources {
			if applied.Server == nil {
				continue
			}
			if _, ok := seenLabelServer[applied.Server.ID]; ok {
				continue
			}
			seenLabelServer[applied.Server.ID] = struct{}{}
			labelSelectorServerIDs = append(labelSelectorServerIDs, applied.Server.ID)
		}
	}

	res, err := CreateResource(runtime, "hetzner.firewall", map[string]*llx.RawData{
		"__id":           llx.StringData(fmt.Sprintf("hetzner.firewall/%d", fw.ID)),
		"id":             llx.IntData(fw.ID),
		"name":           llx.StringData(fw.Name),
		"created":        llx.TimeDataPtr(timePtr(fw.Created)),
		"rules":          dictArrayData(rules),
		"labelSelectors": stringArrayData(labelSelectors),
		"labels":         labelData(fw.Labels),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerFirewall)
	m.cacheServerIDs = serverIDs
	m.cacheLabelSelectorServerIDs = labelSelectorServerIDs
	return m, nil
}

func initHetznerFirewall(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := idArg(args, "id")
	if !ok {
		// Fall back to a connected hetzner-firewall asset, whose id the
		// discovery step stamped on the connection options.
		id, ok = connection.AssetID(conn(runtime).Conf, connection.OptionFirewall)
		if !ok {
			return nil, nil, missingIDErr("firewall")
		}
	}
	fw, _, err := conn(runtime).Client().Firewall.GetByID(ctx(), id)
	if err != nil {
		return nil, nil, err
	}
	if fw == nil {
		return nil, nil, notFoundErr("firewall", id)
	}
	res, err := newMqlHetznerFirewall(runtime, fw)
	return args, res, err
}

// rulesRestrictEgress reports whether a rule set constrains outbound traffic.
// Hetzner permits all egress unless at least one rule carries direction "out",
// at which point only traffic matching those rules is allowed.
func rulesRestrictEgress(rules []any) bool {
	for _, r := range rules {
		rule, ok := r.(map[string]any)
		if !ok {
			continue
		}
		if direction, _ := rule["direction"].(string); direction == "out" {
			return true
		}
	}
	return false
}

func (m *mqlHetznerFirewall) egressRestricted() (bool, error) {
	rules := m.GetRules()
	if rules.Error != nil {
		return false, rules.Error
	}
	return rulesRestrictEgress(rules.Data), nil
}

func (m *mqlHetznerFirewall) servers() ([]any, error) {
	return serverRefs(m.MqlRuntime, m.cacheServerIDs)
}

func (m *mqlHetznerFirewall) labelSelectorTargets() ([]any, error) {
	return serverRefs(m.MqlRuntime, m.cacheLabelSelectorServerIDs)
}

// serverRefs builds lazy hetzner.server references from a list of server IDs.
func serverRefs(runtime *plugin.Runtime, ids []int64) ([]any, error) {
	out := make([]any, 0, len(ids))
	for _, id := range ids {
		ref, err := NewResource(runtime, "hetzner.server", map[string]*llx.RawData{
			"id": llx.IntData(id),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, ref)
	}
	return out, nil
}
