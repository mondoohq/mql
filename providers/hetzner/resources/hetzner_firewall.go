// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"

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
	cacheRules                  []hcloud.FirewallRule
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
	m.cacheRules = fw.Rules
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

func (m *mqlHetznerFirewall) inboundRules() ([]any, error) {
	return m.rulesWithDirection(hcloud.FirewallRuleDirectionIn)
}

func (m *mqlHetznerFirewall) outboundRules() ([]any, error) {
	return m.rulesWithDirection(hcloud.FirewallRuleDirectionOut)
}

// rulesWithDirection builds the rule resources for one direction. The index
// in each __id is the rule's position in the firewall's full rule list, so an
// inbound and an outbound rule never share one, and two identical rules stay
// two resources.
func (m *mqlHetznerFirewall) rulesWithDirection(direction hcloud.FirewallRuleDirection) ([]any, error) {
	out := []any{}
	for i, r := range m.cacheRules {
		if r.Direction != direction {
			continue
		}
		res, err := newMqlHetznerFirewallRule(m, i, r)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// --- firewall.rule sub-resource ---

// mqlHetznerFirewallRuleInternal keeps the firewall the rule was read from.
// Holding the parent itself, rather than its id, lets firewall() answer
// without the per-rule GetByID an init-by-id would cost.
type mqlHetznerFirewallRuleInternal struct {
	cacheFirewall *mqlHetznerFirewall
}

func firewallRuleID(firewallID int64, index int) string {
	return fmt.Sprintf("hetzner.firewall/%d/rule/%d", firewallID, index)
}

func newMqlHetznerFirewallRule(fw *mqlHetznerFirewall, index int, r hcloud.FirewallRule) (*mqlHetznerFirewallRule, error) {
	srcs := make([]string, 0, len(r.SourceIPs))
	for _, ip := range r.SourceIPs {
		srcs = append(srcs, ip.String())
	}
	dsts := make([]string, 0, len(r.DestinationIPs))
	for _, ip := range r.DestinationIPs {
		dsts = append(dsts, ip.String())
	}

	portStart := llx.NilData
	portEnd := llx.NilData
	if r.Port != nil {
		if start, end, ok := parseFirewallPortRange(*r.Port); ok {
			portStart = llx.IntData(start)
			portEnd = llx.IntData(end)
		}
	}

	res, err := CreateResource(fw.MqlRuntime, "hetzner.firewall.rule", map[string]*llx.RawData{
		"__id":           llx.StringData(firewallRuleID(fw.Id.Data, index)),
		"direction":      llx.StringData(string(r.Direction)),
		"protocol":       llx.StringData(string(r.Protocol)),
		"port":           llx.StringDataPtr(r.Port),
		"portStart":      portStart,
		"portEnd":        portEnd,
		"sourceIps":      stringArrayData(srcs),
		"destinationIps": stringArrayData(dsts),
		"description":    llx.StringDataPtr(r.Description),
		"openToInternet": llx.BoolData(firewallRuleAdmitsAnySource(r)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlHetznerFirewallRule)
	m.cacheFirewall = fw
	return m, nil
}

// firewallRuleAdmitsAnySource reports whether a rule is an inbound rule whose
// source admits any address, the same verdict firewallRuleOpenToInternet gives
// for the rule's dict form.
func firewallRuleAdmitsAnySource(r hcloud.FirewallRule) bool {
	if r.Direction != hcloud.FirewallRuleDirectionIn {
		return false
	}
	for _, ip := range r.SourceIPs {
		if ones, _ := ip.Mask.Size(); ones == 0 && ip.IP.IsUnspecified() {
			return true
		}
	}
	return false
}

// parseFirewallPortRange turns a Hetzner firewall port ("22", "1024-5000", or
// "any") into the first and last port it covers. An unparseable value reports
// ok=false, so the bounds stay null rather than claiming a range the rule may
// not have.
func parseFirewallPortRange(port string) (int64, int64, bool) {
	port = strings.TrimSpace(port)
	if strings.EqualFold(port, "any") {
		return 1, 65535, true
	}
	startStr, endStr, isRange := strings.Cut(port, "-")
	start, err := strconv.ParseInt(strings.TrimSpace(startStr), 10, 64)
	if err != nil {
		return 0, 0, false
	}
	end := start
	if isRange {
		end, err = strconv.ParseInt(strings.TrimSpace(endStr), 10, 64)
		if err != nil {
			return 0, 0, false
		}
	}
	if start < 1 || end > 65535 || start > end {
		return 0, 0, false
	}
	return start, end, true
}

func (m *mqlHetznerFirewallRule) firewall() (*mqlHetznerFirewall, error) {
	if m.cacheFirewall == nil {
		m.Firewall.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return m.cacheFirewall, nil
}
