// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// The rule trees below are keyed on synthetic, parent-qualified paths rather
// than on an ARM ID, because none of these are ARM resources: they are elements
// of the policy document. Each level carries its own key plus the SDK slice its
// children come from, so a child can build a stable key without the parent
// having to expose one as a queryable field.

type mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyInternal struct {
	cacheCustomRules     []*network.WebApplicationFirewallCustomRule
	cacheManagedRuleSets []*network.ManagedRuleSet
}

type mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyManagedRuleSetInternal struct {
	baseID                  string
	cacheRuleGroupOverrides []*network.ManagedRuleGroupOverride
}

type mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyManagedRuleSetRuleGroupOverrideInternal struct {
	baseID     string
	cacheRules []*network.ManagedRuleOverride
}

type mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyCustomRuleInternal struct {
	baseID               string
	cacheMatchConditions []*network.MatchCondition
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy) managedRules() ([]any, error) {
	res := []any{}
	for _, rs := range a.cacheManagedRuleSets {
		if rs == nil {
			continue
		}
		ruleSetType := convert.ToValue(rs.RuleSetType)
		ruleSetVersion := convert.ToValue(rs.RuleSetVersion)

		computedDisabled := []any{}
		for _, g := range rs.ComputedDisabledRules {
			if g == nil {
				continue
			}
			d, err := convert.JsonToDict(g)
			if err != nil {
				return nil, err
			}
			computedDisabled = append(computedDisabled, d)
		}

		id := fmt.Sprintf("%s/managedRuleSets/%s/%s", a.Id.Data, ruleSetType, ruleSetVersion)
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.applicationFirewallPolicy.managedRuleSet",
			map[string]*llx.RawData{
				"__id":                  llx.StringData(id),
				"ruleSetType":           llx.StringData(ruleSetType),
				"ruleSetVersion":        llx.StringData(ruleSetVersion),
				"computedDisabledRules": llx.ArrayData(computedDisabled, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		mqlRuleSet := r.(*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyManagedRuleSet)
		mqlRuleSet.baseID = id
		mqlRuleSet.cacheRuleGroupOverrides = rs.RuleGroupOverrides
		res = append(res, mqlRuleSet)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyManagedRuleSet) ruleGroupOverrides() ([]any, error) {
	res := []any{}
	for _, o := range a.cacheRuleGroupOverrides {
		if o == nil {
			continue
		}
		groupName := convert.ToValue(o.RuleGroupName)
		id := fmt.Sprintf("%s/ruleGroupOverrides/%s", a.baseID, groupName)
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.applicationFirewallPolicy.managedRuleSet.ruleGroupOverride",
			map[string]*llx.RawData{
				"__id":          llx.StringData(id),
				"ruleGroupName": llx.StringData(groupName),
				// Azure reads an override that lists no rules as disabling the
				// whole group, so the empty case is the widest one, not the
				// narrowest.
				"disablesEntireGroup": llx.BoolData(len(o.Rules) == 0),
			})
		if err != nil {
			return nil, err
		}
		mqlOverride := r.(*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyManagedRuleSetRuleGroupOverride)
		mqlOverride.baseID = id
		mqlOverride.cacheRules = o.Rules
		res = append(res, mqlOverride)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyManagedRuleSetRuleGroupOverride) rules() ([]any, error) {
	res := []any{}
	for _, rule := range a.cacheRules {
		if rule == nil {
			continue
		}
		ruleID := convert.ToValue(rule.RuleID)
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.applicationFirewallPolicy.managedRuleSet.ruleGroupOverride.rule",
			map[string]*llx.RawData{
				"__id":        llx.StringData(fmt.Sprintf("%s/rules/%s", a.baseID, ruleID)),
				"ruleId":      llx.StringData(ruleID),
				"state":       llx.StringData(string(convert.ToValue(rule.State))),
				"action":      llx.StringData(string(convert.ToValue(rule.Action))),
				"sensitivity": llx.StringData(string(convert.ToValue(rule.Sensitivity))),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicy) customRules() ([]any, error) {
	res := []any{}
	for idx, rule := range a.cacheCustomRules {
		if rule == nil {
			continue
		}
		// Name is optional in the SDK though unique when present; fall back to
		// the rule's position so the cache key stays distinct either way.
		name := convert.ToValue(rule.Name)
		key := name
		if key == "" {
			key = fmt.Sprintf("%d", idx)
		}

		groupBy := []any{}
		for _, g := range rule.GroupByUserSession {
			if g == nil {
				continue
			}
			d, err := convert.JsonToDict(g)
			if err != nil {
				return nil, err
			}
			groupBy = append(groupBy, d)
		}

		var priority, rateLimitThreshold *int64
		if rule.Priority != nil {
			v := int64(*rule.Priority)
			priority = &v
		}
		if rule.RateLimitThreshold != nil {
			v := int64(*rule.RateLimitThreshold)
			rateLimitThreshold = &v
		}

		id := fmt.Sprintf("%s/customRules/%s", a.Id.Data, key)
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.applicationFirewallPolicy.customRule",
			map[string]*llx.RawData{
				"__id":               llx.StringData(id),
				"name":               llx.StringData(name),
				"priority":           llx.IntDataPtr(priority),
				"ruleType":           llx.StringData(string(convert.ToValue(rule.RuleType))),
				"action":             llx.StringData(string(convert.ToValue(rule.Action))),
				"state":              llx.StringData(string(convert.ToValue(rule.State))),
				"rateLimitThreshold": llx.IntDataPtr(rateLimitThreshold),
				"rateLimitDuration":  llx.StringData(string(convert.ToValue(rule.RateLimitDuration))),
				"groupByUserSession": llx.ArrayData(groupBy, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		mqlRule := r.(*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyCustomRule)
		mqlRule.baseID = id
		mqlRule.cacheMatchConditions = rule.MatchConditions
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyCustomRule) matchConditions() ([]any, error) {
	res := []any{}
	for idx, cond := range a.cacheMatchConditions {
		if cond == nil {
			continue
		}

		matchValues := []any{}
		for _, v := range cond.MatchValues {
			if v != nil {
				matchValues = append(matchValues, *v)
			}
		}
		transforms := []any{}
		for _, t := range cond.Transforms {
			if t != nil {
				transforms = append(transforms, string(*t))
			}
		}
		matchVariables := []any{}
		for _, mv := range cond.MatchVariables {
			if mv == nil {
				continue
			}
			d, err := convert.JsonToDict(mv)
			if err != nil {
				return nil, err
			}
			matchVariables = append(matchVariables, d)
		}

		r, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.applicationFirewallPolicy.customRule.matchCondition",
			map[string]*llx.RawData{
				"__id":           llx.StringData(fmt.Sprintf("%s/matchConditions/%d", a.baseID, idx)),
				"operator":       llx.StringData(string(convert.ToValue(cond.Operator))),
				"negate":         llx.BoolData(convert.ToValue(cond.NegationConditon)),
				"matchValues":    llx.ArrayData(matchValues, types.String),
				"matchVariables": llx.ArrayData(matchVariables, types.Dict),
				"transforms":     llx.ArrayData(transforms, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// policyManagedRules returns a policy's managed rules definition, or nil when
// the policy carries none.
func policyManagedRules(waf network.WebApplicationFirewallPolicy) *network.ManagedRulesDefinition {
	if waf.Properties == nil {
		return nil
	}
	return waf.Properties.ManagedRules
}

// wafExclusionsToDicts converts the policy-level managed rule exclusions to
// dicts. Kept separate so azureAppFirewallPolicyToMql stays readable.
func wafExclusionsToDicts(managedRules *network.ManagedRulesDefinition) ([]any, error) {
	res := []any{}
	if managedRules == nil {
		return res, nil
	}
	for _, e := range managedRules.Exclusions {
		if e == nil {
			continue
		}
		d, err := convert.JsonToDict(e)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

var _ plugin.Resource = (*mqlAzureSubscriptionNetworkServiceApplicationFirewallPolicyCustomRule)(nil)
