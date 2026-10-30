// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/frontdoor/armfrontdoor/v2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// Front Door firewall policies are Microsoft.Network/
// FrontDoorWebApplicationFirewallPolicies, a different resource type from the
// Application Gateway policies in network_waf_rules.go. Their rule documents
// come from a different SDK with a different shape (EnabledState rather than
// State, a rate limit in minutes rather than a duration enum, a rule-set-wide
// action, and exclusions at three levels), so they get their own resource tree
// rather than a lossy mapping onto the Application Gateway one.

type mqlAzureSubscriptionFrontDoorServiceWafPolicyInternal struct {
	cacheCustomRules     []*armfrontdoor.CustomRule
	cacheManagedRuleSets []*armfrontdoor.ManagedRuleSet
}

type mqlAzureSubscriptionFrontDoorServiceWafPolicyManagedRuleSetInternal struct {
	baseID                  string
	cacheRuleGroupOverrides []*armfrontdoor.ManagedRuleGroupOverride
}

type mqlAzureSubscriptionFrontDoorServiceWafPolicyManagedRuleSetRuleGroupOverrideInternal struct {
	baseID     string
	cacheRules []*armfrontdoor.ManagedRuleOverride
}

type mqlAzureSubscriptionFrontDoorServiceWafPolicyCustomRuleInternal struct {
	baseID               string
	cacheMatchConditions []*armfrontdoor.MatchCondition
}

// Constructed inline at each call site so the permissions extractor, which
// tracks client variables per function body, records the Front Door firewall
// policy read in azure.permissions.json.

func (a *mqlAzureSubscriptionFrontDoorService) wafPolicies() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armfrontdoor.NewPoliciesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	pager := client.NewListBySubscriptionPager(&armfrontdoor.PoliciesClientListBySubscriptionOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, policy := range page.Value {
			if policy == nil {
				continue
			}
			mqlPolicy, err := frontDoorWafPolicyToMql(a.MqlRuntime, *policy)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}
	return res, nil
}

func initAzureSubscriptionFrontDoorServiceWafPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	// A bare query with no id is a valid empty state, so the key being absent
	// passes through and the runtime builds an empty resource. A key that is
	// present but unusable is different: an empty or non-string id can never
	// resolve, and passing it through would build a husk whose every field is
	// unset, so those report an error instead.
	idRaw := args["id"]
	if idRaw == nil {
		return args, nil, nil
	}
	policyID, ok := idRaw.Value.(string)
	if !ok {
		return nil, nil, errors.New("azure.subscription.frontDoorService.wafPolicy: id must be a string")
	}
	if policyID == "" {
		return nil, nil, errors.New("azure.subscription.frontDoorService.wafPolicy: id must not be empty")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	resourceID, err := ParseResourceID(policyID)
	if err != nil {
		return nil, nil, err
	}
	name, err := resourceID.Component("FrontDoorWebApplicationFirewallPolicies")
	if err != nil {
		return nil, nil, err
	}

	client, err := armfrontdoor.NewPoliciesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	policy, err := client.Get(context.Background(), resourceID.ResourceGroup, name, &armfrontdoor.PoliciesClientGetOptions{})
	if err != nil {
		return nil, nil, err
	}

	// Return the built resource rather than args so the rule documents land on
	// the Internal cache; args alone would leave managedRules() and
	// customRules() empty.
	mqlPolicy, err := frontDoorWafPolicyToMql(runtime, policy.WebApplicationFirewallPolicy)
	if err != nil {
		return nil, nil, err
	}
	return nil, mqlPolicy, nil
}

func frontDoorWafPolicyToMql(runtime *plugin.Runtime, policy armfrontdoor.WebApplicationFirewallPolicy) (*mqlAzureSubscriptionFrontDoorServiceWafPolicy, error) {
	var sku string
	if policy.SKU != nil {
		sku = string(convert.ToValue(policy.SKU.Name))
	}

	var mode, redirectURL, customBlockResponseBody, logScrubbingState, provisioningState, resourceState string
	enabled := true
	requestBodyCheck := false
	var customBlockResponseStatusCode, jsChallengeExpiration, captchaExpiration *int64
	logScrubbingRules := []any{}

	if props := policy.Properties; props != nil {
		provisioningState = convert.ToValue(props.ProvisioningState)
		resourceState = string(convert.ToValue(props.ResourceState))

		if ps := props.PolicySettings; ps != nil {
			mode = string(convert.ToValue(ps.Mode))
			// Azure defaults an unset enabled state to Enabled.
			if ps.EnabledState != nil {
				enabled = *ps.EnabledState == armfrontdoor.PolicyEnabledStateEnabled
			}
			// Likewise the request body check defaults to Enabled.
			requestBodyCheck = ps.RequestBodyCheck == nil || *ps.RequestBodyCheck == armfrontdoor.PolicyRequestBodyCheckEnabled
			redirectURL = convert.ToValue(ps.RedirectURL)
			customBlockResponseBody = convert.ToValue(ps.CustomBlockResponseBody)
			if ps.CustomBlockResponseStatusCode != nil {
				v := int64(*ps.CustomBlockResponseStatusCode)
				customBlockResponseStatusCode = &v
			}
			if ps.JavascriptChallengeExpirationInMinutes != nil {
				v := int64(*ps.JavascriptChallengeExpirationInMinutes)
				jsChallengeExpiration = &v
			}
			if ps.CaptchaExpirationInMinutes != nil {
				v := int64(*ps.CaptchaExpirationInMinutes)
				captchaExpiration = &v
			}
			if ls := ps.LogScrubbing; ls != nil {
				logScrubbingState = string(convert.ToValue(ls.State))
				for _, rule := range ls.ScrubbingRules {
					if rule == nil {
						continue
					}
					d, err := convert.JsonToDict(rule)
					if err != nil {
						return nil, err
					}
					logScrubbingRules = append(logScrubbingRules, d)
				}
			}
		}
	}

	frontendEndpointIds := frontDoorLinkIDs(policy)
	securityPolicyIds := []any{}
	routingRuleIds := []any{}
	if props := policy.Properties; props != nil {
		for _, l := range props.SecurityPolicyLinks {
			if l != nil && l.ID != nil {
				securityPolicyIds = append(securityPolicyIds, *l.ID)
			}
		}
		for _, l := range props.RoutingRuleLinks {
			if l != nil && l.ID != nil {
				routingRuleIds = append(routingRuleIds, *l.ID)
			}
		}
	}

	r, err := CreateResource(runtime, "azure.subscription.frontDoorService.wafPolicy",
		map[string]*llx.RawData{
			"__id":                                   llx.StringDataPtr(policy.ID),
			"id":                                     llx.StringDataPtr(policy.ID),
			"name":                                   llx.StringDataPtr(policy.Name),
			"location":                               llx.StringDataPtr(policy.Location),
			"tags":                                   llx.MapData(convert.PtrMapStrToInterface(policy.Tags), types.String),
			"sku":                                    llx.StringData(sku),
			"mode":                                   llx.StringData(mode),
			"enabled":                                llx.BoolData(enabled),
			"requestBodyCheck":                       llx.BoolData(requestBodyCheck),
			"customBlockResponseStatusCode":          llx.IntDataPtr(customBlockResponseStatusCode),
			"customBlockResponseBody":                llx.StringData(customBlockResponseBody),
			"redirectUrl":                            llx.StringData(redirectURL),
			"javascriptChallengeExpirationInMinutes": llx.IntDataPtr(jsChallengeExpiration),
			"captchaExpirationInMinutes":             llx.IntDataPtr(captchaExpiration),
			"logScrubbingState":                      llx.StringData(logScrubbingState),
			"logScrubbingRules":                      llx.ArrayData(logScrubbingRules, types.Dict),
			"provisioningState":                      llx.StringData(provisioningState),
			"resourceState":                          llx.StringData(resourceState),
			"frontendEndpointIds":                    llx.ArrayData(frontendEndpointIds, types.String),
			"securityPolicyIds":                      llx.ArrayData(securityPolicyIds, types.String),
			"routingRuleIds":                         llx.ArrayData(routingRuleIds, types.String),
		})
	if err != nil {
		return nil, err
	}

	mqlPolicy := r.(*mqlAzureSubscriptionFrontDoorServiceWafPolicy)
	if props := policy.Properties; props != nil {
		if props.CustomRules != nil {
			mqlPolicy.cacheCustomRules = props.CustomRules.Rules
		}
		if props.ManagedRules != nil {
			mqlPolicy.cacheManagedRuleSets = props.ManagedRules.ManagedRuleSets
		}
	}
	return mqlPolicy, nil
}

// frontDoorLinkIDs collects the classic frontend endpoint IDs a policy is
// attached to. Standard and Premium profiles bind policies through a security
// policy instead, so this is empty for them.
func frontDoorLinkIDs(policy armfrontdoor.WebApplicationFirewallPolicy) []any {
	res := []any{}
	if policy.Properties == nil {
		return res
	}
	for _, l := range policy.Properties.FrontendEndpointLinks {
		if l != nil && l.ID != nil {
			res = append(res, *l.ID)
		}
	}
	return res
}

func (a *mqlAzureSubscriptionFrontDoorServiceWafPolicy) managedRules() ([]any, error) {
	res := []any{}
	for _, rs := range a.cacheManagedRuleSets {
		if rs == nil {
			continue
		}
		ruleSetType := convert.ToValue(rs.RuleSetType)
		ruleSetVersion := convert.ToValue(rs.RuleSetVersion)

		exclusions, err := frontDoorExclusionsToDicts(rs.Exclusions)
		if err != nil {
			return nil, err
		}

		id := fmt.Sprintf("%s/managedRuleSets/%s/%s", a.Id.Data, ruleSetType, ruleSetVersion)
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.frontDoorService.wafPolicy.managedRuleSet",
			map[string]*llx.RawData{
				"__id":           llx.StringData(id),
				"ruleSetType":    llx.StringData(ruleSetType),
				"ruleSetVersion": llx.StringData(ruleSetVersion),
				"ruleSetAction":  llx.StringData(string(convert.ToValue(rs.RuleSetAction))),
				"exclusions":     llx.ArrayData(exclusions, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		mqlRuleSet := r.(*mqlAzureSubscriptionFrontDoorServiceWafPolicyManagedRuleSet)
		mqlRuleSet.baseID = id
		mqlRuleSet.cacheRuleGroupOverrides = rs.RuleGroupOverrides
		res = append(res, mqlRuleSet)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionFrontDoorServiceWafPolicyManagedRuleSet) ruleGroupOverrides() ([]any, error) {
	res := []any{}
	for _, o := range a.cacheRuleGroupOverrides {
		if o == nil {
			continue
		}
		groupName := convert.ToValue(o.RuleGroupName)
		exclusions, err := frontDoorExclusionsToDicts(o.Exclusions)
		if err != nil {
			return nil, err
		}

		id := fmt.Sprintf("%s/ruleGroupOverrides/%s", a.baseID, groupName)
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.frontDoorService.wafPolicy.managedRuleSet.ruleGroupOverride",
			map[string]*llx.RawData{
				"__id":          llx.StringData(id),
				"ruleGroupName": llx.StringData(groupName),
				// An override listing no rules disables the whole group.
				"disablesEntireGroup": llx.BoolData(len(o.Rules) == 0),
				"exclusions":          llx.ArrayData(exclusions, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		mqlOverride := r.(*mqlAzureSubscriptionFrontDoorServiceWafPolicyManagedRuleSetRuleGroupOverride)
		mqlOverride.baseID = id
		mqlOverride.cacheRules = o.Rules
		res = append(res, mqlOverride)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionFrontDoorServiceWafPolicyManagedRuleSetRuleGroupOverride) rules() ([]any, error) {
	res := []any{}
	for _, rule := range a.cacheRules {
		if rule == nil {
			continue
		}
		ruleID := convert.ToValue(rule.RuleID)
		exclusions, err := frontDoorExclusionsToDicts(rule.Exclusions)
		if err != nil {
			return nil, err
		}
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.frontDoorService.wafPolicy.managedRuleSet.ruleGroupOverride.rule",
			map[string]*llx.RawData{
				"__id":         llx.StringData(fmt.Sprintf("%s/rules/%s", a.baseID, ruleID)),
				"ruleId":       llx.StringData(ruleID),
				"enabledState": llx.StringData(string(convert.ToValue(rule.EnabledState))),
				"action":       llx.StringData(string(convert.ToValue(rule.Action))),
				"sensitivity":  llx.StringData(string(convert.ToValue(rule.Sensitivity))),
				"exclusions":   llx.ArrayData(exclusions, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionFrontDoorServiceWafPolicy) customRules() ([]any, error) {
	res := []any{}
	for idx, rule := range a.cacheCustomRules {
		if rule == nil {
			continue
		}
		name := convert.ToValue(rule.Name)
		key := name
		if key == "" {
			key = fmt.Sprintf("%d", idx)
		}

		groupBy := []any{}
		for _, g := range rule.GroupBy {
			if g == nil {
				continue
			}
			d, err := convert.JsonToDict(g)
			if err != nil {
				return nil, err
			}
			groupBy = append(groupBy, d)
		}

		var priority, rateLimitThreshold, rateLimitDuration *int64
		if rule.Priority != nil {
			v := int64(*rule.Priority)
			priority = &v
		}
		if rule.RateLimitThreshold != nil {
			v := int64(*rule.RateLimitThreshold)
			rateLimitThreshold = &v
		}
		if rule.RateLimitDurationInMinutes != nil {
			v := int64(*rule.RateLimitDurationInMinutes)
			rateLimitDuration = &v
		}

		id := fmt.Sprintf("%s/customRules/%s", a.Id.Data, key)
		r, err := CreateResource(a.MqlRuntime, "azure.subscription.frontDoorService.wafPolicy.customRule",
			map[string]*llx.RawData{
				"__id":                       llx.StringData(id),
				"name":                       llx.StringData(name),
				"priority":                   llx.IntDataPtr(priority),
				"ruleType":                   llx.StringData(string(convert.ToValue(rule.RuleType))),
				"action":                     llx.StringData(string(convert.ToValue(rule.Action))),
				"enabledState":               llx.StringData(string(convert.ToValue(rule.EnabledState))),
				"rateLimitThreshold":         llx.IntDataPtr(rateLimitThreshold),
				"rateLimitDurationInMinutes": llx.IntDataPtr(rateLimitDuration),
				"groupBy":                    llx.ArrayData(groupBy, types.Dict),
			})
		if err != nil {
			return nil, err
		}
		mqlRule := r.(*mqlAzureSubscriptionFrontDoorServiceWafPolicyCustomRule)
		mqlRule.baseID = id
		mqlRule.cacheMatchConditions = rule.MatchConditions
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionFrontDoorServiceWafPolicyCustomRule) matchConditions() ([]any, error) {
	res := []any{}
	for idx, cond := range a.cacheMatchConditions {
		if cond == nil {
			continue
		}

		matchValues := []any{}
		for _, v := range cond.MatchValue {
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

		r, err := CreateResource(a.MqlRuntime, "azure.subscription.frontDoorService.wafPolicy.customRule.matchCondition",
			map[string]*llx.RawData{
				"__id":          llx.StringData(fmt.Sprintf("%s/matchConditions/%d", a.baseID, idx)),
				"matchVariable": llx.StringData(string(convert.ToValue(cond.MatchVariable))),
				"selector":      llx.StringData(convert.ToValue(cond.Selector)),
				"operator":      llx.StringData(string(convert.ToValue(cond.Operator))),
				"negate":        llx.BoolData(convert.ToValue(cond.NegateCondition)),
				"matchValues":   llx.ArrayData(matchValues, types.String),
				"transforms":    llx.ArrayData(transforms, types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// frontDoorExclusionsToDicts converts managed rule exclusions, which Front Door
// allows at rule set, rule group, and individual rule level.
func frontDoorExclusionsToDicts(exclusions []*armfrontdoor.ManagedRuleExclusion) ([]any, error) {
	res := []any{}
	for _, e := range exclusions {
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

// wafPolicy resolves the firewall policy a security policy binds to its
// profile. The binding carries the policy's ARM ID, which the policy resource's
// init resolves with a direct Get.
func (a *mqlAzureSubscriptionFrontDoorServiceProfileSecurityPolicy) wafPolicy() (*mqlAzureSubscriptionFrontDoorServiceWafPolicy, error) {
	if a.WafPolicyId.Data == "" {
		a.WafPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.frontDoorService.wafPolicy",
		map[string]*llx.RawData{"id": llx.StringData(a.WafPolicyId.Data)})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionFrontDoorServiceWafPolicy), nil
}
