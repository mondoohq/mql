// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sort"

	"github.com/oracle/oci-go-sdk/v65/identitydomains"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// Where multi-factor authentication is enforced, as opposed to offered.
//
// The domain already reports its authentication factor settings, and those
// describe what is *available*: which factors the domain supports and how
// enrollment works. Nothing in them says a user must present one. That
// statement lives in a sign-on policy, in a rule, in the rule's return values,
// and it is gated by a condition that may in turn name a network perimeter.
//
// Shipping the factor settings without the policies therefore reads as
// enforcement coverage while proving nothing, which is why this landed as one
// piece rather than in halves.

// ----- policies -----

type mqlOciIdentityDomainPolicyInternal struct {
	// The domain this policy was listed from.
	//
	// Held as a pointer rather than as an id because rules() resolves against
	// the domain's rule collection, which is already fetched and cached there.
	// Going back through NewResource per policy would run the domain's init
	// before the runtime cache is consulted, turning one listing into a call
	// per policy.
	cacheDomain *mqlOciIdentityDomain

	// Rule ids in the order the policy evaluates them.
	cacheRuleIDs []string
}

func (o *mqlOciIdentityDomain) policies() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	policies, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.Policy, *int, error) {
		response, err := client.ListPolicies(ctx, identitydomains.ListPoliciesRequest{
			StartIndex:    new(startIndex),
			Count:         new(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "sign-on policies")
		}
		return response.Policies.Resources, response.Policies.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(policies))
	for i := range policies {
		policy := policies[i]

		policyType := ""
		if policy.PolicyType != nil {
			policyType = stringValue(policy.PolicyType.Value)
		}

		mqlPolicy, err := CreateResource(o.MqlRuntime, "oci.identity.domain.policy", map[string]*llx.RawData{
			"__id":        llx.StringData(o.Id.Data + "/policy/" + stringValue(policy.Id)),
			"id":          llx.StringDataPtr(policy.Id),
			"ocid":        llx.StringDataPtr(policy.Ocid),
			"name":        llx.StringDataPtr(policy.Name),
			"description": llx.StringDataPtr(policy.Description),
			"policyType":  llx.StringData(policyType),
			"active":      llx.BoolData(boolValue(policy.Active)),
			"created":     llx.TimeDataPtr(ociScimCreatedAt(policy.Meta)),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlPolicy.(*mqlOciIdentityDomainPolicy)
		typed.cacheDomain = o
		typed.cacheRuleIDs = ociPolicyRuleIDsInOrder(policy.Rules)
		res = append(res, typed)
	}

	return res, nil
}

// ociPolicyRuleIDsInOrder returns a policy's rule ids in evaluation order.
//
// The order is the whole point. A sign-on policy stops at the first rule whose
// condition matches, so a permissive rule ahead of a restrictive one makes the
// restrictive one unreachable - and the API returns the references in an
// unspecified order with the position carried in `sequence` instead. Reporting
// them as they arrive would silently lose the only thing that decides which
// rule wins.
//
// Sorted stably so two rules sharing a sequence keep the order the API sent
// them in rather than swapping between scans.
func ociPolicyRuleIDsInOrder(refs []identitydomains.PolicyRules) []string {
	ordered := make([]identitydomains.PolicyRules, 0, len(refs))
	ordered = append(ordered, refs...)

	sort.SliceStable(ordered, func(i, j int) bool {
		return intValue(ordered[i].Sequence) < intValue(ordered[j].Sequence)
	})

	ids := make([]string, 0, len(ordered))
	for i := range ordered {
		if id := stringValue(ordered[i].Value); id != "" {
			ids = append(ids, id)
		}
	}
	return ids
}

// rules returns the rules the policy evaluates, in evaluation order.
//
// Resolved against the domain's rule collection rather than through
// NewResource per reference: the collection is fetched once and shared, and an
// init runs before the runtime cache is consulted, so the per-reference form
// would cost a full SCIM listing for every rule of every policy.
func (o *mqlOciIdentityDomainPolicy) rules() ([]any, error) {
	if len(o.cacheRuleIDs) == 0 {
		return []any{}, nil
	}
	if o.cacheDomain == nil {
		return nil, errors.New("oci.identity.domain.policy: the owning identity domain is not known")
	}

	rules := o.cacheDomain.GetRules()
	if rules.Error != nil {
		return nil, rules.Error
	}

	byID := make(map[string]*mqlOciIdentityDomainRule, len(rules.Data))
	for _, raw := range rules.Data {
		rule, ok := raw.(*mqlOciIdentityDomainRule)
		if !ok {
			continue
		}
		byID[rule.Id.Data] = rule
	}

	res := make([]any, 0, len(o.cacheRuleIDs))
	for _, id := range o.cacheRuleIDs {
		// A referenced rule missing from the listing is skipped rather than
		// reported as an error: it means the rule was deleted between the two
		// calls, and losing one reference should not take the policy's other
		// rules with it.
		if rule, ok := byID[id]; ok {
			res = append(res, rule)
		}
	}
	return res, nil
}

// ----- rules -----

type mqlOciIdentityDomainRuleInternal struct {
	cacheDomain *mqlOciIdentityDomain

	// Id of the condition the rule matches on, empty when it matches on a
	// condition group instead.
	cacheConditionID string
}

func (o *mqlOciIdentityDomain) rules() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	rules, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.Rule, *int, error) {
		response, err := client.ListRules(ctx, identitydomains.ListRulesRequest{
			StartIndex:    new(startIndex),
			Count:         new(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "sign-on policy rules")
		}
		return response.Rules.Resources, response.Rules.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(rules))
	for i := range rules {
		rule := rules[i]

		policyType := ""
		if rule.PolicyType != nil {
			policyType = stringValue(rule.PolicyType.Value)
		}

		conditionGroupType, conditionGroupName, conditionID := ociRuleConditionGroup(rule.ConditionGroup)

		mqlRule, err := CreateResource(o.MqlRuntime, "oci.identity.domain.rule", map[string]*llx.RawData{
			"__id":        llx.StringData(o.Id.Data + "/rule/" + stringValue(rule.Id)),
			"id":          llx.StringDataPtr(rule.Id),
			"ocid":        llx.StringDataPtr(rule.Ocid),
			"name":        llx.StringDataPtr(rule.Name),
			"description": llx.StringDataPtr(rule.Description),
			"policyType":  llx.StringData(policyType),
			// Null rather than false when the service omits the flag: it does
			// not report `active` or `locked` for the rules it ships with, and
			// answering false there would state that the rule requiring
			// multi-factor authentication is switched off.
			"active":              llx.BoolDataPtr(rule.Active),
			"locked":              llx.BoolDataPtr(rule.Locked),
			"conditionExpression": llx.StringDataPtr(rule.Condition),
			"conditionGroupType":  llx.StringData(conditionGroupType),
			"conditionGroupName":  llx.StringData(conditionGroupName),
			"returns":             llx.MapData(ociRuleReturns(rule.Return), types.String),
			"created":             llx.TimeDataPtr(ociScimCreatedAt(rule.Meta)),
		})
		if err != nil {
			return nil, err
		}
		typed := mqlRule.(*mqlOciIdentityDomainRule)
		typed.cacheDomain = o
		typed.cacheConditionID = conditionID
		res = append(res, typed)
	}

	return res, nil
}

// ociRuleReturns flattens a rule's outcome into a map keyed by name.
//
// The API models the outcome as a list of name and value pairs, and the names
// are unique within a rule, so a map is what a query wants: `returns["effect"]`
// rather than a scan over a list. A duplicate name would be a shape the API
// does not produce; last one wins if it ever does.
func ociRuleReturns(returns []identitydomains.RuleReturn) map[string]any {
	out := make(map[string]any, len(returns))
	for i := range returns {
		name := stringValue(returns[i].Name)
		if name == "" {
			continue
		}
		out[name] = stringValue(returns[i].Value)
	}
	return out
}

// ociRuleConditionGroup reports what a rule matches on: the kind of reference,
// its name, and - only when it points at a single condition - the id to
// resolve.
//
// The distinction is load-bearing. A rule may point at one condition or at a
// group of them, the reference carries the same shape either way, and there is
// no list API for condition groups. Returning an empty id for a group keeps
// the condition accessor null rather than resolving a group id against the
// condition collection, which would find nothing and read as "this rule
// matches on nothing".
func ociRuleConditionGroup(group *identitydomains.RuleConditionGroup) (groupType, groupName, conditionID string) {
	if group == nil {
		return "", "", ""
	}
	groupType = string(group.Type)
	groupName = stringValue(group.Name)
	if group.Type == identitydomains.RuleConditionGroupTypeCondition {
		conditionID = stringValue(group.Value)
	}
	return groupType, groupName, conditionID
}

func (o *mqlOciIdentityDomainRule) condition() (*mqlOciIdentityDomainCondition, error) {
	if o.cacheConditionID == "" || o.cacheDomain == nil {
		o.Condition.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conditions := o.cacheDomain.GetConditions()
	if conditions.Error != nil {
		return nil, conditions.Error
	}

	for _, raw := range conditions.Data {
		condition, ok := raw.(*mqlOciIdentityDomainCondition)
		if !ok {
			continue
		}
		if condition.Id.Data == o.cacheConditionID {
			return condition, nil
		}
	}

	// Referenced but absent from the listing: deleted between the two calls,
	// or not readable. Null is the honest answer for a reference with nothing
	// behind it.
	o.Condition.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// ----- conditions -----

func (o *mqlOciIdentityDomain) conditions() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	conditions, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.Condition, *int, error) {
		response, err := client.ListConditions(ctx, identitydomains.ListConditionsRequest{
			StartIndex:    new(startIndex),
			Count:         new(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "sign-on policy conditions")
		}
		return response.Conditions.Resources, response.Conditions.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(conditions))
	for i := range conditions {
		condition := conditions[i]

		mqlCondition, err := CreateResource(o.MqlRuntime, "oci.identity.domain.condition", map[string]*llx.RawData{
			"__id":                llx.StringData(o.Id.Data + "/condition/" + stringValue(condition.Id)),
			"id":                  llx.StringDataPtr(condition.Id),
			"ocid":                llx.StringDataPtr(condition.Ocid),
			"name":                llx.StringDataPtr(condition.Name),
			"description":         llx.StringDataPtr(condition.Description),
			"attributeName":       llx.StringDataPtr(condition.AttributeName),
			"operator":            llx.StringData(string(condition.Operator)),
			"attributeValue":      llx.StringDataPtr(condition.AttributeValue),
			"evaluateConditionIf": llx.StringDataPtr(condition.EvaluateConditionIf),
			"created":             llx.TimeDataPtr(ociScimCreatedAt(condition.Meta)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCondition)
	}

	return res, nil
}

// ----- network perimeters -----

func (o *mqlOciIdentityDomain) networkPerimeters() ([]any, error) {
	client, err := o.domainClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	perimeters, err := ociScimPaginate(ctx, func(ctx context.Context, startIndex int) ([]identitydomains.NetworkPerimeter, *int, error) {
		response, err := client.ListNetworkPerimeters(ctx, identitydomains.ListNetworkPerimetersRequest{
			StartIndex:    new(startIndex),
			Count:         new(ociScimPageSize),
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, nil, ociScimError(err, o.Name.Data, "network perimeters")
		}
		return response.NetworkPerimeters.Resources, response.NetworkPerimeters.TotalResults, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(perimeters))
	for i := range perimeters {
		perimeter := perimeters[i]

		addressDicts, err := convert.JsonToDictSlice(perimeter.IpAddresses)
		if err != nil {
			return nil, err
		}

		perimeterID := o.Id.Data + "/networkPerimeter/" + stringValue(perimeter.Id)
		addresses := make([]any, 0, len(perimeter.IpAddresses))
		for j := range perimeter.IpAddresses {
			entry := perimeter.IpAddresses[j]
			mqlAddress, err := CreateResource(o.MqlRuntime, "oci.identity.domain.networkPerimeter.address", map[string]*llx.RawData{
				"__id":    llx.StringData(perimeterID + "/address/" + stringValue(entry.Value)),
				"value":   llx.StringDataPtr(entry.Value),
				"type":    llx.StringData(string(entry.Type)),
				"version": llx.StringData(string(entry.Version)),
			})
			if err != nil {
				return nil, err
			}
			addresses = append(addresses, mqlAddress)
		}

		mqlPerimeter, err := CreateResource(o.MqlRuntime, "oci.identity.domain.networkPerimeter", map[string]*llx.RawData{
			"__id":        llx.StringData(perimeterID),
			"id":          llx.StringDataPtr(perimeter.Id),
			"ocid":        llx.StringDataPtr(perimeter.Ocid),
			"name":        llx.StringDataPtr(perimeter.Name),
			"description": llx.StringDataPtr(perimeter.Description),
			"ipAddresses": llx.ArrayData(addressDicts, types.Dict),
			"addresses":   llx.ArrayData(addresses, types.Resource("oci.identity.domain.networkPerimeter.address")),
			"created":     llx.TimeDataPtr(ociScimCreatedAt(perimeter.Meta)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPerimeter)
	}

	return res, nil
}

// ----- keep-me-signed-in -----

// kmsiSetting reads the domain's keep-me-signed-in configuration.
//
// A domain has exactly one, but the API only offers it as a list, so the
// single member is picked out here. A domain that has never had the feature
// configured returns none, which is reported as nil and read by the accessors
// below as the feature being off - which is what it is.
func (o *mqlOciIdentityDomain) kmsiSetting() (*identitydomains.KmsiSetting, error) {
	return o.kmsi.get(func() (*identitydomains.KmsiSetting, error) {
		client, err := o.domainClient()
		if err != nil {
			return nil, err
		}

		response, err := client.ListKmsiSettings(context.Background(), identitydomains.ListKmsiSettingsRequest{
			AttributeSets: ociScimAttributeSets,
		})
		if err != nil {
			return nil, ociScimError(err, o.Name.Data, "keep-me-signed-in settings")
		}
		if len(response.KmsiSettings.Resources) == 0 {
			return nil, nil
		}
		return &response.KmsiSettings.Resources[0], nil
	})
}

func (o *mqlOciIdentityDomain) keepMeSignedInEnabled() (bool, error) {
	setting, err := o.kmsiSetting()
	if err != nil {
		return false, err
	}
	// False rather than null for an unconfigured domain: the question is
	// whether sessions can outlive the browser, and with no configuration they
	// cannot. A null here would make `keepMeSignedInEnabled == false` skip
	// every domain that never turned it on.
	if setting == nil {
		return false, nil
	}
	return boolValue(setting.KmsiFeatureEnabled), nil
}

func (o *mqlOciIdentityDomain) keepMeSignedInPromptEnabled() (bool, error) {
	setting, err := o.kmsiSetting()
	if err != nil {
		return false, err
	}
	if setting == nil {
		return false, nil
	}
	return boolValue(setting.KmsiPromptEnabled), nil
}

func (o *mqlOciIdentityDomain) keepMeSignedInTokenValidityInDays() (int64, error) {
	setting, err := o.kmsiSetting()
	if err != nil {
		return 0, err
	}
	return ociKmsiInt(setting, &o.KeepMeSignedInTokenValidityInDays, func(s *identitydomains.KmsiSetting) *int {
		return s.TokenValidityInDays
	})
}

func (o *mqlOciIdentityDomain) keepMeSignedInLastUsedValidityInDays() (int64, error) {
	setting, err := o.kmsiSetting()
	if err != nil {
		return 0, err
	}
	return ociKmsiInt(setting, &o.KeepMeSignedInLastUsedValidityInDays, func(s *identitydomains.KmsiSetting) *int {
		return s.LastUsedValidityInDays
	})
}

func (o *mqlOciIdentityDomain) keepMeSignedInMaxAllowedSessions() (int64, error) {
	setting, err := o.kmsiSetting()
	if err != nil {
		return 0, err
	}
	return ociKmsiInt(setting, &o.KeepMeSignedInMaxAllowedSessions, func(s *identitydomains.KmsiSetting) *int {
		return s.MaxAllowedSessions
	})
}

func (o *mqlOciIdentityDomain) termsOfUsePromptDisabled() (bool, error) {
	setting, err := o.kmsiSetting()
	if err != nil {
		return false, err
	}
	if setting == nil {
		return false, nil
	}
	return boolValue(setting.TouPromptDisabled), nil
}

// ociKmsiInt reports one of the keep-me-signed-in durations, keeping an absent
// one null.
//
// Unlike the booleans these have no safe zero reading: a token validity of 0
// days would say a session expires immediately, which is the opposite of what
// an unconfigured domain means.
func ociKmsiInt(
	setting *identitydomains.KmsiSetting,
	field *plugin.TValue[int64],
	value func(*identitydomains.KmsiSetting) *int,
) (int64, error) {
	if setting == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	v := value(setting)
	if v == nil {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return 0, nil
	}
	return int64(*v), nil
}
