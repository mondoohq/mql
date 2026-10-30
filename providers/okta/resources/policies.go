// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/providers/okta/resources/sdk"
)

// https://developer.okta.com/docs/api/openapi/okta-management/management/tags/policy
type PolicyType string

const (
	OKTA_SIGN_ON               PolicyType = "OKTA_SIGN_ON"
	PASSWORD                              = "PASSWORD"
	MFA_ENROLL                            = "MFA_ENROLL"
	OAUTH_AUTHORIZATION_POLICY            = "OAUTH_AUTHORIZATION_POLICY"
	IDP_DISCOVERY                         = "IDP_DISCOVERY"
	ACCESS_POLICY                         = "ACCESS_POLICY"
	PROFILE_ENROLLMENT                    = "PROFILE_ENROLLMENT"
	ENTITY_RISK                           = "ENTITY_RISK"
	POST_AUTH_SESSION                     = "POST_AUTH_SESSION"
)

// oktaPolicyRuleRaw captures the policy-rule fields we expose. Okta models
// policy rules as a discriminated union whose common fields live in different
// places per variant, so we decode the canonical JSON into this shared shape.
type oktaPolicyRuleRaw struct {
	Id          string          `json:"id,omitempty"`
	Name        string          `json:"name,omitempty"`
	Priority    int64           `json:"priority,omitempty"`
	Status      string          `json:"status,omitempty"`
	System      *bool           `json:"system,omitempty"`
	Type        string          `json:"type,omitempty"`
	Actions     json.RawMessage `json:"actions,omitempty"`
	Conditions  json.RawMessage `json:"conditions,omitempty"`
	Created     *time.Time      `json:"created,omitempty"`
	LastUpdated *time.Time      `json:"lastUpdated,omitempty"`
}

func (o *mqlOktaPolicies) id() (string, error) {
	return "okta.policies", nil
}

// listPoliciesOfType lists every policy of one type. unavailable reports that
// the org will not answer for the type at all, which is a different reading
// from the org having none of them: several policy types exist only on an
// Identity Engine org or behind a licensed feature, and those answer 404, a
// 400 naming an invalid policy type, or 401 E0000015.
func listPoliciesOfType(runtime *plugin.Runtime, policyType PolicyType) (list []any, unavailable bool, err error) {
	conn := runtime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	respList, resp, err := apiSupplement.ListPolicies(ctx, string(policyType), queryLimit)
	if err != nil {
		// handle case where no policy exists
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, true, nil
		}
		// handle special case where the policy type does not exist
		if resp != nil && resp.StatusCode == http.StatusBadRequest && strings.Contains(strings.ToLower(err.Error()), "invalid policy type") {
			return nil, true, nil
		}
		if isOktaRawFeatureUnavailable(resp, err) {
			return nil, true, nil
		}
		return nil, false, err
	}

	if len(respList) == 0 {
		return nil, false, nil
	}

	result := []any{}
	for i := range respList {
		r, err := newMqlOktaPolicy(runtime, respList[i])
		if err != nil {
			return nil, false, err
		}
		result = append(result, r)
	}

	return result, false, nil
}

// listPolicies lists a policy type every org answers for, so an unanswered
// request is reported the way it always has been, as an empty collection.
func listPolicies(runtime *plugin.Runtime, policyType PolicyType) ([]any, error) {
	list, _, err := listPoliciesOfType(runtime, policyType)
	return list, err
}

// listOptionalPolicies lists a policy type the org may not have at all,
// reporting the field as null rather than as an empty collection when it does
// not. An empty list would say the org has no such policy as a fact, and an
// audit written on that list would pass without anything having been checked.
func listOptionalPolicies(runtime *plugin.Runtime, policyType PolicyType, field *plugin.TValue[[]any]) ([]any, error) {
	list, unavailable, err := listPoliciesOfType(runtime, policyType)
	if err != nil {
		return nil, err
	}
	if unavailable {
		return oktaUnreadableList(field)
	}
	return list, nil
}

func (o *mqlOktaPolicies) password() ([]any, error) {
	return listPolicies(o.MqlRuntime, PASSWORD)
}

func (o *mqlOktaPolicies) mfaEnroll() ([]any, error) {
	return listPolicies(o.MqlRuntime, MFA_ENROLL)
}

func (o *mqlOktaPolicies) signOn() ([]any, error) {
	return listPolicies(o.MqlRuntime, OKTA_SIGN_ON)
}

func (o *mqlOktaPolicies) oauthAuthorizationPolicy() ([]any, error) {
	return listPolicies(o.MqlRuntime, OAUTH_AUTHORIZATION_POLICY)
}

func (o *mqlOktaPolicies) idpDiscovery() ([]any, error) {
	return listPolicies(o.MqlRuntime, IDP_DISCOVERY)
}

func (o *mqlOktaPolicies) accessPolicy() ([]any, error) {
	return listPolicies(o.MqlRuntime, ACCESS_POLICY)
}

func (o *mqlOktaPolicies) profileEnrollment() ([]any, error) {
	return listPolicies(o.MqlRuntime, PROFILE_ENROLLMENT)
}

func (o *mqlOktaPolicies) entityRisk() ([]any, error) {
	return listOptionalPolicies(o.MqlRuntime, ENTITY_RISK, &o.EntityRisk)
}

func (o *mqlOktaPolicies) postAuthSession() ([]any, error) {
	return listOptionalPolicies(o.MqlRuntime, POST_AUTH_SESSION, &o.PostAuthSession)
}

func newMqlOktaPolicy(runtime *plugin.Runtime, entry *sdk.PolicyWrapper) (any, error) {
	conditions, err := convert.JsonToDict(entry.Conditions)
	if err != nil {
		return nil, err
	}

	settings, err := convert.JsonToDict(entry.Settings)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.policy", map[string]*llx.RawData{
		"id":          llx.StringData(entry.Id),
		"name":        llx.StringData(entry.Name),
		"description": llx.StringData(entry.Description),
		"priority":    llx.IntData(entry.Priority),
		"status":      llx.StringData(entry.Status),
		"system":      llx.BoolData(oktaBool(entry.System)),
		"type":        llx.StringData(entry.Type),
		"conditions":  llx.DictData(conditions),
		"settings":    llx.DictData(settings),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaPolicy) id() (string, error) {
	return "okta.policy/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaPolicy) rules() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}

	if o.Type.Data == ACCESS_POLICY {
		return getAccessPolicyRules(ctx, o.MqlRuntime, o.Id.Data, conn.ApiExtension())
	}

	rules, resp, err := client.PolicyAPI.ListPolicyRules(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}

	if len(rules) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.ListPolicyRules200ResponseInner) error {
		for i := range datalist {
			raw, err := json.Marshal(datalist[i])
			if err != nil {
				return err
			}
			var entry oktaPolicyRuleRaw
			if err := json.Unmarshal(raw, &entry); err != nil {
				return err
			}
			r, err := newMqlOktaPolicyRule(o.MqlRuntime, &entry)
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	err = appendEntry(rules)
	if err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var rules []okta.ListPolicyRules200ResponseInner
		resp, err = resp.Next(&rules)
		if err != nil {
			return nil, err
		}
		err = appendEntry(rules)
		if err != nil {
			return nil, err
		}
	}
	return list, nil
}

func getAccessPolicyRules(ctx context.Context, runtime *plugin.Runtime, policyId string, apiSupplement *sdk.ApiExtension) ([]any, error) {
	rules, err := fetchAccessPolicyRules(ctx, policyId, apiSupplement)
	if err != nil {
		return nil, err
	}
	res := []any{}
	for i := range rules {
		mqlRule, err := newMqlOktaPolicyRule(runtime, &rules[i])
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func newMqlOktaPolicyRule(runtime *plugin.Runtime, entry *oktaPolicyRuleRaw) (any, error) {
	actions, err := convert.JsonToDict(entry.Actions)
	if err != nil {
		return nil, err
	}

	conditions, err := convert.JsonToDict(entry.Conditions)
	if err != nil {
		return nil, err
	}

	return CreateResource(runtime, "okta.policyRule", map[string]*llx.RawData{
		"id":          llx.StringData(entry.Id),
		"name":        llx.StringData(entry.Name),
		"priority":    llx.IntData(entry.Priority),
		"status":      llx.StringData(entry.Status),
		"system":      llx.BoolData(oktaBool(entry.System)),
		"type":        llx.StringData(entry.Type),
		"actions":     llx.DictData(actions),
		"conditions":  llx.DictData(conditions),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaPolicyRule) id() (string, error) {
	return "okta.policyRule/" + o.Id.Data, o.Id.Error
}

// see https://github.com/okta/okta-sdk-golang/issues/286 for context. okta's sdk doesn't let you fetch
// type-specific rules which differ between the different policies. as such, we fetch those manually.
func fetchAccessPolicyRules(ctx context.Context, policyid string, apiSupplement *sdk.ApiExtension) ([]oktaPolicyRuleRaw, error) {
	raws, err := apiSupplement.ListPolicyRules(ctx, policyid, queryLimit)
	if err != nil {
		return nil, err
	}

	result := make([]oktaPolicyRuleRaw, 0, len(raws))
	for _, raw := range raws {
		var entry oktaPolicyRuleRaw
		if err := json.Unmarshal(raw, &entry); err != nil {
			return nil, err
		}
		result = append(result, entry)
	}
	return result, nil
}
