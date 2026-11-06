// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// openai.workloadIdentityProvider

// workloadIdentityProviderArgs maps a workload identity provider onto resource
// arguments. The verification block is a union: a discovery provider carries a
// discovery URL and no key set, an uploaded one carries a key set and no URL,
// so the side that does not apply reads as null.
func workloadIdentityProviderArgs(p openai.WorkloadIdentityProvider) map[string]*llx.RawData {
	var discoveryURL *string
	var jwks any
	switch p.Verification.Type {
	case "discovery":
		discoveryURL = emptyToNil(p.Verification.AsDiscovery().DiscoveryURL)
	case "uploaded_jwks":
		if keys := p.Verification.AsUploadedJwks().Jwks; keys != nil {
			jwks = keys
		}
	}

	transformations := make(map[string]any, len(p.AttributeTransformations))
	for _, t := range p.AttributeTransformations {
		transformations[t.Attribute] = t.Expression
	}

	return map[string]*llx.RawData{
		"__id":                     llx.StringData(p.ID),
		"id":                       llx.StringData(p.ID),
		"name":                     llx.StringData(p.Name),
		"description":              llx.StringData(p.Description),
		"enabled":                  llx.BoolData(p.Enabled),
		"type":                     llx.StringData(string(p.Type)),
		"issuer":                   llx.StringData(p.Issuer),
		"audience":                 llx.StringData(p.Audience),
		"verificationType":         llx.StringDataPtr(emptyToNil(p.Verification.Type)),
		"discoveryUrl":             llx.StringDataPtr(discoveryURL),
		"jwks":                     llx.DictData(jwks),
		"attributeTransformations": llx.MapData(transformations, types.String),
		"createdAt":                llx.TimeDataPtr(unixToNullableTime(p.CreatedAt)),
		"updatedAt":                llx.TimeDataPtr(unixToNullableTime(p.UpdatedAt)),
	}
}

func (r *mqlOpenai) workloadIdentityProviders() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.workloadIdentityProviders")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	res := []any{}
	err = walkPages(
		client.Admin.Organization.WorkloadIdentityProviders.ListAutoPaging(ctx, openai.AdminOrganizationWorkloadIdentityProviderListParams{}),
		func(p openai.WorkloadIdentityProvider) string { return p.ID },
		func(p openai.WorkloadIdentityProvider) error {
			mqlProvider, err := CreateResource(r.MqlRuntime, "openai.workloadIdentityProvider", workloadIdentityProviderArgs(p))
			if err != nil {
				return err
			}
			res = append(res, mqlProvider)
			return nil
		})
	if err != nil {
		return nil, classifyReportError(err, "workload identity provider list")
	}
	return res, nil
}

func (r *mqlOpenaiWorkloadIdentityProvider) federationRules() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.workloadIdentityProvider.federationRules")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	res := []any{}
	err = walkPages(
		client.Admin.Organization.WorkloadIdentityProviders.FederationRules.ListAutoPaging(ctx, r.Id.Data, openai.AdminOrganizationWorkloadIdentityProviderFederationRuleListParams{}),
		func(fr openai.FederationRule) string { return fr.ID },
		func(fr openai.FederationRule) error {
			args, err := federationRuleArgs(r.Id.Data, fr)
			if err != nil {
				return err
			}
			mqlRule, err := CreateResource(r.MqlRuntime, "openai.workloadIdentityProvider.federationRule", args)
			if err != nil {
				return err
			}
			rule := mqlRule.(*mqlOpenaiWorkloadIdentityProviderFederationRule)
			rule.provider = r
			rule.cacheProjectId = fr.ProjectID
			rule.cacheServiceAccountId = fr.ServiceAccountID
			res = append(res, mqlRule)
			return nil
		})
	if err != nil {
		return nil, classifyReportError(err, fmt.Sprintf("federation rule list of workload identity provider %s", r.Id.Data))
	}
	return res, nil
}

// openai.workloadIdentityProvider.federationRule

type mqlOpenaiWorkloadIdentityProviderFederationRuleInternal struct {
	provider              *mqlOpenaiWorkloadIdentityProvider
	cacheProjectId        string
	cacheServiceAccountId string
}

// federationRuleArgs maps a federation rule onto resource arguments. The cache
// key carries the provider id, since rules are listed per provider.
func federationRuleArgs(providerID string, fr openai.FederationRule) (map[string]*llx.RawData, error) {
	matchers, err := attributeMatcherValues(fr.AttributeMatchers)
	if err != nil {
		return nil, fmt.Errorf("failed to read the attribute matchers of federation rule %s: %w", fr.ID, err)
	}

	var scopes []any
	if fr.Permissions.Type == "restricted" {
		scopes = convertStringSlice(fr.Permissions.AsRestricted().Scopes)
	}

	return map[string]*llx.RawData{
		"__id":              llx.StringData(providerID + "/" + fr.ID),
		"id":                llx.StringData(fr.ID),
		"name":              llx.StringData(fr.Name),
		"description":       llx.StringData(fr.Description),
		"enabled":           llx.BoolData(fr.Enabled),
		"attributeMatchers": llx.DictData(matchers),
		"permissionType":    llx.StringDataPtr(emptyToNil(fr.Permissions.Type)),
		"permissionScopes":  nullableStringArray(scopes),
		"createdAt":         llx.TimeDataPtr(unixToNullableTime(fr.CreatedAt)),
		"updatedAt":         llx.TimeDataPtr(unixToNullableTime(fr.UpdatedAt)),
	}, nil
}

// nullableStringArray reports a nil slice as a null array, so a field that does
// not apply stays distinct from one that applies and is empty.
func nullableStringArray(values []any) *llx.RawData {
	if values == nil {
		return llx.NilData
	}
	return llx.ArrayData(values, types.String)
}

// attributeMatcherValues reads each matcher's raw value. A matcher is a string,
// a boolean or a number, and reading the raw JSON keeps the value in the type
// the API sent instead of the zero value of the variants it did not.
func attributeMatcherValues(matchers map[string]openai.FederationRuleAttributeMatcherUnion) (map[string]any, error) {
	res := make(map[string]any, len(matchers))
	for name, m := range matchers {
		raw := m.RawJSON()
		if raw == "" {
			res[name] = nil
			continue
		}
		var v any
		if err := json.Unmarshal([]byte(raw), &v); err != nil {
			return nil, fmt.Errorf("matcher %s: %w", name, err)
		}
		res[name] = v
	}
	return res, nil
}

func (r *mqlOpenaiWorkloadIdentityProviderFederationRule) workloadIdentityProvider() (*mqlOpenaiWorkloadIdentityProvider, error) {
	if r.provider == nil {
		r.WorkloadIdentityProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return r.provider, nil
}

func (r *mqlOpenaiWorkloadIdentityProviderFederationRule) project() (*mqlOpenaiProject, error) {
	if r.cacheProjectId == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveProject(r.MqlRuntime, r.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

func (r *mqlOpenaiWorkloadIdentityProviderFederationRule) serviceAccount() (*mqlOpenaiProjectServiceAccount, error) {
	sa, err := findProjectServiceAccount(r.MqlRuntime, r.cacheProjectId, r.cacheServiceAccountId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		r.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return sa, nil
}

// openai.project.serviceAccount

func (r *mqlOpenaiProjectServiceAccount) federationRules() ([]any, error) {
	obj, err := CreateResource(r.MqlRuntime, "openai", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	providers := obj.(*mqlOpenai).GetWorkloadIdentityProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}

	var rules []any
	for _, item := range providers.Data {
		p, ok := item.(*mqlOpenaiWorkloadIdentityProvider)
		if !ok {
			continue
		}
		list := p.GetFederationRules()
		if list.Error != nil {
			return nil, list.Error
		}
		rules = append(rules, list.Data...)
	}
	return federationRulesFor(rules, r.cacheProjectId, r.Id.Data), nil
}

// federationRulesFor picks the rules that grant the service account with the
// given id in the given project.
func federationRulesFor(rules []any, projectID, serviceAccountID string) []any {
	res := []any{}
	if serviceAccountID == "" {
		return res
	}
	for _, item := range rules {
		fr, ok := item.(*mqlOpenaiWorkloadIdentityProviderFederationRule)
		if !ok || fr.cacheServiceAccountId != serviceAccountID {
			continue
		}
		if projectID != "" && fr.cacheProjectId != projectID {
			continue
		}
		res = append(res, fr)
	}
	return res
}
