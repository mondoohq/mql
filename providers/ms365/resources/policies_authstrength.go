// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// policyReadAll is the Graph application permission every policy read in this
// file needs.
const policyReadAll = "Policy.Read.All"

// authenticationStrengthPolicies lists the tenant's built-in and custom
// authentication strengths.
// https://learn.microsoft.com/en-us/graph/api/authenticationstrengthroot-list-policies
// requires Policy.Read.All
func (a *mqlMicrosoftPolicies) authenticationStrengthPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().AuthenticationStrengthPolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}
	strengths, err := iterate[models.AuthenticationStrengthPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateAuthenticationStrengthPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}

	res := []any{}
	for _, p := range strengths {
		if p == nil || p.GetId() == nil {
			continue
		}
		mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceMicrosoftPoliciesAuthenticationStrengthPolicy,
			map[string]*llx.RawData{
				"__id":                  llx.StringDataPtr(p.GetId()),
				"id":                    llx.StringDataPtr(p.GetId()),
				"displayName":           llx.StringDataPtr(p.GetDisplayName()),
				"description":           llx.StringDataPtr(p.GetDescription()),
				"policyType":            llx.StringDataPtr(enumPtrString(p.GetPolicyType())),
				"requirementsSatisfied": llx.StringDataPtr(enumPtrString(p.GetRequirementsSatisfied())),
				"allowedCombinations":   llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(p.GetAllowedCombinations())), types.String),
				"createdDateTime":       llx.TimeDataPtr(p.GetCreatedDateTime()),
				"modifiedDateTime":      llx.TimeDataPtr(p.GetModifiedDateTime()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// combinationConfigurations reads the per-method restrictions of the strength.
// The list endpoint does not return them, so they are read per strength.
func (a *mqlMicrosoftPoliciesAuthenticationStrengthPolicy) combinationConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	policyId := a.Id.Data
	resp, err := graphClient.Policies().AuthenticationStrengthPolicies().ByAuthenticationStrengthPolicyId(policyId).CombinationConfigurations().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}
	configs, err := iterate[models.AuthenticationCombinationConfigurationable](ctx, resp, graphClient.GetAdapter(), models.CreateAuthenticationCombinationConfigurationCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}

	res := []any{}
	for _, c := range configs {
		if c == nil || c.GetId() == nil {
			continue
		}
		fields := combinationConfigurationFields(c)
		mqlConfig, err := CreateResource(a.MqlRuntime, ResourceMicrosoftPoliciesAuthenticationStrengthPolicyCombinationConfiguration,
			map[string]*llx.RawData{
				"__id":                  llx.StringData(policyId + "/" + *c.GetId()),
				"id":                    llx.StringDataPtr(c.GetId()),
				"type":                  llx.StringData(fields.configType),
				"appliesToCombinations": llx.ArrayData(convert.SliceAnyToInterface(convertEnumCollectionToStrings(c.GetAppliesToCombinations())), types.String),
				"allowedAAGUIDs":        llx.ArrayData(convert.SliceAnyToInterface(fields.allowedAAGUIDs), types.String),
				"allowedIssuerSkis":     llx.ArrayData(convert.SliceAnyToInterface(fields.allowedIssuerSkis), types.String),
				"allowedPolicyOIDs":     llx.ArrayData(convert.SliceAnyToInterface(fields.allowedPolicyOIDs), types.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
	}
	return res, nil
}

type combinationConfigurationValues struct {
	configType        string
	allowedAAGUIDs    []string
	allowedIssuerSkis []string
	allowedPolicyOIDs []string
}

// combinationConfigurationFields reads the method-specific values of a
// combination configuration. The method is taken from the concrete type the
// SDK decoded, falling back to the OData type for a method the SDK does not
// model yet. The lists are never nil, so a configuration of another type
// reports empty lists rather than nulls.
func combinationConfigurationFields(c models.AuthenticationCombinationConfigurationable) combinationConfigurationValues {
	v := combinationConfigurationValues{
		allowedAAGUIDs:    []string{},
		allowedIssuerSkis: []string{},
		allowedPolicyOIDs: []string{},
	}
	switch cfg := c.(type) {
	case models.Fido2CombinationConfigurationable:
		v.configType = "fido2"
		if aaguids := cfg.GetAllowedAAGUIDs(); aaguids != nil {
			v.allowedAAGUIDs = aaguids
		}
	case models.X509CertificateCombinationConfigurationable:
		v.configType = "x509Certificate"
		if skis := cfg.GetAllowedIssuerSkis(); skis != nil {
			v.allowedIssuerSkis = skis
		}
		if oids := cfg.GetAllowedPolicyOIDs(); oids != nil {
			v.allowedPolicyOIDs = oids
		}
	default:
		v.configType = combinationConfigurationTypeFromOData(c.GetOdataType())
	}
	return v
}

// combinationConfigurationTypeFromOData turns an OData type such as
// "#microsoft.graph.fido2CombinationConfiguration" into "fido2".
func combinationConfigurationTypeFromOData(odataType *string) string {
	if odataType == nil {
		return ""
	}
	t := strings.TrimPrefix(*odataType, "#microsoft.graph.")
	return strings.TrimSuffix(t, "CombinationConfiguration")
}

// conditionalAccessPolicies lists the Conditional Access policies whose grant
// controls require this strength. It reads the tenant's Conditional Access
// policy list, which is fetched once and shared with
// microsoft.conditionalAccess.policies.
func (a *mqlMicrosoftPoliciesAuthenticationStrengthPolicy) conditionalAccessPolicies() ([]any, error) {
	caResource, err := CreateResource(a.MqlRuntime, ResourceMicrosoftConditionalAccess, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	caPolicies := caResource.(*mqlMicrosoftConditionalAccess).GetPolicies()
	if caPolicies.Error != nil {
		return nil, caPolicies.Error
	}

	res := []any{}
	for _, raw := range caPolicies.Data {
		p, ok := raw.(*mqlMicrosoftConditionalAccessPolicy)
		if !ok {
			continue
		}
		if conditionalAccessPolicyStrengthId(p) == a.Id.Data {
			res = append(res, p)
		}
	}
	return res, nil
}

// conditionalAccessPolicyStrengthId returns the id of the authentication
// strength a Conditional Access policy requires, or "" when it requires none.
func conditionalAccessPolicyStrengthId(p *mqlMicrosoftConditionalAccessPolicy) string {
	grant := p.GetGrantControls()
	if grant.Error != nil || grant.Data == nil {
		return ""
	}
	strength := grant.Data.GetAuthenticationStrength()
	if strength.Error != nil || strength.Data == nil {
		return ""
	}
	return strength.Data.Id.Data
}

// authenticationStrengthPolicy resolves the strength a Conditional Access
// policy requires to the tenant's strength policy, through the tenant's
// strength list.
func (a *mqlMicrosoftConditionalAccessPolicyGrantControlsAuthenticationStrength) authenticationStrengthPolicy() (*mqlMicrosoftPoliciesAuthenticationStrengthPolicy, error) {
	id := a.Id.Data
	if id == "" {
		a.AuthenticationStrengthPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	policiesResource, err := CreateResource(a.MqlRuntime, ResourceMicrosoftPolicies, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	strengths := policiesResource.(*mqlMicrosoftPolicies).GetAuthenticationStrengthPolicies()
	if strengths.Error != nil {
		return nil, strengths.Error
	}
	for _, raw := range strengths.Data {
		p, ok := raw.(*mqlMicrosoftPoliciesAuthenticationStrengthPolicy)
		if ok && p.Id.Data == id {
			return p, nil
		}
	}

	a.AuthenticationStrengthPolicy.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// authenticationFlowsPolicy reads the tenant's authentication flows policy.
// https://learn.microsoft.com/en-us/graph/api/authenticationflowspolicy-get
// requires Policy.Read.All
func (a *mqlMicrosoftPolicies) authenticationFlowsPolicy() (*mqlMicrosoftAuthenticationFlowsPolicy, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	policy, err := graphClient.Policies().AuthenticationFlowsPolicy().Get(context.Background(), nil)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}
	if policy == nil || policy.GetId() == nil {
		a.AuthenticationFlowsPolicy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	var selfServiceSignUp *bool
	if s := policy.GetSelfServiceSignUp(); s != nil {
		selfServiceSignUp = s.GetIsEnabled()
	}

	mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceMicrosoftAuthenticationFlowsPolicy,
		map[string]*llx.RawData{
			"__id":                     llx.StringDataPtr(policy.GetId()),
			"id":                       llx.StringDataPtr(policy.GetId()),
			"displayName":              llx.StringDataPtr(policy.GetDisplayName()),
			"description":              llx.StringDataPtr(policy.GetDescription()),
			"selfServiceSignUpEnabled": llx.BoolDataPtr(selfServiceSignUp),
		})
	if err != nil {
		return nil, err
	}
	return mqlPolicy.(*mqlMicrosoftAuthenticationFlowsPolicy), nil
}

// featureRolloutPolicies lists the tenant's staged rollout policies.
// https://learn.microsoft.com/en-us/graph/api/list-featurerolloutpolicies
// requires Policy.Read.All
func (a *mqlMicrosoftPolicies) featureRolloutPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().FeatureRolloutPolicies().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}
	rollouts, err := iterate[models.FeatureRolloutPolicyable](ctx, resp, graphClient.GetAdapter(), models.CreateFeatureRolloutPolicyCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}

	res := []any{}
	for _, p := range rollouts {
		if p == nil || p.GetId() == nil {
			continue
		}
		mqlPolicy, err := CreateResource(a.MqlRuntime, ResourceMicrosoftPoliciesFeatureRolloutPolicy,
			map[string]*llx.RawData{
				"__id":                    llx.StringDataPtr(p.GetId()),
				"id":                      llx.StringDataPtr(p.GetId()),
				"displayName":             llx.StringDataPtr(p.GetDisplayName()),
				"description":             llx.StringDataPtr(p.GetDescription()),
				"feature":                 llx.StringDataPtr(enumPtrString(p.GetFeature())),
				"isEnabled":               llx.BoolDataPtr(p.GetIsEnabled()),
				"isAppliedToOrganization": llx.BoolDataPtr(p.GetIsAppliedToOrganization()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// groups resolves the directory objects the rollout applies to. The list
// endpoint does not return them, so they are read per policy.
func (a *mqlMicrosoftPoliciesFeatureRolloutPolicy) groups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().FeatureRolloutPolicies().ByFeatureRolloutPolicyId(a.Id.Data).AppliesTo().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}
	objects, err := iterate[models.DirectoryObjectable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, policyReadAll)
	}

	return resolveDirectoryRefs(a.MqlRuntime, ResourceMicrosoftGroup, convert.SliceAnyToInterface(directoryObjectGroupIds(objects)))
}

// directoryObjectGroupIds returns the ids of the groups among a list of
// directory objects. Staged rollout only targets groups, but the API models
// the list as generic directory objects.
func directoryObjectGroupIds(objects []models.DirectoryObjectable) []string {
	ids := []string{}
	for _, o := range objects {
		if o == nil || o.GetId() == nil {
			continue
		}
		_, isGroup := o.(models.Groupable)
		if !isGroup && (o.GetOdataType() == nil || *o.GetOdataType() != "#microsoft.graph.group") {
			continue
		}
		ids = append(ids, *o.GetId())
	}
	return ids
}
