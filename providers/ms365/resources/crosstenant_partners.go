// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
)

// crossTenantPolicyPermission is the Graph application permission every
// cross-tenant access policy read needs.
const crossTenantPolicyPermission = "Policy.Read.All"

// crossTenantPartnerId builds the __id of a partner configuration. The settings
// below a partner derive their ids from it, so two partners never share a
// cached b2bSetting, inboundTrust or consent settings resource, and none of them
// collides with the default configuration's ("crossTenantAccessPolicyDefault-...").
func crossTenantPartnerId(tenantId string) string {
	return "crossTenantAccessPolicyPartner/" + tenantId
}

// crossTenantAllowedCloudEndpoints lists the additional Microsoft clouds the
// tenant collaborates with, read from the top-level cross-tenant access policy.
func (a *mqlMicrosoftPolicies) crossTenantAllowedCloudEndpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	policy, err := graphClient.Policies().CrossTenantAccessPolicy().Get(context.Background(), nil)
	if err != nil {
		return nil, classifyGraphError(err, crossTenantPolicyPermission)
	}
	if policy == nil {
		return nil, errors.New("cross-tenant access policy not found")
	}

	res := []any{}
	for _, endpoint := range policy.GetAllowedCloudEndpoints() {
		res = append(res, endpoint)
	}
	return res, nil
}

// crossTenantAccessPolicyPartners lists the partner-specific cross-tenant
// access configurations. The list response carries every inline setting of a
// partner, so the whole resource is built from it.
func (a *mqlMicrosoftPolicies) crossTenantAccessPolicyPartners() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	resp, err := graphClient.Policies().CrossTenantAccessPolicy().Partners().Get(ctx, nil)
	if err != nil {
		return nil, classifyGraphError(err, crossTenantPolicyPermission)
	}
	if resp == nil {
		return []any{}, nil
	}

	partners, err := iterate[models.CrossTenantAccessPolicyConfigurationPartnerable](ctx, resp, graphClient.GetAdapter(), models.CreateCrossTenantAccessPolicyConfigurationPartnerCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyGraphError(err, crossTenantPolicyPermission)
	}

	res := []any{}
	for _, partner := range partners {
		if partner == nil || partner.GetTenantId() == nil || *partner.GetTenantId() == "" {
			continue
		}
		mqlPartner, err := newMqlCrossTenantAccessPolicyPartner(a.MqlRuntime, partner)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPartner)
	}
	return res, nil
}

func newMqlCrossTenantAccessPolicyPartner(runtime *plugin.Runtime, partner models.CrossTenantAccessPolicyConfigurationPartnerable) (*mqlMicrosoftCrossTenantAccessPolicyPartner, error) {
	tenantId := *partner.GetTenantId()
	id := crossTenantPartnerId(tenantId)

	b2bSetting := func(setting models.CrossTenantAccessPolicyB2BSettingable, name string) (*llx.RawData, error) {
		if setting == nil {
			return llx.NilData, nil
		}
		r, err := newB2BSetting(runtime, setting, id+"-"+name)
		if err != nil {
			return nil, err
		}
		return llx.ResourceData(r, string(ResourceMicrosoftCrossTenantAccessPolicyDefaultB2bSetting)), nil
	}

	args := map[string]*llx.RawData{
		"__id":                         llx.StringData(id),
		"tenantId":                     llx.StringData(tenantId),
		"isServiceProvider":            llx.BoolDataPtr(partner.GetIsServiceProvider()),
		"isInMultiTenantOrganization":  llx.BoolDataPtr(partner.GetIsInMultiTenantOrganization()),
		"automaticUserConsentSettings": llx.NilData,
		"inboundTrust":                 llx.NilData,
	}

	b2bSettings := []struct {
		name    string
		setting models.CrossTenantAccessPolicyB2BSettingable
	}{
		{"b2bCollaborationInbound", partner.GetB2bCollaborationInbound()},
		{"b2bCollaborationOutbound", partner.GetB2bCollaborationOutbound()},
		{"b2bDirectConnectInbound", partner.GetB2bDirectConnectInbound()},
		{"b2bDirectConnectOutbound", partner.GetB2bDirectConnectOutbound()},
	}
	if tr := partner.GetTenantRestrictions(); tr != nil {
		b2bSettings = append(b2bSettings, struct {
			name    string
			setting models.CrossTenantAccessPolicyB2BSettingable
		}{"tenantRestrictions", tr})
	} else {
		args["tenantRestrictions"] = llx.NilData
	}
	for _, s := range b2bSettings {
		data, err := b2bSetting(s.setting, s.name)
		if err != nil {
			return nil, err
		}
		args[s.name] = data
	}

	if consent := partner.GetAutomaticUserConsentSettings(); consent != nil {
		r, err := newAutomaticUserConsentSettings(runtime, consent, id+"-automaticUserConsentSettings")
		if err != nil {
			return nil, err
		}
		args["automaticUserConsentSettings"] = llx.ResourceData(r, string(ResourceMicrosoftCrossTenantAccessPolicyDefaultAutomaticUserConsentSettings))
	}

	if trust := partner.GetInboundTrust(); trust != nil {
		r, err := newInboundTrust(runtime, trust, id+"-inboundTrust")
		if err != nil {
			return nil, err
		}
		args["inboundTrust"] = llx.ResourceData(r, string(ResourceMicrosoftCrossTenantAccessPolicyDefaultInboundTrust))
	}

	resource, err := CreateResource(runtime, ResourceMicrosoftCrossTenantAccessPolicyPartner, args)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlMicrosoftCrossTenantAccessPolicyPartner), nil
}

// isUserSyncInboundAllowed reads whether an identity synchronization policy
// lets the partner's users be synchronized into this tenant. An absent policy,
// an absent userSyncInbound block, and an absent isSyncAllowed all mean no
// synchronization is allowed, so each reads false.
func isUserSyncInboundAllowed(policy models.CrossTenantIdentitySyncPolicyPartnerable) bool {
	if policy == nil {
		return false
	}
	inbound := policy.GetUserSyncInbound()
	if inbound == nil || inbound.GetIsSyncAllowed() == nil {
		return false
	}
	return *inbound.GetIsSyncAllowed()
}

// userSyncInboundAllowed reads the partner's identity synchronization policy,
// a navigation property the partner list does not return.
func (a *mqlMicrosoftCrossTenantAccessPolicyPartner) userSyncInboundAllowed() (bool, error) {
	if a.TenantId.Error != nil {
		return false, a.TenantId.Error
	}
	if a.TenantId.Data == "" {
		return false, errors.New("partner tenantId is required to read its identity synchronization policy")
	}

	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return false, err
	}

	policy, err := graphClient.Policies().CrossTenantAccessPolicy().Partners().
		ByCrossTenantAccessPolicyConfigurationPartnerTenantId(a.TenantId.Data).
		IdentitySynchronization().
		Get(context.Background(), nil)
	if err != nil {
		// Graph answers 404 for a partner that has no identity synchronization
		// policy, which means no user may be synchronized from it.
		if graphStatusCode(err) == 404 {
			return false, nil
		}
		return false, classifyGraphError(err, crossTenantPolicyPermission)
	}
	return isUserSyncInboundAllowed(policy), nil
}
