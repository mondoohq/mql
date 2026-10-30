// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A partner as Graph returns it from GET policies/crossTenantAccessPolicy/partners,
// following the shape of the published v1.0 example. b2bCollaborationInbound
// and automaticUserConsentSettings are omitted, so they inherit the default.
const partnerJSON = `{
  "tenantId": "123f4846-ba00-4fd7-ba43-dac1f8f63013",
  "isServiceProvider": true,
  "isInMultiTenantOrganization": false,
  "inboundTrust": {
    "isMfaAccepted": true,
    "isCompliantDeviceAccepted": false,
    "isHybridAzureADJoinedDeviceAccepted": false
  },
  "b2bCollaborationOutbound": null,
  "b2bDirectConnectOutbound": {
    "usersAndGroups": {
      "accessType": "blocked",
      "targets": [{"target": "6f546279-4da5-4b53-a095-09ea0cef9971", "targetType": "group"}]
    },
    "applications": {
      "accessType": "allowed",
      "targets": [{"target": "AllApplications", "targetType": "application"}]
    }
  },
  "tenantRestrictions": {
    "devices": null,
    "usersAndGroups": {
      "accessType": "allowed",
      "targets": [{"target": "AllUsers", "targetType": "user"}]
    },
    "applications": {
      "accessType": "blocked",
      "targets": [{"target": "Office365", "targetType": "application"}]
    }
  }
}`

func parsePartner(t *testing.T, payload string) models.CrossTenantAccessPolicyConfigurationPartnerable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateCrossTenantAccessPolicyConfigurationPartnerFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.CrossTenantAccessPolicyConfigurationPartnerable)
}

func TestCrossTenantPartnerDecode(t *testing.T) {
	p := parsePartner(t, partnerJSON)

	require.NotNil(t, p.GetTenantId())
	assert.Equal(t, "123f4846-ba00-4fd7-ba43-dac1f8f63013", *p.GetTenantId())
	require.NotNil(t, p.GetIsServiceProvider())
	assert.True(t, *p.GetIsServiceProvider())
	require.NotNil(t, p.GetIsInMultiTenantOrganization())
	assert.False(t, *p.GetIsInMultiTenantOrganization())

	require.NotNil(t, p.GetInboundTrust())
	require.NotNil(t, p.GetInboundTrust().GetIsMfaAccepted())
	assert.True(t, *p.GetInboundTrust().GetIsMfaAccepted())

	// Omitted and explicit-null settings both decode as nil, which the
	// partner resource reports as null (inherits the default).
	assert.Nil(t, p.GetB2bCollaborationInbound())
	assert.Nil(t, p.GetB2bCollaborationOutbound())
	assert.Nil(t, p.GetAutomaticUserConsentSettings())

	out := p.GetB2bDirectConnectOutbound()
	require.NotNil(t, out)
	require.NotNil(t, out.GetUsersAndGroups())
	assert.Equal(t, "blocked", out.GetUsersAndGroups().GetAccessType().String())
	require.Len(t, out.GetUsersAndGroups().GetTargets(), 1)
	assert.Equal(t, "group", out.GetUsersAndGroups().GetTargets()[0].GetTargetType().String())

	// tenantRestrictions has its own model type; it is passed to newB2BSetting,
	// so its usersAndGroups and applications must decode through it.
	tr := p.GetTenantRestrictions()
	require.NotNil(t, tr)
	var asB2B models.CrossTenantAccessPolicyB2BSettingable = tr
	require.NotNil(t, asB2B.GetApplications())
	assert.Equal(t, "blocked", asB2B.GetApplications().GetAccessType().String())
	require.Len(t, asB2B.GetApplications().GetTargets(), 1)
	assert.Equal(t, "Office365", *asB2B.GetApplications().GetTargets()[0].GetTarget())
}

func parseIdentitySync(t *testing.T, payload string) models.CrossTenantIdentitySyncPolicyPartnerable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateCrossTenantIdentitySyncPolicyPartnerFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.CrossTenantIdentitySyncPolicyPartnerable)
}

func TestIsUserSyncInboundAllowed(t *testing.T) {
	allowed := parseIdentitySync(t, `{"tenantId": "t1", "displayName": "Fabrikam", "userSyncInbound": {"isSyncAllowed": true}}`)
	assert.True(t, isUserSyncInboundAllowed(allowed))

	denied := parseIdentitySync(t, `{"tenantId": "t1", "userSyncInbound": {"isSyncAllowed": false}}`)
	assert.False(t, isUserSyncInboundAllowed(denied))

	noBlock := parseIdentitySync(t, `{"tenantId": "t1"}`)
	assert.False(t, isUserSyncInboundAllowed(noBlock))

	noFlag := parseIdentitySync(t, `{"tenantId": "t1", "userSyncInbound": {}}`)
	assert.False(t, isUserSyncInboundAllowed(noFlag))

	assert.False(t, isUserSyncInboundAllowed(nil))
}

func TestCrossTenantPartnerId_DistinctPerPartnerAndFromDefault(t *testing.T) {
	a := crossTenantPartnerId("tenant-a") + "-inboundTrust"
	b := crossTenantPartnerId("tenant-b") + "-inboundTrust"
	assert.NotEqual(t, a, b)
	// The default configuration's sub-resources use this prefix.
	assert.NotEqual(t, "crossTenantAccessPolicyDefault-inboundTrust", a)
}
