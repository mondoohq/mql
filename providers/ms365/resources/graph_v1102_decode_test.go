// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"testing"
	"time"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
)

// Every payload below is deserialized through the SDK's own discriminator
// factory rather than assembled with SetX calls. Kiota decides per property
// whether a value lands in the typed backing store or in AdditionalData, and it
// picks the concrete union member from @odata.type; a hand-built object skips
// both decisions and would pass over code that cannot read a real response.

func rawString(t *testing.T, args map[string]*llx.RawData, key string) string {
	t.Helper()
	raw, ok := args[key]
	require.True(t, ok, "argument %q missing", key)
	require.Equal(t, types.String, raw.Type, "argument %q is not a string", key)
	return raw.Value.(string)
}

// ---------------------------------------------------------------------------
// Item 7: access review reviewer scope
// ---------------------------------------------------------------------------

// namedReviewerScopeJSON is a reviewer named directly, the shape that reported
// nothing identifying before reviewerId and scopeType were exposed.
const namedReviewerScopeJSON = `{
  "@odata.type": "#microsoft.graph.accessReviewReviewerScope",
  "reviewerId": "8f9e0d54-3f2b-4c9a-9b7e-1a2b3c4d5e6f",
  "scopeType": "group"
}`

// queryReviewerScopeJSON selects reviewers with a query and reports no
// scopeType at all, which is the case the enum's zero value would misreport.
const queryReviewerScopeJSON = `{
  "@odata.type": "#microsoft.graph.accessReviewReviewerScope",
  "query": "/groups/07a3f2d1-8b6c-4d5e-9f0a-1b2c3d4e5f60/owners",
  "queryType": "MicrosoftGraph",
  "queryRoot": "decisions"
}`

func parseReviewerScope(t *testing.T, payload string) models.AccessReviewReviewerScopeable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateAccessReviewReviewerScopeFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.AccessReviewReviewerScopeable)
}

func TestAccessReviewReviewerScopeType_AbsentIsEmptyNotUser(t *testing.T) {
	// The Kiota enum's zero value is "user". Dereferencing a nil scope type
	// would report every query-selected reviewer as a directly named user.
	assert.Equal(t, "", accessReviewReviewerScopeType(nil))

	for _, name := range []string{"user", "group", "self", "manager", "sponsor", "resourceOwner", "managerOrSponsor", "unknownFutureValue"} {
		parsed, err := models.ParseAccessReviewReviewerScopeType(name)
		require.NoError(t, err)
		require.NotNil(t, parsed, "SDK no longer knows scope type %q", name)
		assert.Equal(t, name, accessReviewReviewerScopeType(parsed.(*models.AccessReviewReviewerScopeType)))
	}
}

func TestAccessReviewReviewerScopeArgs_NamedReviewer(t *testing.T) {
	args := newAccessReviewReviewerScopeArgs("def-1", 0, parseReviewerScope(t, namedReviewerScopeJSON))

	assert.Equal(t, "def-1/reviewerScopes/0", rawString(t, args, "__id"))
	assert.Equal(t, "8f9e0d54-3f2b-4c9a-9b7e-1a2b3c4d5e6f", rawString(t, args, "reviewerId"))
	assert.Equal(t, "group", rawString(t, args, "scopeType"))
	// A directly named reviewer carries no query; it must read null rather
	// than as an empty query that a policy could mistake for "selects nobody".
	assert.Equal(t, llx.NilData, args["query"])
	assert.Equal(t, llx.NilData, args["queryType"])
}

func TestAccessReviewReviewerScopeArgs_QuerySelectedReviewer(t *testing.T) {
	args := newAccessReviewReviewerScopeArgs("def-1", 2, parseReviewerScope(t, queryReviewerScopeJSON))

	assert.Equal(t, "def-1/reviewerScopes/2", rawString(t, args, "__id"))
	assert.Equal(t, "/groups/07a3f2d1-8b6c-4d5e-9f0a-1b2c3d4e5f60/owners", rawString(t, args, "query"))
	assert.Equal(t, "MicrosoftGraph", rawString(t, args, "queryType"))
	assert.Equal(t, "decisions", rawString(t, args, "queryRoot"))
	assert.Equal(t, "", rawString(t, args, "scopeType"))
	assert.Equal(t, llx.NilData, args["reviewerId"])
}

// TestAccessReviewReviewerScopeArgs_IdCarriesPosition pins the identity
// dimension: two reviewer scopes on one definition may hold identical values,
// and a cache key built from the definition alone would collapse them onto the
// first one's data.
func TestAccessReviewReviewerScopeArgs_IdCarriesPosition(t *testing.T) {
	scope := parseReviewerScope(t, namedReviewerScopeJSON)
	first := newAccessReviewReviewerScopeArgs("def-1", 0, scope)
	second := newAccessReviewReviewerScopeArgs("def-1", 1, scope)

	assert.NotEqual(t, rawString(t, first, "__id"), rawString(t, second, "__id"))
}

// ---------------------------------------------------------------------------
// Item 8: cross-tenant Microsoft 365 capability
// ---------------------------------------------------------------------------

// allowedCapabilityJSON is one capability of the heterogeneous collection the
// default policy returns, scoped to a group and excluding one user.
const allowedCapabilityJSON = `{
  "@odata.type": "#microsoft.graph.crossTenantCalendarSharingFreeBusyDetail",
  "name": "crossTenantCalendarSharingFreeBusyDetail",
  "lastModifiedDateTime": "2026-05-04T09:12:33Z",
  "inboundAccess": {
    "isAllowed": true,
    "resourceScopes": {
      "included": [
        { "resourceId": "b1c2d3e4-f506-4708-89ab-cdef01234567", "resourceType": "group" }
      ],
      "excluded": [
        { "resourceId": "0fedcba9-8765-4321-0fed-cba987654321", "resourceType": "user" }
      ]
    }
  }
}`

// blockedCapabilityJSON reports the capability as blocked and scopes it to
// every user with the literal All, which is not an object identifier.
const blockedCapabilityJSON = `{
  "@odata.type": "#microsoft.graph.crossTenantMailTipsAll",
  "name": "crossTenantMailTipsAll",
  "inboundAccess": {
    "isAllowed": false,
    "resourceScopes": {
      "included": [ { "resourceId": "All", "resourceType": "user" } ],
      "excluded": [ {} ]
    }
  }
}`

// capabilityWithoutInboundAccessJSON has no inboundAccess block at all.
const capabilityWithoutInboundAccessJSON = `{
  "@odata.type": "#microsoft.graph.crossTenantOpenProfileCard",
  "name": "crossTenantOpenProfileCard"
}`

func parseCapability(t *testing.T, payload string) models.M365CapabilityBaseable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateM365CapabilityBaseFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.M365CapabilityBaseable)
}

func TestM365CapabilityInboundAllowed(t *testing.T) {
	assert.True(t, m365CapabilityInboundAllowed(parseCapability(t, allowedCapabilityJSON)))
	assert.False(t, m365CapabilityInboundAllowed(parseCapability(t, blockedCapabilityJSON)))
	// No inbound access block means nothing was opened, which must read as
	// blocked rather than as an unread field an assertion would skip.
	assert.False(t, m365CapabilityInboundAllowed(parseCapability(t, capabilityWithoutInboundAccessJSON)))
}

func TestM365Capability_LastModifiedDateTimeDecodes(t *testing.T) {
	capability := parseCapability(t, allowedCapabilityJSON)
	require.NotNil(t, capability.GetLastModifiedDateTime())
	assert.Equal(t, time.Date(2026, 5, 4, 9, 12, 33, 0, time.UTC), capability.GetLastModifiedDateTime().UTC())

	// Absent stays absent, so the field reads null rather than reporting the
	// zero time as a real modification date.
	assert.Nil(t, parseCapability(t, capabilityWithoutInboundAccessJSON).GetLastModifiedDateTime())
}

func TestM365ResourceTypeString_AbsentIsEmptyNotNone(t *testing.T) {
	// The Kiota enum's zero value is "none", a deliberate "no resource type
	// selected". An absent value said nothing, and must not be reported as
	// that deliberate choice.
	assert.Equal(t, "", m365ResourceTypeString(nil))

	for _, name := range []string{"none", "group", "user", "unknownFutureValue"} {
		parsed, err := models.ParseM365ResourceType(name)
		require.NoError(t, err)
		require.NotNil(t, parsed, "SDK no longer knows resource type %q", name)
		assert.Equal(t, name, m365ResourceTypeString(parsed.(*models.M365ResourceType)))
	}
}

func TestM365CapabilityResourceScopeArgs(t *testing.T) {
	capability := parseCapability(t, allowedCapabilityJSON)
	scopes := capability.GetInboundAccess().GetResourceScopes()
	require.NotNil(t, scopes)
	require.Len(t, scopes.GetIncluded(), 1)
	require.Len(t, scopes.GetExcluded(), 1)

	included := newM365CapabilityResourceScopeArgs("cap/included", 0, scopes.GetIncluded()[0])
	assert.Equal(t, "cap/included/0", rawString(t, included, "__id"))
	assert.Equal(t, "b1c2d3e4-f506-4708-89ab-cdef01234567", rawString(t, included, "resourceId"))
	assert.Equal(t, "group", rawString(t, included, "resourceType"))

	excluded := newM365CapabilityResourceScopeArgs("cap/excluded", 0, scopes.GetExcluded()[0])
	assert.Equal(t, "cap/excluded/0", rawString(t, excluded, "__id"))
	assert.Equal(t, "0fedcba9-8765-4321-0fed-cba987654321", rawString(t, excluded, "resourceId"))
	assert.Equal(t, "user", rawString(t, excluded, "resourceType"))
}

// TestM365CapabilityResourceScopeArgs_EmptyExclusionPlaceholder covers the
// empty object Microsoft's own migration guidance sends as "nothing excluded".
// It has neither property, so both must read null rather than picking up the
// enum zero value.
func TestM365CapabilityResourceScopeArgs_EmptyExclusionPlaceholder(t *testing.T) {
	capability := parseCapability(t, blockedCapabilityJSON)
	excluded := capability.GetInboundAccess().GetResourceScopes().GetExcluded()
	require.Len(t, excluded, 1)

	args := newM365CapabilityResourceScopeArgs("cap/excluded", 0, excluded[0])
	assert.Equal(t, llx.NilData, args["resourceId"])
	assert.Equal(t, "", rawString(t, args, "resourceType"))
}

// ---------------------------------------------------------------------------
// Item 14: domain federation configuration
// ---------------------------------------------------------------------------

// federationConfigurationJSON is a federated domain that accepts the MFA claim
// asserted by its identity provider, the federated MFA bypass posture.
const federationConfigurationJSON = `{
  "@odata.type": "#microsoft.graph.internalDomainFederation",
  "id": "6f3b1c2a-9d4e-4f50-8a1b-2c3d4e5f6071",
  "displayName": "Contoso ADFS",
  "issuerUri": "http://contoso.com/adfs/services/trust",
  "metadataExchangeUri": "https://sts.contoso.com/adfs/services/trust/mex",
  "passiveSignInUri": "https://sts.contoso.com/adfs/ls/",
  "activeSignInUri": "https://sts.contoso.com/adfs/services/trust/2005/usernamemixed",
  "signOutUri": "https://sts.contoso.com/adfs/ls/",
  "passwordResetUri": "https://sts.contoso.com/adfs/portal/updatepassword/",
  "preferredAuthenticationProtocol": "wsFed",
  "federatedIdpMfaBehavior": "acceptIfMfaDoneByFederatedIdp",
  "isSignedAuthenticationRequestRequired": true,
  "promptLoginBehavior": "nativeSupport",
  "signingCertificate": "MIIDdzCCAl+gAwIBAgIEbG9jYWw=",
  "nextSigningCertificate": "MIIDdzCCAl+gAwIBAgIEbmV4dA==",
  "signingCertificateUpdateStatus": {
    "certificateUpdateResult": "success",
    "lastRunDateTime": "2026-04-01T02:30:00Z"
  },
  "systemBrowserEnabledOn": "ios,android"
}`

// minimalFederationConfigurationJSON reports only an identifier, the shape a
// freshly created federation carries before rotation has ever run.
const minimalFederationConfigurationJSON = `{
  "@odata.type": "#microsoft.graph.internalDomainFederation",
  "id": "1a2b3c4d-5e6f-4071-8293-a4b5c6d7e8f9"
}`

func parseFederationConfiguration(t *testing.T, payload string) models.InternalDomainFederationable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateInternalDomainFederationFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.InternalDomainFederationable)
}

func TestFederatedIdpMfaBehaviorString_AbsentIsEmptyNotPermissive(t *testing.T) {
	// The Kiota enum's zero value is acceptIfMfaDoneByFederatedIdp, the
	// permissive setting. Dereferencing a nil would report the federated MFA
	// bypass as configured on a domain that reported nothing.
	assert.Equal(t, "", federatedIdpMfaBehaviorString(nil))

	for _, name := range []string{"acceptIfMfaDoneByFederatedIdp", "enforceMfaByFederatedIdp", "rejectMfaByFederatedIdp", "unknownFutureValue"} {
		parsed, err := models.ParseFederatedIdpMfaBehavior(name)
		require.NoError(t, err)
		require.NotNil(t, parsed, "SDK no longer knows MFA behavior %q", name)
		assert.Equal(t, name, federatedIdpMfaBehaviorString(parsed.(*models.FederatedIdpMfaBehavior)))
	}
}

func TestPromptLoginBehaviorString(t *testing.T) {
	assert.Equal(t, "", promptLoginBehaviorString(nil))

	for _, name := range []string{"translateToFreshPasswordAuthentication", "nativeSupport", "disabled", "unknownFutureValue"} {
		parsed, err := models.ParsePromptLoginBehavior(name)
		require.NoError(t, err)
		require.NotNil(t, parsed, "SDK no longer knows prompt login behavior %q", name)
		assert.Equal(t, name, promptLoginBehaviorString(parsed.(*models.PromptLoginBehavior)))
	}
}

func TestAuthenticationProtocolString(t *testing.T) {
	assert.Equal(t, "", authenticationProtocolString(nil))

	for _, name := range []string{"wsFed", "saml", "unknownFutureValue"} {
		parsed, err := models.ParseAuthenticationProtocol(name)
		require.NoError(t, err)
		require.NotNil(t, parsed, "SDK no longer knows authentication protocol %q", name)
		assert.Equal(t, name, authenticationProtocolString(parsed.(*models.AuthenticationProtocol)))
	}
}

// TestSystemBrowserEnabledOnList covers the flags enum the SDK renders as one
// comma-joined string. An unset flag set renders as "", which a plain Split
// would turn into a list holding a single empty platform name.
func TestSystemBrowserEnabledOnList(t *testing.T) {
	assert.Equal(t, []any{}, systemBrowserEnabledOnList(nil))

	var unset models.SystemBrowserEnabledOn
	assert.Equal(t, []any{}, systemBrowserEnabledOnList(&unset))

	parsed, err := models.ParseSystemBrowserEnabledOn("ios,android")
	require.NoError(t, err)
	require.NotNil(t, parsed)
	assert.Equal(t, []any{"ios", "android"}, systemBrowserEnabledOnList(parsed.(*models.SystemBrowserEnabledOn)))

	single, err := models.ParseSystemBrowserEnabledOn("none")
	require.NoError(t, err)
	assert.Equal(t, []any{"none"}, systemBrowserEnabledOnList(single.(*models.SystemBrowserEnabledOn)))
}

func TestDomainFederationConfigurationArgs(t *testing.T) {
	args := newDomainFederationConfigurationArgs("contoso.com", parseFederationConfiguration(t, federationConfigurationJSON))

	assert.Equal(t, "contoso.com/federationConfiguration/6f3b1c2a-9d4e-4f50-8a1b-2c3d4e5f6071", rawString(t, args, "__id"))
	assert.Equal(t, "Contoso ADFS", rawString(t, args, "displayName"))
	assert.Equal(t, "http://contoso.com/adfs/services/trust", rawString(t, args, "issuerUri"))
	assert.Equal(t, "https://sts.contoso.com/adfs/services/trust/mex", rawString(t, args, "metadataExchangeUri"))
	assert.Equal(t, "https://sts.contoso.com/adfs/ls/", rawString(t, args, "passiveSignInUri"))
	assert.Equal(t, "https://sts.contoso.com/adfs/services/trust/2005/usernamemixed", rawString(t, args, "activeSignInUri"))
	assert.Equal(t, "https://sts.contoso.com/adfs/portal/updatepassword/", rawString(t, args, "passwordResetUri"))
	assert.Equal(t, "wsFed", rawString(t, args, "preferredAuthenticationProtocol"))
	assert.Equal(t, "acceptIfMfaDoneByFederatedIdp", rawString(t, args, "federatedIdpMfaBehavior"))
	assert.Equal(t, "nativeSupport", rawString(t, args, "promptLoginBehavior"))
	assert.Equal(t, "MIIDdzCCAl+gAwIBAgIEbG9jYWw=", rawString(t, args, "signingCertificate"))
	assert.Equal(t, "MIIDdzCCAl+gAwIBAgIEbmV4dA==", rawString(t, args, "nextSigningCertificate"))
	assert.Equal(t, "success", rawString(t, args, "signingCertificateUpdateResult"))
	assert.Equal(t, true, args["isSignedAuthenticationRequestRequired"].Value)
	assert.Equal(t, []any{"ios", "android"}, args["systemBrowserEnabledOn"].Value)

	lastRun, ok := args["signingCertificateUpdateLastRunDateTime"].Value.(*time.Time)
	require.True(t, ok, "rotation timestamp did not decode as a time")
	assert.Equal(t, time.Date(2026, 4, 1, 2, 30, 0, 0, time.UTC), lastRun.UTC())
}

// TestDomainFederationConfigurationArgs_Minimal pins the absent case: a
// federation that has never rotated reports no rotation, not a successful one
// that ran at the zero time.
func TestDomainFederationConfigurationArgs_Minimal(t *testing.T) {
	args := newDomainFederationConfigurationArgs("contoso.com", parseFederationConfiguration(t, minimalFederationConfigurationJSON))

	assert.Equal(t, "", rawString(t, args, "signingCertificateUpdateResult"))
	assert.Equal(t, llx.NilData, args["signingCertificateUpdateLastRunDateTime"])
	assert.Equal(t, "", rawString(t, args, "federatedIdpMfaBehavior"))
	assert.Equal(t, "", rawString(t, args, "promptLoginBehavior"))
	assert.Equal(t, "", rawString(t, args, "preferredAuthenticationProtocol"))
	assert.Equal(t, []any{}, args["systemBrowserEnabledOn"].Value)
	assert.Equal(t, llx.NilData, args["signingCertificate"])
}

// ---------------------------------------------------------------------------
// Item 17: entitlement management external origin resource connector
// ---------------------------------------------------------------------------

// sapIagConnectorJSON is the SAP Cloud Identity Access Governance connector.
// It carries a stray clientSecret that Microsoft Graph does not return, present
// only so the credential-omission test has something to catch.
const sapIagConnectorJSON = `{
  "@odata.type": "#microsoft.graph.externalOriginResourceConnector",
  "id": "e363ebb8-6faa-4980-ac5b-eefc196e1cd4",
  "displayName": "SAP IAG production",
  "description": "Pulls SAP roles into entitlement management",
  "connectorType": "sapIag",
  "createdBy": "9a8b7c6d-5e4f-4032-8190-abcdef012345",
  "createdDateTime": "2026-02-11T14:05:00Z",
  "modifiedBy": "9a8b7c6d-5e4f-4032-8190-abcdef012345",
  "modifiedDateTime": "2026-03-02T08:44:10Z",
  "connectionInfo": {
    "@odata.type": "#microsoft.graph.externalTokenBasedSapIagConnectionInfo",
    "url": "https://iag.contoso.example/api",
    "accessTokenUrl": "https://iag.contoso.example/oauth/token",
    "clientId": "sb-iag-integration",
    "subscriptionId": "3c4d5e6f-7081-4293-a4b5-c6d7e8f90123",
    "resourceGroup": "rg-identity",
    "keyVaultName": "kv-identity-prod",
    "secretName": "sap-iag-client-secret",
    "clientSecret": "NEVER-REPORT-THIS-VALUE"
  }
}`

// unmodeledConnectionInfoJSON uses the base connectionInfo shape, standing in
// for a union member added after this code was written.
const unmodeledConnectionInfoJSON = `{
  "@odata.type": "#microsoft.graph.externalOriginResourceConnector",
  "id": "7d8e9f00-1122-4334-8556-778899aabbcc",
  "displayName": "Some future system",
  "connectionInfo": {
    "@odata.type": "#microsoft.graph.connectionInfo",
    "url": "https://future.contoso.example/api"
  }
}`

func parseConnector(t *testing.T, payload string) models.ExternalOriginResourceConnectorable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateExternalOriginResourceConnectorFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.ExternalOriginResourceConnectorable)
}

func TestConnectorTypeString_AbsentIsEmptyNotSapIag(t *testing.T) {
	// The Kiota enum's zero value is "sapIag". Dereferencing a nil would name
	// an external system Microsoft Graph never reported.
	assert.Equal(t, "", connectorTypeString(nil))

	for _, name := range []string{"sapIag", "unknownFutureValue"} {
		parsed, err := models.ParseConnectorType(name)
		require.NoError(t, err)
		require.NotNil(t, parsed, "SDK no longer knows connector type %q", name)
		assert.Equal(t, name, connectorTypeString(parsed.(*models.ConnectorType)))
	}
}

func TestConnectionArgs_TokenBasedSapIagMember(t *testing.T) {
	connector := parseConnector(t, sapIagConnectorJSON)
	require.NotNil(t, connector.GetConnectionInfo())

	args := newMqlConnectionArgs("conn/connectionInfo", connector.GetConnectionInfo())

	assert.Equal(t, connectionInfoKindSapIag, rawString(t, args, "kind"))
	assert.Equal(t, "https://iag.contoso.example/api", rawString(t, args, "url"))
	assert.Equal(t, "https://iag.contoso.example/oauth/token", rawString(t, args, "accessTokenUrl"))
	assert.Equal(t, "sb-iag-integration", rawString(t, args, "clientId"))
	assert.Equal(t, "3c4d5e6f-7081-4293-a4b5-c6d7e8f90123", rawString(t, args, "subscriptionId"))
	assert.Equal(t, "rg-identity", rawString(t, args, "resourceGroup"))
	assert.Equal(t, "kv-identity-prod", rawString(t, args, "keyVaultName"))
	assert.Equal(t, "sap-iag-client-secret", rawString(t, args, "secretName"))
}

// TestConnectionArgs_UnmodeledMemberReportsUnknown covers the union's default
// branch. A member this provider does not model must say so through kind, and
// still report the base url, rather than reading as a connector with no
// connection details.
func TestConnectionArgs_UnmodeledMemberReportsUnknown(t *testing.T) {
	connector := parseConnector(t, unmodeledConnectionInfoJSON)
	require.NotNil(t, connector.GetConnectionInfo())

	args := newMqlConnectionArgs("conn/connectionInfo", connector.GetConnectionInfo())

	assert.Equal(t, connectionInfoKindUnknown, rawString(t, args, "kind"))
	assert.Equal(t, "https://future.contoso.example/api", rawString(t, args, "url"))
	// The SAP-only fields read null, not empty: nothing was reported for them.
	for _, key := range []string{"accessTokenUrl", "clientId", "subscriptionId", "resourceGroup", "keyVaultName", "secretName"} {
		assert.Equal(t, llx.NilData, args[key], "field %q should be null on an unmodeled member", key)
	}
}

// TestConnectionArgs_OmitsCredentialMaterial is the guarantee the schema makes:
// the connector reports where its secret lives, never the secret. The payload
// carries a clientSecret in the connection object; every argument value must be
// free of it, and no argument may exist beyond the declared set. This fails the
// moment someone spills AdditionalData or adds a credential field.
func TestConnectionArgs_OmitsCredentialMaterial(t *testing.T) {
	const secret = "NEVER-REPORT-THIS-VALUE"

	connector := parseConnector(t, sapIagConnectorJSON)
	args := newMqlConnectionArgs("conn/connectionInfo", connector.GetConnectionInfo())

	declared := map[string]struct{}{
		"__id": {}, "kind": {}, "url": {}, "accessTokenUrl": {}, "clientId": {},
		"subscriptionId": {}, "resourceGroup": {}, "keyVaultName": {}, "secretName": {},
	}
	for key, raw := range args {
		_, ok := declared[key]
		assert.True(t, ok, "undeclared argument %q reached the connection resource", key)
		if value, isString := raw.Value.(string); isString {
			assert.False(t, strings.Contains(value, secret), "argument %q carries credential material", key)
		}
	}
}
