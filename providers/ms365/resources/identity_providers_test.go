// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"go.mondoo.com/mql/types"
	"net/http"
	"strings"
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Payloads below follow the Microsoft Graph v1.0 documentation examples and
// are decoded through the SDK's own discriminator factory, so the provider
// kind is picked from @odata.type exactly as for a live response.

const socialIdpJSON = `{
  "@odata.type": "#microsoft.graph.socialIdentityProvider",
  "id": "Google-OAUTH",
  "displayName": "Login with Google",
  "identityProviderType": "Google",
  "clientId": "56433757-cadd-4135-8431-2c9e3fd68ae8",
  "clientSecret": "SECRET-VALUE-MUST-NOT-LEAK"
}`

const builtInIdpJSON = `{
  "@odata.type": "#microsoft.graph.builtInIdentityProvider",
  "id": "EmailOtpSignup-OAUTH",
  "displayName": "Email One Time Passcode",
  "identityProviderType": "EmailOTP"
}`

const appleIdpJSON = `{
  "@odata.type": "#microsoft.graph.appleManagedIdentityProvider",
  "id": "Apple-Managed-OIDC",
  "displayName": "Sign in with Apple",
  "developerId": "UBF8T346G9",
  "serviceId": "com.contoso.app",
  "keyId": "99P6D879C4",
  "certificateData": "PRIVATE-KEY-MUST-NOT-LEAK"
}`

const oidcIdpJSON = `{
  "@odata.type": "#microsoft.graph.oidcIdentityProvider",
  "id": "contoso-oidc",
  "displayName": "Contoso OIDC",
  "clientId": "00001111-aaaa-2222-bbbb-3333cccc4444",
  "issuer": "https://login.contoso.com/",
  "wellKnownEndpoint": "https://login.contoso.com/.well-known/openid-configuration",
  "responseType": "code",
  "scope": "openid profile email",
  "clientAuthentication": {
    "@odata.type": "#microsoft.graph.oidcClientSecretAuthentication",
    "clientSecret": "OIDC-SECRET-MUST-NOT-LEAK"
  }
}`

const samlIdpJSON = `{
  "@odata.type": "#microsoft.graph.samlOrWsFedExternalDomainFederation",
  "id": "8d9c4f57-5a4d-4d5b-9b0e-1a2b3c4d5e6f",
  "displayName": "Contoso",
  "issuerUri": "https://contoso.com/issuerUri",
  "metadataExchangeUri": "https://contoso.com/metadataExchangeUri",
  "passiveSignInUri": "https://contoso.com/signin",
  "preferredAuthenticationProtocol": "wsFed",
  "signingCertificate": "MIIDADCCAeigAwIBAgIQEX41y8r6",
  "domains": [
    {"@odata.type": "#microsoft.graph.externalDomainName", "id": "contoso.com"},
    {"@odata.type": "#microsoft.graph.externalDomainName", "id": "fabrikam.com"}
  ]
}`

func parseIdentityProvider(t *testing.T, payload string) models.IdentityProviderBaseable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateIdentityProviderBaseFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.IdentityProviderBaseable)
}

func assertIdpNull(t *testing.T, args map[string]*llx.RawData, keys ...string) {
	t.Helper()
	for _, key := range keys {
		raw, ok := args[key]
		require.True(t, ok, "argument %q missing", key)
		assert.Nil(t, raw.Value, "argument %q should be null", key)
	}
}

// assertIdpNoSecret fails when any argument carries the given secret value.
func assertIdpNoSecret(t *testing.T, args map[string]*llx.RawData, secret string) {
	t.Helper()
	for key, raw := range args {
		if s, ok := raw.Value.(string); ok {
			assert.NotContains(t, s, secret, "argument %q leaks a secret", key)
		}
	}
}

func TestIdentityProviderArgs_Social(t *testing.T) {
	args := newIdentityProviderArgs(parseIdentityProvider(t, socialIdpJSON))

	assert.Equal(t, "Google-OAUTH", rawString(t, args, "__id"))
	assert.Equal(t, "socialIdentityProvider", rawString(t, args, "type"))
	assert.Equal(t, "Google", rawString(t, args, "identityProviderType"))
	assert.Equal(t, "56433757-cadd-4135-8431-2c9e3fd68ae8", rawString(t, args, "clientId"))
	assertIdpNull(t, args, "issuer", "issuerUri", "developerId", "clientAuthenticationMethod")
	assertIdpNoSecret(t, args, "SECRET-VALUE-MUST-NOT-LEAK")
}

func TestIdentityProviderArgs_BuiltIn(t *testing.T) {
	args := newIdentityProviderArgs(parseIdentityProvider(t, builtInIdpJSON))

	assert.Equal(t, "builtInIdentityProvider", rawString(t, args, "type"))
	assert.Equal(t, "EmailOTP", rawString(t, args, "identityProviderType"))
	assertIdpNull(t, args, "clientId")
}

func TestIdentityProviderArgs_Apple(t *testing.T) {
	args := newIdentityProviderArgs(parseIdentityProvider(t, appleIdpJSON))

	assert.Equal(t, "appleManagedIdentityProvider", rawString(t, args, "type"))
	assert.Equal(t, "UBF8T346G9", rawString(t, args, "developerId"))
	assert.Equal(t, "com.contoso.app", rawString(t, args, "serviceId"))
	assert.Equal(t, "99P6D879C4", rawString(t, args, "keyId"))
	assertIdpNull(t, args, "identityProviderType", "clientId")
	assertIdpNoSecret(t, args, "PRIVATE-KEY-MUST-NOT-LEAK")
}

func TestIdentityProviderArgs_Oidc(t *testing.T) {
	args := newIdentityProviderArgs(parseIdentityProvider(t, oidcIdpJSON))

	assert.Equal(t, "oidcIdentityProvider", rawString(t, args, "type"))
	assert.Equal(t, "00001111-aaaa-2222-bbbb-3333cccc4444", rawString(t, args, "clientId"))
	assert.Equal(t, "https://login.contoso.com/", rawString(t, args, "issuer"))
	assert.Equal(t, "https://login.contoso.com/.well-known/openid-configuration", rawString(t, args, "wellKnownEndpoint"))
	assert.Equal(t, "code", rawString(t, args, "responseType"))
	assert.Equal(t, "openid profile email", rawString(t, args, "scope"))
	assert.Equal(t, "clientSecret", rawString(t, args, "clientAuthenticationMethod"))
	assertIdpNoSecret(t, args, "OIDC-SECRET-MUST-NOT-LEAK")
}

func TestIdentityProviderArgs_OidcPrivateKeyJwt(t *testing.T) {
	payload := strings.Replace(oidcIdpJSON, "#microsoft.graph.oidcClientSecretAuthentication", "#microsoft.graph.oidcPrivateJwtKeyClientAuthentication", 1)
	args := newIdentityProviderArgs(parseIdentityProvider(t, payload))
	assert.Equal(t, "privateKeyJwt", rawString(t, args, "clientAuthenticationMethod"))
}

func TestIdentityProviderArgs_OidcAbsentResponseTypeIsNull(t *testing.T) {
	// The OidcResponseType zero value renders as an empty string, but an absent
	// value must stay null rather than read as a configured response type.
	payload := strings.Replace(oidcIdpJSON, `"responseType": "code",`, "", 1)
	args := newIdentityProviderArgs(parseIdentityProvider(t, payload))
	assertIdpNull(t, args, "responseType")
}

func TestIdentityProviderArgs_SamlOrWsFed(t *testing.T) {
	args := newIdentityProviderArgs(parseIdentityProvider(t, samlIdpJSON))

	assert.Equal(t, "samlOrWsFedExternalDomainFederation", rawString(t, args, "type"))
	assert.Equal(t, "https://contoso.com/issuerUri", rawString(t, args, "issuerUri"))
	assert.Equal(t, "https://contoso.com/metadataExchangeUri", rawString(t, args, "metadataExchangeUri"))
	assert.Equal(t, "https://contoso.com/signin", rawString(t, args, "passiveSignInUri"))
	assert.Equal(t, "wsFed", rawString(t, args, "preferredAuthenticationProtocol"))
	assert.Equal(t, "MIIDADCCAeigAwIBAgIQEX41y8r6", rawString(t, args, "signingCertificate"))
	assert.Equal(t, []any{"contoso.com", "fabrikam.com"}, args["domains"].Value)
	assertStringList(t, args["domains"])
	assertIdpNull(t, args, "identityProviderType", "clientId")
}

func TestIdentityProviderArgs_AbsentProtocolIsNullNotWsFed(t *testing.T) {
	// The AuthenticationProtocol zero value is wsFed; an absent protocol must
	// not read as one.
	payload := strings.Replace(samlIdpJSON, `"preferredAuthenticationProtocol": "wsFed",`, "", 1)
	args := newIdentityProviderArgs(parseIdentityProvider(t, payload))
	assertIdpNull(t, args, "preferredAuthenticationProtocol")
}

func TestIdentityProviderArgs_UnmodeledKindIsUnknown(t *testing.T) {
	payload := `{"@odata.type": "#microsoft.graph.identityProviderBase", "id": "x", "displayName": "X"}`
	args := newIdentityProviderArgs(parseIdentityProvider(t, payload))
	assert.Equal(t, "unknown", rawString(t, args, "type"))
	assert.Equal(t, []any{}, args["domains"].Value)
	assertStringList(t, args["domains"])
}

// assertStringList checks a []string field carries the string array type and
// serializes. A malformed element type makes Result panic.
func assertStringList(t *testing.T, data *llx.RawData) {
	t.Helper()
	assert.Equal(t, types.Array(types.String), data.Type)
	assert.NotPanics(t, func() { data.Result() })
}

const b2xUserFlowJSON = `{
  "@odata.type": "#microsoft.graph.b2xIdentityUserFlow",
  "id": "B2X_1_Partner",
  "userFlowType": "signUp",
  "userFlowTypeVersion": 1,
  "apiConnectorConfiguration": {
    "postFederationSignup": {
      "id": "be1f2d5a-6c0e-4b7d-8f3a-1a2b3c4d5e6f",
      "displayName": "Approval",
      "targetUrl": "https://approval.contoso.com/signup",
      "authenticationConfiguration": {
        "@odata.type": "#microsoft.graph.basicAuthentication",
        "username": "flowuser",
        "password": "BASIC-PASSWORD-MUST-NOT-LEAK"
      }
    }
  }
}`

func parseB2xUserFlow(t *testing.T, payload string) models.B2xIdentityUserFlowable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateB2xIdentityUserFlowFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.B2xIdentityUserFlowable)
}

func TestB2xUserFlowArgs(t *testing.T) {
	args := newB2xUserFlowArgs(parseB2xUserFlow(t, b2xUserFlowJSON))
	assert.Equal(t, "B2X_1_Partner", rawString(t, args, "__id"))
	assert.Equal(t, "signUp", rawString(t, args, "userFlowType"))
	assert.Equal(t, float64(1), args["userFlowTypeVersion"].Value)
}

func TestB2xUserFlowArgs_AbsentTypeIsNullNotSignUp(t *testing.T) {
	// The UserFlowType zero value is signUp.
	payload := `{"@odata.type": "#microsoft.graph.b2xIdentityUserFlow", "id": "B2X_1_X"}`
	args := newB2xUserFlowArgs(parseB2xUserFlow(t, payload))
	assertIdpNull(t, args, "userFlowType", "userFlowTypeVersion")
}

func TestApiConnectorArgs_Basic(t *testing.T) {
	flow := parseB2xUserFlow(t, b2xUserFlowJSON)
	cfg := flow.GetApiConnectorConfiguration()
	require.NotNil(t, cfg)
	require.Nil(t, cfg.GetPostAttributeCollection())
	connector := cfg.GetPostFederationSignup()
	require.NotNil(t, connector)

	args := newApiConnectorArgs(connector)
	assert.Equal(t, "be1f2d5a-6c0e-4b7d-8f3a-1a2b3c4d5e6f", rawString(t, args, "__id"))
	assert.Equal(t, "Approval", rawString(t, args, "displayName"))
	assert.Equal(t, "https://approval.contoso.com/signup", rawString(t, args, "targetUrl"))
	assert.Equal(t, "basic", rawString(t, args, "authenticationType"))
	assertIdpNoSecret(t, args, "BASIC-PASSWORD-MUST-NOT-LEAK")
}

func TestApiConnectorArgs_ClientCertificate(t *testing.T) {
	payload := strings.Replace(b2xUserFlowJSON, "#microsoft.graph.basicAuthentication", "#microsoft.graph.clientCertificateAuthentication", 1)
	connector := parseB2xUserFlow(t, payload).GetApiConnectorConfiguration().GetPostFederationSignup()
	args := newApiConnectorArgs(connector)
	assert.Equal(t, "clientCertificate", rawString(t, args, "authenticationType"))
}

func newIdpODataError(status int) error {
	e := odataerrors.NewODataError()
	e.ResponseStatusCode = status
	main := odataerrors.NewMainError()
	code, msg := "Authorization_RequestDenied", "Insufficient privileges to complete the operation."
	main.SetCode(&code)
	main.SetMessage(&msg)
	e.SetErrorEscaped(main)
	return e
}

func TestClassifyGraphError_NamesIdentityPermission(t *testing.T) {
	forbidden := classifyGraphError(newIdpODataError(http.StatusForbidden), permIdentityProviderReadAll)
	assert.True(t, errors.Is(forbidden, llx.ErrForbidden))
	var lerr *llx.Error
	require.True(t, errors.As(forbidden, &lerr))
	assert.Contains(t, lerr.Permissions, permIdentityProviderReadAll)

	// A server error is not a refusal: the service is unavailable.
	other := classifyGraphError(newIdpODataError(http.StatusInternalServerError))
	assert.False(t, errors.Is(other, llx.ErrForbidden))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(other))

	// A missing object is not a refusal either and stays unclassified.
	notFound := classifyGraphError(newIdpODataError(http.StatusNotFound))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(notFound))

	// A transport failure is never a refusal.
	transport := classifyGraphError(errors.New("connection reset"))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(transport))
}
