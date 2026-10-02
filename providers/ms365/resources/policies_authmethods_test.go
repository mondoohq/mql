// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/microsoft/kiota-abstractions-go/authentication"
	msgraphsdkgo "github.com/microsoftgraph/msgraph-sdk-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Shape of GET /v1.0/policies/authenticationMethodsPolicy as Graph returns it
// without a query: every method configuration carries its includeTargets.
const authMethodsPolicyPlainBody = `{
  "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#authenticationMethodsPolicy",
  "id": "authenticationMethodsPolicy",
  "displayName": "Authentication Methods Policy",
  "policyVersion": "1.5",
  "authenticationMethodConfigurations@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations",
  "authenticationMethodConfigurations": [
    {
      "@odata.type": "#microsoft.graph.fido2AuthenticationMethodConfiguration",
      "id": "Fido2",
      "state": "enabled",
      "isSelfServiceRegistrationAllowed": true,
      "isAttestationEnforced": false,
      "excludeTargets": [],
      "keyRestrictions": {"isEnforced": false, "enforcementType": "block", "aaGuids": []},
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('Fido2')/microsoft.graph.fido2AuthenticationMethodConfiguration/includeTargets",
      "includeTargets": [
        {"targetType": "group", "id": "all_users", "isRegistrationRequired": false}
      ]
    },
    {
      "@odata.type": "#microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration",
      "id": "MicrosoftAuthenticator",
      "state": "enabled",
      "isSoftwareOathEnabled": false,
      "excludeTargets": [{"targetType": "group", "id": "00000000-0000-0000-0000-0000000000aa"}],
      "includeTargets@odata.context": "https://graph.microsoft.com/v1.0/$metadata#policies/authenticationMethodsPolicy/authenticationMethodConfigurations('MicrosoftAuthenticator')/microsoft.graph.microsoftAuthenticatorAuthenticationMethodConfiguration/includeTargets",
      "includeTargets": [
        {"targetType": "group", "id": "00000000-0000-0000-0000-0000000000bb", "isRegistrationRequired": false, "authenticationMode": "any"}
      ]
    }
  ]
}`

// newAuthMethodsPolicyGraph serves the policy the way Graph v1.0 does: with
// $expand=authenticationMethodConfigurations, includeTargets is a navigation
// property that is left out of every configuration.
func newAuthMethodsPolicyGraph(t *testing.T) *msgraphsdkgo.GraphServiceClient {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1.0/policies/authenticationMethodsPolicy" {
			http.NotFound(w, r)
			return
		}
		body := []byte(authMethodsPolicyPlainBody)
		if r.URL.Query().Has("$expand") {
			var policy map[string]any
			require.NoError(t, json.Unmarshal(body, &policy))
			for _, cfg := range policy["authenticationMethodConfigurations"].([]any) {
				delete(cfg.(map[string]any), "includeTargets")
				delete(cfg.(map[string]any), "includeTargets@odata.context")
			}
			var err error
			body, err = json.Marshal(policy)
			require.NoError(t, err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)

	adapter, err := msgraphsdkgo.NewGraphRequestAdapter(&authentication.AnonymousAuthenticationProvider{})
	require.NoError(t, err)
	adapter.SetBaseUrl(srv.URL + "/v1.0")
	return msgraphsdkgo.NewGraphServiceClient(adapter)
}

// Each method's includeTargets must come through. Reading the policy with
// $expand=authenticationMethodConfigurations makes Graph drop them, which left
// every method reporting an empty includeTargets list.
func TestFetchAuthenticationMethodsPolicy_KeepsIncludeTargets(t *testing.T) {
	policy, err := fetchAuthenticationMethodsPolicy(context.Background(), newAuthMethodsPolicyGraph(t))
	require.NoError(t, err)

	var fido2 models.Fido2AuthenticationMethodConfigurationable
	var authenticator models.MicrosoftAuthenticatorAuthenticationMethodConfigurationable
	for _, cfg := range policy.GetAuthenticationMethodConfigurations() {
		switch c := cfg.(type) {
		case models.Fido2AuthenticationMethodConfigurationable:
			fido2 = c
		case models.MicrosoftAuthenticatorAuthenticationMethodConfigurationable:
			authenticator = c
		}
	}
	require.NotNil(t, fido2)
	require.NotNil(t, authenticator)

	assert.Equal(t, []any{
		map[string]any{"id": "all_users", "targetType": "group"},
	}, authMethodTargets(fido2.GetIncludeTargets()))
	assert.Equal(t, []any{
		map[string]any{"id": "00000000-0000-0000-0000-0000000000bb", "targetType": "group"},
	}, authMethodTargets(authenticator.GetIncludeTargets()))
	assert.Equal(t, []any{
		map[string]any{"id": "00000000-0000-0000-0000-0000000000aa", "targetType": "group"},
	}, authMethodTargets(authenticator.GetExcludeTargets()))
}
