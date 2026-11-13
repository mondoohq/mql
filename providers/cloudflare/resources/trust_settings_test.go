// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const trustSettingsPath = "/accounts/" + testAccountID + "/access/organizations/trust_settings"

// newTrustTestOrg serves the organization and the account list, and returns
// the organization with trustHandler answering the trust settings endpoint.
func newTrustTestOrg(t *testing.T, trustHandler http.HandlerFunc) (*mqlCloudflareOneOrganization, *int) {
	t.Helper()
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/access/organizations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("access_organization"))
	})
	env.Mux.HandleFunc("/accounts", func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, loadFixture("accounts"))
	})
	calls := 0
	env.Mux.HandleFunc(trustSettingsPath, func(w http.ResponseWriter, r *http.Request) {
		calls++
		assert.Equal(t, http.MethodGet, r.Method)
		trustHandler(w, r)
	})

	org, err := one.organization()
	require.NoError(t, err)
	require.NotNil(t, org)
	return org, &calls
}

func TestOrganizationTrustSettings(t *testing.T) {
	// Synthetic: no live account with cross-account trust configured. The IDs
	// cover one account in the token's account list, one outside it, a repeat
	// and an empty string.
	org, calls := newTrustTestOrg(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"errors":[],"messages":[],"result":{
			"grant_trust_to_all_accounts_in_org": true,
			"trusting_accounts": ["9d4e6c8f0a2b1d3f5e7c9b1a8f6e4d2c", "ffffffffffffffffffffffffffffffff", "9d4e6c8f0a2b1d3f5e7c9b1a8f6e4d2c", ""]
		}}`)
	})

	grant := org.GetGrantTrustToAllAccountsInOrg()
	require.NoError(t, grant.Error)
	assert.True(t, grant.Data)

	accs := org.GetTrustedAccounts()
	require.NoError(t, accs.Error)
	require.Len(t, accs.Data, 2)

	listed := accs.Data[0].(*mqlCloudflareAccount)
	assert.Equal(t, "9d4e6c8f0a2b1d3f5e7c9b1a8f6e4d2c", listed.Id.Data)
	assert.Equal(t, "Production Account", listed.Name.Data, "a readable account resolves to the listed one")

	outside := accs.Data[1].(*mqlCloudflareAccount)
	assert.Equal(t, "ffffffffffffffffffffffffffffffff", outside.Id.Data)
	assert.True(t, outside.Name.IsNull(), "an unreadable account keeps its id and reports no name")
	assert.True(t, outside.CreatedOn.IsNull())

	assert.Equal(t, 1, *calls, "both fields share one trust settings request")
}

func TestOrganizationTrustSettingsEmpty(t *testing.T) {
	// Synthetic: trust_settings omits trusting_accounts when the list is empty.
	org, _ := newTrustTestOrg(t, func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"errors":[],"messages":[],"result":{"grant_trust_to_all_accounts_in_org": false}}`)
	})

	grant := org.GetGrantTrustToAllAccountsInOrg()
	require.NoError(t, grant.Error)
	assert.False(t, grant.Data)
	assert.False(t, grant.IsNull(), "an explicit false is reported, not null")

	accs := org.GetTrustedAccounts()
	require.NoError(t, accs.Error)
	assert.Empty(t, accs.Data)
}

func TestOrganizationTrustSettingsRefused(t *testing.T) {
	t.Run("flag off: refusal reads as null and empty", func(t *testing.T) {
		org, _ := newTrustTestOrg(t, refuse(http.StatusForbidden))

		grant := org.GetGrantTrustToAllAccountsInOrg()
		require.NoError(t, grant.Error)
		assert.True(t, grant.IsNull())

		accs := org.GetTrustedAccounts()
		require.NoError(t, accs.Error)
		assert.Empty(t, accs.Data)
	})

	t.Run("structured errors: refusal is an error", func(t *testing.T) {
		enableStructuredErrors(t)
		org, _ := newTrustTestOrg(t, refuse(http.StatusForbidden))

		assert.Error(t, org.GetGrantTrustToAllAccountsInOrg().Error)
		assert.Error(t, org.GetTrustedAccounts().Error)
	})
}

func TestDedupeStrings(t *testing.T) {
	assert.Equal(t, []string{"a", "b"}, dedupeStrings([]string{"a", "", "b", "a"}))
	assert.Empty(t, dedupeStrings(nil))
}
