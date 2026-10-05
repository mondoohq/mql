// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAccountAPITokens(t *testing.T) {
	env := setupTestEnv(t)
	account := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/tokens", testAccountID), pagedFixture("account_tokens"))

	result, err := account.apiTokens()
	require.NoError(t, err)
	require.Len(t, result, 2)

	ci := result[0].(*mqlCloudflareApiToken)
	assert.Equal(t, "9a7806061c88ada191ed06f989cc3dac", ci.Id.Data)
	assert.Equal(t, "ci-deploy", ci.Name.Data)
	assert.Equal(t, "active", ci.Status.Data)
	assert.Equal(t, testAccountID, ci.AccountId.Data)
	assert.Equal(t, []any{"203.0.113.0/24"}, ci.IpIn.Data)
	assert.Equal(t, []any{"198.51.100.0/24"}, ci.IpNotIn.Data)
	assert.False(t, ci.ExpiresOn.IsNull())
	assert.False(t, ci.LastUsedOn.IsNull())
	assert.Equal(t, "ci-owner@example.com", ci.CreatorEmail.Data)
	assert.Equal(t, "oauth", ci.ProvisionerType.Data)
	assert.Equal(t, "3f1c9a7e2b5d4e8f", ci.ProvisionerId.Data)

	require.Len(t, ci.Policies.Data, 1)
	policy := ci.Policies.Data[0].(map[string]any)
	assert.Equal(t, "allow", policy["effect"])
	assert.Equal(t, map[string]any{"com.cloudflare.api.account.zone.*": "*"}, policy["resources"])
	assert.Equal(t, []any{map[string]any{
		"id":   "c8fed203ed3043cba015a93ad1616f1f",
		"name": "Zone Read",
	}}, policy["permissionGroups"])

	// A token with no expiry and no recorded use: both must read null rather
	// than the zero time, which would look like an expiry in year 1.
	stale := result[1].(*mqlCloudflareApiToken)
	assert.True(t, stale.ExpiresOn.IsNull(), "a token that never expires must not report a zero expiry")
	assert.True(t, stale.LastUsedOn.IsNull())
	assert.True(t, stale.NotBefore.IsNull())
	assert.Empty(t, stale.IpIn.Data, "no IP allowlist means the token works from anywhere")
	// A token created directly by a person carries no creator email or
	// provisioner, whether the key is absent or explicitly null.
	assert.True(t, stale.CreatorEmail.IsNull(), "an absent creator email must read null, not empty")
	assert.True(t, stale.ProvisionerType.IsNull())
	assert.True(t, stale.ProvisionerId.IsNull(), "an explicit null provisioner_id must read null")
}

func TestAccountAPITokens_degradesWhenUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	account := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/tokens", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"not entitled"}]}`)
	})

	result, err := account.apiTokens()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestUserAPITokens_distinctCacheKeyFromAccountTokens(t *testing.T) {
	env := setupTestEnv(t)
	account := createTestAccount(t, env)
	root, err := CreateResource(env.Runtime, "cloudflare", map[string]*llx.RawData{})
	require.NoError(t, err)

	env.Mux.HandleFunc("/user/tokens", pagedFixture("account_tokens"))
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/tokens", testAccountID), pagedFixture("account_tokens"))

	userTokens, err := root.(*mqlCloudflare).apiTokens()
	require.NoError(t, err)
	accountTokens, err := account.apiTokens()
	require.NoError(t, err)
	require.Len(t, userTokens, 2)
	require.Len(t, accountTokens, 2)

	// A user token and an account token are different objects even when they
	// share a token id, so they must not collapse onto one cached resource.
	assert.NotEqual(t,
		userTokens[0].(*mqlCloudflareApiToken).__id,
		accountTokens[0].(*mqlCloudflareApiToken).__id,
	)
	// A user-owned token belongs to no single account.
	assert.True(t, userTokens[0].(*mqlCloudflareApiToken).AccountId.IsNull())
}

func TestUserAPITokens_credentialScopeFailureSurfaces(t *testing.T) {
	env := setupTestEnv(t)
	root, err := CreateResource(env.Runtime, "cloudflare", map[string]*llx.RawData{})
	require.NoError(t, err)

	// 9109 means an account-scoped token was used against the user endpoint.
	// That says nothing about whether tokens exist, so it must not degrade to
	// an empty list and let token checks pass vacuously.
	env.Mux.HandleFunc("/user/tokens", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":9109,"message":"Valid user-level authentication not found"}]}`)
	})

	_, err = root.(*mqlCloudflare).apiTokens()
	require.Error(t, err)
}

func TestTokenStringOrNil(t *testing.T) {
	assert.True(t, tokenStringOrNil("", true).Value == nil)
	assert.True(t, tokenStringOrNil("", false).Value == nil, "an empty string carries no value")
	assert.True(t, tokenStringOrNil("x", true).Value == nil, "a null JSON field wins over a stale value")
	assert.Equal(t, "x", tokenStringOrNil("x", false).Value)
}
