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

func TestAccountRoles(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/roles", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, loadFixture("account_roles"))
	})

	result, err := acc.roles()
	require.NoError(t, err)
	require.Len(t, result, 2)

	admin := result[0].(*mqlCloudflareAccountRole)
	assert.Equal(t, "role-admin", admin.Id.Data)
	assert.Equal(t, "Administrator", admin.Name.Data)
	assert.Equal(t, "Full access to all account resources", admin.Description.Data)

	readonly := result[1].(*mqlCloudflareAccountRole)
	assert.Equal(t, "role-readonly", readonly.Id.Data)
	assert.Equal(t, "Read Only", readonly.Name.Data)
}

// Synthetic: a role granting DNS write and billing read, and a role record
// without permissions; no live account was checked. The permissions must come
// from the raw payload, so areas the role does not mention stay out rather
// than appearing as read:false, write:false.
func TestAccountRolePermissions(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/roles", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		if page := r.URL.Query().Get("page"); page != "" && page != "1" {
			jsonResponse(w, `{"result":[],"success":true,"errors":[],"messages":[]}`)
			return
		}
		jsonResponse(w, `{"success":true,"result":[
			{"id":"role-dns","name":"DNS","description":"DNS editors",
			 "permissions":{"dns":{"read":true,"write":true},"billing":{"read":true,"write":false}}},
			{"id":"role-bare","name":"Bare","description":"no permissions reported"}
		]}`)
	})

	result, err := acc.roles()
	require.NoError(t, err)
	require.Len(t, result, 2)

	dns := result[0].(*mqlCloudflareAccountRole)
	assert.Equal(t, map[string]any{
		"dns":     map[string]any{"read": true, "write": true},
		"billing": map[string]any{"read": true, "write": false},
	}, dns.Permissions.Data)

	assert.True(t, result[1].(*mqlCloudflareAccountRole).Permissions.IsNull())
}

func TestAccountOrStub(t *testing.T) {
	// Synthetic: one listed account and an id outside the token's reach; no
	// live account was checked.
	env := setupTestEnv(t)
	known := createTestAccount(t, env)
	byID := map[string]any{testAccountID: known}

	got, err := accountOrStub(env.Runtime, byID, testAccountID)
	require.NoError(t, err)
	assert.Same(t, known, got)

	stub, err := accountOrStub(env.Runtime, byID, "unknown-account")
	require.NoError(t, err)
	acc := stub.(*mqlCloudflareAccount)
	assert.Equal(t, "unknown-account", acc.Id.Data)
	assert.True(t, acc.Name.IsNull())
	assert.True(t, acc.CreatedOn.IsNull())
}
