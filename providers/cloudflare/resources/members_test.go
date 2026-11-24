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

// Synthetic: a member holding a role with permissions and a domain-scoped
// grant, and a member with neither; no live account was checked.
func TestAccountMemberPoliciesAndRolePermissions(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/members", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"id":"m1","status":"accepted","user":{"id":"u1","email":"admin@example.com"},
			 "roles":[{"id":"role-admin","name":"Administrator","description":"all",
			   "permissions":{"zones":{"read":true,"write":true}}}],
			 "policies":[{"id":"pol-1","access":"allow",
			   "permission_groups":[{"id":"pg-1","name":"Zone Read","meta":{"key":"k","value":"v"}}],
			   "resource_groups":[{"id":"rg-1","name":"Prod zones",
			     "scope":{"key":"com.cloudflare.api.account.abc","objects":[{"key":"com.cloudflare.api.account.zone.z1"}]}}]}]},
			{"id":"m2","status":"pending","user":{"id":"u2","email":"invitee@example.com"}}
		],"result_info":{"page":1,"total_pages":1}}`)
	})

	result, err := acc.members()
	require.NoError(t, err)
	require.Len(t, result, 2)

	admin := result[0].(*mqlCloudflareAccountMember)
	assert.Equal(t, []any{map[string]any{
		"id":     "pol-1",
		"access": "allow",
		"permissionGroups": []any{
			map[string]any{"id": "pg-1", "name": "Zone Read"},
		},
		"resourceGroups": []any{
			map[string]any{
				"id":   "rg-1",
				"name": "Prod zones",
				"scope": map[string]any{
					"key":     "com.cloudflare.api.account.abc",
					"objects": []any{map[string]any{"key": "com.cloudflare.api.account.zone.z1"}},
				},
			},
		},
	}}, admin.Policies.Data)

	require.Len(t, admin.Roles.Data, 1)
	role := admin.Roles.Data[0].(*mqlCloudflareAccountRole)
	assert.Equal(t, map[string]any{"zones": map[string]any{"read": true, "write": true}}, role.Permissions.Data)

	invitee := result[1].(*mqlCloudflareAccountMember)
	assert.Equal(t, []any{}, invitee.Policies.Data)
}
