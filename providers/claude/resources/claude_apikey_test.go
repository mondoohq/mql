// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeAPIKey(t *testing.T, payload string) anthropic.BetaAPIKey {
	t.Helper()
	var k anthropic.BetaAPIKey
	require.NoError(t, json.Unmarshal([]byte(payload), &k))
	return k
}

func TestApiKeyArgsWorkspaceScopedUserKey(t *testing.T) {
	k := decodeAPIKey(t, `{
		"id": "apikey_0000",
		"type": "api_key",
		"name": "ci",
		"status": "active",
		"partial_key_hint": "sk-ant-...AAAA",
		"created_at": "2026-03-01T10:00:00Z",
		"expires_at": "2027-03-01T10:00:00Z",
		"created_by": {"id": "user_0001", "type": "user"},
		"principal": {"type": "user_actor", "user_id": "user_0002"},
		"scope": {"type": "workspace", "workspace_id": "wrkspc_0001"}
	}`)

	args := apiKeyArgs(k)
	assert.Equal(t, "apikey_0000", args["id"].Value)
	assert.Equal(t, "active", args["status"].Value)
	// The principal is who the key acts as, which is not the same as who
	// created it: a key created by an admin can act as somebody else.
	assert.Equal(t, "user_actor", args["principalType"].Value)
	assert.Equal(t, "workspace", args["scopeType"].Value)
	assert.NotNil(t, args["expiresAt"].Value)
}

// An organization-scoped key reaches every workspace, so scopeType is the
// field that separates it from a confined one.
func TestApiKeyArgsOrganizationScopedServiceAccountKey(t *testing.T) {
	k := decodeAPIKey(t, `{
		"id": "apikey_0001",
		"type": "api_key",
		"name": "platform",
		"status": "active",
		"partial_key_hint": "sk-ant-...BBBB",
		"created_at": "2026-03-01T10:00:00Z",
		"created_by": {"id": "user_0001", "type": "user"},
		"principal": {"type": "service_account_actor", "service_account_id": "svac_0000"},
		"scope": {"type": "organization"}
	}`)

	args := apiKeyArgs(k)
	assert.Equal(t, "service_account_actor", args["principalType"].Value)
	assert.Equal(t, "organization", args["scopeType"].Value)
}

// A key that never expires must report no expiry. The SDK decodes the absent
// timestamp into the zero time, which would date the key's expiry to year 1
// and make an "expired credentials" check fire on every non-expiring key.
func TestApiKeyArgsNonExpiringKeyReadsNull(t *testing.T) {
	k := decodeAPIKey(t, `{
		"id": "apikey_0002",
		"type": "api_key",
		"name": "no-expiry",
		"status": "active",
		"partial_key_hint": "sk-ant-...CCCC",
		"created_at": "2026-03-01T10:00:00Z",
		"expires_at": null,
		"created_by": {"id": "user_0001", "type": "user"},
		"principal": {"type": "user_actor", "user_id": "user_0002"},
		"scope": {"type": "workspace", "workspace_id": "wrkspc_0001"}
	}`)

	args := apiKeyArgs(k)
	assert.Nil(t, args["expiresAt"].Value)
}

// A legacy or federation-minted key is bound to no principal at all. That must
// read as null rather than "", so a policy looking for unbound keys can find
// them instead of matching an empty string it cannot interpret.
func TestApiKeyArgsUnboundKeyReadsNullPrincipal(t *testing.T) {
	k := decodeAPIKey(t, `{
		"id": "apikey_0003",
		"type": "api_key",
		"name": "legacy",
		"status": "active",
		"partial_key_hint": "sk-ant-...DDDD",
		"created_at": "2026-03-01T10:00:00Z",
		"created_by": {"id": "user_0001", "type": "user"},
		"principal": null,
		"scope": {"type": "workspace", "workspace_id": "wrkspc_0001"}
	}`)

	args := apiKeyArgs(k)
	assert.Nil(t, args["principalType"].Value)
}
