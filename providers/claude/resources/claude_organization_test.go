// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/claude/connection"
)

func decodeWorkspace(t *testing.T, payload string) connection.AdminWorkspace {
	t.Helper()
	var w connection.AdminWorkspace
	require.NoError(t, json.Unmarshal([]byte(payload), &w))
	return w
}

// A live workspace has no archive date. Reporting the zero time instead of
// null dates every active workspace to year 1, so a query looking for the
// workspaces archived before a cutoff returns the entire organization.
func TestWorkspaceArgsLiveWorkspaceReadsNullArchivedAt(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0000",
		"type": "workspace",
		"name": "platform",
		"display_color": "#6C5BB9",
		"created_at": "2026-01-15T09:00:00Z",
		"archived_at": null,
		"data_residency": {
			"workspace_geo": "us",
			"default_inference_geo": "us",
			"allowed_inference_geos": "unrestricted"
		}
	}`)

	args, err := workspaceArgs(w)
	require.NoError(t, err)

	assert.Nil(t, args["archivedAt"].Value)
	assert.Equal(t, "platform", args["name"].Value)
	assert.Equal(t, "us", args["workspaceGeo"].Value)
	assert.Equal(t, []interface{}{"unrestricted"}, args["allowedInferenceGeos"].Value)
}

// The encryption binding is the most audit-relevant thing the workspace list
// returns. A workspace with a customer-managed key must report it, along with
// the compartment a key policy scopes to and the workspace's tags.
func TestWorkspaceArgsCarriesEncryptionBindingAndTags(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0003",
		"type": "workspace",
		"name": "regulated",
		"created_at": "2026-01-15T09:00:00Z",
		"compartment_id": "f8a7b6c5-4d3e-4f1a-8b9c-0d1e2f3a4b5c",
		"external_key_id": "ekey_0001",
		"tags": {"env": "prod", "owner": "platform"}
	}`)

	args, err := workspaceArgs(w)
	require.NoError(t, err)

	assert.Equal(t, "ekey_0001", args["externalKeyId"].Value)
	assert.Equal(t, "f8a7b6c5-4d3e-4f1a-8b9c-0d1e2f3a4b5c", args["compartmentId"].Value)
	assert.Equal(t, map[string]interface{}{"env": "prod", "owner": "platform"}, args["tags"].Value)
}

// A workspace on Anthropic-managed encryption has no key at all. Reporting ""
// would let a check for "every workspace is covered by a customer-managed key"
// match a workspace that is not.
func TestWorkspaceArgsUnencryptedWorkspaceReadsNullKey(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0004",
		"type": "workspace",
		"name": "sandbox",
		"created_at": "2026-01-15T09:00:00Z",
		"external_key_id": null,
		"compartment_id": "",
		"tags": {}
	}`)

	args, err := workspaceArgs(w)
	require.NoError(t, err)

	assert.Nil(t, args["externalKeyId"].Value)
	assert.Nil(t, args["compartmentId"].Value)
	assert.Equal(t, map[string]interface{}{}, args["tags"].Value)
}

func decodeActivity(t *testing.T, payload string) connection.AdminActivity {
	t.Helper()
	var a connection.AdminActivity
	require.NoError(t, json.Unmarshal([]byte(payload), &a))
	return a
}

// A signed-in user is the one actor kind that carries an address, and it also
// carries where the action came from.
func TestActivityArgsUserActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0000",
		"created_at": "2026-04-10T08:09:10Z",
		"type": "claude_chat_created",
		"actor": {
			"type": "user_actor",
			"email_address": "auditor@example.invalid",
			"user_id": "user_0001",
			"ip_address": "192.0.2.34",
			"user_agent": "Mozilla/5.0"
		}
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "user_actor", args["actorType"].Value)
	assert.Equal(t, "auditor@example.invalid", args["actorEmail"].Value)
	assert.Equal(t, "user_0001", args["actorId"].Value)
	assert.Equal(t, "192.0.2.34", args["ipAddress"].Value)
	assert.Equal(t, "Mozilla/5.0", args["userAgent"].Value)
	// No credential is involved, so nothing may look like one.
	assert.Nil(t, args["apiKeyId"].Value)
	assert.Nil(t, args["adminApiKeyId"].Value)
	assert.Nil(t, args["unauthenticatedEmail"].Value)
}

// An api_actor has no email at all. Before this change actorEmail was the only
// attribution the schema offered, so machine traffic read as unattributed;
// actorType plus apiKeyId is what replaces that.
func TestActivityArgsApiActorReadsNullEmail(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0001",
		"created_at": "2026-04-10T08:10:00Z",
		"type": "compliance_api_accessed",
		"actor": {
			"type": "api_actor",
			"api_key_id": "apikey_0001",
			"ip_address": "198.51.100.7",
			"user_agent": "curl/8.7.1"
		}
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "api_actor", args["actorType"].Value)
	assert.Nil(t, args["actorEmail"].Value)
	assert.Nil(t, args["actorId"].Value)
	assert.Equal(t, "apikey_0001", args["apiKeyId"].Value)
	assert.Nil(t, args["adminApiKeyId"].Value)
}

// An administrative change made with an admin key reports that key, and must
// not report it as an ordinary API key.
func TestActivityArgsAdminApiKeyActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0002",
		"created_at": "2026-04-10T08:11:00Z",
		"type": "organization_user_added",
		"actor": {
			"type": "admin_api_key_actor",
			"admin_api_key_id": "adminkey_0001",
			"ip_address": "203.0.113.19"
		}
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "admin_api_key_actor", args["actorType"].Value)
	assert.Equal(t, "adminkey_0001", args["adminApiKeyId"].Value)
	assert.Nil(t, args["apiKeyId"].Value)
	assert.Nil(t, args["userAgent"].Value)
}

// A pre-sign-in action reports a claimed address, kept apart from actorEmail
// so a policy cannot mistake it for an authenticated identity.
func TestActivityArgsUnauthenticatedActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0003",
		"created_at": "2026-04-10T08:12:00Z",
		"type": "sso_login_initiated",
		"actor": {
			"type": "unauthenticated_user_actor",
			"unauthenticated_email_address": "stranger@example.invalid",
			"ip_address": "203.0.113.55"
		}
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "stranger@example.invalid", args["unauthenticatedEmail"].Value)
	assert.Nil(t, args["actorEmail"].Value)
	assert.Equal(t, "203.0.113.55", args["ipAddress"].Value)
}

// A directory sync has no address, no IP and no user agent. Everything it does
// not measure has to read as null, and its three identifiers have to survive.
func TestActivityArgsScimDirectorySyncActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0004",
		"created_at": "2026-04-10T08:14:00Z",
		"type": "organization_user_removed",
		"actor": {
			"type": "scim_directory_sync_actor",
			"workos_event_id": "event_0001",
			"directory_id": "directory_0001",
			"idp_connection_type": "OktaSCIMV2"
		}
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "scim_directory_sync_actor", args["actorType"].Value)
	assert.Equal(t, "directory_0001", args["directoryId"].Value)
	assert.Equal(t, "OktaSCIMV2", args["idpConnectionType"].Value)
	assert.Equal(t, "event_0001", args["workosEventId"].Value)
	assert.Nil(t, args["ipAddress"].Value)
	assert.Nil(t, args["userAgent"].Value)
	assert.Nil(t, args["actorEmail"].Value)
}

// Anthropic acting on the organization reports no address by design. That has
// to read as null, so "unattributed" and "attributed to Anthropic" stay
// distinguishable through actorType.
func TestActivityArgsAnthropicActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0005",
		"created_at": "2026-04-10T08:13:00Z",
		"type": "organization_accessed",
		"actor": {"type": "anthropic_actor", "email_address": null}
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "anthropic_actor", args["actorType"].Value)
	assert.Nil(t, args["actorEmail"].Value)
}

// An actor kind this schema does not name yet still reports its discriminator,
// so a query can find the activity instead of it reading as unattributed.
func TestActivityArgsUnknownActorTypeSurvives(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0006",
		"created_at": "2026-04-10T08:16:00Z",
		"type": "something_new",
		"actor": {"type": "workload_identity_actor", "ip_address": "192.0.2.99"}
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "workload_identity_actor", args["actorType"].Value)
	assert.Equal(t, "192.0.2.99", args["ipAddress"].Value)
}

// An activity with no actor block at all must report nothing rather than a set
// of empty strings that look like measurements.
func TestActivityArgsMissingActorReadsNull(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0007",
		"created_at": "2026-04-10T08:17:00Z",
		"type": "claude_file_uploaded"
	}`)

	args, err := activityArgs(a)
	require.NoError(t, err)

	assert.Equal(t, "activity_0007", args["__id"].Value)
	for _, field := range []string{
		"actorType", "actorEmail", "actorId", "unauthenticatedEmail",
		"ipAddress", "userAgent", "apiKeyId", "adminApiKeyId",
		"directoryId", "idpConnectionType", "workosEventId",
	} {
		assert.Nil(t, args[field].Value, field)
	}
}

// A malformed timestamp has to surface rather than date the activity to year 1.
func TestActivityArgsRejectsUnparseableCreatedAt(t *testing.T) {
	a := decodeActivity(t, `{"id": "activity_0008", "created_at": "just now"}`)

	_, err := activityArgs(a)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "createdAt")
}

// An archived workspace reports when it was archived, which is the whole
// reason to list archived workspaces at all.
func TestWorkspaceArgsArchivedWorkspaceCarriesTimestamp(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0001",
		"type": "workspace",
		"name": "retired-team",
		"display_color": "#111111",
		"created_at": "2025-03-04T12:00:00Z",
		"archived_at": "2026-02-01T18:30:00Z"
	}`)

	args, err := workspaceArgs(w)
	require.NoError(t, err)

	require.NotNil(t, args["archivedAt"].Value)
	assert.Equal(t, time.Date(2026, 2, 1, 18, 30, 0, 0, time.UTC), args["archivedAt"].Value.(*time.Time).UTC())
	assert.Equal(t, "wrkspc_0001", args["__id"].Value)

	// A workspace with no data_residency block must not invent a geo. An
	// empty string is the API saying nothing, not "no restriction".
	assert.Equal(t, "", args["workspaceGeo"].Value)
	assert.Equal(t, []interface{}{}, args["allowedInferenceGeos"].Value)
}

// A malformed timestamp has to surface as an error rather than resolve to the
// zero time, which would read as an archived workspace on an active one.
func TestWorkspaceArgsRejectsUnparseableArchivedAt(t *testing.T) {
	w := decodeWorkspace(t, `{
		"id": "wrkspc_0002",
		"created_at": "2025-03-04T12:00:00Z",
		"archived_at": "yesterday"
	}`)

	_, err := workspaceArgs(w)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "archivedAt")
}
