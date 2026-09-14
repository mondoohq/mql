// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeActivity(t *testing.T, payload string) AdminActivity {
	t.Helper()
	var a AdminActivity
	require.NoError(t, json.Unmarshal([]byte(payload), &a))
	return a
}

// A signed-in user arrives with email_address and user_id, not email and id.
// Reading the wrong keys leaves every activity in the feed unattributed while
// the decode succeeds, which is the failure this pins.
func TestActorDecodeUserActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0000",
		"created_at": "2026-04-10T08:09:10Z",
		"type": "claude_chat_created",
		"actor": {
			"type": "user_actor",
			"email_address": "auditor@example.invalid",
			"user_id": "user_0001",
			"ip_address": "192.0.2.34",
			"user_agent": "Mozilla/5.0 (X11; Linux x86_64)"
		}
	}`)

	assert.Equal(t, "activity_0000", a.ID)
	assert.Equal(t, "user_actor", a.Actor.Type)
	assert.Equal(t, "auditor@example.invalid", a.Actor.Email)
	assert.Equal(t, "user_0001", a.Actor.ID)
	assert.Equal(t, "192.0.2.34", a.Actor.IPAddress)
	assert.Equal(t, "Mozilla/5.0 (X11; Linux x86_64)", a.Actor.UserAgent)
	// A user acted, so none of the machine credentials are involved.
	assert.Empty(t, a.Actor.APIKeyID)
	assert.Empty(t, a.Actor.AdminAPIKeyID)
}

// A customer-issued API key acted. There is no email to attribute it to, and
// api_key_id is the whole attribution.
func TestActorDecodeApiActor(t *testing.T) {
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

	assert.Equal(t, "api_actor", a.Actor.Type)
	assert.Equal(t, "apikey_0001", a.Actor.APIKeyID)
	assert.Equal(t, "198.51.100.7", a.Actor.IPAddress)
	assert.Equal(t, "curl/8.7.1", a.Actor.UserAgent)
	assert.Empty(t, a.Actor.Email)
	assert.Empty(t, a.Actor.ID)
}

// An admin key is a distinct credential from a customer API key and arrives
// under its own key. Decoding it into APIKeyID would make an administrative
// change look like ordinary API traffic.
func TestActorDecodeAdminApiKeyActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0002",
		"created_at": "2026-04-10T08:11:00Z",
		"type": "organization_user_added",
		"actor": {
			"type": "admin_api_key_actor",
			"admin_api_key_id": "adminkey_0001",
			"ip_address": "203.0.113.19",
			"user_agent": "mondoo/1.0"
		}
	}`)

	assert.Equal(t, "admin_api_key_actor", a.Actor.Type)
	assert.Equal(t, "adminkey_0001", a.Actor.AdminAPIKeyID)
	assert.Empty(t, a.Actor.APIKeyID)
}

// An action taken before sign-in completed carries a claimed address under its
// own key. It must not land in Email, which is reserved for an address the
// platform actually authenticated.
func TestActorDecodeUnauthenticatedUserActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0003",
		"created_at": "2026-04-10T08:12:00Z",
		"type": "sso_login_initiated",
		"actor": {
			"type": "unauthenticated_user_actor",
			"unauthenticated_email_address": "stranger@example.invalid",
			"ip_address": "203.0.113.55",
			"user_agent": "Mozilla/5.0"
		}
	}`)

	assert.Equal(t, "unauthenticated_user_actor", a.Actor.Type)
	assert.Equal(t, "stranger@example.invalid", a.Actor.UnauthenticatedEmail)
	assert.Empty(t, a.Actor.Email)
	assert.Equal(t, "203.0.113.55", a.Actor.IPAddress)
}

// Anthropic acting on the organization reports email_address as an explicit
// null. Decoding it must not panic on the nil and must not invent a value.
func TestActorDecodeAnthropicActorNullEmail(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0004",
		"created_at": "2026-04-10T08:13:00Z",
		"type": "organization_accessed",
		"actor": {
			"type": "anthropic_actor",
			"email_address": null
		}
	}`)

	assert.Equal(t, "anthropic_actor", a.Actor.Type)
	assert.Empty(t, a.Actor.Email)
	assert.Empty(t, a.Actor.IPAddress)
}

// A directory sync carries no address, no IP and no user agent: the
// identity provider is the actor. Its three identifiers are all there is.
func TestActorDecodeScimDirectorySyncActor(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0005",
		"created_at": "2026-04-10T08:14:00Z",
		"type": "organization_user_removed",
		"actor": {
			"type": "scim_directory_sync_actor",
			"workos_event_id": "event_0001",
			"directory_id": "directory_0001",
			"idp_connection_type": "OktaSCIMV2"
		}
	}`)

	assert.Equal(t, "scim_directory_sync_actor", a.Actor.Type)
	assert.Equal(t, "event_0001", a.Actor.WorkosEventID)
	assert.Equal(t, "directory_0001", a.Actor.DirectoryID)
	assert.Equal(t, "OktaSCIMV2", a.Actor.IdpConnectionType)
	assert.Empty(t, a.Actor.Email)
	assert.Empty(t, a.Actor.IPAddress)
}

// idp_connection_type is nullable even on a directory sync. A null must not
// fail the decode of the whole activity, which would take the entire feed
// down over one entry.
func TestActorDecodeScimActorNullConnectionType(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0006",
		"created_at": "2026-04-10T08:15:00Z",
		"type": "organization_user_removed",
		"actor": {
			"type": "scim_directory_sync_actor",
			"directory_id": "directory_0002",
			"idp_connection_type": null
		}
	}`)

	assert.Equal(t, "directory_0002", a.Actor.DirectoryID)
	assert.Empty(t, a.Actor.IdpConnectionType)
}

// The union is open: Anthropic documents that new actor kinds will appear and
// that consumers must pass unrecognized ones through. An unknown kind has to
// decode, keep its discriminator, and keep the shared values it does carry.
func TestActorDecodeUnknownActorTypePassesThrough(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0007",
		"created_at": "2026-04-10T08:16:00Z",
		"type": "something_new",
		"actor": {
			"type": "workload_identity_actor",
			"ip_address": "192.0.2.99",
			"some_future_field": {"nested": true}
		}
	}`)

	assert.Equal(t, "workload_identity_actor", a.Actor.Type)
	assert.Equal(t, "192.0.2.99", a.Actor.IPAddress)
	assert.Empty(t, a.Actor.Email)
}

// An activity whose actor block is absent entirely must decode to an actor
// with nothing set, rather than failing.
func TestActorDecodeMissingActorBlock(t *testing.T) {
	a := decodeActivity(t, `{
		"id": "activity_0008",
		"created_at": "2026-04-10T08:17:00Z",
		"type": "claude_file_uploaded"
	}`)

	assert.Equal(t, "activity_0008", a.ID)
	assert.Empty(t, a.Actor.Type)
	assert.Empty(t, a.Actor.Email)
}

// The workspace list carries the encryption binding and the tags. A mistyped
// key here reads as "no customer-managed key" on a workspace that has one,
// which is the wrong direction for an encryption check to fail in.
func TestWorkspaceDecodeEncryptionAndTags(t *testing.T) {
	var w AdminWorkspace
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "wrkspc_0000",
		"type": "workspace",
		"name": "platform",
		"display_color": "#6C5BB9",
		"created_at": "2026-01-15T09:00:00Z",
		"archived_at": null,
		"compartment_id": "f8a7b6c5-4d3e-4f1a-8b9c-0d1e2f3a4b5c",
		"external_key_id": "ekey_0001",
		"tags": {"env": "prod", "team": "platform"}
	}`), &w))

	require.NotNil(t, w.ExternalKeyID)
	assert.Equal(t, "ekey_0001", *w.ExternalKeyID)
	assert.Equal(t, "f8a7b6c5-4d3e-4f1a-8b9c-0d1e2f3a4b5c", w.CompartmentID)
	assert.Equal(t, map[string]string{"env": "prod", "team": "platform"}, w.Tags)
}

// A workspace on Anthropic-managed encryption reports external_key_id as null.
// The pointer keeps that distinguishable from a key whose id decoded to "".
func TestWorkspaceDecodeNullExternalKey(t *testing.T) {
	var w AdminWorkspace
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "wrkspc_0001",
		"created_at": "2026-01-15T09:00:00Z",
		"external_key_id": null,
		"tags": {}
	}`), &w))

	assert.Nil(t, w.ExternalKeyID)
	assert.Empty(t, w.Tags)
}
