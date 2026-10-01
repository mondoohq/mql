// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func decode[T any](t *testing.T, raw string) T {
	t.Helper()
	var v T
	require.NoError(t, json.Unmarshal([]byte(raw), &v))
	return v
}

// RBAC

func TestRbacGroupArgs(t *testing.T) {
	g := decode[anthropic.BetaRBACGroup](t, `{
		"id": "rbacgrp_01", "type": "rbac_group", "name": "Engineering",
		"source_type": "scim", "role_ids": ["rbacrole_a", "rbacrole_b"],
		"created_at": "2026-09-01T10:00:00Z", "updated_at": "2026-09-02T10:00:00Z"
	}`)

	args := rbacGroupArgs(g)
	assert.Equal(t, "rbacgrp_01", args["id"].Value)
	assert.Equal(t, "Engineering", args["name"].Value)
	assert.Equal(t, "scim", args["sourceType"].Value)
	assert.Equal(t, time.Date(2026, 9, 2, 10, 0, 0, 0, time.UTC), *args["updatedAt"].Value.(*time.Time))
	assert.Equal(t, []string{"rbacrole_a", "rbacrole_b"}, rbacGroupRoleIDs(g))
}

// role_ids null means the API could not read the group's roles. It must stay
// apart from a group with no roles, or a role audit would read "no roles".
func TestRbacGroupRoleIDsNullIsNotEmpty(t *testing.T) {
	unavailable := decode[anthropic.BetaRBACGroup](t, `{"id": "rbacgrp_01", "role_ids": null}`)
	assert.Nil(t, rbacGroupRoleIDs(unavailable))

	none := decode[anthropic.BetaRBACGroup](t, `{"id": "rbacgrp_02", "role_ids": []}`)
	ids := rbacGroupRoleIDs(none)
	assert.NotNil(t, ids)
	assert.Empty(t, ids)
}

func testGroup(id string, roleIDs []string) *mqlClaudeOrganizationRbacGroup {
	g := &mqlClaudeOrganizationRbacGroup{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
	g.cacheRoleIDs = roleIDs
	return g
}

func TestGroupsHoldingRole(t *testing.T) {
	admins := testGroup("rbacgrp_admins", []string{"rbacrole_admin", "rbacrole_user"})
	users := testGroup("rbacgrp_users", []string{"rbacrole_user"})
	none := testGroup("rbacgrp_none", []string{})

	got, err := groupsHoldingRole([]interface{}{admins, users, none}, "rbacrole_admin")
	require.NoError(t, err)
	assert.Equal(t, []interface{}{admins}, got)

	got, err = groupsHoldingRole([]interface{}{admins, users, none}, "rbacrole_user")
	require.NoError(t, err)
	assert.Equal(t, []interface{}{admins, users}, got)
}

// One group whose roles could not be read makes "which groups hold this
// role" unanswerable. A shorter list would pass an assertion that the role is
// held by no one.
func TestGroupsHoldingRoleFailsOnUnreadableGroup(t *testing.T) {
	_, err := groupsHoldingRole([]interface{}{
		testGroup("rbacgrp_ok", []string{"rbacrole_admin"}),
		testGroup("rbacgrp_unknown", nil),
	}, "rbacrole_admin")
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
}

func TestRbacGroupMemberArgsKeyedByGroupAndUser(t *testing.T) {
	m := decode[anthropic.BetaRBACGroupMember](t, `{
		"type": "rbac_group_member", "user_id": "user_01", "rbac_group_id": "rbacgrp_a",
		"email": "dev@example.com", "created_at": "2026-09-01T10:00:00Z"
	}`)

	a := rbacGroupMemberArgs("rbacgrp_a", m)
	b := rbacGroupMemberArgs("rbacgrp_b", m)
	assert.Equal(t, "dev@example.com", a["email"].Value)
	assert.Equal(t, time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC), *a["addedAt"].Value.(*time.Time))
	assert.NotEqual(t, a["__id"].Value, b["__id"].Value,
		"the same user in two groups is two memberships")
}

func TestRbacRolePermissionArgs(t *testing.T) {
	tool := decode[anthropic.BetaRBACRolePermission](t, `{
		"type": "rbac_role_permission", "action": "always_allow",
		"resource": {"type": "connector_tool", "connector_id": "conn_1", "tool_name": "delete_file"}
	}`)
	args := rbacRolePermissionArgs("rbacrole_a", tool)
	assert.Equal(t, "always_allow", args["action"].Value)
	assert.Equal(t, "connector_tool", args["resourceType"].Value)
	assert.Equal(t, "conn_1", args["connectorId"].Value)
	assert.Equal(t, "delete_file", args["toolName"].Value)
	assert.Nil(t, args["scope"].Value)

	org := decode[anthropic.BetaRBACRolePermission](t, `{
		"type": "rbac_role_permission", "action": "capability_access_all",
		"resource": {"type": "organization", "organization_id": "org_1"}
	}`)
	args = rbacRolePermissionArgs("rbacrole_a", org)
	assert.Equal(t, "organization", args["resourceType"].Value)
	assert.Nil(t, args["connectorId"].Value)
	assert.Nil(t, args["toolName"].Value)
}

// Two grants that differ only in the tool they name are two permissions. A
// key missing the tool would cache the first and report it twice.
func TestRbacRolePermissionArgsDistinctTools(t *testing.T) {
	read := decode[anthropic.BetaRBACRolePermission](t, `{"action": "use",
		"resource": {"type": "connector_tool", "connector_id": "conn_1", "tool_name": "read_file"}}`)
	del := decode[anthropic.BetaRBACRolePermission](t, `{"action": "use",
		"resource": {"type": "connector_tool", "connector_id": "conn_1", "tool_name": "delete_file"}}`)
	assert.NotEqual(t,
		rbacRolePermissionArgs("rbacrole_a", read)["__id"].Value,
		rbacRolePermissionArgs("rbacrole_a", del)["__id"].Value)
}

// Spend limits

func TestEffectiveSpendLimitArgs(t *testing.T) {
	row := decode[anthropic.BetaSpendSummary](t, `{
		"actor": {"type": "user_actor", "user_id": "user_01", "email_address": "dev@example.com", "name": "Dev", "deleted": false},
		"amount": "50000", "currency": "USD", "period": "monthly",
		"period_to_date_spend": "12050.5",
		"scope": {"type": "user", "user_id": "user_01"},
		"source": {"type": "rbac_group", "rbac_group_id": "rbacgrp_eng"},
		"spend_limit_id": "spl_01"
	}`)

	args, err := effectiveSpendLimitArgs(row)
	require.NoError(t, err)
	assert.Equal(t, int64(50000), args["amount"].Value)
	assert.Equal(t, 12050.5, args["periodToDateSpend"].Value)
	assert.Equal(t, "monthly", args["period"].Value)
	assert.Equal(t, "USD", args["currency"].Value)
	assert.Equal(t, "user_actor", args["actorType"].Value)
	assert.Equal(t, "dev@example.com", args["actorEmail"].Value)
	assert.Equal(t, "rbac_group", args["sourceType"].Value)
	assert.Nil(t, args["sourceSeatTier"].Value)
	assert.Equal(t, "spl_01", args["spendLimitId"].Value)
	assert.Equal(t, "user_01", effectiveSpendLimitUserID(row))
}

// A null amount means no limit applies for the period. Zero would read as a
// cap that blocks every request, the opposite answer.
func TestEffectiveSpendLimitArgsUncappedReadsNull(t *testing.T) {
	row := decode[anthropic.BetaSpendSummary](t, `{
		"actor": {"type": "user_actor", "user_id": "user_01", "email_address": null, "name": null, "deleted": true},
		"amount": null, "currency": "USD", "period": "daily", "period_to_date_spend": "0",
		"scope": {"type": "user", "user_id": "user_01"},
		"source": {"type": "organization"}, "spend_limit_id": "spl_02"
	}`)

	args, err := effectiveSpendLimitArgs(row)
	require.NoError(t, err)
	assert.Nil(t, args["amount"].Value)
	assert.Equal(t, float64(0), args["periodToDateSpend"].Value)
	assert.Nil(t, args["actorEmail"].Value)
}

func TestEffectiveSpendLimitArgsRejectsMalformedAmount(t *testing.T) {
	row := decode[anthropic.BetaSpendSummary](t, `{"amount": "500.00", "period": "monthly", "period_to_date_spend": "1"}`)
	_, err := effectiveSpendLimitArgs(row)
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}

// One member resolves one row per period, so the period is part of the key.
func TestEffectiveSpendLimitArgsKeyedByPeriod(t *testing.T) {
	daily := decode[anthropic.BetaSpendSummary](t, `{"actor": {"type": "user_actor", "user_id": "user_01"},
		"amount": "100", "period": "daily", "period_to_date_spend": "1", "scope": {"type": "user", "user_id": "user_01"}}`)
	monthly := decode[anthropic.BetaSpendSummary](t, `{"actor": {"type": "user_actor", "user_id": "user_01"},
		"amount": "100", "period": "monthly", "period_to_date_spend": "1", "scope": {"type": "user", "user_id": "user_01"}}`)
	a, err := effectiveSpendLimitArgs(daily)
	require.NoError(t, err)
	b, err := effectiveSpendLimitArgs(monthly)
	require.NoError(t, err)
	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
}

func TestEffectiveSpendLimitUserIDFallsBackToScope(t *testing.T) {
	row := decode[anthropic.BetaSpendSummary](t, `{"actor": {"type": "scoped_api_key_actor", "scoped_api_key_id": "apikey_1"},
		"scope": {"type": "user", "user_id": "user_09"}}`)
	assert.Equal(t, "user_09", effectiveSpendLimitUserID(row))
}

// Plugins

func TestPluginArgsOrganizationOwned(t *testing.T) {
	p := decode[anthropic.BetaPlugin](t, `{
		"id": "plugin_01", "type": "plugin", "name": "deploy-helper", "display_name": "Deploy Helper",
		"description": "ships things", "manifest_version": "1.2.0", "marketplace_id": "marketplace_org",
		"owner": {"type": "organization"},
		"reach": "remote",
		"organization_installation_preference": "required",
		"organization_installation_preference_inherited": false,
		"served_version_id": "pluginver_1", "served_version_pinned": true, "latest_version_id": "pluginver_2",
		"content_scan": {"status": "completed", "assessment": "warn", "reason": "credential-exposure"},
		"components": [{"type": "mcp_server", "name": "deployer", "description": "talks to prod"}],
		"created_by": {"type": "api_actor", "api_key_id": "apikey_1"},
		"created_at": "2026-09-01T10:00:00Z", "updated_at": "2026-09-03T10:00:00Z"
	}`)

	args := pluginArgs(p)
	assert.Equal(t, "deploy-helper", args["name"].Value)
	assert.Equal(t, "Deploy Helper", args["displayName"].Value)
	assert.Equal(t, "1.2.0", args["manifestVersion"].Value)
	assert.Equal(t, "remote", args["reach"].Value)
	assert.Equal(t, "required", args["installationPreference"].Value)
	assert.Equal(t, false, args["installationPreferenceInherited"].Value)
	assert.Equal(t, true, args["servedVersionPinned"].Value)
	assert.Equal(t, "pluginver_1", args["servedVersionId"].Value)
	assert.Equal(t, "pluginver_2", args["latestVersionId"].Value)
	assert.Equal(t, "completed", args["contentScanStatus"].Value)
	assert.Equal(t, "warn", args["contentScanAssessment"].Value)
	assert.Equal(t, "credential-exposure", args["contentScanReason"].Value)
	assert.Equal(t, "api_actor", args["createdByType"].Value)
	assert.Equal(t, "organization", args["ownerType"].Value)

	comps := pluginComponents(p)
	require.Len(t, comps, 1)
	assert.Equal(t, anthropic.BetaPluginComponentType("mcp_server"), comps[0].Type)
}

// A member-owned plugin has no organization-wide setting, and an unscanned
// version has no verdict. Both must read as null: an empty assessment would
// compare unequal to "fail" and pass a "no failing plugins" check.
func TestPluginArgsMemberOwnedUnscannedReadsNull(t *testing.T) {
	p := decode[anthropic.BetaPlugin](t, `{
		"id": "plugin_02", "name": "mine", "marketplace_id": "marketplace_user",
		"owner": {"type": "user", "user_id": "user_01"},
		"reach": null,
		"organization_installation_preference": null,
		"organization_installation_preference_inherited": null,
		"content_scan": null, "components": null, "created_by": null,
		"created_at": "2026-09-01T10:00:00Z", "updated_at": "2026-09-01T10:00:00Z"
	}`)

	args := pluginArgs(p)
	assert.Equal(t, "user", args["ownerType"].Value)
	assert.Nil(t, args["reach"].Value)
	assert.Nil(t, args["installationPreference"].Value)
	assert.Nil(t, args["installationPreferenceInherited"].Value)
	assert.Nil(t, args["contentScanStatus"].Value)
	assert.Nil(t, args["contentScanAssessment"].Value)
	assert.Nil(t, args["createdByType"].Value)
	assert.Nil(t, pluginComponents(p), "components not enumerated must stay apart from none")

	empty := decode[anthropic.BetaPlugin](t, `{"id": "plugin_03", "components": []}`)
	comps := pluginComponents(empty)
	assert.NotNil(t, comps)
	assert.Empty(t, comps)
}

func TestPluginComponentArgsKeyedByType(t *testing.T) {
	skill := anthropic.BetaPluginComponent{Name: "deploy", Type: "skill"}
	command := anthropic.BetaPluginComponent{Name: "deploy", Type: "command"}
	assert.NotEqual(t,
		pluginComponentArgs("plugin_01", skill)["__id"].Value,
		pluginComponentArgs("plugin_01", command)["__id"].Value)
}

func TestPluginMarketplaceArgs(t *testing.T) {
	synced := decode[anthropic.BetaPluginMarketplace](t, `{
		"id": "marketplace_1", "type": "plugin_marketplace", "name": "acme-plugins", "source": "github",
		"owner": {"type": "organization"}, "default_installation_preference": "available",
		"sync_status": "failed_auth", "last_sync_ended_at": "2026-09-05T10:00:00Z",
		"last_sync_read_sha": "0123abcd", "created_at": "2026-09-01T10:00:00Z"
	}`)
	args := pluginMarketplaceArgs(synced)
	assert.Equal(t, "acme-plugins", args["name"].Value)
	assert.Equal(t, "github", args["source"].Value)
	assert.Equal(t, "organization", args["ownerType"].Value)
	assert.Equal(t, "available", args["defaultInstallationPreference"].Value)
	assert.Equal(t, "failed_auth", args["syncStatus"].Value)
	assert.Equal(t, "0123abcd", args["lastSyncReadSha"].Value)
	assert.Equal(t, time.Date(2026, 9, 5, 10, 0, 0, 0, time.UTC), *args["lastSyncEndedAt"].Value.(*time.Time))

	manual := decode[anthropic.BetaPluginMarketplace](t, `{
		"id": "marketplace_2", "name": "library", "source": "manual",
		"owner": {"type": "user", "user_id": "user_01"}, "default_installation_preference": null,
		"sync_status": null, "last_sync_ended_at": null, "last_sync_read_sha": null,
		"created_at": "2026-09-01T10:00:00Z"
	}`)
	args = pluginMarketplaceArgs(manual)
	assert.Nil(t, args["syncStatus"].Value)
	assert.Nil(t, args["lastSyncEndedAt"].Value)
	assert.Nil(t, args["lastSyncReadSha"].Value)
	assert.Nil(t, args["defaultInstallationPreference"].Value)
}

func TestPluginsInMarketplace(t *testing.T) {
	a := &mqlClaudeOrganizationPlugin{}
	a.cacheMarketplaceID = "marketplace_1"
	b := &mqlClaudeOrganizationPlugin{}
	b.cacheMarketplaceID = "marketplace_2"
	assert.Equal(t, []interface{}{b}, pluginsInMarketplace([]interface{}{a, b}, "marketplace_2"))
}

// External keys

func TestExternalKeyArgsAWS(t *testing.T) {
	k := decode[anthropic.ExternalKey](t, `{
		"id": "ekey_01", "type": "external_key", "display_name": "prod",
		"geo": "us", "attachment": {"type": "attached"},
		"provider_config": {"type": "aws", "kms_arn": "arn:aws:kms:us-east-1:111122223333:key/abcd", "region": "us-east-1"},
		"created_at": "2026-09-01T10:00:00Z", "updated_at": "2026-09-01T10:00:00Z"
	}`)
	args := externalKeyArgs(k)
	assert.Equal(t, "ekey_01", args["id"].Value)
	assert.Equal(t, "prod", args["displayName"].Value)
	assert.Equal(t, "us", args["geo"].Value)
	assert.Equal(t, "aws", args["provider"].Value)
	assert.Equal(t, "arn:aws:kms:us-east-1:111122223333:key/abcd", args["kmsArn"].Value)
	assert.Equal(t, "us-east-1", args["region"].Value)
	assert.Equal(t, true, args["attached"].Value)
	assert.Nil(t, args["vaultUri"].Value)
	assert.Nil(t, args["keyName"].Value)
}

func TestExternalKeyArgsAzureUnattached(t *testing.T) {
	k := decode[anthropic.ExternalKey](t, `{
		"id": "ekey_02", "display_name": null, "geo": "us", "attachment": {"type": "unattached"},
		"provider_config": {"type": "azure", "vault_uri": "https://example.vault.azure.net",
			"key_name": "claude", "tenant_id": "00000000-0000-0000-0000-000000000001", "client_id": null},
		"created_at": "2026-09-01T10:00:00Z", "updated_at": "2026-09-01T10:00:00Z"
	}`)
	args := externalKeyArgs(k)
	assert.Equal(t, "azure", args["provider"].Value)
	assert.Equal(t, "https://example.vault.azure.net", args["vaultUri"].Value)
	assert.Equal(t, "claude", args["keyName"].Value)
	assert.Equal(t, "00000000-0000-0000-0000-000000000001", args["tenantId"].Value)
	assert.Nil(t, args["clientId"].Value, "no client id means Anthropic's multitenant app")
	assert.Nil(t, args["displayName"].Value)
	assert.Nil(t, args["kmsArn"].Value)
	assert.Equal(t, false, args["attached"].Value)
}

// An attachment state this schema does not know is not a "no".
func TestExternalKeyArgsUnknownAttachmentReadsNull(t *testing.T) {
	k := decode[anthropic.ExternalKey](t, `{"id": "ekey_03", "attachment": {"type": "detaching"},
		"provider_config": {"type": "gcp", "key_name": "projects/p/locations/us/keyRings/r/cryptoKeys/k"}}`)
	args := externalKeyArgs(k)
	assert.Nil(t, args["attached"].Value)
	assert.Equal(t, "projects/p/locations/us/keyRings/r/cryptoKeys/k", args["keyName"].Value)
}

func testWorkspace(id string, keyID *string) *mqlClaudeOrganizationWorkspace {
	ws := &mqlClaudeOrganizationWorkspace{Id: plugin.TValue[string]{Data: id, State: plugin.StateIsSet}}
	ws.ExternalKeyId = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	if keyID != nil {
		ws.ExternalKeyId = plugin.TValue[string]{Data: *keyID, State: plugin.StateIsSet}
	}
	return ws
}

func TestWorkspacesUsingKey(t *testing.T) {
	key := "ekey_01"
	other := "ekey_02"
	a := testWorkspace("wrkspc_a", &key)
	b := testWorkspace("wrkspc_b", &other)
	c := testWorkspace("wrkspc_c", nil)

	assert.Equal(t, []interface{}{a}, workspacesUsingKey([]interface{}{a, b, c}, "ekey_01"))
	assert.Empty(t, workspacesUsingKey([]interface{}{a, b, c}, ""),
		"an empty key id must not match every unencrypted workspace")
}
