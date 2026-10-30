// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/openai/openai-go/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeBatch decodes an API-shaped batch payload the way the SDK does, so the
// presence flags the mappers read are populated exactly as they are at runtime.
func decodeBatch(t *testing.T, payload string) openai.Batch {
	t.Helper()
	var b openai.Batch
	require.NoError(t, json.Unmarshal([]byte(payload), &b))
	return b
}

func TestMapBatch(t *testing.T) {
	b := decodeBatch(t, `{
		"id": "batch_0000",
		"object": "batch",
		"endpoint": "/v1/chat/completions",
		"errors": null,
		"input_file_id": "file-input0",
		"completion_window": "24h",
		"status": "completed",
		"output_file_id": "file-output0",
		"error_file_id": "file-error0",
		"created_at": 1711471533,
		"in_progress_at": 1711471538,
		"expires_at": 1711557933,
		"finalizing_at": 1711493133,
		"completed_at": 1711493163,
		"model": "gpt-4o-mini",
		"request_counts": {"total": 100, "completed": 95, "failed": 5},
		"metadata": {"owner": "platform-team"}
	}`)

	args := mapBatch(b)
	assert.Equal(t, "batch_0000", args["__id"].Value)
	assert.Equal(t, "batch_0000", args["id"].Value)
	assert.Equal(t, "/v1/chat/completions", args["endpoint"].Value)
	assert.Equal(t, "completed", args["status"].Value)
	assert.Equal(t, "24h", args["completionWindow"].Value)

	// the timestamps the batch actually reported are real times
	assert.NotNil(t, args["createdAt"].Value)
	assert.NotNil(t, args["completedAt"].Value)

	// the ones it did not report stay null rather than becoming the zero time,
	// which would put a cancellation in January of year 1
	assert.Nil(t, args["cancelledAt"].Value, "a batch that was never cancelled has no cancellation time")
	assert.Nil(t, args["cancellingAt"].Value)
	assert.Nil(t, args["failedAt"].Value)
	assert.Nil(t, args["expiredAt"].Value)

	counts, ok := args["requestCounts"].Value.(map[string]any)
	require.True(t, ok, "request counts decode to a dict")
	assert.Equal(t, int64(100), counts["total"])
	assert.Equal(t, int64(95), counts["completed"])
	assert.Equal(t, int64(5), counts["failed"], "a failed-request tally that reads 0 hides a partially failed batch")

	assert.Equal(t, map[string]any{"owner": "platform-team"}, args["metadata"].Value)

	// the file and model references are cached for the accessors rather than
	// mapped, so they must not leak into the resource args as raw ids
	assert.NotContains(t, args, "inputFileId")
	assert.NotContains(t, args, "model")
}

func TestBatchRequestCountsAndMetadataStayNullWhenAbsent(t *testing.T) {
	// A batch that has not been counted yet omits the object entirely. Zeros
	// here would report a batch with no failed requests.
	b := decodeBatch(t, `{"id":"batch_0001","status":"validating","endpoint":"/v1/responses","metadata":null}`)
	assert.Nil(t, batchRequestCounts(b), "an uncounted batch reports no counts, not zero counts")
	assert.Nil(t, batchMetadata(b), "a batch with no metadata reports null, not an empty map")

	args := mapBatch(b)
	assert.Nil(t, args["requestCounts"].Value)
	assert.Nil(t, args["metadata"].Value)
	assert.Nil(t, args["createdAt"].Value)
}

func TestBatchCachesReferencesForTypedAccessors(t *testing.T) {
	b := decodeBatch(t, `{
		"id": "batch_0002",
		"input_file_id": "file-input0",
		"output_file_id": "",
		"model": "gpt-4o-mini"
	}`)
	assert.Equal(t, "file-input0", b.InputFileID)
	assert.Equal(t, "", b.OutputFileID, "an unfinished batch has no output file and must not resolve one")
	assert.Equal(t, "gpt-4o-mini", b.Model)
}

func TestVectorStoreFileArgs(t *testing.T) {
	var f openai.VectorStoreFile
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "file-0000",
		"object": "vector_store.file",
		"usage_bytes": 1234,
		"created_at": 1698107661,
		"vector_store_id": "vs_0000",
		"status": "completed",
		"last_error": null,
		"chunking_strategy": {"type": "static", "static": {"chunk_overlap_tokens": 400, "max_chunk_size_tokens": 800}}
	}`), &f))

	args := vectorStoreFileArgs("vs_0000", f)
	assert.Equal(t, "vs_0000/file-0000", args["__id"].Value,
		"the same upload is attached to several stores, so the membership id has to carry the store")
	assert.Equal(t, "file-0000", args["id"].Value)
	assert.Equal(t, "completed", args["status"].Value)
	assert.Equal(t, int64(1234), args["usageBytes"].Value)
	assert.Equal(t, "static", args["chunkingStrategyType"].Value)
	assert.Nil(t, args["lastErrorCode"].Value, "a file that embedded cleanly reports no error code")
	assert.Nil(t, args["lastErrorMessage"].Value)

	var failed openai.VectorStoreFile
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "file-0001",
		"status": "failed",
		"usage_bytes": 0,
		"created_at": 1698107661,
		"last_error": {"code": "unsupported_file", "message": "the file type is not supported"}
	}`), &failed))
	failedArgs := vectorStoreFileArgs("vs_0000", failed)
	assert.Equal(t, "unsupported_file", failedArgs["lastErrorCode"].Value)
	assert.Equal(t, "the file type is not supported", failedArgs["lastErrorMessage"].Value)
	assert.Nil(t, failedArgs["chunkingStrategyType"].Value, "a file with no reported strategy has none, not an empty one")
}

func TestMapSkill(t *testing.T) {
	var s openai.Skill
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "skill_0000",
		"object": "skill",
		"name": "expense-report",
		"description": "files an expense report",
		"default_version": "3",
		"latest_version": "5",
		"created_at": 1711471533
	}`), &s))

	args := mapSkill(s)
	assert.Equal(t, "skill_0000", args["__id"].Value)
	assert.Equal(t, "expense-report", args["name"].Value)
	assert.Equal(t, "3", args["defaultVersion"].Value,
		"the default version is what callers load, so it must not be read off the latest version")
	assert.Equal(t, "5", args["latestVersion"].Value)
	assert.NotNil(t, args["createdAt"].Value)
}

// decodeAuditLog decodes an API-shaped audit log entry, keeping the raw
// document the detail extraction reads.
func decodeAuditLog(t *testing.T, payload string) openai.AdminOrganizationAuditLogListResponse {
	t.Helper()
	var entry openai.AdminOrganizationAuditLogListResponse
	require.NoError(t, json.Unmarshal([]byte(payload), &entry))
	return entry
}

const sessionActorEntry = `{
	"id": "audit_log_0000",
	"type": "api_key.created",
	"effective_at": 1711471533,
	"project": {"id": "proj_0000", "name": "Production"},
	"actor": {
		"type": "session",
		"session": {
			"ip_address": "198.51.100.10",
			"user": {"id": "user_0000", "email": "member@example.com"}
		}
	},
	"api_key.created": {
		"id": "key_0000",
		"data": {"scopes": ["api.model.request"]}
	}
}`

const apiKeyActorEntry = `{
	"id": "audit_log_0001",
	"type": "login.succeeded",
	"effective_at": 1711471533,
	"actor": {
		"type": "api_key",
		"api_key": {
			"id": "key_0001",
			"type": "service_account",
			"service_account": {"id": "svc_acct_0000"}
		}
	}
}`

func TestAuditLogActorFields(t *testing.T) {
	session := decodeAuditLog(t, sessionActorEntry)
	require.NotNil(t, auditLogActorIPAddress(session.Actor))
	assert.Equal(t, "198.51.100.10", *auditLogActorIPAddress(session.Actor),
		`"who changed this, and from where" is unanswerable without the address`)
	assert.Nil(t, auditLogActorAPIKeyType(session.Actor), "a browser session has no API key behind it")
	assert.Equal(t, "user_0000", auditLogActorUserID(session.Actor))

	apiKey := decodeAuditLog(t, apiKeyActorEntry)
	assert.Nil(t, auditLogActorIPAddress(apiKey.Actor),
		"the API reports no address for a key, and \"\" would read as an event from an unknown address")
	require.NotNil(t, auditLogActorAPIKeyType(apiKey.Actor))
	assert.Equal(t, "service_account", *auditLogActorAPIKeyType(apiKey.Actor))
	assert.Equal(t, "", auditLogActorUserID(apiKey.Actor),
		"a service account key names no organization member")
}

func TestAuditLogActorUserIDForAUserKey(t *testing.T) {
	entry := decodeAuditLog(t, `{
		"id": "audit_log_0002",
		"type": "project.updated",
		"actor": {
			"type": "api_key",
			"api_key": {"id": "key_0002", "type": "user", "user": {"id": "user_0001", "email": "member@example.com"}}
		}
	}`)
	assert.Equal(t, "user_0001", auditLogActorUserID(entry.Actor),
		"a key issued to a person resolves back to that person")
}

func TestAuditLogDetails(t *testing.T) {
	entry := decodeAuditLog(t, sessionActorEntry)
	details, err := auditLogDetails(entry.RawJSON(), string(entry.Type))
	require.NoError(t, err)

	payload, ok := details.(map[string]any)
	require.True(t, ok, "the change record decodes to a dict")
	assert.Equal(t, "key_0000", payload["id"])
	data, ok := payload["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, []any{"api.model.request"}, data["scopes"])
}

func TestAuditLogDetailsForAnEventTypeTheSDKHasNoFieldFor(t *testing.T) {
	// The IP allowlist and workload identity events have no read endpoint of
	// their own, so the change record in the log is the only place their
	// configuration is visible. Reading by event-type key covers them without
	// a field per event type.
	entry := decodeAuditLog(t, `{
		"id": "audit_log_0003",
		"type": "ip_allowlist.updated",
		"actor": {"type": "session", "session": {"ip_address": "198.51.100.10"}},
		"ip_allowlist.updated": {
			"id": "ipal_0000",
			"changes_requested": {"allowed_ips": ["203.0.113.0/24"]}
		}
	}`)
	details, err := auditLogDetails(entry.RawJSON(), string(entry.Type))
	require.NoError(t, err)
	payload, ok := details.(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "ipal_0000", payload["id"])
}

func TestAuditLogDetailsAreNullWhenTheEventCarriesNone(t *testing.T) {
	entry := decodeAuditLog(t, apiKeyActorEntry)
	details, err := auditLogDetails(entry.RawJSON(), string(entry.Type))
	require.NoError(t, err)
	assert.Nil(t, details, "login.succeeded carries no payload, and an empty dict would claim one was read")

	details, err = auditLogDetails("", "api_key.created")
	require.NoError(t, err)
	assert.Nil(t, details)

	_, err = auditLogDetails("not json", "api_key.created")
	assert.Error(t, err, "an unreadable payload is reported, not silently nulled")
}

func decodeRoleAssignment(t *testing.T, payload string) openai.AdminOrganizationUserRoleListResponse {
	t.Helper()
	var role openai.AdminOrganizationUserRoleListResponse
	require.NoError(t, json.Unmarshal([]byte(payload), &role))
	return role
}

func TestRoleAssignmentIsDirect(t *testing.T) {
	direct := decodeRoleAssignment(t, `{
		"id": "role_0000",
		"name": "Owner",
		"permissions": ["organization.manage"],
		"predefined_role": true,
		"resource_type": "organization",
		"assignment_sources": [{"principal_id": "user_0000", "principal_type": "user"}]
	}`)
	isDirect, known := roleAssignmentIsDirect(direct.AssignmentSources, direct.JSON.AssignmentSources.Valid())
	assert.True(t, known)
	assert.True(t, isDirect)
	assert.Empty(t, roleAssignmentGroupIDs(direct.AssignmentSources))

	inherited := decodeRoleAssignment(t, `{
		"id": "role_0001",
		"name": "Owner",
		"assignment_sources": [
			{"principal_id": "group_0000", "principal_type": "group"},
			{"principal_id": "group_0001", "principal_type": "group"}
		]
	}`)
	isDirect, known = roleAssignmentIsDirect(inherited.AssignmentSources, inherited.JSON.AssignmentSources.Valid())
	assert.True(t, known)
	assert.False(t, isDirect,
		"a role held only through a group is not removable by editing the member")
	assert.Equal(t, []string{"group_0000", "group_0001"}, roleAssignmentGroupIDs(inherited.AssignmentSources))

	both := decodeRoleAssignment(t, `{
		"id": "role_0002",
		"assignment_sources": [
			{"principal_id": "group_0000", "principal_type": "group"},
			{"principal_id": "user_0000", "principal_type": "user"}
		]
	}`)
	isDirect, known = roleAssignmentIsDirect(both.AssignmentSources, both.JSON.AssignmentSources.Valid())
	assert.True(t, known)
	assert.True(t, isDirect, "a direct grant survives removal from every group that also confers it")
	assert.Equal(t, []string{"group_0000"}, roleAssignmentGroupIDs(both.AssignmentSources))
}

func TestRoleAssignmentIsDirectIsUnknownWithoutSources(t *testing.T) {
	// The API documents assignment sources as reported "when available". With
	// none reported neither answer is known, and a fabricated false would let
	// `.all(isDirect == false)` pass on a role nothing was read about.
	role := decodeRoleAssignment(t, `{"id": "role_0003", "name": "Reader"}`)
	require.False(t, role.JSON.AssignmentSources.Valid())
	isDirect, known := roleAssignmentIsDirect(role.AssignmentSources, role.JSON.AssignmentSources.Valid())
	assert.False(t, known, "the field has to stay null")
	assert.False(t, isDirect)

	// An empty but reported list is a different statement: sources were read
	// and none of them names a user.
	empty := decodeRoleAssignment(t, `{"id": "role_0004", "assignment_sources": []}`)
	require.True(t, empty.JSON.AssignmentSources.Valid())
	isDirect, known = roleAssignmentIsDirect(empty.AssignmentSources, empty.JSON.AssignmentSources.Valid())
	assert.True(t, known)
	assert.False(t, isDirect)
}

func TestMapProjectResidency(t *testing.T) {
	var p openai.Project
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "proj_0000",
		"object": "organization.project",
		"name": "Production",
		"status": "active",
		"residency": "EU_STORAGE_PROCESSING",
		"created_at": 1711471533
	}`), &p))

	args := mapProject(p)
	assert.Equal(t, "EU_STORAGE_PROCESSING", args["residency"].Value,
		"a project pinned to a region must report that region, not the SDK's typed wrapper")
}

// A project with no residency configuration must read as null. The SDK types
// Residency as a bare string, so a mapping that skips the empty check reports
// "" -- which a policy comparing against a region name cannot distinguish from
// a project that was never read.
func TestMapProjectResidencyIsNullWhenAbsent(t *testing.T) {
	var p openai.Project
	require.NoError(t, json.Unmarshal([]byte(`{
		"id": "proj_0001",
		"object": "organization.project",
		"name": "Sandbox",
		"status": "active",
		"created_at": 1711471533
	}`), &p))

	args := mapProject(p)
	assert.Nil(t, args["residency"].Value)
}
