// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestAuditLogWindowDefault(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	w, err := auditLogWindowFromArgs(map[string]*llx.RawData{}, now)
	require.NoError(t, err)

	assert.Equal(t, now.Add(-7*24*time.Hour), w.since)
	assert.False(t, w.sinceExplicit)
	assert.Equal(t, "activityDateTime ge 2026-09-24T12:00:00Z", w.odataFilter())
}

func TestAuditLogWindowExplicitSince(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	// A non-UTC zone must be rendered as UTC in the filter.
	since := time.Date(2026, 9, 1, 2, 30, 0, 0, time.FixedZone("CEST", 2*60*60))
	w, err := auditLogWindowFromArgs(map[string]*llx.RawData{"since": llx.TimeData(since)}, now)
	require.NoError(t, err)

	assert.True(t, w.sinceExplicit)
	assert.Equal(t, "activityDateTime ge 2026-09-01T00:30:00Z", w.odataFilter())
}

func TestAuditLogWindowFilterIsParenthesized(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	w, err := auditLogWindowFromArgs(map[string]*llx.RawData{
		"filter": llx.StringData("  category eq 'RoleManagement' or category eq 'Policy' "),
	}, now)
	require.NoError(t, err)

	assert.Equal(t,
		"activityDateTime ge 2026-09-24T12:00:00Z and (category eq 'RoleManagement' or category eq 'Policy')",
		w.odataFilter(),
		"an `or` in the caller's filter must not widen the time window")
}

func TestAuditLogWindowBlankFilterAddsNothing(t *testing.T) {
	now := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	w, err := auditLogWindowFromArgs(map[string]*llx.RawData{"filter": llx.StringData("   ")}, now)
	require.NoError(t, err)
	assert.Equal(t, "activityDateTime ge 2026-09-24T12:00:00Z", w.odataFilter())
}

func TestAuditLogWindowRejectsWrongTypes(t *testing.T) {
	now := time.Now()
	_, err := auditLogWindowFromArgs(map[string]*llx.RawData{"since": llx.StringData("yesterday")}, now)
	assert.Error(t, err)
	_, err = auditLogWindowFromArgs(map[string]*llx.RawData{"filter": llx.IntData(1)}, now)
	assert.Error(t, err)
}

func TestAuditLogCacheID(t *testing.T) {
	t1 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	t2 := t1.Add(time.Minute)

	defaultA, err := auditLogWindowFromArgs(map[string]*llx.RawData{}, t1)
	require.NoError(t, err)
	defaultB, err := auditLogWindowFromArgs(map[string]*llx.RawData{}, t2)
	require.NoError(t, err)
	assert.Equal(t, defaultA.cacheID("r"), defaultB.cacheID("r"),
		"argument-less lists share one cache entry even when created at different times")

	explicit, err := auditLogWindowFromArgs(map[string]*llx.RawData{"since": llx.TimeData(defaultA.since)}, t1)
	require.NoError(t, err)
	assert.NotEqual(t, defaultA.cacheID("r"), explicit.cacheID("r"))

	other, err := auditLogWindowFromArgs(map[string]*llx.RawData{"since": llx.TimeData(t2)}, t1)
	require.NoError(t, err)
	assert.NotEqual(t, explicit.cacheID("r"), other.cacheID("r"))

	filtered, err := auditLogWindowFromArgs(map[string]*llx.RawData{"filter": llx.StringData("category eq 'Policy'")}, t1)
	require.NoError(t, err)
	assert.NotEqual(t, defaultA.cacheID("r"), filtered.cacheID("r"))

	assert.NotEqual(t, defaultA.cacheID("a"), defaultA.cacheID("b"))
}

func TestInitAuditLogListFillsFields(t *testing.T) {
	args, err := initAuditLogList("microsoft.auditLogs.directoryAudits", map[string]*llx.RawData{})
	require.NoError(t, err)

	since, ok := args["since"].Value.(*time.Time)
	require.True(t, ok)
	assert.WithinDuration(t, time.Now().Add(-7*24*time.Hour), *since, time.Minute)
	assert.Equal(t, "", args["filter"].Value)
	assert.Equal(t, "microsoft.auditLogs.directoryAudits/since/default/filter/<none>", args["__id"].Value)
}

func TestClassifyAuditLogError(t *testing.T) {
	assert.Nil(t, classifyAuditLogError(nil))

	denied := classifyAuditLogError(transformError(odataErrWithStatus("Authorization_RequestDenied", http.StatusForbidden)))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(denied))
	var e *llx.Error
	require.True(t, errors.As(denied, &e))
	assert.Equal(t, []string{"AuditLog.Read.All"}, e.Permissions)

	unlicensed := classifyAuditLogError(transformError(odataErrWithStatus(graphCodeNonPremiumTenant, http.StatusForbidden)))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(unlicensed))

	// An error straight from the SDK is classified the same as one that
	// already went through transformError.
	rawDenied := classifyAuditLogError(odataErrWithStatus("Authorization_RequestDenied", http.StatusForbidden))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(rawDenied))
	rawUnlicensed := classifyAuditLogError(odataErrWithStatus(graphCodeNonPremiumTenant, http.StatusForbidden))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(rawUnlicensed))

	badRequest := classifyAuditLogError(odataErrWithStatus("BadRequest", http.StatusBadRequest))
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(badRequest))
	assert.Equal(t, http.StatusBadRequest, graphStatusCode(badRequest), "the Graph error stays reachable")

	transport := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyAuditLogError(transport)))
}

func parseDirectoryAudit(t *testing.T, raw string) models.DirectoryAuditable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(raw))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDirectoryAuditFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.DirectoryAuditable)
}

const userInitiatedAuditJSON = `{
  "id": "Directory_ce218a67-0e3f-4b19-8f9d-2e7e6a1b0c11",
  "category": "GroupManagement",
  "correlationId": "da159bfb-54fa-4092-8a38-6e1fa7870e30",
  "result": "failure",
  "resultReason": "Member already exists",
  "activityDisplayName": "Add member to group",
  "activityDateTime": "2026-09-30T21:20:02.7215374Z",
  "loggedByService": "Core Directory",
  "operationType": "Assign",
  "initiatedBy": {
    "app": null,
    "user": {
      "id": "728309ae-4a37-4b7d-9a6e-1f8f2e2bd7f1",
      "displayName": null,
      "userPrincipalName": "admin@contoso.example",
      "ipAddress": "203.0.113.7"
    }
  },
  "targetResources": [
    {
      "@odata.type": "#microsoft.graph.targetResourceGroup",
      "id": "ef7e527d-6c92-4234-8c6d-cf6fdfb57f95",
      "displayName": "Finance",
      "type": "Group",
      "groupType": "unifiedGroups",
      "modifiedProperties": [
        {"displayName": "Group.DisplayName", "oldValue": null, "newValue": "\"Finance\""}
      ]
    }
  ],
  "additionalDetails": [
    {"key": "User-Agent", "value": "Mozilla/5.0"},
    {"key": "User-Agent", "value": "second"},
    {"key": "Empty", "value": null}
  ]
}`

func TestDirectoryAuditArgsUserInitiated(t *testing.T) {
	args, userID, spID, err := directoryAuditArgs(parseDirectoryAudit(t, userInitiatedAuditJSON))
	require.NoError(t, err)

	assert.Equal(t, "728309ae-4a37-4b7d-9a6e-1f8f2e2bd7f1", userID)
	assert.Empty(t, spID)

	assert.Equal(t, "Directory_ce218a67-0e3f-4b19-8f9d-2e7e6a1b0c11", args["__id"].Value)
	assert.Equal(t, "GroupManagement", args["category"].Value)
	assert.Equal(t, "da159bfb-54fa-4092-8a38-6e1fa7870e30", args["correlationId"].Value)
	assert.Equal(t, "failure", args["result"].Value)
	assert.Equal(t, "Member already exists", args["resultReason"].Value)
	assert.Equal(t, "Add member to group", args["activityDisplayName"].Value)
	assert.Equal(t, "Core Directory", args["loggedByService"].Value)
	assert.Equal(t, "Assign", args["operationType"].Value)
	ts := args["activityDateTime"].Value.(*time.Time)
	assert.Equal(t, time.Date(2026, 9, 30, 21, 20, 2, 721537400, time.UTC), ts.UTC())

	ib := args["initiatedBy"].Value.(map[string]any)
	user := ib["user"].(map[string]any)
	assert.Equal(t, "admin@contoso.example", user["userPrincipalName"])
	assert.Equal(t, "203.0.113.7", user["ipAddress"])

	targets := args["targetResources"].Value.([]any)
	require.Len(t, targets, 1)
	target := targets[0].(map[string]any)
	assert.Equal(t, "Group", target["type"])
	assert.Equal(t, "unifiedGroups", target["groupType"])
	mods := target["modifiedProperties"].([]any)
	require.Len(t, mods, 1)
	assert.Equal(t, `"Finance"`, mods[0].(map[string]any)["newValue"])

	details := args["additionalDetails"].Value.(map[string]any)
	assert.Equal(t, "Mozilla/5.0", details["User-Agent"], "the first value of a repeated key is kept")
	assert.Equal(t, "", details["Empty"])
}

func TestDirectoryAuditArgsAppInitiated(t *testing.T) {
	const raw = `{
  "id": "Directory_1",
  "result": "success",
  "initiatedBy": {
    "user": null,
    "app": {
      "appId": "0a1b2c3d-0000-0000-0000-000000000001",
      "displayName": "Provisioning Agent",
      "servicePrincipalId": "5f2c1e7a-0000-0000-0000-000000000002",
      "servicePrincipalName": null
    }
  }
}`
	args, userID, spID, err := directoryAuditArgs(parseDirectoryAudit(t, raw))
	require.NoError(t, err)
	assert.Empty(t, userID)
	assert.Equal(t, "5f2c1e7a-0000-0000-0000-000000000002", spID)
	app := args["initiatedBy"].Value.(map[string]any)["app"].(map[string]any)
	assert.Equal(t, "0a1b2c3d-0000-0000-0000-000000000001", app["appId"])
	assert.Equal(t, "success", args["result"].Value)
}

func TestDirectoryAuditArgsAbsentValues(t *testing.T) {
	args, userID, spID, err := directoryAuditArgs(parseDirectoryAudit(t, `{"id": "Directory_2"}`))
	require.NoError(t, err)
	assert.Empty(t, userID)
	assert.Empty(t, spID)
	assert.Nil(t, args["initiatedBy"].Value)
	assert.Nil(t, args["result"].Value)
	assert.Nil(t, args["activityDateTime"].Value, "an absent timestamp is null, not year 1")
	assert.Equal(t, []any{}, args["targetResources"].Value)
	assert.Equal(t, map[string]any{}, args["additionalDetails"].Value)
}

func parseProvisioningEvent(t *testing.T, raw string) models.ProvisioningObjectSummaryable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(raw))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateProvisioningObjectSummaryFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.ProvisioningObjectSummaryable)
}

const provisioningEventJSON = `{
  "id": "75b5b0a6-8f5a-4a9b-9a0e-0d2b6e0b7c41",
  "activityDateTime": "2026-09-29T18:24:11Z",
  "tenantId": "00000000-0000-0000-0000-000000000000",
  "jobId": "aws.7e2b.1c9e",
  "cycleId": "13b4b0c6-5b2a-4a5c-9e6a-6f4a0c8f0b21",
  "changeId": "4d3c9b52-1a45-4e0e-9b2e-3b0a7c9e7d10",
  "provisioningAction": "stagedDelete",
  "durationInMilliseconds": 571,
  "servicePrincipal": {"id": "8f4c2e9a-0000-0000-0000-000000000003", "displayName": "AWS Single-Account Access"},
  "sourceSystem": {"id": "0b4d0d4e-0000-0000-0000-000000000004", "displayName": "Azure Active Directory", "details": {}},
  "targetSystem": {"id": "c1a2b3c4-0000-0000-0000-000000000005", "displayName": "AWS", "details": {"ApplicationId": "app-123", "ServicePrincipalDisplayName": "AWS"}},
  "sourceIdentity": {"id": "e5f6a7b8-0000-0000-0000-000000000006", "displayName": "Jane Doe", "identityType": "User", "details": {}},
  "targetIdentity": {"id": "", "displayName": "", "identityType": "User", "details": {}},
  "provisioningStatusInfo": {
    "status": "failure",
    "errorInformation": {
      "errorCode": "AzureActiveDirectoryCannotUpdateObjectsMasteredOnPremises",
      "errorCategory": "nonServiceFailure",
      "reason": "The object is mastered on premises.",
      "additionalDetails": null,
      "recommendedAction": null
    }
  }
}`

func TestProvisioningEventArgs(t *testing.T) {
	args, spID, err := provisioningEventArgs(parseProvisioningEvent(t, provisioningEventJSON))
	require.NoError(t, err)

	assert.Equal(t, "8f4c2e9a-0000-0000-0000-000000000003", spID)
	assert.Equal(t, "75b5b0a6-8f5a-4a9b-9a0e-0d2b6e0b7c41", args["__id"].Value)
	assert.Equal(t, "aws.7e2b.1c9e", args["jobId"].Value)
	assert.Equal(t, "13b4b0c6-5b2a-4a5c-9e6a-6f4a0c8f0b21", args["cycleId"].Value)
	assert.Equal(t, "4d3c9b52-1a45-4e0e-9b2e-3b0a7c9e7d10", args["changeId"].Value)
	assert.Equal(t, "stagedDelete", args["provisioningAction"].Value)
	assert.Equal(t, int64(571), args["durationInMilliseconds"].Value)
	assert.Equal(t, "failure", args["status"].Value)
	ts := args["activityDateTime"].Value.(*time.Time)
	assert.Equal(t, time.Date(2026, 9, 29, 18, 24, 11, 0, time.UTC), ts.UTC())

	errInfo := args["errorInformation"].Value.(map[string]any)
	assert.Equal(t, "AzureActiveDirectoryCannotUpdateObjectsMasteredOnPremises", errInfo["errorCode"])
	assert.Equal(t, "nonServiceFailure", errInfo["errorCategory"])

	// details is an open type: its keys exist only in the SDK's additional data.
	target := args["targetSystem"].Value.(map[string]any)
	assert.Equal(t, "AWS", target["displayName"])
	assert.Equal(t, "app-123", target["details"].(map[string]any)["ApplicationId"])

	source := args["sourceIdentity"].Value.(map[string]any)
	assert.Equal(t, "Jane Doe", source["displayName"])
	assert.Equal(t, "User", source["identityType"])
}

func TestProvisioningEventArgsAbsentValues(t *testing.T) {
	args, spID, err := provisioningEventArgs(parseProvisioningEvent(t, `{"id": "p1", "provisioningStatusInfo": {"status": "success"}}`))
	require.NoError(t, err)
	assert.Empty(t, spID)
	assert.Equal(t, "success", args["status"].Value)
	assert.Nil(t, args["errorInformation"].Value, "a successful event carries no error")
	assert.Nil(t, args["durationInMilliseconds"].Value)
	assert.Nil(t, args["provisioningAction"].Value)
	assert.Nil(t, args["targetSystem"].Value)
}

func TestAuditLogRefsEmptyIDIsNull(t *testing.T) {
	// No runtime: an empty id must short-circuit before any list is fetched.
	refs := &auditLogRefs{}
	u, err := refs.user("")
	assert.NoError(t, err)
	assert.Nil(t, u)
	sp, err := refs.servicePrincipal("")
	assert.NoError(t, err)
	assert.Nil(t, sp)
}
