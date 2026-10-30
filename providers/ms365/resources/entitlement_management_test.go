// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"
	"time"

	"github.com/microsoft/kiota-abstractions-go/serialization"
	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// An assignment policy as Microsoft Graph returns it from
// /identityGovernance/entitlementManagement/assignmentPolicies?$expand=accessPackage($select=id),
// shaped after the v1.0 accessPackageAssignmentPolicy documentation.
const approvalPolicyJSON = `{
  "id": "b2eba9a1-b357-42ee-83a8-336522ed6cbf",
  "displayName": "Users in sales",
  "description": "Sales staff request with manager approval",
  "allowedTargetScope": "specificDirectoryUsers",
  "createdDateTime": "2024-03-01T10:00:00Z",
  "modifiedDateTime": "2024-04-02T11:30:00Z",
  "specificAllowedTargets": [
    {"@odata.type": "#microsoft.graph.groupMembers", "groupId": "7c4d1f6b-1a2b-4c3d-8e9f-0a1b2c3d4e5f", "description": "Sales"}
  ],
  "expiration": {"endDateTime": null, "duration": "P365D", "type": "afterDuration"},
  "requestorSettings": {
    "enableTargetsToSelfAddAccess": true,
    "enableTargetsToSelfUpdateAccess": false,
    "enableTargetsToSelfRemoveAccess": true,
    "allowCustomAssignmentSchedule": false,
    "enableOnBehalfRequestorsToAddAccess": false,
    "enableOnBehalfRequestorsToUpdateAccess": false,
    "enableOnBehalfRequestorsToRemoveAccess": false,
    "onBehalfRequestors": []
  },
  "requestApprovalSettings": {
    "isApprovalRequiredForAdd": true,
    "isApprovalRequiredForUpdate": false,
    "isRequestorJustificationRequired": true,
    "stages": [
      {
        "durationBeforeAutomaticDenial": "P14D",
        "isApproverJustificationRequired": true,
        "isEscalationEnabled": false,
        "durationBeforeEscalation": "PT0S",
        "primaryApprovers": [
          {"@odata.type": "#microsoft.graph.singleUser", "userId": "e6a4b3c2-1111-4a2b-9c8d-123456789abc", "description": "Approver"}
        ],
        "fallbackPrimaryApprovers": [],
        "escalationApprovers": [],
        "fallbackEscalationApprovers": []
      }
    ]
  },
  "reviewSettings": {
    "isEnabled": true,
    "expirationBehavior": "removeAccess",
    "schedule": {
      "startDateTime": "2024-03-01T10:00:00Z",
      "expiration": {"duration": "P14D", "type": "afterDuration"},
      "recurrence": {"pattern": {"type": "absoluteMonthly", "interval": 3}}
    },
    "isRecommendationEnabled": true,
    "isReviewerJustificationRequired": true,
    "isSelfReview": false,
    "primaryReviewers": [],
    "fallbackReviewers": []
  },
  "accessPackage": {"id": "56ff43fd-6b05-48df-9634-956a777fce6d"}
}`

// A policy that admits any external user, with no approval, review or
// expiration settings in the payload.
const externalOpenPolicyJSON = `{
  "id": "a1b2c3d4-0000-4000-8000-000000000001",
  "displayName": "Anyone outside",
  "allowedTargetScope": "allExternalUsers",
  "automaticRequestSettings": {
    "requestAccessForAllowedTargets": true,
    "removeAccessWhenTargetLeavesAllowedTargets": true,
    "gracePeriodBeforeAccessRemoval": "P7D"
  }
}`

func parseAssignmentPolicy(t *testing.T, payload string) models.AccessPackageAssignmentPolicyable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateAccessPackageAssignmentPolicyFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.AccessPackageAssignmentPolicyable)
}

func TestAccessPackageAssignmentPolicyArgs_ApprovalPolicy(t *testing.T) {
	args, err := accessPackageAssignmentPolicyArgs(parseAssignmentPolicy(t, approvalPolicyJSON))
	require.NoError(t, err)

	assert.Equal(t, "microsoft.identityAndAccess.accessPackageAssignmentPolicy/b2eba9a1-b357-42ee-83a8-336522ed6cbf", args["__id"].Value)
	assert.Equal(t, "specificDirectoryUsers", args["allowedTargetScope"].Value)
	assert.Equal(t, false, args["allowsExternalRequestors"].Value)

	assert.Equal(t, true, args["isApprovalRequiredForAdd"].Value)
	assert.Equal(t, false, args["isApprovalRequiredForUpdate"].Value)
	assert.Equal(t, true, args["isRequestorJustificationRequired"].Value)

	stages := args["approvalStages"].Value.([]any)
	require.Len(t, stages, 1)
	stage := stages[0].(map[string]any)
	// Kiota alone would render these as P2W and a bare P.
	assert.Equal(t, "P14D", stage["durationBeforeAutomaticDenial"])
	assert.Equal(t, "PT0S", stage["durationBeforeEscalation"])
	approvers := stage["primaryApprovers"].([]any)
	require.Len(t, approvers, 1)
	approver := approvers[0].(map[string]any)
	assert.Equal(t, "#microsoft.graph.singleUser", approver["@odata.type"])
	assert.Equal(t, "e6a4b3c2-1111-4a2b-9c8d-123456789abc", approver["userId"])

	targets := args["specificAllowedTargets"].Value.([]any)
	require.Len(t, targets, 1)
	target := targets[0].(map[string]any)
	assert.Equal(t, "#microsoft.graph.groupMembers", target["@odata.type"])
	assert.Equal(t, "7c4d1f6b-1a2b-4c3d-8e9f-0a1b2c3d4e5f", target["groupId"])

	assert.Equal(t, "afterDuration", args["expirationType"].Value)
	assert.Equal(t, "P365D", args["expirationDuration"].Value)
	assert.Nil(t, args["expirationEndDateTime"].Value)

	requestor := args["requestorSettings"].Value.(map[string]any)
	assert.Equal(t, true, requestor["enableTargetsToSelfAddAccess"])
	assert.Equal(t, false, requestor["enableTargetsToSelfUpdateAccess"])

	assert.Equal(t, true, args["isAccessReviewEnabled"].Value)
	review := args["reviewSettings"].Value.(map[string]any)
	assert.Equal(t, "removeAccess", review["expirationBehavior"])
	// Kiota alone would render this nested duration as P2W.
	reviewExpiration := review["schedule"].(map[string]any)["expiration"].(map[string]any)
	assert.Equal(t, "P14D", reviewExpiration["duration"])

	assert.Nil(t, args["automaticRequestSettings"].Value)

	created := args["createdDateTime"].Value.(*time.Time)
	assert.Equal(t, time.Date(2024, 3, 1, 10, 0, 0, 0, time.UTC), created.UTC())
}

func TestAccessPackageAssignmentPolicyArgs_AbsentSettingsReadNull(t *testing.T) {
	args, err := accessPackageAssignmentPolicyArgs(parseAssignmentPolicy(t, externalOpenPolicyJSON))
	require.NoError(t, err)

	assert.Equal(t, true, args["allowsExternalRequestors"].Value)
	// No approval block means Graph said nothing about approval: null, not
	// false, so an approval check does not read a measured "not required".
	assert.Nil(t, args["isApprovalRequiredForAdd"].Value)
	assert.Nil(t, args["isAccessReviewEnabled"].Value)
	assert.Nil(t, args["reviewSettings"].Value)
	assert.Nil(t, args["requestorSettings"].Value)
	assert.Nil(t, args["expirationType"].Value)
	assert.Nil(t, args["expirationDuration"].Value)
	assert.Empty(t, args["approvalStages"].Value)
	assert.Empty(t, args["specificAllowedTargets"].Value)

	auto := args["automaticRequestSettings"].Value.(map[string]any)
	assert.Equal(t, true, auto["removeAccessWhenTargetLeavesAllowedTargets"])
	assert.Equal(t, "P7D", auto["gracePeriodBeforeAccessRemoval"])
}

// A duration Kiota cannot normalize (P7DT12H folds into 1W12H, and ISO 8601
// allows weeks only alone) made its JSON writer panic, failing the whole
// assignment policy list.
func TestAccessPackageAssignmentPolicyArgs_UnnormalizableDuration(t *testing.T) {
	policy := parseAssignmentPolicy(t, `{
  "id": "c3d4e5f6-0000-4000-8000-000000000002",
  "reviewSettings": {
    "isEnabled": true,
    "schedule": {"expiration": {"duration": "P7DT12H", "type": "afterDuration"}}
  },
  "automaticRequestSettings": {"gracePeriodBeforeAccessRemoval": "P7DT12H"}
}`)
	var args map[string]*llx.RawData
	require.NotPanics(t, func() {
		var err error
		args, err = accessPackageAssignmentPolicyArgs(policy)
		require.NoError(t, err)
	})

	review := args["reviewSettings"].Value.(map[string]any)
	reviewExpiration := review["schedule"].(map[string]any)["expiration"].(map[string]any)
	assert.Equal(t, "P7DT12H", reviewExpiration["duration"])
	auto := args["automaticRequestSettings"].Value.(map[string]any)
	assert.Equal(t, "P7DT12H", auto["gracePeriodBeforeAccessRemoval"])

	// The durations are still on the model after serialization.
	d := policy.GetReviewSettings().GetSchedule().GetExpiration().GetDuration()
	require.NotNil(t, d)
	assert.Equal(t, "P7DT12H", *isoDurationPtr(d))
}

func TestIsoDurationPtr(t *testing.T) {
	assert.Nil(t, isoDurationPtr(nil))
	for in, want := range map[string]string{
		"P14D":      "P14D",
		"P2W":       "P14D",
		"P30D":      "P30D",
		"PT0S":      "PT0S",
		"P1DT2H30M": "P1DT2H30M",
		"PT1.5S":    "PT1.500S",
		"P1Y":       "P1Y",
		"PT36H":     "PT36H",
		"P6M":       "P6M",
		"P18M":      "P18M",
		"P1Y6M10D":  "P1Y6M10D",
		"P2Y14M":    "P2Y14M",
		"P6MT12H":   "P6MT12H",
	} {
		d, err := serialization.ParseISODuration(in)
		require.NoError(t, err, in)
		got := isoDurationPtr(d)
		require.NotNil(t, got, in)
		assert.Equal(t, want, *got, in)
	}
}

func TestAllowsExternalRequestors(t *testing.T) {
	assert.False(t, allowsExternalRequestors(nil))
	external := []string{"specificConnectedOrganizationUsers", "allConfiguredConnectedOrganizationUsers", "allExternalUsers"}
	internal := []string{"notSpecified", "specificDirectoryUsers", "specificDirectoryServicePrincipals", "allMemberUsers", "allDirectoryUsers", "allDirectoryServicePrincipals", "allDirectoryAgentIdentities", "unknownFutureValue"}
	for _, name := range external {
		scope, err := models.ParseAllowedTargetScope(name)
		require.NoError(t, err)
		assert.True(t, allowsExternalRequestors(scope.(*models.AllowedTargetScope)), name)
	}
	for _, name := range internal {
		scope, err := models.ParseAllowedTargetScope(name)
		require.NoError(t, err)
		assert.False(t, allowsExternalRequestors(scope.(*models.AllowedTargetScope)), name)
	}
}

func parseEntitlementManagementSettings(t *testing.T, payload string) models.EntitlementManagementSettingsable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateEntitlementManagementSettingsFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.EntitlementManagementSettingsable)
}

func TestEntitlementManagementSettingsArgs(t *testing.T) {
	args := entitlementManagementSettingsArgs(parseEntitlementManagementSettings(t,
		`{"id":"settings","durationUntilExternalUserDeletedAfterBlocked":"P30D","externalUserLifecycleAction":"blockSignInAndDelete"}`))
	assert.Equal(t, "blockSignInAndDelete", args["externalUserLifecycleAction"].Value)
	assert.Equal(t, "P30D", args["durationUntilExternalUserDeletedAfterBlocked"].Value)

	// The Kiota enum's zero value is "none": an absent action must not read
	// as a tenant that never removes external users.
	absent := entitlementManagementSettingsArgs(parseEntitlementManagementSettings(t, `{"id":"settings"}`))
	assert.Nil(t, absent["externalUserLifecycleAction"].Value)
	assert.Nil(t, absent["durationUntilExternalUserDeletedAfterBlocked"].Value)
}

func TestClassifyGraphErrorEntitlementManagement(t *testing.T) {
	forbidden := classifyGraphError(odataErrWithStatus("Authorization_RequestDenied", 403), entitlementManagementReadPermission)
	assert.True(t, errors.Is(forbidden, llx.ErrForbidden))
	detail := llx.ErrorDetailOf(forbidden)
	require.NotNil(t, detail)
	assert.Equal(t, []string{entitlementManagementReadPermission}, detail.Permissions)

	// A tenant without the Entra ID P2 or Governance license is refused with
	// a 403 too, but no permission grant would change the answer.
	notLicensed := classifyGraphError(odataErrWithStatus("AadPremiumLicenseRequired", 403), entitlementManagementReadPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(notLicensed))

	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(classifyGraphError(odataErrWithStatus("Request_ResourceNotFound", 404))))
}
