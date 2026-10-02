// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"
	"testing"
	"time"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	igmodels "github.com/microsoftgraph/msgraph-sdk-go/models/identitygovernance"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// The payloads below follow the response examples of the Microsoft Graph v1.0
// reference for each resource and are decoded through the SDK's own
// discriminator factories, so a property that Kiota files somewhere the
// mapping does not read shows up as a failing assertion.

const agreementJSON = `{
  "id": "0ec9f6a6-159d-4dd8-a563-1f8b2d1a0a4e",
  "displayName": "Contoso ToU for guest users",
  "isViewingBeforeAcceptanceRequired": true,
  "isPerDeviceAcceptanceRequired": false,
  "userReacceptRequiredFrequency": "P90D",
  "termsExpiration": {
    "startDateTime": "2026-01-01T00:00:00Z",
    "frequency": "P365D"
  }
}`

// agreementNoExpiryJSON has neither an expiration schedule nor a reaccept
// frequency, which must read as null rather than as a zero duration.
const agreementNoExpiryJSON = `{
  "id": "5b8d1c0e-2f5a-4b8e-9a1c-3d4e5f6a7b8c",
  "displayName": "Employee terms",
  "isViewingBeforeAcceptanceRequired": false,
  "isPerDeviceAcceptanceRequired": true,
  "userReacceptRequiredFrequency": null,
  "termsExpiration": null
}`

func parseAgreement(t *testing.T, payload string) models.Agreementable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateAgreementFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.Agreementable)
}

func TestTermsOfUseAgreementArgs(t *testing.T) {
	args := newTermsOfUseAgreementArgs(parseAgreement(t, agreementJSON))

	assert.Equal(t, "0ec9f6a6-159d-4dd8-a563-1f8b2d1a0a4e", args["__id"].Value)
	assert.Equal(t, "Contoso ToU for guest users", args["displayName"].Value)
	assert.Equal(t, true, args["isViewingBeforeAcceptanceRequired"].Value)
	assert.Equal(t, false, args["isPerDeviceAcceptanceRequired"].Value)
	assert.Equal(t, "P90D", args["userReacceptRequiredFrequency"].Value)
	assert.Equal(t, "P365D", args["termsExpirationFrequency"].Value)
	start, ok := args["termsExpirationStartDateTime"].Value.(*time.Time)
	require.True(t, ok)
	assert.Equal(t, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), start.UTC())
}

func TestTermsOfUseAgreementArgsWithoutExpiry(t *testing.T) {
	args := newTermsOfUseAgreementArgs(parseAgreement(t, agreementNoExpiryJSON))

	assert.Nil(t, args["userReacceptRequiredFrequency"].Value)
	assert.Nil(t, args["termsExpirationFrequency"].Value)
	assert.Nil(t, args["termsExpirationStartDateTime"].Value)
	assert.Equal(t, true, args["isPerDeviceAcceptanceRequired"].Value)
}

// agreementWeeksJSON holds durations Kiota folds into weeks: P14D would read
// back as P2W, and P7DT12H normalizes to 1W12H, which Kiota refuses to render.
const agreementWeeksJSON = `{
  "id": "9a7c2e1d-3b4f-4c5d-8e6f-7a8b9c0d1e2f",
  "displayName": "Contractor terms",
  "userReacceptRequiredFrequency": "P14D",
  "termsExpiration": {
    "startDateTime": "2026-01-01T00:00:00Z",
    "frequency": "P7DT12H"
  }
}`

func TestTermsOfUseAgreementArgsKeepDaysForm(t *testing.T) {
	args := newTermsOfUseAgreementArgs(parseAgreement(t, agreementWeeksJSON))

	assert.Equal(t, "P14D", args["userReacceptRequiredFrequency"].Value)
	assert.Equal(t, "P7DT12H", args["termsExpirationFrequency"].Value)
}

const workflowJSON = `{
  "category": "leaver",
  "description": "Remove access on the last day of work",
  "displayName": "Offboard departing employees",
  "lastModifiedDateTime": "2026-03-02T10:00:00Z",
  "createdDateTime": "2026-03-01T09:00:00Z",
  "id": "15239232-66ed-445b-8292-2f5bbb2eb833",
  "isEnabled": true,
  "isSchedulingEnabled": false,
  "nextScheduleRunDateTime": null,
  "version": 3,
  "executionConditions": {
    "@odata.type": "#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions",
    "scope": {
      "@odata.type": "#microsoft.graph.identityGovernance.ruleBasedSubjectSet",
      "rule": "(department eq 'Marketing')"
    },
    "trigger": {
      "@odata.type": "#microsoft.graph.identityGovernance.timeBasedAttributeTrigger",
      "timeBasedAttribute": "employeeLeaveDateTime",
      "offsetInDays": 0
    }
  }
}`

func parseWorkflow(t *testing.T, payload string) igmodels.Workflowable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(igmodels.CreateWorkflowFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(igmodels.Workflowable)
}

func TestLifecycleWorkflowArgs(t *testing.T) {
	args, err := newLifecycleWorkflowArgs(parseWorkflow(t, workflowJSON))
	require.NoError(t, err)

	assert.Equal(t, "15239232-66ed-445b-8292-2f5bbb2eb833", args["__id"].Value)
	assert.Equal(t, "leaver", args["category"].Value)
	assert.Equal(t, true, args["isEnabled"].Value)
	assert.Equal(t, false, args["isSchedulingEnabled"].Value)
	assert.Equal(t, int64(3), args["version"].Value)
	assert.Nil(t, args["nextScheduleRunDateTime"].Value)

	conditions, ok := args["executionConditions"].Value.(map[string]any)
	require.True(t, ok, "executionConditions must be a dict")
	assert.Equal(t, "#microsoft.graph.identityGovernance.triggerAndScopeBasedConditions", conditions["@odata.type"])
	trigger, ok := conditions["trigger"].(map[string]any)
	require.True(t, ok, "trigger must survive the round trip")
	assert.Equal(t, "employeeLeaveDateTime", trigger["timeBasedAttribute"])
	scope, ok := conditions["scope"].(map[string]any)
	require.True(t, ok, "scope must survive the round trip")
	assert.Equal(t, "(department eq 'Marketing')", scope["rule"])
}

func TestLifecycleWorkflowArgsWithoutConditions(t *testing.T) {
	args, err := newLifecycleWorkflowArgs(parseWorkflow(t, `{"id": "w1", "category": "joiner"}`))
	require.NoError(t, err)
	assert.Nil(t, args["executionConditions"].Value)
	assert.Nil(t, args["version"].Value)
	assert.Nil(t, args["isEnabled"].Value)
}

const taskCollectionJSON = `{
  "value": [
    {
      "id": "b2", "displayName": "Remove user from all groups", "category": "leaver",
      "taskDefinitionId": "b3a31406-2a15-4c9a-b25b-a658fa5f07fc",
      "isEnabled": true, "continueOnError": false, "executionSequence": 2,
      "arguments": []
    },
    {
      "id": "a1", "displayName": "Disable user account", "category": "joiner,leaver",
      "taskDefinitionId": "1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950",
      "isEnabled": false, "continueOnError": true, "executionSequence": 1,
      "arguments": [
        {"name": "cc", "value": "1baa57fa-3c4e-4526-ba5a-db47a9df95f0"},
        {"name": "customSubject", "value": ""}
      ]
    }
  ]
}`

func parseTasks(t *testing.T, payload string) []igmodels.Taskable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(igmodels.CreateTaskCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(igmodels.TaskCollectionResponseable).GetValue()
}

func TestLifecycleWorkflowTasks(t *testing.T) {
	tasks := parseTasks(t, taskCollectionJSON)
	require.Len(t, tasks, 2)

	sortTasksByExecutionSequence(tasks)
	assert.Equal(t, "a1", *tasks[0].GetId(), "tasks must be ordered by executionSequence")
	assert.Equal(t, "b2", *tasks[1].GetId())

	args := newLifecycleWorkflowTaskArgs("wf", tasks[0])
	assert.Equal(t, "wf/tasks/a1", args["__id"].Value)
	assert.Equal(t, "1dfdfcc7-52fa-4c2e-bf3a-e3919cc12950", args["taskDefinitionId"].Value)
	assert.Equal(t, "joiner,leaver", args["category"].Value)
	assert.Equal(t, false, args["isEnabled"].Value)
	assert.Equal(t, true, args["continueOnError"].Value)
	assert.Equal(t, int64(1), args["executionSequence"].Value)
	assert.Equal(t, map[string]any{
		"cc":            "1baa57fa-3c4e-4526-ba5a-db47a9df95f0",
		"customSubject": "",
	}, args["arguments"].Value)

	empty := newLifecycleWorkflowTaskArgs("wf", tasks[1])
	assert.Equal(t, map[string]any{}, empty["arguments"].Value)
}

func TestLifecycleWorkflowTaskIdsCarryTheWorkflow(t *testing.T) {
	tasks := parseTasks(t, taskCollectionJSON)
	a := newLifecycleWorkflowTaskArgs("workflow-1", tasks[0])
	b := newLifecycleWorkflowTaskArgs("workflow-2", tasks[0])
	assert.NotEqual(t, a["__id"].Value, b["__id"].Value)
}

func TestSortTasksWithoutSequenceSortLast(t *testing.T) {
	tasks := parseTasks(t, `{"value": [{"id": "none"}, {"id": "two", "executionSequence": 2}, {"id": "one", "executionSequence": 1}]}`)
	sortTasksByExecutionSequence(tasks)
	assert.Equal(t, "one", *tasks[0].GetId())
	assert.Equal(t, "two", *tasks[1].GetId())
	assert.Equal(t, "none", *tasks[2].GetId())
}

func TestKeyValuePairsToMapDropsNamelessPairs(t *testing.T) {
	tasks := parseTasks(t, `{"value": [{"id": "x", "arguments": [{"value": "orphan"}, {"name": "k", "value": null}]}]}`)
	assert.Equal(t, map[string]any{"k": ""}, keyValuePairsToMap(tasks[0].GetArguments()))
}

const customSecurityAttributeDefinitionJSON = `{
  "attributeSet": "Engineering",
  "description": "Target completion date",
  "id": "Engineering_ProjectDate",
  "isCollection": false,
  "isSearchable": true,
  "name": "ProjectDate",
  "status": "Deprecated",
  "type": "String",
  "usePreDefinedValuesOnly": true
}`

func TestCustomSecurityAttributeDefinitionArgs(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(customSecurityAttributeDefinitionJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateCustomSecurityAttributeDefinitionFromDiscriminatorValue)
	require.NoError(t, err)
	definition := parsed.(models.CustomSecurityAttributeDefinitionable)

	args := newCustomSecurityAttributeDefinitionArgs(definition)
	assert.Equal(t, "Engineering_ProjectDate", args["__id"].Value)
	assert.Equal(t, "ProjectDate", args["name"].Value)
	assert.Equal(t, "String", args["type"].Value)
	assert.Equal(t, "Deprecated", args["status"].Value)
	assert.Equal(t, false, args["isCollection"].Value)
	assert.Equal(t, true, args["isSearchable"].Value)
	assert.Equal(t, true, args["usePreDefinedValuesOnly"].Value)
	assert.Equal(t, "Engineering", *definition.GetAttributeSet())
}

func TestSelectByID(t *testing.T) {
	all := []any{"a", "b", "c"}
	idOf := func(r any) string { return r.(string) }

	assert.Equal(t, []any{"c", "a"}, selectByID(all, []any{"c", "missing", "a"}, idOf),
		"keeps the referenced order and skips ids with no match")
	assert.Equal(t, []any{}, selectByID(all, []any{}, idOf))
}

// lifecycleWorkflowsUnlicensed is the refusal Graph answered lifecycle
// workflows with on a tenant without an Entra ID Governance license.
func lifecycleWorkflowsUnlicensed() *odataerrors.ODataError {
	return graphStatusErr(http.StatusForbidden, "Access denied",
		"Insufficient license to complete this operation. User workflows require an Entra ID Governance license.")
}

// insufficientPrivileges is the refusal Graph answered custom security
// attribute definitions with when the app lacks the permission.
func insufficientPrivileges() *odataerrors.ODataError {
	return graphStatusErr(http.StatusForbidden, "Authorization_RequestDenied",
		"Insufficient privileges to complete the operation.")
}

func TestClassifyLifecycleWorkflowsError(t *testing.T) {
	t.Run("missing license is not applicable", func(t *testing.T) {
		err := classifyLifecycleWorkflowsError(lifecycleWorkflowsUnlicensed())
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE, llx.KindOf(err))
		assert.Contains(t, err.Error(), "Entra ID Governance license")
	})

	t.Run("missing permission is forbidden and names it", func(t *testing.T) {
		err := classifyLifecycleWorkflowsError(insufficientPrivileges())
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
		var lerr *llx.Error
		require.True(t, errors.As(err, &lerr))
		assert.Equal(t, []string{permLifecycleWorkflowsReadAll}, lerr.Permissions)
	})

	t.Run("a license word outside a 403 is not a refusal", func(t *testing.T) {
		err := classifyLifecycleWorkflowsError(graphStatusErr(http.StatusInternalServerError, "UnknownError", "license service unreachable"))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAVAILABLE, llx.KindOf(err))
	})

	t.Run("transport failures stay unclassified", func(t *testing.T) {
		err := classifyLifecycleWorkflowsError(errors.New("dial tcp: connection refused"))
		assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	})
}
