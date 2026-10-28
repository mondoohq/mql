// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/security/armsecurity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Synthetic: the shape of the ARM governance rule response (api-version
// 2022-01-01-preview); no subscription available to us had a rule.
const governanceRuleByTagJSON = `{
  "id": "/subscriptions/0000/providers/Microsoft.Security/governanceRules/ad9a8e26-29d9-4829-bb30-e597a58cdbb8",
  "name": "ad9a8e26-29d9-4829-bb30-e597a58cdbb8",
  "type": "Microsoft.Security/governanceRules",
  "properties": {
    "displayName": "Admin's rule",
    "description": "A rule for critical recommendations",
    "remediationTimeframe": "7.00:00:00",
    "isGracePeriod": true,
    "rulePriority": 200,
    "isDisabled": false,
    "ruleType": "Integrated",
    "sourceResourceType": "Assessments",
    "excludedScopes": ["/subscriptions/0000/resourceGroups/sandbox"],
    "includeMemberScopes": false,
    "conditionSets": [
      {"conditions": [{"property": "$.AssessmentKey", "value": "[\"b1cd27e0-4ecc-4246-939f-49c426d9d72f\"]", "operator": "In"}]}
    ],
    "ownerSource": {"type": "ByTag", "value": "Owner"},
    "governanceEmailNotification": {"disableManagerEmailNotification": true, "disableOwnerEmailNotification": false}
  }
}`

func TestGovernanceRuleArgs(t *testing.T) {
	t.Run("rule with every property", func(t *testing.T) {
		var rule armsecurity.GovernanceRule
		require.NoError(t, json.Unmarshal([]byte(governanceRuleByTagJSON), &rule))

		args, err := governanceRuleArgs(&rule)
		require.NoError(t, err)
		assert.Equal(t, "Admin's rule", args["displayName"].Value)
		assert.Equal(t, "7.00:00:00", args["remediationTimeframe"].Value)
		assert.Equal(t, int64(200), args["rulePriority"].Value)
		assert.Equal(t, true, args["isGracePeriod"].Value)
		assert.Equal(t, false, args["isDisabled"].Value)
		assert.Equal(t, "Integrated", args["ruleType"].Value)
		assert.Equal(t, "Assessments", args["sourceResourceType"].Value)
		assert.Equal(t, "ByTag", args["ownerSourceType"].Value)
		assert.Equal(t, "Owner", args["ownerSource"].Value)
		assert.Equal(t, true, args["disableManagerEmailNotification"].Value)
		assert.Equal(t, false, args["disableOwnerEmailNotification"].Value)
		assert.Equal(t, []any{"/subscriptions/0000/resourceGroups/sandbox"}, args["excludedScopes"].Value)

		sets := args["conditionSets"].Value.([]any)
		require.Len(t, sets, 1)
		conds := sets[0].(map[string]any)["conditions"].([]any)
		require.Len(t, conds, 1)
		assert.Equal(t, "$.AssessmentKey", conds[0].(map[string]any)["property"])
		assert.Equal(t, "In", conds[0].(map[string]any)["operator"])
	})

	t.Run("absent properties read as null, not false or zero", func(t *testing.T) {
		// Synthetic: a rule with no properties block; no target showed this.
		args, err := governanceRuleArgs(&armsecurity.GovernanceRule{ID: new("/x"), Name: new("x")})
		require.NoError(t, err)
		for _, field := range []string{"isDisabled", "rulePriority", "isGracePeriod", "ownerSource", "ownerSourceType", "disableOwnerEmailNotification"} {
			assert.Nil(t, args[field].Value, field)
		}
		assert.Empty(t, args["conditionSets"].Value)
	})
}

func TestNoGovernanceAssignments(t *testing.T) {
	// Measured: Azure Resource Manager, 2026-10-27, listing the governance
	// assignments of a Defender assessment with none answered 404 with
	// {"Error":{"Code":"ResourceNotFound","Message":"No Governance Assignments found ..."}}.
	assert.True(t, noGovernanceAssignments(&azcore.ResponseError{StatusCode: http.StatusNotFound, ErrorCode: "ResourceNotFound"}))
	// Synthetic: a refusal and a transport failure are not absences; no target showed these.
	assert.False(t, noGovernanceAssignments(&azcore.ResponseError{StatusCode: http.StatusForbidden}))
	assert.False(t, noGovernanceAssignments(errors.New("dial tcp: connection refused")))
}

func TestGovernanceAssignmentArgs(t *testing.T) {
	t.Run("assignment with an ETA", func(t *testing.T) {
		// Synthetic: the shape of the ARM governance assignment response
		// (api-version 2022-01-01-preview); no assessment we could read had one.
		payload := `{
		  "id": "/subscriptions/0000/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm/providers/Microsoft.Security/assessments/6b0cc5f1/governanceAssignments/6634ff9f",
		  "name": "6634ff9f",
		  "properties": {
		    "owner": "user@contoso.com",
		    "remediationDueDate": "2022-01-07T13:00:00.0000000Z",
		    "remediationEta": {"eta": "2022-01-08T13:00:00.0000000Z", "justification": "Justification of ETA"},
		    "isGracePeriod": true,
		    "governanceEmailNotification": {"disableManagerEmailNotification": false, "disableOwnerEmailNotification": true}
		  }
		}`
		var asg armsecurity.GovernanceAssignment
		require.NoError(t, json.Unmarshal([]byte(payload), &asg))

		args := governanceAssignmentArgs(&asg)
		assert.Equal(t, "user@contoso.com", args["owner"].Value)
		assert.Equal(t, time.Date(2022, 1, 7, 13, 0, 0, 0, time.UTC), (*args["remediationDueDate"].Value.(*time.Time)).UTC())
		assert.Equal(t, time.Date(2022, 1, 8, 13, 0, 0, 0, time.UTC), (*args["remediationEta"].Value.(*time.Time)).UTC())
		assert.Equal(t, "Justification of ETA", args["remediationEtaJustification"].Value)
		assert.Equal(t, true, args["isGracePeriod"].Value)
		assert.Equal(t, true, args["disableOwnerEmailNotification"].Value)
	})

	t.Run("no ETA reads as null", func(t *testing.T) {
		// Synthetic: an assignment whose owner never set an ETA; no target showed this.
		args := governanceAssignmentArgs(&armsecurity.GovernanceAssignment{
			ID:         new("/a"),
			Properties: &armsecurity.GovernanceAssignmentProperties{Owner: new("o@contoso.com")},
		})
		assert.Nil(t, args["remediationEta"].Value)
		assert.Nil(t, args["remediationEtaJustification"].Value)
		assert.Nil(t, args["remediationDueDate"].Value)
		assert.Nil(t, args["isGracePeriod"].Value)
	})
}
