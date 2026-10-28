// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/policyinsights/armpolicyinsights"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRemediationArgs(t *testing.T) {
	t.Run("remediation with a deployment summary", func(t *testing.T) {
		// Synthetic: the documented shape of a remediation (api-version
		// 2021-10-01); no subscription available to us had one.
		payload := `{
		  "id": "/subscriptions/0000/providers/microsoft.policyinsights/remediations/storageRemediation",
		  "name": "storageRemediation",
		  "properties": {
		    "policyAssignmentId": "/subscriptions/0000/providers/microsoft.authorization/policyassignments/b101830944f246d8a14088c5",
		    "policyDefinitionReferenceId": "8c8fa9e4",
		    "resourceDiscoveryMode": "ReEvaluateCompliance",
		    "provisioningState": "Succeeded",
		    "statusMessage": "Remediation extended status",
		    "createdOn": "2018-09-13T21:51:09.075918Z",
		    "lastUpdatedOn": "2018-09-13T21:52:10.0011706Z",
		    "deploymentStatus": {"totalDeployments": 2, "successfulDeployments": 1, "failedDeployments": 1}
		  }
		}`
		var r armpolicyinsights.Remediation
		require.NoError(t, json.Unmarshal([]byte(payload), &r))

		args := remediationArgs(&r)
		assert.Equal(t, "8c8fa9e4", args["policyDefinitionReferenceId"].Value)
		assert.Equal(t, "ReEvaluateCompliance", args["resourceDiscoveryMode"].Value)
		assert.Equal(t, "Succeeded", args["provisioningState"].Value)
		assert.Equal(t, int64(2), args["totalDeployments"].Value)
		assert.Equal(t, int64(1), args["successfulDeployments"].Value)
		assert.Equal(t, int64(1), args["failedDeployments"].Value)
		assert.Equal(t, 2018, args["createdOn"].Value.(*time.Time).Year())
	})

	t.Run("no deployment summary reads as null, not zero", func(t *testing.T) {
		// Synthetic: a remediation that has not started deploying; no target showed this.
		args := remediationArgs(&armpolicyinsights.Remediation{
			ID:         new("/r"),
			Properties: &armpolicyinsights.RemediationProperties{ProvisioningState: new("Accepted")},
		})
		assert.Nil(t, args["totalDeployments"].Value)
		assert.Nil(t, args["failedDeployments"].Value)
		assert.Nil(t, args["createdOn"].Value)
	})
}

func TestAttestationArgs(t *testing.T) {
	// Synthetic: the documented shape of an attestation (api-version
	// 2022-09-01); no subscription available to us had one.
	payload := `{
	  "id": "/subscriptions/0000/providers/microsoft.policyinsights/attestations/790996e6-9871-4b1f-9cd9-ec42cd6ced1e",
	  "name": "790996e6-9871-4b1f-9cd9-ec42cd6ced1e",
	  "properties": {
	    "policyAssignmentId": "/subscriptions/0000/providers/microsoft.authorization/policyassignments/b101830944f246d8a14088c5",
	    "policyDefinitionReferenceId": "0b158b46-ff42-4799-8e39-08a5c23b4551",
	    "complianceState": "Compliant",
	    "expiresOn": "2021-06-15T00:00:00Z",
	    "owner": "55a32e28-3aa5-4eea-9b5a-4cd85153b966",
	    "comments": "This subscription has passed a security audit.",
	    "evidence": [
	      {"description": "The results of the security audit.", "sourceUri": "https://gist.github.com/contoso/9573e238762c60166c090ae16b814011"},
	      null
	    ],
	    "assessmentDate": "2021-06-10T00:00:00Z",
	    "lastComplianceStateChangeAt": "2021-06-10T00:00:00Z",
	    "provisioningState": "Succeeded"
	  }
	}`
	var at armpolicyinsights.Attestation
	require.NoError(t, json.Unmarshal([]byte(payload), &at))

	args := attestationArgs(&at)
	assert.Equal(t, "Compliant", args["complianceState"].Value)
	assert.Equal(t, "This subscription has passed a security audit.", args["comments"].Value)
	assert.Equal(t, "55a32e28-3aa5-4eea-9b5a-4cd85153b966", args["owner"].Value)
	assert.Equal(t, time.Date(2021, 6, 15, 0, 0, 0, 0, time.UTC), args["expiresOn"].Value.(*time.Time).UTC())
	// A plain URL comes back unchanged.
	assert.Equal(t, []any{map[string]any{
		"description":          "The results of the security audit.",
		"sourceUri":            "https://gist.github.com/contoso/9573e238762c60166c090ae16b814011",
		"sourceUriHasSasToken": false,
	}}, args["evidence"].Value)

	t.Run("SAS token in evidence and free text is removed", func(t *testing.T) {
		// Synthetic: evidence stored in a blob behind a SAS URL, also quoted in
		// the comments; no target showed this.
		sasURL := "https://acct.blob.core.windows.net/evidence/audit.pdf?sv=2022-11-02&se=2026-12-31&sr=b&sp=r&sig=c2VjcmV0c2lnbmF0dXJl"
		at := armpolicyinsights.Attestation{
			ID: new("/a"),
			Properties: &armpolicyinsights.AttestationProperties{
				Comments: new("Audit report at " + sasURL + " reviewed."),
				Evidence: []*armpolicyinsights.AttestationEvidence{{Description: new("audit"), SourceURI: new(sasURL)}},
			},
		}
		args := attestationArgs(&at)
		ev := args["evidence"].Value.([]any)[0].(map[string]any)
		assert.Equal(t, "https://acct.blob.core.windows.net/evidence/audit.pdf", ev["sourceUri"])
		assert.NotContains(t, ev["sourceUri"], "sig=")
		assert.Equal(t, true, ev["sourceUriHasSasToken"])
		assert.Equal(t, "Audit report at https://acct.blob.core.windows.net/evidence/audit.pdf reviewed.", args["comments"].Value)

		rem := remediationArgs(&armpolicyinsights.Remediation{
			ID:         new("/r"),
			Properties: &armpolicyinsights.RemediationProperties{StatusMessage: new("Deployment failed reading " + sasURL)},
		})
		assert.NotContains(t, rem["statusMessage"].Value, "sig=")
	})

	// Synthetic: an attestation with no expiry; no target showed this.
	empty := attestationArgs(&armpolicyinsights.Attestation{ID: new("/a"), Properties: &armpolicyinsights.AttestationProperties{}})
	assert.Nil(t, empty["expiresOn"].Value)
	assert.Nil(t, empty["complianceState"].Value)
	assert.Empty(t, empty["evidence"].Value)
}
