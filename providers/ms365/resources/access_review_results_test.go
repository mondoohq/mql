// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityPrincipalType(t *testing.T) {
	s := func(v string) *string { return &v }
	assert.Equal(t, "user", identityPrincipalType(s("#microsoft.graph.userIdentity")))
	assert.Equal(t, "servicePrincipal", identityPrincipalType(s("#microsoft.graph.servicePrincipalIdentity")))
	assert.Equal(t, "", identityPrincipalType(s("#microsoft.graph.groupIdentity")), "an unresolved identity type is empty")
	assert.Equal(t, "", identityPrincipalType(nil))
}

func TestReviewerID(t *testing.T) {
	s := func(v string) *string { return &v }
	assert.Equal(t, "8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b", reviewerID(s("8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b")))
	// Synthetic: Graph's placeholder for "no reviewer yet".
	assert.Equal(t, "", reviewerID(s("00000000-0000-0000-0000-000000000000")))
	assert.Equal(t, "", reviewerID(s("")))
	assert.Equal(t, "", reviewerID(nil))
}

func TestFetchAccessReviewDecisions(t *testing.T) {
	// Synthetic: one reviewed decision on a user and one pending decision on a
	// service principal, across two pages; bodies follow the Graph v1.0
	// accessReviewInstanceDecisionItem shape.
	base := "/identityGovernance/accessReviews/definitions/def-1/instances/inst-1/decisions"
	f := newFakeGraph(t, map[string]fakeRoute{
		base: {status: 200, body: `{
			"@odata.nextLink": "{{base}}` + base + `/page2",
			"value": [{
				"id": "d-1", "decision": "Deny", "recommendation": "Deny", "justification": "left the team",
				"reviewedDateTime": "2026-10-01T08:00:00Z", "applyResult": "AppliedSuccessfully", "appliedDateTime": "2026-10-02T08:00:00Z",
				"reviewedBy": {"id": "8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b", "displayName": "Reviewer", "userPrincipalName": "reviewer@example.com"},
				"principal": {"@odata.type": "#microsoft.graph.userIdentity", "id": "u-1", "displayName": "Alex"},
				"resource": {"id": "g-1", "displayName": "Admins", "type": "group"}
			}]}`},
		base + "/page2": {status: 200, body: `{"value": [{
				"id": "d-2", "decision": "NotReviewed", "recommendation": "NoInfoAvailable", "applyResult": "New",
				"reviewedBy": {"id": "00000000-0000-0000-0000-000000000000", "displayName": ""},
				"principal": {"@odata.type": "#microsoft.graph.servicePrincipalIdentity", "id": "sp-1", "displayName": "deploy"},
				"resource": {"id": "g-1", "displayName": "Admins", "type": "group"}
			}]}`},
		"/identityGovernance/accessReviews/definitions/def-2/instances/inst-9/decisions": {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`},
	})

	items, err := fetchAccessReviewDecisions(context.Background(), f.client(), "def-1", "inst-1")
	require.NoError(t, err)
	require.Len(t, items, 2, "the second page is followed")

	reviewed := accessReviewDecisionArgs("def-1/inst-1", items[0])
	assert.Equal(t, "def-1/inst-1/d-1", reviewed["__id"].Value)
	assert.Equal(t, "Deny", reviewed["decision"].Value)
	assert.Equal(t, "user", reviewed["principalType"].Value)
	assert.Equal(t, "u-1", reviewed["principalId"].Value)
	assert.Equal(t, "group", reviewed["resourceType"].Value)
	assert.Equal(t, time.Date(2026, 10, 1, 8, 0, 0, 0, time.UTC), reviewed["reviewedDateTime"].Value.(*time.Time).UTC())
	assert.Equal(t, "8f3c9a2e-1b4d-4e5f-9a6b-7c8d9e0f1a2b", reviewerID(items[0].GetReviewedBy().GetId()))

	pending := accessReviewDecisionArgs("def-1/inst-1", items[1])
	assert.Equal(t, "NotReviewed", pending["decision"].Value)
	assert.Equal(t, "servicePrincipal", pending["principalType"].Value)
	assert.Nil(t, pending["reviewedDateTime"].Value, "a pending decision has no review time")
	assert.Equal(t, "", reviewerID(items[1].GetReviewedBy().GetId()), "a pending decision has no reviewer")

	_, err = fetchAccessReviewDecisions(context.Background(), f.client(), "def-2", "inst-9")
	assert.Error(t, err, "a refusal is an error, not an empty decision list")
}
