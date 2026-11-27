// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ids(recs []resourceGroupRecord) []int {
	out := []int{}
	for _, r := range recs {
		out = append(out, r.id)
	}
	return out
}

// Synthetic: the token's own resource groups merged with an organization's;
// no live Codesphere account was available.
func TestMergeResourceGroups(t *testing.T) {
	org := ptr("org-1")
	own := []resourceGroupRecord{{id: 1, orgID: org}, {id: 2}}
	byOrg := [][]resourceGroupRecord{{{id: 1, orgID: org}, {id: 3, orgID: org}}}

	assert.Equal(t, []int{1, 2, 3}, ids(mergeResourceGroups(own, byOrg, "", 0)), "each resource group once, own first")
	assert.Equal(t, []int{1, 3}, ids(mergeResourceGroups(own, byOrg, "org-1", 0)), "--org drops resource groups outside it")
	assert.Equal(t, []int{3}, ids(mergeResourceGroups(own, byOrg, "", 3)), "--resource-group keeps one")
	assert.Empty(t, mergeResourceGroups(own, byOrg, "org-2", 0))
	assert.Empty(t, mergeResourceGroups(nil, nil, "", 0))
}

// Synthetic: list entries shaped per the API schema, decoded by the vendor
// client; no live Codesphere account was available.
func TestResourceGroupFromTeam(t *testing.T) {
	var inOrg cs.TeamsListTeams200ResponseInner
	require.NoError(t, json.Unmarshal([]byte(`{"id":12,"defaultDataCenterId":2,"name":"payments","description":"Payments team","avatarId":null,"avatarUrl":null,"isFirst":false,"organizationId":"org-1","role":0}`), &inOrg))
	rec := resourceGroupFromTeam(inOrg)
	assert.Equal(t, 12, rec.id)
	assert.Equal(t, "payments", rec.name)
	assert.Equal(t, 2, rec.dataCenterID)
	require.NotNil(t, rec.orgID)
	assert.Equal(t, "org-1", *rec.orgID)
	require.NotNil(t, rec.description)
	assert.Equal(t, "Payments team", *rec.description)

	var legacy cs.TeamsListTeams200ResponseInner
	require.NoError(t, json.Unmarshal([]byte(`{"id":5,"defaultDataCenterId":1,"name":"personal","description":null,"avatarId":null,"avatarUrl":null,"role":0}`), &legacy))
	rec = resourceGroupFromTeam(legacy)
	assert.Nil(t, rec.orgID, "a resource group outside any organization has no organization")
	assert.Nil(t, rec.description, "a null description stays null")

	var emptyOrg cs.TeamsListTeams200ResponseInner
	require.NoError(t, json.Unmarshal([]byte(`{"id":6,"defaultDataCenterId":1,"name":"x","description":null,"avatarId":null,"avatarUrl":null,"organizationId":"","role":1}`), &emptyOrg))
	assert.Nil(t, resourceGroupFromTeam(emptyOrg).orgID, "an empty organization ID is no organization")
}

// Synthetic: an organization's list does not repeat the organization on each
// entry, so it comes from the list.
func TestResourceGroupFromOrgTeam(t *testing.T) {
	var team cs.OrganizationsListOrgTeams200ResponseInner
	require.NoError(t, json.Unmarshal([]byte(`{"id":9,"defaultDataCenterId":3,"name":"platform"}`), &team))
	rec := resourceGroupFromOrgTeam("org-1", team)
	require.NotNil(t, rec.orgID)
	assert.Equal(t, "org-1", *rec.orgID)
	assert.Equal(t, 3, rec.dataCenterID)
	assert.Nil(t, rec.description)
}

// Synthetic: member entries with absent optional fields.
func TestRgMemberArgs(t *testing.T) {
	var m cs.TeamsListMembers200ResponseInner
	require.NoError(t, json.Unmarshal([]byte(`{"userId":42,"teamId":12,"role":1,"pending":true,"createdAt":"2026-01-02T03:04:05Z","name":null,"email":null,"avatarUrl":null}`), &m))
	args := rgMemberArgs(m)
	assert.Equal(t, "12/42", args["__id"].Value, "unique per resource group, since one user joins many")
	assert.Equal(t, "member", args["role"].Value)
	assert.Equal(t, true, args["pending"].Value)
	assert.Nil(t, args["email"].Value)
	assert.Nil(t, args["deletedAt"].Value, "an active user has no deletion time")
}
