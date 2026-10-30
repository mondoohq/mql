// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdministrativeUnitArgs_DecodesGraphPayload(t *testing.T) {
	payload := `{
		"id": "4d7ea995-bc0f-45c0-8c4a-6d7b9e2f1a3c",
		"displayName": "Seattle District Technical Schools",
		"description": "Seattle district technical schools administration",
		"visibility": "HiddenMembership",
		"isMemberManagementRestricted": true,
		"membershipType": "Dynamic",
		"membershipRule": "(user.country -eq \"United States\")",
		"membershipRuleProcessingState": "Paused"
	}`
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateAdministrativeUnitFromDiscriminatorValue)
	require.NoError(t, err)

	args := administrativeUnitArgs(parsed.(models.AdministrativeUnitable))
	assert.Equal(t, "4d7ea995-bc0f-45c0-8c4a-6d7b9e2f1a3c", args["__id"].Value)
	assert.Equal(t, "4d7ea995-bc0f-45c0-8c4a-6d7b9e2f1a3c", args["id"].Value)
	assert.Equal(t, "Seattle District Technical Schools", args["displayName"].Value)
	assert.Equal(t, "Seattle district technical schools administration", args["description"].Value)
	assert.Equal(t, "HiddenMembership", args["visibility"].Value)
	assert.Equal(t, true, args["isMemberManagementRestricted"].Value)
	assert.Equal(t, "Dynamic", args["membershipType"].Value)
	assert.Equal(t, `(user.country -eq "United States")`, args["membershipRule"].Value)
	assert.Equal(t, "Paused", args["membershipRuleProcessingState"].Value)
}

func TestAdministrativeUnitArgs_AbsentPropertiesAreNull(t *testing.T) {
	// A public, assigned unit as Graph returns it: visibility and the dynamic
	// membership properties are null.
	payload := `{
		"id": "a1b2c3d4-0000-0000-0000-000000000001",
		"displayName": "Contoso Sales",
		"visibility": null,
		"isMemberManagementRestricted": false,
		"membershipType": "Assigned",
		"membershipRule": null,
		"membershipRuleProcessingState": null
	}`
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateAdministrativeUnitFromDiscriminatorValue)
	require.NoError(t, err)

	args := administrativeUnitArgs(parsed.(models.AdministrativeUnitable))
	assert.Nil(t, args["visibility"].Value)
	assert.Nil(t, args["description"].Value)
	assert.Nil(t, args["membershipRule"].Value)
	assert.Nil(t, args["membershipRuleProcessingState"].Value)
	assert.Equal(t, false, args["isMemberManagementRestricted"].Value)
	assert.Equal(t, "Assigned", args["membershipType"].Value)
}

func TestScopedRoleMemberPrincipalId(t *testing.T) {
	payload := `{
		"id": "zTVcE8KFQ0W4bI9tvt6kz-5AOA62QHJLgnvAbh9Z0OfMZBo-fX5JQYOwusp6HKMx",
		"roleId": "135a0ba7-f9c6-4b6f-8bd1-ce1d5cc6f0dd",
		"administrativeUnitId": "4d7ea995-bc0f-45c0-8c4a-6d7b9e2f1a3c",
		"roleMemberInfo": {
			"id": "5f2a8c0b-3c1d-4e9f-a7b2-1d0e9c8b7a65",
			"displayName": "Adele Vance"
		}
	}`
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateScopedRoleMembershipFromDiscriminatorValue)
	require.NoError(t, err)

	m := parsed.(models.ScopedRoleMembershipable)
	assert.Equal(t, "5f2a8c0b-3c1d-4e9f-a7b2-1d0e9c8b7a65", scopedRoleMemberPrincipalId(m))

	noInfo, err := kjson.NewJsonParseNode([]byte(`{"id": "x", "roleId": "y"}`))
	require.NoError(t, err)
	parsedNoInfo, err := noInfo.GetObjectValue(models.CreateScopedRoleMembershipFromDiscriminatorValue)
	require.NoError(t, err)
	assert.Equal(t, "", scopedRoleMemberPrincipalId(parsedNoInfo.(models.ScopedRoleMembershipable)))
	assert.Equal(t, "", scopedRoleMemberPrincipalId(nil))
}

func TestDirectoryObjectShortType(t *testing.T) {
	cases := map[string]string{
		`{"@odata.type": "#microsoft.graph.user", "id": "u1"}`:             "user",
		`{"@odata.type": "#microsoft.graph.group", "id": "g1"}`:            "group",
		`{"@odata.type": "#microsoft.graph.servicePrincipal", "id": "s1"}`: "servicePrincipal",
	}
	for payload, want := range cases {
		node, err := kjson.NewJsonParseNode([]byte(payload))
		require.NoError(t, err)
		parsed, err := node.GetObjectValue(models.CreateDirectoryObjectFromDiscriminatorValue)
		require.NoError(t, err)
		assert.Equal(t, want, directoryObjectShortType(parsed.(models.DirectoryObjectable)), payload)
	}
	// a principal missing from getByIds (deleted) has no type
	assert.Equal(t, "", directoryObjectShortType(nil))
}

func TestDirectoryRoleTemplateIds(t *testing.T) {
	payload := `{
		"value": [
			{
				"id": "135a0ba7-f9c6-4b6f-8bd1-ce1d5cc6f0dd",
				"displayName": "User Administrator",
				"roleTemplateId": "fe930be7-5e62-47db-91af-98c3a49a38b1"
			},
			{
				"id": "4a5d8f65-41da-4de4-8968-e035b65339cf",
				"displayName": "Helpdesk Administrator",
				"roleTemplateId": "729827e3-9c14-49f7-bb1b-9608f156bbb8"
			},
			{
				"id": "0000aaaa-0000-0000-0000-000000000000",
				"displayName": "Role without template"
			}
		]
	}`
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDirectoryRoleCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)

	got := directoryRoleTemplateIds(parsed.(models.DirectoryRoleCollectionResponseable).GetValue())
	assert.Equal(t, map[string]string{
		"135a0ba7-f9c6-4b6f-8bd1-ce1d5cc6f0dd": "fe930be7-5e62-47db-91af-98c3a49a38b1",
		"4a5d8f65-41da-4de4-8968-e035b65339cf": "729827e3-9c14-49f7-bb1b-9608f156bbb8",
	}, got)
}
