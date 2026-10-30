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

func TestOdataEqFilter(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
		want  string
	}{
		{"plain value", "displayName", "Lee Gu", "displayName eq 'Lee Gu'"},
		{"single quote is doubled", "displayName", "O'Brien", "displayName eq 'O''Brien'"},
		{"every quote is doubled", "displayName", "a'b'c", "displayName eq 'a''b''c'"},
		{"quote cannot close the literal early", "userPrincipalName", "x' or displayName eq 'y", "userPrincipalName eq 'x'' or displayName eq ''y'"},
		{"empty value", "displayName", "", "displayName eq ''"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, odataEqFilter(tc.field, tc.value))
		})
	}
}

// An owners response as Graph returns it for an application owned by a user
// and by a service principal.
const applicationOwnersJSON = `{
	"@odata.context": "https://graph.microsoft.com/v1.0/$metadata#directoryObjects",
	"value": [
		{"@odata.type": "#microsoft.graph.user", "id": "e4d36492-338d-4910-b67c-2d9e1839b84d", "displayName": "Adele Vance"},
		{"@odata.type": "#microsoft.graph.servicePrincipal", "id": "7b0f4d8e-3c51-4d1a-9b8e-2a6c0f1e9d33", "displayName": "deploy-automation"},
		{"@odata.type": "#microsoft.graph.user", "id": "26a04e55-2df0-490d-a1d4-8d2ea8df4a41", "displayName": "Alex Wilber"}
	]
}`

func TestUserOwnersSkipsNonUsers(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(applicationOwnersJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDirectoryObjectCollectionResponseFromDiscriminatorValue)
	require.NoError(t, err)
	owners := parsed.(models.DirectoryObjectCollectionResponseable).GetValue()
	require.Len(t, owners, 3)

	users := userOwners(owners)
	ids := make([]string, 0, len(users))
	for _, u := range users {
		ids = append(ids, *u.GetId())
	}
	assert.Equal(t, []string{"e4d36492-338d-4910-b67c-2d9e1839b84d", "26a04e55-2df0-490d-a1d4-8d2ea8df4a41"}, ids)
	assert.Equal(t, "Adele Vance", *users[0].GetDisplayName())
}

func TestUserOwnersEmpty(t *testing.T) {
	assert.Empty(t, userOwners(nil))
}
