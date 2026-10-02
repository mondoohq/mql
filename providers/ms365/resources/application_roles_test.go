// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Microsoft publishes the same appRole UUID on different resource service
// principals with different text, so a role is only unique per parent.
const sharedAppRoleID = "df021288-bdef-4463-88db-98f22de89214"

func appRoleJSON(name, value string) string {
	return `{"id": "` + sharedAppRoleID + `", "displayName": "` + name + `", "description": "` + name + ` description", "value": "` + value + `", "allowedMemberTypes": ["Application"], "isEnabled": true}`
}

func decodeServicePrincipal(t *testing.T, raw string) models.ServicePrincipalable {
	node, err := kjson.NewJsonParseNode([]byte(raw))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateServicePrincipalFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.ServicePrincipalable)
}

func decodeApplication(t *testing.T, raw string) models.Applicationable {
	node, err := kjson.NewJsonParseNode([]byte(raw))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateApplicationFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.Applicationable)
}

func onlyAppRole(t *testing.T, roles []any) *mqlMicrosoftApplicationRole {
	require.Len(t, roles, 1)
	return roles[0].(*mqlMicrosoftApplicationRole)
}

func TestServicePrincipalAppRolesWithSharedIdKeepTheirOwnText(t *testing.T) {
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)

	graph, err := newMqlMicrosoftServicePrincipal(runtime, decodeServicePrincipal(t,
		`{"id": "sp-graph", "appRoles": [`+appRoleJSON("Read all users' full profiles", "User.Read.All")+`]}`))
	require.NoError(t, err)
	sharepoint, err := newMqlMicrosoftServicePrincipal(runtime, decodeServicePrincipal(t,
		`{"id": "sp-sharepoint", "appRoles": [`+appRoleJSON("Read user profiles", "User.Read.All")+`]}`))
	require.NoError(t, err)

	graphRole := onlyAppRole(t, graph.AppRoles.Data)
	sharepointRole := onlyAppRole(t, sharepoint.AppRoles.Data)

	assert.Equal(t, "Read all users' full profiles", graphRole.Name.Data)
	assert.Equal(t, "Read all users' full profiles description", graphRole.Description.Data)
	assert.Equal(t, "Read user profiles", sharepointRole.Name.Data)
	assert.Equal(t, "Read user profiles description", sharepointRole.Description.Data)

	// the role UUID stays visible as the id field
	assert.Equal(t, sharedAppRoleID, sharepointRole.Id.Data)
	assert.Equal(t, "sp-sharepoint/appRoles/"+sharedAppRoleID, sharepointRole.MqlID())
}

func TestApplicationAppRolesWithSharedIdKeepTheirOwnText(t *testing.T) {
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)

	first, err := newMqlMicrosoftApplication(runtime, decodeApplication(t,
		`{"id": "app-1", "appRoles": [`+appRoleJSON("Approver", "Approve")+`]}`))
	require.NoError(t, err)
	second, err := newMqlMicrosoftApplication(runtime, decodeApplication(t,
		`{"id": "app-2", "appRoles": [`+appRoleJSON("Auditor", "Audit")+`]}`))
	require.NoError(t, err)

	assert.Equal(t, "Approver", onlyAppRole(t, first.AppRoles.Data).Name.Data)
	secondRole := onlyAppRole(t, second.AppRoles.Data)
	assert.Equal(t, "Auditor", secondRole.Name.Data)
	assert.Equal(t, "Audit", secondRole.Value.Data)
	assert.Equal(t, sharedAppRoleID, secondRole.Id.Data)
}

func TestAppRolesSkipRolesWithoutId(t *testing.T) {
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)

	sp, err := newMqlMicrosoftServicePrincipal(runtime, decodeServicePrincipal(t,
		`{"id": "sp-1", "appRoles": [{"displayName": "no id"}, `+appRoleJSON("Reader", "Read")+`]}`))
	require.NoError(t, err)
	assert.Equal(t, "Reader", onlyAppRole(t, sp.AppRoles.Data).Name.Data)
}
