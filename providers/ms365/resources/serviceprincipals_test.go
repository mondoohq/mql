// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// servicePrincipalSourcedProperties maps a Graph property that must appear in
// the $select list to the microsoft.serviceprincipal field it populates.
//
// $select restricts the payload, so a field the creator reads out of a property
// that was not selected reads as absent forever. When that read is also
// conditional, the arg key is skipped entirely and the MQL field ends up UNSET
// rather than null -- which surfaces to the user as "encountered a primitive
// with no type information" with no attribution. termsOfServiceUrl shipped that
// way because "info" was missing here.
var servicePrincipalSourcedProperties = map[string]string{
	"info":              "termsOfServiceUrl",
	"verifiedPublisher": "verifiedPublisher",
	"appRoles":          "appRoles",
	"appId":             "appId",
	"displayName":       "name",
}

func TestServicePrincipalFieldsCoverSourcedProperties(t *testing.T) {
	selected := make(map[string]bool, len(servicePrincipalFields))
	for _, f := range servicePrincipalFields {
		selected[f] = true
	}
	for property, field := range servicePrincipalSourcedProperties {
		assert.Truef(t, selected[property],
			"$select is missing %q, which sources microsoft.serviceprincipal.%s; "+
				"Graph will omit it and the field will never resolve", property, field)
	}
}

// A duplicated entry is harmless on the wire but signals the list is being
// edited without being read, which is how "info" went missing in the first
// place.
func TestServicePrincipalFieldsHasNoDuplicates(t *testing.T) {
	seen := map[string]int{}
	for _, f := range servicePrincipalFields {
		seen[f]++
	}
	for f, n := range seen {
		assert.Equalf(t, 1, n, "servicePrincipalFields lists %q %d times", f, n)
	}
}

func TestServicePrincipalIDs(t *testing.T) {
	// Synthetic: Graph can return null entries in a collection page; no target showed one.
	a := models.NewServicePrincipal()
	idA := "sp-a"
	a.SetId(&idA)
	blank := models.NewServicePrincipal()
	empty := ""
	blank.SetId(&empty)

	assert.Equal(t, []string{"sp-a"}, servicePrincipalIDs([]models.ServicePrincipalable{nil, a, blank, models.NewServicePrincipal()}))
	assert.Empty(t, servicePrincipalIDs(nil))
}

func TestBuildServicePrincipalPermissions(t *testing.T) {
	// Synthetic: one granted application permission, one available app role on
	// the same API, and one tenant-wide delegated grant with two scopes. The
	// role ids are Microsoft Graph's published app role ids.
	runtime := plugin.NewRuntime(nil, nil, false, CreateResource, NewResource, GetData, SetData, nil)
	res, err := CreateResource(runtime, "microsoft", map[string]*llx.RawData{})
	require.NoError(t, err)
	ms := res.(*mqlMicrosoft)

	graphSpID := "1b4c6a1f-0000-4000-8000-00000000a001"
	roleMgmt := uuid.MustParse("9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8")
	dirRead := uuid.MustParse("7ab1d382-f21e-4acd-a863-ba3e13f7da61")
	newRole := func(id uuid.UUID, value string) models.AppRoleable {
		r := models.NewAppRole()
		r.SetId(&id)
		r.SetValue(&value)
		r.SetDisplayName(&value)
		return r
	}
	ms.IndexAppRole(graphSpID, newRole(roleMgmt, "RoleManagement.ReadWrite.Directory"), newRole(dirRead, "Directory.Read.All"))
	ms.IndexAppName(graphSpID, "Microsoft Graph")

	granted := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	assignment := models.NewAppRoleAssignment()
	assignmentID, resourceName := "assignment-1", "Microsoft Graph"
	resourceID := uuid.MustParse(graphSpID)
	assignment.SetId(&assignmentID)
	assignment.SetResourceId(&resourceID)
	assignment.SetAppRoleId(&roleMgmt)
	assignment.SetResourceDisplayName(&resourceName)
	assignment.SetCreatedDateTime(&granted)

	grant := models.NewOAuth2PermissionGrant()
	grantID, consent, scopes := "grant-1", "AllPrincipals", "User.Read Mail.Read"
	grant.SetId(&grantID)
	grant.SetResourceId(&graphSpID)
	grant.SetConsentType(&consent)
	grant.SetScope(&scopes)

	list, err := ms.buildServicePrincipalPermissions([]models.AppRoleAssignmentable{assignment}, []models.OAuth2PermissionGrantable{grant})
	require.NoError(t, err)
	require.Len(t, list, 4)

	byName := map[string]*mqlMicrosoftApplicationPermission{}
	for _, item := range list {
		p := item.(*mqlMicrosoftApplicationPermission)
		byName[p.Name.Data] = p
		assert.Equal(t, graphSpID, p.cacheResourceID, "%s resolves to the API's service principal", p.Name.Data)
	}

	app := byName["RoleManagement.ReadWrite.Directory"]
	assert.Equal(t, "granted", app.Status.Data)
	assert.Equal(t, granted, app.GrantedDateTime.Data.UTC())
	assert.Equal(t, "", app.ConsentType.Data)

	available := byName["Directory.Read.All"]
	assert.Equal(t, "available", available.Status.Data)
	assert.Nil(t, available.GrantedDateTime.Data, "an available role was never granted")

	for _, scope := range []string{"User.Read", "Mail.Read"} {
		delegated := byName[scope]
		require.NotNil(t, delegated, scope)
		assert.Equal(t, "delegated", delegated.Type.Data)
		assert.Equal(t, "AllPrincipals", delegated.ConsentType.Data)
		assert.Nil(t, delegated.GrantedDateTime.Data, "delegated grants carry no creation time")
	}
}

func TestFetchServicePrincipalGroupMemberships(t *testing.T) {
	// Synthetic: a service principal whose groups span two pages and one the
	// directory refuses; bodies follow the Graph v1.0 group collection shape.
	f := newFakeGraph(t, map[string]fakeRoute{
		"/servicePrincipals/sp-1/transitiveMemberOf/graph.group": {status: 200, body: `{
			"@odata.nextLink": "{{base}}/servicePrincipals/sp-1/transitiveMemberOf/graph.group/page2",
			"value": [{"id": "g-1", "displayName": "Automation"}]}`},
		"/servicePrincipals/sp-1/transitiveMemberOf/graph.group/page2": {status: 200, body: `{
			"value": [{"id": "g-2", "displayName": "Tier0 admins", "isAssignableToRole": true}]}`},
		"/servicePrincipals/sp-2/transitiveMemberOf/graph.group": {status: 403, body: `{"error":{"code":"Authorization_RequestDenied","message":"denied"}}`},
		"/servicePrincipals/sp-1/memberOf/graph.group":           {status: 200, body: `{"value": [{"id": "g-1", "displayName": "Automation"}]}`},
	})

	got, errs, err := fetchServicePrincipalGroupMemberships(context.Background(), f.client(), []string{"sp-1", "sp-2"}, true)
	require.NoError(t, err)
	ids := []string{}
	for _, g := range got["sp-1"] {
		ids = append(ids, *g.GetId())
	}
	assert.Equal(t, []string{"g-1", "g-2"}, ids, "the second page is followed")
	assert.Error(t, errs["sp-2"])
	assert.NotContains(t, got, "sp-2", "a refused lookup is an error, not an empty membership")

	direct, errs, err := fetchServicePrincipalGroupMemberships(context.Background(), f.client(), []string{"sp-1"}, false)
	require.NoError(t, err)
	assert.NoError(t, errs["sp-1"])
	require.Len(t, direct["sp-1"], 1)
	assert.Equal(t, "g-1", *direct["sp-1"][0].GetId())
}
