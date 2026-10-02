// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	kjson "github.com/microsoft/kiota-serialization-json-go"
	betamodels "github.com/microsoftgraph/msgraph-beta-sdk-go/models"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// Payloads are deserialized through the SDK's own discriminator factories, so
// the tests cover where Kiota actually puts each property.

const exchangeRoleAssignmentJSON = `{
  "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
  "id": "b2b8e5f4-5d6c-4c3a-9e2f-0c1d2e3f4a5b",
  "principalId": "6c0b2a8e-1f3d-4e5a-8b7c-9d0e1f2a3b4c",
  "roleDefinitionId": "a7c1e2d3-4b5f-4a6e-9c8d-7e6f5a4b3c2d",
  "directoryScopeId": "/",
  "appScopeId": "/",
  "condition": "@Resource[exchange/recipient/name] StringEquals 'Finance'"
}`

const defenderRoleAssignmentJSON = `{
  "@odata.type": "#microsoft.graph.unifiedRoleAssignmentMultiple",
  "id": "3f2e1d0c-9b8a-4765-a4b3-c2d1e0f9a8b7",
  "displayName": "SOC analysts",
  "description": "Tier 1 responders",
  "roleDefinitionId": "1a2b3c4d-5e6f-4789-8abc-def012345678",
  "principalIds": [
    "11111111-1111-4111-8111-111111111111",
    "22222222-2222-4222-8222-222222222222"
  ],
  "directoryScopeIds": ["/"],
  "appScopeIds": ["/", "/securityDomain/devicegroup1"]
}`

const exchangeRoleDefinitionJSON = `{
  "@odata.type": "#microsoft.graph.unifiedRoleDefinition",
  "id": "a7c1e2d3-4b5f-4a6e-9c8d-7e6f5a4b3c2d",
  "displayName": "Mail Recipients",
  "isBuiltIn": true,
  "isEnabled": true,
  "rolePermissions": [
    {
      "allowedResourceActions": [
        "exchange/recipient/read",
        "exchange/recipient/update"
      ],
      "excludedResourceActions": ["exchange/recipient/delete"],
      "condition": null
    }
  ]
}`

func TestExchangeRoleAssignmentDecode(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(exchangeRoleAssignmentJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateUnifiedRoleAssignmentFromDiscriminatorValue)
	require.NoError(t, err)
	a := parsed.(betamodels.UnifiedRoleAssignmentable)

	assert.Equal(t, "6c0b2a8e-1f3d-4e5a-8b7c-9d0e1f2a3b4c", *a.GetPrincipalId())
	assert.Equal(t, "a7c1e2d3-4b5f-4a6e-9c8d-7e6f5a4b3c2d", *a.GetRoleDefinitionId())
	assert.Equal(t, "/", *a.GetDirectoryScopeId())
	assert.Equal(t, "/", *a.GetAppScopeId())
	assert.Equal(t, "@Resource[exchange/recipient/name] StringEquals 'Finance'", *a.GetCondition())
}

func TestDefenderRoleAssignmentDecode(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(defenderRoleAssignmentJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateUnifiedRoleAssignmentMultipleFromDiscriminatorValue)
	require.NoError(t, err)
	a := parsed.(betamodels.UnifiedRoleAssignmentMultipleable)

	assert.Equal(t, "SOC analysts", *a.GetDisplayName())
	assert.Equal(t, "Tier 1 responders", *a.GetDescription())
	assert.Equal(t, "1a2b3c4d-5e6f-4789-8abc-def012345678", *a.GetRoleDefinitionId())
	assert.Equal(t, []string{"11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222"}, a.GetPrincipalIds())
	assert.Equal(t, []string{"/"}, a.GetDirectoryScopeIds())
	assert.Equal(t, []string{"/", "/securityDomain/devicegroup1"}, a.GetAppScopeIds())
	assert.Nil(t, a.GetCondition())
}

func TestNewRolePermissionsFromBetaDefinition(t *testing.T) {
	node, err := kjson.NewJsonParseNode([]byte(exchangeRoleDefinitionJSON))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(betamodels.CreateUnifiedRoleDefinitionFromDiscriminatorValue)
	require.NoError(t, err)
	def := parsed.(betamodels.UnifiedRoleDefinitionable)

	perms := newRolePermissions(def.GetRolePermissions())
	require.Len(t, perms, 1)
	assert.Equal(t, []string{"exchange/recipient/read", "exchange/recipient/update"}, perms[0].AllowedResourceActions)
	assert.Equal(t, []string{"exchange/recipient/delete"}, perms[0].ExcludedResourceActions)
	assert.Equal(t, "", perms[0].Condition)

	assert.Empty(t, newRolePermissions(nil))
}

func parseDirectoryObject(t *testing.T, payload string) models.DirectoryObjectable {
	t.Helper()
	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDirectoryObjectFromDiscriminatorValue)
	require.NoError(t, err)
	return parsed.(models.DirectoryObjectable)
}

func TestSplitPrincipalsByType(t *testing.T) {
	objects := map[string]models.DirectoryObjectable{
		"u1": parseDirectoryObject(t, `{"@odata.type":"#microsoft.graph.user","id":"u1","displayName":"Ada"}`),
		"g1": parseDirectoryObject(t, `{"@odata.type":"#microsoft.graph.group","id":"g1","displayName":"SOC"}`),
		"s1": parseDirectoryObject(t, `{"@odata.type":"#microsoft.graph.servicePrincipal","id":"s1","displayName":"Automation"}`),
		"d1": parseDirectoryObject(t, `{"@odata.type":"#microsoft.graph.device","id":"d1","displayName":"laptop"}`),
	}

	got, skipped := splitPrincipalsByType([]string{"u1", "g1", "s1", "d1", "gone"}, objects)
	assert.Equal(t, []string{"u1"}, got.userIds)
	assert.Equal(t, []string{"g1"}, got.groupIds)
	assert.Equal(t, []string{"s1"}, got.servicePrincipalIds)
	assert.Equal(t, []string{"d1", "gone"}, skipped)

	empty, skipped := splitPrincipalsByType(nil, objects)
	assert.Empty(t, empty.userIds)
	assert.Empty(t, empty.groupIds)
	assert.Empty(t, empty.servicePrincipalIds)
	assert.Empty(t, skipped)
}

func TestUnifiedRBACIDIsNamespaced(t *testing.T) {
	id := "a7c1e2d3-4b5f-4a6e-9c8d-7e6f5a4b3c2d"
	exchange := unifiedRBACID(rbacProviderExchange, "roleDefinition", id)
	defender := unifiedRBACID(rbacProviderDefender, "roleDefinition", id)
	assignment := unifiedRBACID(rbacProviderExchange, "roleAssignment", id)

	assert.NotEqual(t, id, exchange, "must not collide with a directory role definition")
	assert.NotEqual(t, exchange, defender)
	assert.NotEqual(t, exchange, assignment)
}

func TestExchangePrincipalInfo(t *testing.T) {
	// principal ids as the Exchange provider returns them
	cases := []struct {
		id, wantType, wantName string
	}{
		{"/RoleGroups/Organization Management", "roleGroup", "Organization Management"},
		{"/RoleAssignmentPolicies/Default Role Assignment Policy", "roleAssignmentPolicy", "Default Role Assignment Policy"},
		{"O365 Support View Only", "", ""},
		{"/RoleGroups/", "", ""},
		{"6c0b2a8e-1f3d-4e5a-8b7c-9d0e1f2a3b4c", "", ""},
		{"", "", ""},
	}
	for _, c := range cases {
		gotType, gotName := exchangePrincipalInfo(c.id)
		assert.Equal(t, c.wantType, gotType, c.id)
		assert.Equal(t, c.wantName, gotName, c.id)
	}
}

func TestDirectoryObjectIds(t *testing.T) {
	a := "11111111-1111-4111-8111-111111111111"
	b := "22222222-2222-4222-8222-222222222222"
	got := directoryObjectIds([]string{a, "/RoleGroups/Information Protection", b, a, ""})
	assert.Equal(t, []string{a, b}, got)
	assert.Empty(t, directoryObjectIds(nil))
}

func TestClassifyGraphError(t *testing.T) {
	assert.NoError(t, classifyGraphError(nil, "X"))

	denied := betaODataErrWithCode("Authorization_RequestDenied")
	denied.ResponseStatusCode = 403
	err := classifyGraphError(denied, exchangeRBACReadPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))
	var lerr *llx.Error
	require.True(t, errors.As(err, &lerr))
	assert.Equal(t, []string{exchangeRBACReadPermission}, lerr.Permissions)
	// the ODataError stays reachable for code-based checks
	assert.Equal(t, "Authorization_RequestDenied", graphErrorCode(err))

	// a v1 refusal that already went through transformError is classified too
	v1Denied := odataErrWithCode("Authorization_RequestDenied")
	v1Denied.ResponseStatusCode = 403
	err = classifyGraphError(transformError(v1Denied), directoryReadPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(err))

	notFound := betaODataErrWithCode("Request_ResourceNotFound")
	notFound.ResponseStatusCode = 404
	err = classifyGraphError(notFound, exchangeRBACReadPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	assert.True(t, isResourceNotFound(err))

	transport := errors.New("dial tcp: connection refused")
	err = classifyGraphError(transport, exchangeRBACReadPermission)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(err))
	assert.Equal(t, transport, err)
}

// pagedReads replays the reads of an unstable listing: each read returns the
// same number of entries, some repeated and others missing.
func pagedReads(reads ...[]string) func() ([]string, error) {
	i := 0
	return func() ([]string, error) {
		r := reads[min(i, len(reads)-1)]
		i++
		return r, nil
	}
}

func identityKey(s string) string { return s }

func TestListDistinct(t *testing.T) {
	t.Run("stable listing is read once", func(t *testing.T) {
		calls := 0
		got, err := listDistinct(func() ([]string, error) {
			calls++
			return []string{"a", "b", "c"}, nil
		}, identityKey)
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b", "c"}, got)
		assert.Equal(t, 1, calls)
	})

	t.Run("repeated entries are read again and combined", func(t *testing.T) {
		// "c" is missing from the first read, "a" from the second
		got, err := listDistinct(pagedReads(
			[]string{"a", "b", "a"},
			[]string{"b", "c", "c"},
		), identityKey)
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"a", "b", "c"}, got)
	})

	t.Run("a listing that never completes is an error", func(t *testing.T) {
		_, err := listDistinct(pagedReads([]string{"a", "a", "b"}), identityKey)
		assert.ErrorContains(t, err, "2 of 3")
	})

	t.Run("entries without id are dropped", func(t *testing.T) {
		got, err := listDistinct(pagedReads([]string{"a", "", "b"}), identityKey)
		require.NoError(t, err)
		assert.Equal(t, []string{"a", "b"}, got)
	})

	t.Run("read errors are returned", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := listDistinct(func() ([]string, error) { return nil, boom }, identityKey)
		assert.ErrorIs(t, err, boom)
	})
}

func TestEntityIDNil(t *testing.T) {
	var def betamodels.UnifiedRoleDefinitionable
	assert.Equal(t, "", entityID(def))
	def = betamodels.NewUnifiedRoleDefinition()
	id := "x"
	def.SetId(&id)
	assert.Equal(t, "x", entityID(def))
}
