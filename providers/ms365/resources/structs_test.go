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

// Guards against the inverted nil-check the function used to carry —
// it now returns nil on a nil input instead of panicking on the
// dereference inside the constructor.
func TestNewAdminConsentRequestPolicy_NilInput(t *testing.T) {
	assert.Nil(t, newAdminConsentRequestPolicy(nil))
}

func TestDirectoryObjectDisplayName(t *testing.T) {
	name := "Alice Admin"
	tests := []struct {
		name string
		in   map[string]any
		want string
	}{
		{"nil map", nil, ""},
		{"missing key", map[string]any{"other": "x"}, ""},
		{"string value", map[string]any{"displayName": "Global Admins"}, "Global Admins"},
		{"pointer value", map[string]any{"displayName": &name}, name},
		{"nil pointer", map[string]any{"displayName": (*string)(nil)}, ""},
		{"wrong type", map[string]any{"displayName": 42}, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, directoryObjectDisplayName(tc.in))
		})
	}
}

func TestDirectoryPrincipalInfo(t *testing.T) {
	t.Run("nil principal", func(t *testing.T) {
		pt, pn := directoryPrincipalInfo(nil)
		assert.Empty(t, pt)
		assert.Empty(t, pn)
	})

	t.Run("user with display name", func(t *testing.T) {
		p := models.NewDirectoryObject()
		p.SetOdataType(new("#microsoft.graph.user"))
		p.SetAdditionalData(map[string]any{"displayName": "Alice Admin"})
		pt, pn := directoryPrincipalInfo(p)
		assert.Equal(t, "user", pt)
		assert.Equal(t, "Alice Admin", pn)
	})

	t.Run("group without display name", func(t *testing.T) {
		p := models.NewDirectoryObject()
		p.SetOdataType(new("#microsoft.graph.group"))
		pt, pn := directoryPrincipalInfo(p)
		assert.Equal(t, "group", pt)
		assert.Empty(t, pn)
	})

	t.Run("missing odata type", func(t *testing.T) {
		p := models.NewDirectoryObject()
		pt, pn := directoryPrincipalInfo(p)
		assert.Empty(t, pt)
		assert.Empty(t, pn)
	})

	t.Run("typed principal reads its typed displayName", func(t *testing.T) {
		u := models.NewUser()
		u.SetOdataType(new("#microsoft.graph.user"))
		u.SetDisplayName(new("Alice Admin"))
		pt, pn := directoryPrincipalInfo(u)
		assert.Equal(t, "user", pt)
		assert.Equal(t, "Alice Admin", pn)
	})
}

// The role-assignment request uses $expand=principal, so the SDK deserializes
// the principal through CreateDirectoryObjectFromDiscriminatorValue and builds
// a concrete *models.User whose displayName is a TYPED property. It therefore
// never lands in AdditionalData.
//
// A fixture built with models.NewDirectoryObject() + SetAdditionalData is a
// shape production never produces, so a test using one passes while the real
// path returns "". Decode the actual payload instead.
func TestDirectoryPrincipalInfoFromExpandedPrincipal(t *testing.T) {
	const payload = `{
	  "id": "ra-1",
	  "principalId": "u-1",
	  "principal": {
	    "@odata.type": "#microsoft.graph.user",
	    "id": "u-1",
	    "displayName": "Alice Admin",
	    "userPrincipalName": "alice@contoso.com"
	  }
	}`

	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateUnifiedRoleAssignmentFromDiscriminatorValue)
	require.NoError(t, err)

	principal := parsed.(models.UnifiedRoleAssignmentable).GetPrincipal()
	require.NotNil(t, principal)
	assert.IsType(t, &models.User{}, principal, "the discriminator builds a concrete type")
	assert.Empty(t, principal.GetAdditionalData(),
		"displayName is typed on *models.User, so AdditionalData is empty -- this is why the bag read failed")

	pt, pn := directoryPrincipalInfo(principal)
	assert.Equal(t, "user", pt)
	assert.Equal(t, "Alice Admin", pn)
}

// A group principal resolves the same way, through the shared accessor rather
// than a per-type branch.
func TestDirectoryPrincipalInfoFromExpandedGroup(t *testing.T) {
	const payload = `{"@odata.type":"#microsoft.graph.group","id":"g-1","displayName":"Global Admins"}`

	node, err := kjson.NewJsonParseNode([]byte(payload))
	require.NoError(t, err)
	parsed, err := node.GetObjectValue(models.CreateDirectoryObjectFromDiscriminatorValue)
	require.NoError(t, err)

	pt, pn := directoryPrincipalInfo(parsed.(models.DirectoryObjectable))
	assert.Equal(t, "group", pt)
	assert.Equal(t, "Global Admins", pn)
}

// A bare DirectoryObject has no typed displayName, so the AdditionalData
// fallback must still work.
func TestDirectoryPrincipalInfoFallsBackToAdditionalData(t *testing.T) {
	p := models.NewDirectoryObject()
	p.SetOdataType(new("#microsoft.graph.user"))
	p.SetAdditionalData(map[string]any{"displayName": "Bare Object"})
	pt, pn := directoryPrincipalInfo(p)
	assert.Equal(t, "user", pt)
	assert.Equal(t, "Bare Object", pn)
}
