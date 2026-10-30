// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// clientScopePayload is a scope as the admin API answers
// GET /admin/realms/{realm}/client-scopes.
const clientScopePayload = `{
  "id": "sc-1",
  "name": "profile",
  "description": "OpenID Connect built-in scope: profile",
  "protocol": "openid-connect",
  "attributes": {
    "include.in.token.scope": "true",
    "display.on.consent.screen": "true",
    "consent.screen.text": "${profileScopeConsentText}",
    "gui.order": "2"
  },
  "protocolMappers": [
    {
      "id": "pm-1",
      "name": "username",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-usermodel-property-mapper",
      "config": {
        "user.model.property": "username",
        "claim.name": "preferred_username",
        "access.token.claim": "true",
        "id.token.claim": "true",
        "userinfo.token.claim": "true",
        "jsonType.label": "String"
      }
    },
    {
      "id": "pm-2",
      "name": "groups",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-group-membership-mapper",
      "config": {
        "claim.name": "groups",
        "full.path": "false",
        "access.token.claim": "true",
        "id.token.claim": "true",
        "userinfo.token.claim": "true"
      }
    }
  ]
}`

func TestClientScopeRecordDecode(t *testing.T) {
	var rec clientScopeRecord
	require.NoError(t, json.Unmarshal([]byte(clientScopePayload), &rec))

	assert.Equal(t, "profile", rec.Name)
	assert.Equal(t, "openid-connect", rec.Protocol)
	assert.True(t, configBool(rec.Attributes[scopeAttrIncludeInTokenScope]))
	assert.True(t, configBool(rec.Attributes[scopeAttrDisplayOnConsentScreen]))
	assert.Equal(t, "2", rec.Attributes[scopeAttrGuiOrder])

	// The scope list carries its mappers, so they need no second call.
	require.Len(t, rec.ProtocolMappers, 2)
	assert.Equal(t, "oidc-usermodel-property-mapper", rec.ProtocolMappers[0].ProtocolMapper)
	assert.Equal(t, "preferred_username", rec.ProtocolMappers[0].Config[mapperConfigClaimName])
	assert.Equal(t, "groups", rec.ProtocolMappers[1].Config[mapperConfigClaimName])
}

func TestProtocolMapperDecodeOfAnAudienceMapper(t *testing.T) {
	// An audience mapper lets a token issued for one client be accepted by
	// another, which is why the audience is modeled as a field.
	const payload = `{
      "id": "pm-aud",
      "name": "cluster-audience",
      "protocol": "openid-connect",
      "protocolMapper": "oidc-audience-mapper",
      "config": {
        "included.client.audience": "kubernetes",
        "access.token.claim": "true",
        "id.token.claim": "false",
        "introspection.token.claim": "true"
      }
    }`

	var rec protocolMapperRecord
	require.NoError(t, json.Unmarshal([]byte(payload), &rec))

	assert.Equal(t, "oidc-audience-mapper", rec.ProtocolMapper)
	assert.Equal(t, "kubernetes", rec.Config[mapperConfigIncludedClientAud])
	assert.True(t, configBool(rec.Config[mapperConfigAccessToken]))
	assert.False(t, configBool(rec.Config[mapperConfigIDToken]))
	assert.True(t, configBool(rec.Config[mapperConfigIntrospection]))
	// An audience mapper writes no named claim.
	assert.Empty(t, rec.Config[mapperConfigClaimName])
}

func TestMapperUserAttribute(t *testing.T) {
	// An attribute mapper stores the source under user.attribute.
	assert.Equal(t, "department", MapperUserAttribute(map[string]string{
		"user.attribute": "department",
	}))

	// A mapper that reads a built-in property stores it under
	// user.model.property, so reading only user.attribute would report none.
	assert.Equal(t, "email", MapperUserAttribute(map[string]string{
		"user.model.property": "email",
	}))

	// The attribute wins when both are present.
	assert.Equal(t, "department", MapperUserAttribute(map[string]string{
		"user.attribute":      "department",
		"user.model.property": "email",
	}))

	assert.Empty(t, MapperUserAttribute(map[string]string{}))
	assert.Empty(t, MapperUserAttribute(nil))
}

func TestCollectMappedRolesWalksEveryClient(t *testing.T) {
	// The roles that reach a token are the union across every client mapping.
	// Stopping at the first would miss the ones after it.
	mappings := &roleMappingsRecord{
		RealmMappings: []roleRecord{{ID: "r1", Name: "offline_access"}},
		ClientMappings: map[string]clientRoleMappings{
			"account": {
				Client:   "account",
				Mappings: []roleRecord{{ID: "c1", Name: "view-profile", ClientRole: true}},
			},
			"realm-management": {
				Client:   "realm-management",
				Mappings: []roleRecord{{ID: "c2", Name: "realm-admin", ClientRole: true}},
			},
		},
	}

	got := collectMappedRoles(mappings)
	require.Len(t, got, 3)

	names := map[string]bool{}
	for _, rec := range got {
		names[rec.Name] = true
	}
	assert.True(t, names["offline_access"])
	assert.True(t, names["view-profile"])
	assert.True(t, names["realm-admin"])
}

func TestCollectMappedRolesOnEmptyInput(t *testing.T) {
	assert.Empty(t, collectMappedRoles(nil))
	assert.Empty(t, collectMappedRoles(&roleMappingsRecord{}))
}

func TestRealmDefaultScopesMarksMembership(t *testing.T) {
	// The realm's default list is what makes a mapper reach every client.
	const defaults = `[{"id":"sc-1","name":"profile"},{"id":"sc-2","name":"email"}]`
	const optional = `[{"id":"sc-3","name":"address"}]`

	var defaultRecs, optionalRecs []clientScopeRecord
	require.NoError(t, json.Unmarshal([]byte(defaults), &defaultRecs))
	require.NoError(t, json.Unmarshal([]byte(optional), &optionalRecs))

	sets := &realmDefaultScopes{
		defaults: map[string]struct{}{},
		optional: map[string]struct{}{},
	}
	for _, rec := range defaultRecs {
		sets.defaults[rec.ID] = struct{}{}
		sets.names = append(sets.names, rec.Name)
	}
	for _, rec := range optionalRecs {
		sets.optional[rec.ID] = struct{}{}
		sets.optNames = append(sets.optNames, rec.Name)
	}

	assert.Equal(t, []string{"profile", "email"}, sets.names)
	assert.Equal(t, []string{"address"}, sets.optNames)

	_, isDefault := sets.defaults["sc-1"]
	assert.True(t, isDefault)
	_, isOptional := sets.optional["sc-3"]
	assert.True(t, isOptional)
	_, notDefault := sets.defaults["sc-3"]
	assert.False(t, notDefault)
}
