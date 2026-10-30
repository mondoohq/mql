// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strconv"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/types"
)

// mqlKeycloakClientScopeInternal holds the realm the scope belongs to and the
// mappers the scope was fetched with, so the mapper list costs no second call.
type mqlKeycloakClientScopeInternal struct {
	parentRealm    *mqlKeycloakRealm
	cacheMappers   []protocolMapperRecord
	mappersFetched bool
}

type clientScopeRecord struct {
	ID              string                 `json:"id"`
	Name            string                 `json:"name"`
	Description     string                 `json:"description"`
	Protocol        string                 `json:"protocol"`
	Attributes      map[string]string      `json:"attributes"`
	ProtocolMappers []protocolMapperRecord `json:"protocolMappers"`
}

// Client scope settings Keycloak keeps in the attribute map rather than as
// fields of the representation. Every value there is a string.
const (
	scopeAttrIncludeInTokenScope    = "include.in.token.scope"
	scopeAttrDisplayOnConsentScreen = "display.on.consent.screen"
	scopeAttrConsentScreenText      = "consent.screen.text"
	scopeAttrGuiOrder               = "gui.order"
)

// realmDefaultScopes names the scopes a realm attaches to every new client and
// the ones it offers as optional. Both lists are read once per realm and shared
// by every scope resource, so the two endpoints are called once rather than
// once per scope.
type realmDefaultScopes struct {
	defaults map[string]struct{}
	optional map[string]struct{}
	names    []string
	optNames []string
}

func fetchRealmDefaultScopes(ctx context.Context, c *connection.KeycloakConnection, realm string) (*realmDefaultScopes, error) {
	res := &realmDefaultScopes{
		defaults: map[string]struct{}{},
		optional: map[string]struct{}{},
	}

	var defaults []clientScopeRecord
	if err := c.Get(ctx, connection.AdminPath(realm, "default-default-client-scopes"), nil, &defaults); err != nil {
		return nil, err
	}
	for _, rec := range defaults {
		res.defaults[rec.ID] = struct{}{}
		res.names = append(res.names, rec.Name)
	}

	var optional []clientScopeRecord
	if err := c.Get(ctx, connection.AdminPath(realm, "default-optional-client-scopes"), nil, &optional); err != nil {
		return nil, err
	}
	for _, rec := range optional {
		res.optional[rec.ID] = struct{}{}
		res.optNames = append(res.optNames, rec.Name)
	}

	return res, nil
}

func newKeycloakClientScope(runtime *plugin.Runtime, realm *mqlKeycloakRealm, rec *clientScopeRecord, realmScopes *realmDefaultScopes) (*mqlKeycloakClientScope, error) {
	isDefault := false
	isOptional := false
	if realmScopes != nil {
		_, isDefault = realmScopes.defaults[rec.ID]
		_, isOptional = realmScopes.optional[rec.ID]
	}

	res, err := CreateResource(runtime, "keycloak.clientScope", map[string]*llx.RawData{
		"__id":                   llx.StringData(realm.realmName() + "/clientScope/" + rec.ID),
		"id":                     llx.StringData(rec.ID),
		"name":                   llx.StringData(rec.Name),
		"description":            llx.StringData(rec.Description),
		"protocol":               llx.StringData(rec.Protocol),
		"includeInTokenScope":    llx.BoolData(configBool(rec.Attributes[scopeAttrIncludeInTokenScope])),
		"displayOnConsentScreen": llx.BoolData(configBool(rec.Attributes[scopeAttrDisplayOnConsentScreen])),
		"consentScreenText":      llx.StringData(rec.Attributes[scopeAttrConsentScreenText]),
		"guiOrder":               llx.StringData(rec.Attributes[scopeAttrGuiOrder]),
		"attributes":             llx.MapData(mapStrToAny(rec.Attributes), types.String),
		"isRealmDefault":         llx.BoolData(isDefault),
		"isRealmOptional":        llx.BoolData(isOptional),
	})
	if err != nil {
		return nil, err
	}

	scope := res.(*mqlKeycloakClientScope)
	scope.parentRealm = realm
	// The scope list carries its mappers, so they are kept rather than fetched
	// again per scope.
	scope.cacheMappers = rec.ProtocolMappers
	scope.mappersFetched = true
	return scope, nil
}

func (s *mqlKeycloakClientScope) id() (string, error) {
	return s.__id, nil
}

func (s *mqlKeycloakClientScope) realm() (*mqlKeycloakRealm, error) {
	if s.parentRealm == nil {
		setNullResource(&s.Realm)
		return nil, nil
	}
	return s.parentRealm, nil
}

func (s *mqlKeycloakClientScope) protocolMappers() ([]any, error) {
	if s.parentRealm == nil {
		return nil, nil
	}

	records := s.cacheMappers
	if !s.mappersFetched {
		ctx := context.Background()
		conn := keycloakConn(s.MqlRuntime)
		path := connection.AdminPath(s.parentRealm.realmName(), "client-scopes", s.Id.Data, "protocol-mappers", "models")

		var fetched []protocolMapperRecord
		if err := conn.Get(ctx, path, nil, &fetched); err != nil {
			return nil, err
		}
		records = fetched
	}

	return newProtocolMappers(s.MqlRuntime, s.__id, records)
}

// scopeMappings lists the roles the scope lets through into a token.
func (s *mqlKeycloakClientScope) scopeMappings() ([]any, error) {
	if s.parentRealm == nil {
		return nil, nil
	}

	ctx := context.Background()
	conn := keycloakConn(s.MqlRuntime)
	path := connection.AdminPath(s.parentRealm.realmName(), "client-scopes", s.Id.Data, "scope-mappings")

	return fetchScopeMappings(ctx, conn, s.MqlRuntime, s.parentRealm, path)
}

// --- protocol mappers -----------------------------------------------------

type protocolMapperRecord struct {
	ID             string            `json:"id"`
	Name           string            `json:"name"`
	Protocol       string            `json:"protocol"`
	ProtocolMapper string            `json:"protocolMapper"`
	Config         map[string]string `json:"config"`
}

// Protocol mapper settings Keycloak keeps in the config map. Every value there
// is a string, so a boolean setting arrives as "true" or "false".
const (
	mapperConfigClaimName            = "claim.name"
	mapperConfigAccessToken          = "access.token.claim"
	mapperConfigIDToken              = "id.token.claim"
	mapperConfigUserInfo             = "userinfo.token.claim"
	mapperConfigIntrospection        = "introspection.token.claim"
	mapperConfigIncludedClientAud    = "included.client.audience"
	mapperConfigIncludedCustomAud    = "included.custom.audience"
	mapperConfigUserAttribute        = "user.attribute"
	mapperConfigUserModelProperty    = "user.model.property"
	mapperConfigFullPath             = "full.path"
	mapperConfigUserSessionNoteClaim = "user.session.note"
)

// newProtocolMappers builds the mapper resources of one owner. The owner's
// cache key prefixes each mapper, since a stock mapper name such as "username"
// appears on many scopes and clients.
func newProtocolMappers(runtime *plugin.Runtime, ownerKey string, records []protocolMapperRecord) ([]any, error) {
	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]

		key := rec.ID
		if key == "" {
			key = rec.Name + "/" + strconv.Itoa(i)
		}

		created, err := CreateResource(runtime, "keycloak.protocolMapper", map[string]*llx.RawData{
			"__id":                   llx.StringData(ownerKey + "/mapper/" + key),
			"id":                     llx.StringData(rec.ID),
			"name":                   llx.StringData(rec.Name),
			"protocol":               llx.StringData(rec.Protocol),
			"mapperType":             llx.StringData(rec.ProtocolMapper),
			"claimName":              llx.StringData(rec.Config[mapperConfigClaimName]),
			"addToAccessToken":       llx.BoolData(configBool(rec.Config[mapperConfigAccessToken])),
			"addToIdToken":           llx.BoolData(configBool(rec.Config[mapperConfigIDToken])),
			"addToUserInfo":          llx.BoolData(configBool(rec.Config[mapperConfigUserInfo])),
			"addToIntrospection":     llx.BoolData(configBool(rec.Config[mapperConfigIntrospection])),
			"includedClientAudience": llx.StringData(rec.Config[mapperConfigIncludedClientAud]),
			"includedCustomAudience": llx.StringData(rec.Config[mapperConfigIncludedCustomAud]),
			"userAttribute":          llx.StringData(MapperUserAttribute(rec.Config)),
			"fullPath":               llx.BoolData(configBool(rec.Config[mapperConfigFullPath])),
			"config":                 llx.MapData(mapStrToAny(rec.Config), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, created)
	}
	return res, nil
}

// MapperUserAttribute returns the user value a mapper reads. Keycloak stores it
// under user.attribute for an attribute mapper and under user.model.property
// for one that reads a built-in property, so both are read.
func MapperUserAttribute(config map[string]string) string {
	if v := config[mapperConfigUserAttribute]; v != "" {
		return v
	}
	return config[mapperConfigUserModelProperty]
}

func (m *mqlKeycloakProtocolMapper) id() (string, error) {
	return m.__id, nil
}

// --- shared scope mapping lookup ------------------------------------------

// fetchScopeMappings reads the roles a client or a scope lets through. The
// response carries the realm roles and the client roles together, and both are
// returned, since a client role is as capable as a realm role.
func fetchScopeMappings(ctx context.Context, conn *connection.KeycloakConnection, runtime *plugin.Runtime, realm *mqlKeycloakRealm, path string) ([]any, error) {
	var mappings roleMappingsRecord
	if err := conn.Get(ctx, path, nil, &mappings); err != nil {
		// A token that cannot read the mappings leaves them unknown. Reporting
		// an empty list would claim the token carries no roles at all.
		return nil, err
	}

	records := collectMappedRoles(&mappings)

	res := make([]any, 0, len(records))
	for i := range records {
		role, err := newKeycloakRole(runtime, realm, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, role)
	}
	return res, nil
}

// collectMappedRoles flattens a role mapping response into one list. Every
// client mapping is walked, not only the first, since the roles that reach a
// token are the union across all of them.
func collectMappedRoles(mappings *roleMappingsRecord) []roleRecord {
	if mappings == nil {
		return nil
	}

	records := make([]roleRecord, 0, len(mappings.RealmMappings))
	records = append(records, mappings.RealmMappings...)
	for _, mapping := range mappings.ClientMappings {
		records = append(records, mapping.Mappings...)
	}
	return records
}
