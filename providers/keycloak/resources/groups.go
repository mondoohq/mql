// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/types"
)

// mqlKeycloakGroupInternal holds the realm the group belongs to and the nested
// groups the list response already carried, so walking a group tree costs no
// call beyond the one that fetched it.
type mqlKeycloakGroupInternal struct {
	parentRealm    *mqlKeycloakRealm
	cacheSubGroups []groupRecord

	// roles, clientRoleMappings and allRoles all read the same response, so it
	// is fetched once per group rather than once per field.
	roleMappingsLock    sync.Mutex
	roleMappingsFetched bool
	cacheRoleMappings   *roleMappingsRecord
}

type groupRecord struct {
	ID            string              `json:"id"`
	Name          string              `json:"name"`
	Path          string              `json:"path"`
	SubGroupCount int64               `json:"subGroupCount"`
	Attributes    map[string][]string `json:"attributes"`
	RealmRoles    []string            `json:"realmRoles"`
	ClientRoles   map[string][]string `json:"clientRoles"`
	SubGroups     []groupRecord       `json:"subGroups"`
}

func newKeycloakGroup(runtime *plugin.Runtime, realm *mqlKeycloakRealm, rec *groupRecord) (*mqlKeycloakGroup, error) {
	res, err := CreateResource(runtime, "keycloak.group", map[string]*llx.RawData{
		"__id":          llx.StringData(realm.realmName() + "/group/" + rec.ID),
		"id":            llx.StringData(rec.ID),
		"name":          llx.StringData(rec.Name),
		"path":          llx.StringData(rec.Path),
		"subGroupCount": llx.IntData(subGroupCount(rec)),
		"attributes":    llx.DictData(multiMapToDict(rec.Attributes)),
		"realmRoles":    llx.ArrayData(strSliceToAny(rec.RealmRoles), types.String),
		"clientRoles":   llx.DictData(multiMapToDict(rec.ClientRoles)),
	})
	if err != nil {
		return nil, err
	}

	group := res.(*mqlKeycloakGroup)
	group.parentRealm = realm
	group.cacheSubGroups = rec.SubGroups
	return group, nil
}

// subGroupCount prefers the count the server reports. Keycloak stopped
// embedding the nested groups in the list response, so a server that still
// embeds them is counted from what it sent.
func subGroupCount(rec *groupRecord) int64 {
	if rec.SubGroupCount > 0 {
		return rec.SubGroupCount
	}
	return int64(len(rec.SubGroups))
}

func (g *mqlKeycloakGroup) id() (string, error) {
	return g.__id, nil
}

func (g *mqlKeycloakGroup) realm() (*mqlKeycloakRealm, error) {
	if g.parentRealm == nil {
		setNullResource(&g.Realm)
		return nil, nil
	}
	return g.parentRealm, nil
}

// subGroups lists the groups nested under this one. A server that embedded them
// in the list response is answered from what it sent, and a newer one that only
// reports a count is asked for the children.
func (g *mqlKeycloakGroup) subGroups() ([]any, error) {
	if g.parentRealm == nil {
		return nil, nil
	}

	records := g.cacheSubGroups
	if len(records) == 0 && g.SubGroupCount.Data > 0 {
		ctx := context.Background()
		conn := keycloakConn(g.MqlRuntime)
		path := connection.AdminPath(g.parentRealm.realmName(), "groups", g.Id.Data, "children")

		fetched, err := connection.GetPaged[groupRecord](ctx, conn, path, connection.FullRepresentation())
		if err != nil {
			return nil, err
		}
		records = fetched
	}

	res := make([]any, 0, len(records))
	for i := range records {
		child, err := newKeycloakGroup(g.MqlRuntime, g.parentRealm, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, child)
	}
	return res, nil
}

// roleMappingsRecord is the shape of a role mapping response for a user or a
// group. The client mappings are keyed by client identifier.
type roleMappingsRecord struct {
	RealmMappings  []roleRecord                  `json:"realmMappings"`
	ClientMappings map[string]clientRoleMappings `json:"clientMappings"`
}

type clientRoleMappings struct {
	ID       string       `json:"id"`
	Client   string       `json:"client"`
	Mappings []roleRecord `json:"mappings"`
}

// roles resolves the realm roles the group grants. The client roles stay in
// the clientRoles field, since resolving each one costs a call per client.
func (g *mqlKeycloakGroup) roles() ([]any, error) {
	if g.parentRealm == nil {
		return nil, nil
	}

	mappings, err := g.roleMappings()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(mappings.RealmMappings))
	for i := range mappings.RealmMappings {
		role, err := newKeycloakRole(g.MqlRuntime, g.parentRealm, &mappings.RealmMappings[i])
		if err != nil {
			return nil, err
		}
		res = append(res, role)
	}
	return res, nil
}

// clientRoleMappings resolves the client roles the group grants. They come from
// the same response the realm roles do, so they cost no extra call.
func (g *mqlKeycloakGroup) clientRoleMappings() ([]any, error) {
	return g.mappedRoles(func(m *roleMappingsRecord) []roleRecord {
		records := []roleRecord{}
		for _, mapping := range m.ClientMappings {
			records = append(records, mapping.Mappings...)
		}
		return records
	})
}

// allRoles resolves every role the group grants, realm and client alike.
func (g *mqlKeycloakGroup) allRoles() ([]any, error) {
	return g.mappedRoles(collectMappedRoles)
}

func (g *mqlKeycloakGroup) mappedRoles(pick func(*roleMappingsRecord) []roleRecord) ([]any, error) {
	if g.parentRealm == nil {
		return nil, nil
	}

	mappings, err := g.roleMappings()
	if err != nil {
		return nil, err
	}

	records := pick(mappings)
	res := make([]any, 0, len(records))
	for i := range records {
		role, err := newKeycloakRole(g.MqlRuntime, g.parentRealm, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, role)
	}
	return res, nil
}

// roleMappings reads the group's role mappings once and keeps the response,
// since roles, clientRoleMappings and allRoles all need it.
func (g *mqlKeycloakGroup) roleMappings() (*roleMappingsRecord, error) {
	if g.roleMappingsFetched {
		return g.cacheRoleMappings, nil
	}

	g.roleMappingsLock.Lock()
	defer g.roleMappingsLock.Unlock()
	if g.roleMappingsFetched {
		return g.cacheRoleMappings, nil
	}

	ctx := context.Background()
	conn := keycloakConn(g.MqlRuntime)
	path := connection.AdminPath(g.parentRealm.realmName(), "groups", g.Id.Data, "role-mappings")

	var mappings roleMappingsRecord
	if err := conn.Get(ctx, path, nil, &mappings); err != nil {
		// A failure is not cached, so a later query retries rather than
		// reporting an empty mapping set as fact.
		return nil, err
	}

	g.cacheRoleMappings = &mappings
	g.roleMappingsFetched = true
	return g.cacheRoleMappings, nil
}
