// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
)

// mqlKeycloakRoleInternal holds the realm the role belongs to, which the
// composite lookup addresses and the client accessor resolves against.
type mqlKeycloakRoleInternal struct {
	parentRealm *mqlKeycloakRealm
}

type roleRecord struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Description string              `json:"description"`
	Composite   bool                `json:"composite"`
	ClientRole  bool                `json:"clientRole"`
	ContainerID string              `json:"containerId"`
	Attributes  map[string][]string `json:"attributes"`
}

func newKeycloakRole(runtime *plugin.Runtime, realm *mqlKeycloakRealm, rec *roleRecord) (*mqlKeycloakRole, error) {
	res, err := CreateResource(runtime, "keycloak.role", map[string]*llx.RawData{
		"__id":        llx.StringData(realm.realmName() + "/role/" + rec.ID),
		"id":          llx.StringData(rec.ID),
		"name":        llx.StringData(rec.Name),
		"description": llx.StringData(rec.Description),
		"composite":   llx.BoolData(rec.Composite),
		"clientRole":  llx.BoolData(rec.ClientRole),
		"containerId": llx.StringData(rec.ContainerID),
		"attributes":  llx.DictData(multiMapToDict(rec.Attributes)),
	})
	if err != nil {
		return nil, err
	}

	role := res.(*mqlKeycloakRole)
	role.parentRealm = realm
	return role, nil
}

func (r *mqlKeycloakRole) id() (string, error) {
	return r.__id, nil
}

func (r *mqlKeycloakRole) realm() (*mqlKeycloakRealm, error) {
	if r.parentRealm == nil {
		setNullResource(&r.Realm)
		return nil, nil
	}
	return r.parentRealm, nil
}

// client resolves the client that defines the role through the realm's cached
// client list, so resolving it on many roles costs one call for the scan
// rather than one call per role.
func (r *mqlKeycloakRole) client() (*mqlKeycloakClient, error) {
	if !r.ClientRole.Data || r.parentRealm == nil || r.ContainerId.Data == "" {
		setNullResource(&r.Client)
		return nil, nil
	}

	clients := r.parentRealm.GetClients()
	if clients.Error != nil {
		return nil, clients.Error
	}

	for _, it := range clients.Data {
		client, ok := it.(*mqlKeycloakClient)
		if ok && client.Id.Data == r.ContainerId.Data {
			return client, nil
		}
	}

	setNullResource(&r.Client)
	return nil, nil
}

// composites lists the roles a composite role grants. A role that grants
// nothing reports an empty list rather than a failure, since Keycloak answers
// the endpoint for every role.
func (r *mqlKeycloakRole) composites() ([]any, error) {
	if !r.Composite.Data || r.parentRealm == nil {
		return nil, nil
	}

	records, err := fetchRoleComposites(r.MqlRuntime, r.parentRealm, r.Id.Data)
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		role, err := newKeycloakRole(r.MqlRuntime, r.parentRealm, &records[i])
		if err != nil {
			return nil, err
		}
		res = append(res, role)
	}
	return res, nil
}

// fetchRoleComposites reads the roles a composite role grants directly. The
// roles-by-id endpoint is used because it takes the role's identifier, which
// works for a realm role and a client role alike.
func fetchRoleComposites(runtime *plugin.Runtime, realm *mqlKeycloakRealm, roleID string) ([]roleRecord, error) {
	if roleID == "" {
		return nil, nil
	}

	conn := keycloakConn(runtime)
	path := connection.AdminPath(realm.realmName(), "roles-by-id", roleID, "composites")

	var records []roleRecord
	if err := conn.Get(context.Background(), path, nil, &records); err != nil {
		return nil, err
	}
	return records, nil
}
