// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
)

// initKeycloakRealm selects a realm by name, so a policy can address one realm
// directly with `keycloak.realm(name: "master")` rather than filtering the
// whole list.
func initKeycloakRealm(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// The args are already complete when the runtime rebuilds a resource it
	// created earlier, so nothing needs looking up.
	if len(args) > 1 {
		return args, nil, nil
	}

	nameArg, ok := args["name"]
	if !ok {
		return args, nil, nil
	}
	name, ok := nameArg.Value.(string)
	if !ok || name == "" {
		return nil, nil, fmt.Errorf("keycloak.realm needs a realm name")
	}

	conn := keycloakConn(runtime)

	// A connection scoped to one realm cannot read another, so asking for a
	// different realm is reported rather than answered with an empty resource.
	if scoped := conn.RealmFilter(); scoped != "" && scoped != name {
		return nil, nil, fmt.Errorf(
			"keycloak.realm %q is out of scope, the connection is scoped to realm %q", name, scoped)
	}

	var rec realmRecord
	if err := conn.Get(context.Background(), connection.AdminPath(name), nil, &rec); err != nil {
		if connection.IsNotFound(err) {
			return nil, nil, fmt.Errorf("keycloak.realm %q not found", name)
		}
		return nil, nil, err
	}
	if rec.Realm == "" {
		return nil, nil, fmt.Errorf("keycloak.realm %q not found", name)
	}

	realm, err := newKeycloakRealm(runtime, &rec)
	if err != nil {
		return nil, nil, err
	}
	return args, realm, nil
}

// initKeycloakClient selects a client by its client id across the realms in
// scope. A client id is only unique within a realm, so a match in more than one
// realm is reported rather than resolved to whichever came first.
func initKeycloakClient(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	clientIDArg, ok := args["clientId"]
	if !ok {
		return args, nil, nil
	}
	clientID, ok := clientIDArg.Value.(string)
	if !ok || clientID == "" {
		return nil, nil, fmt.Errorf("keycloak.client needs a client id")
	}

	root, err := getKeycloak(runtime)
	if err != nil {
		return nil, nil, err
	}

	realms := root.GetRealms()
	if realms.Error != nil {
		return nil, nil, realms.Error
	}

	var found *mqlKeycloakClient
	var foundIn []string

	// Every realm is searched, not only until the first hit, so an ambiguous
	// client id is reported instead of silently resolving to one realm's copy.
	for _, it := range realms.Data {
		realm, ok := it.(*mqlKeycloakRealm)
		if !ok {
			continue
		}

		clients := realm.GetClients()
		if clients.Error != nil {
			return nil, nil, clients.Error
		}

		for _, cit := range clients.Data {
			client, ok := cit.(*mqlKeycloakClient)
			if ok && client.ClientId.Data == clientID {
				found = client
				foundIn = append(foundIn, realm.Name.Data)
			}
		}
	}

	if len(foundIn) > 1 {
		return nil, nil, fmt.Errorf(
			"keycloak.client %q exists in %d realms (%v), scope the connection with --realm",
			clientID, len(foundIn), foundIn)
	}
	if found == nil {
		return nil, nil, fmt.Errorf("keycloak.client %q not found", clientID)
	}

	return args, found, nil
}
