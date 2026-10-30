// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/keycloak/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover emits one asset per realm in scope, so a scan reports each realm
// separately instead of folding every realm of a server into one result.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := keycloakConn(runtime)

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conn.Asset().Connections[0].Discover.Targets)
	if !stringx.Contains(targets, connection.DiscoveryRealms) {
		return in, nil
	}

	// A connection already scoped to one realm is that realm's asset, so
	// emitting it again would scan it twice.
	if conn.RealmFilter() != "" {
		return in, nil
	}

	root, err := getKeycloak(runtime)
	if err != nil {
		return in, err
	}

	realms := root.GetRealms()
	if realms.Error != nil {
		return in, realms.Error
	}

	conf := conn.Asset().Connections[0]
	for _, it := range realms.Data {
		realm, ok := it.(*mqlKeycloakRealm)
		if !ok {
			continue
		}

		name := realm.Name.Data
		if name == "" {
			continue
		}

		in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
			PlatformIds: []string{connection.NewKeycloakRealmIdentifier(conn.Host(), name)},
			Name:        conn.Host() + "/" + name,
			Platform:    connection.NewKeycloakRealmPlatform(conn.Host(), name),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{scopedConfig(conn, conf, name)},
		})
	}

	return in, nil
}

// scopedConfig clones the root connection config for a discovered realm asset,
// stamping the realm it is scoped to. The realm the token is requested from is
// carried over rather than recomputed, since its default depends on the realm
// the connection is scoped to and the child is scoped where the root was not.
func scopedConfig(conn *connection.KeycloakConnection, conf *inventory.Config, realm string) *inventory.Config {
	child := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))

	options := map[string]string{
		"realmName":  realm,
		"auth-realm": conn.AuthRealm(),
	}
	for _, key := range []string{"url", "client-id", "username"} {
		if value := conf.Options[key]; value != "" {
			options[key] = value
		}
	}
	child.Options = options

	return child
}

func handleTargets(targets []string) []string {
	if stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryAuto) {
		return []string{connection.DiscoveryRealms}
	}
	return targets
}
