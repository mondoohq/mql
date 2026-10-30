// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/mongo/connection"
	"go.mondoo.com/mql/utils/stringx"
	"go.mongodb.org/mongo-driver/v2/bson"
)

// discover enumerates the server's databases and emits each as a child asset.
// Only the server connection discovers children; a database-scoped connection
// is already a leaf.
func (s *Service) discover(conn *connection.MongoConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}
	if conn.ScopedDatabase() != "" {
		return nil, nil
	}
	if !stringx.ContainsAnyOf(conf.Discover.Targets,
		connection.DiscoveryAll, connection.DiscoveryDatabases) {
		return nil, nil
	}

	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	names, err := client.ListDatabaseNames(context.Background(), bson.D{})
	if err != nil {
		return nil, err
	}

	serverID := conn.ServerID()
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	for _, name := range names {
		dbConf := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		if dbConf.Options == nil {
			dbConf.Options = map[string]string{}
		}
		dbConf.Options[connection.OptionScopedDatabase] = name

		id := connection.NewMongoDatabaseIdentifier(serverID, name)
		in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
			PlatformIds: []string{id},
			Name:        name,
			Platform:    connection.NewMongoDatabasePlatform(serverID, name),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{dbConf},
		})
	}
	return in, nil
}
