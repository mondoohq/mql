// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/mysqldb/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discover enumerates the server's schemas and emits each as a child asset.
// Only the server connection discovers children; a schema-scoped connection is
// already a leaf.
func (s *Service) discover(conn *connection.MysqldbConnection) (*inventory.Inventory, error) {
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

	serverID, err := conn.ServerID()
	if err != nil {
		return nil, err
	}
	db, err := conn.Client()
	if err != nil {
		return nil, err
	}
	rows, err := db.QueryContext(context.Background(),
		"SELECT SCHEMA_NAME FROM information_schema.SCHEMATA ORDER BY SCHEMA_NAME")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	for rows.Next() {
		var schema string
		if err := rows.Scan(&schema); err != nil {
			return nil, err
		}
		dbConf := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		if dbConf.Options == nil {
			dbConf.Options = map[string]string{}
		}
		dbConf.Options[connection.OptionDatabase] = schema
		dbConf.Options[connection.OptionScopedDatabase] = schema

		id := connection.NewMysqldbDatabaseIdentifier(serverID, schema)
		in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
			PlatformIds: []string{id},
			Name:        schema,
			Platform:    connection.NewMysqldbDatabasePlatform(serverID, schema),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{dbConf},
		})
	}
	return in, rows.Err()
}
