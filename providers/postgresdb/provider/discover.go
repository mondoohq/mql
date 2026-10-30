// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/postgresdb/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discover enumerates the server's connectable databases and emits each as a
// child asset scoped to that database. Only the server connection discovers
// children; a database-scoped connection is already a leaf.
func (s *Service) discover(conn *connection.PostgresdbConnection) (*inventory.Inventory, error) {
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

	systemID, err := conn.SystemID()
	if err != nil {
		return nil, err
	}
	pool, err := conn.Client("")
	if err != nil {
		return nil, err
	}

	// datallowconn excludes template0 and any database that forbids connections.
	rows, err := pool.Query(context.Background(),
		"SELECT datname FROM pg_database WHERE datallowconn ORDER BY datname")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	for rows.Next() {
		var db string
		if err := rows.Scan(&db); err != nil {
			return nil, err
		}
		dbConf := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		if dbConf.Options == nil {
			dbConf.Options = map[string]string{}
		}
		dbConf.Options[connection.OptionDatabase] = db
		dbConf.Options[connection.OptionScopedDatabase] = db

		id := connection.NewPostgresDatabaseIdentifier(systemID, db)
		in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
			PlatformIds: []string{id},
			Name:        db,
			Platform:    connection.NewPostgresDatabasePlatform(systemID, db),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{dbConf},
		})
	}
	return in, rows.Err()
}
