// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/mssql/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discover enumerates the instance's online databases and emits each as a child
// asset scoped to that database. Only the instance connection discovers
// children; a database-scoped connection is already a leaf.
func (s *Service) discover(conn *connection.MssqlConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	// A database-scoped connection does not discover further.
	if conn.Database() != "" {
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

	// state = 0 is ONLINE; only online databases can be queried.
	rows, err := client.QueryContext(context.Background(),
		"SELECT name FROM sys.databases WHERE state = 0 ORDER BY database_id")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	instanceID := conn.InstanceID()
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	for rows.Next() {
		var db string
		if err := rows.Scan(&db); err != nil {
			return nil, err
		}

		// Clone preserves credentials and options; we then scope the clone to a
		// single database and drop discovery so the child stays a leaf.
		dbConf := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		if dbConf.Options == nil {
			dbConf.Options = map[string]string{}
		}
		dbConf.Options[connection.OptionDatabase] = db

		id := connection.NewMssqlDatabaseIdentifier(instanceID, db)
		in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
			PlatformIds: []string{id},
			Name:        db,
			Platform:    connection.NewMssqlDatabasePlatform(instanceID, db),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{dbConf},
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return in, nil
}
