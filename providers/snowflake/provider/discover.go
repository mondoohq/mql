// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"github.com/Snowflake-Labs/terraform-provider-snowflake/pkg/sdk"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/snowflake/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discover enumerates the account's databases and emits each as a child asset
// scoped to that database. Only the account connection discovers children; a
// database-scoped connection is already a leaf.
func (s *Service) discover(conn *connection.SnowflakeConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}

	// Only the account plane discovers child assets (databases).
	if conn.IsDatabaseScoped() {
		return nil, nil
	}

	if !stringx.ContainsAnyOf(conf.Discover.Targets,
		connection.DiscoveryAll, connection.DiscoveryAuto, connection.DiscoveryDatabases) {
		return nil, nil
	}

	account, err := conn.Account()
	if err != nil {
		return nil, err
	}

	databases, err := conn.Client().Databases.Show(context.Background(), &sdk.ShowDatabaseRequest{})
	if err != nil {
		return nil, err
	}

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	for i := range databases {
		db := databases[i].Name

		// Clone preserves credentials and options; we then scope the clone to a
		// single database and drop discovery so the child stays a leaf.
		dbConf := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		if dbConf.Options == nil {
			dbConf.Options = map[string]string{}
		}
		dbConf.Options[connection.OptionDatabase] = db

		asset := &inventory.Asset{
			PlatformIds: []string{connection.NewSnowflakeDatabaseIdentifier(account, db)},
			Name:        db,
			Platform:    connection.NewSnowflakeDatabasePlatform(account, db),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{dbConf},
		}
		in.Spec.Assets = append(in.Spec.Assets, asset)
	}

	return in, nil
}
