// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"context"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/weaviate/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// discover enumerates the server's collections and emits each as a child asset.
// Only the server connection discovers children; a collection-scoped connection
// is already a leaf.
func (s *Service) discover(conn *connection.WeaviateConnection) (*inventory.Inventory, error) {
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil {
		return nil, nil
	}
	if conn.ScopedCollection() != "" {
		return nil, nil
	}
	if !stringx.ContainsAnyOf(conf.Discover.Targets,
		connection.DiscoveryAll, connection.DiscoveryAuto, connection.DiscoveryCollections) {
		return nil, nil
	}

	client, err := conn.Client()
	if err != nil {
		return nil, err
	}
	schema, err := client.Schema().Getter().Do(context.Background())
	if err != nil {
		return nil, err
	}

	serverID := conn.ServerID()
	in := &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: []*inventory.Asset{}}}
	for _, class := range schema.Classes {
		collConf := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		if collConf.Options == nil {
			collConf.Options = map[string]string{}
		}
		collConf.Options[connection.OptionScopedCollection] = class.Class

		id := connection.NewWeaviateCollectionIdentifier(serverID, class.Class)
		in.Spec.Assets = append(in.Spec.Assets, &inventory.Asset{
			PlatformIds: []string{id},
			Name:        class.Class,
			Platform:    connection.NewWeaviateCollectionPlatform(serverID, class.Class),
			Labels:      map[string]string{},
			Connections: []*inventory.Config{collConf},
		})
	}
	return in, nil
}
