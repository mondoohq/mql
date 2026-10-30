// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nutanix/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover enumerates the clusters and nodes managed by a Prism Central
// instance and returns one asset per discovered cluster and node.
func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.NutanixConnection)
	conf := conn.Asset().Connections[0]

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: []*inventory.Asset{},
	}}

	targets := handleTargets(conf.Discover.Targets)

	nutanix, err := getMqlNutanix(runtime)
	if err != nil {
		return nil, err
	}

	for _, target := range targets {
		switch target {
		case connection.DiscoveryClusters:
			clusters, err := nutanix.clusters()
			if err != nil {
				return nil, err
			}
			for _, ic := range clusters {
				cluster := ic.(*mqlNutanixCluster)
				id := cluster.Id.Data
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewClusterIdentifier(id)},
					Name:        cluster.Name.Data,
					Platform:    connection.NewClusterPlatform(id),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), "cluster-id", id)},
				}
				in.Spec.Assets = append(in.Spec.Assets, asset)
			}
		case connection.DiscoveryNodes:
			hosts, err := nutanix.hosts()
			if err != nil {
				return nil, err
			}
			for _, ih := range hosts {
				host := ih.(*mqlNutanixHost)
				id := host.Id.Data
				asset := &inventory.Asset{
					PlatformIds: []string{connection.NewNodeIdentifier(id)},
					Name:        host.Name.Data,
					Platform:    connection.NewNodePlatform(id),
					Labels:      map[string]string{},
					Connections: []*inventory.Config{scopedConfig(conf, conn.ID(), "node-id", id)},
				}
				in.Spec.Assets = append(in.Spec.Assets, asset)
			}
		default:
			continue
		}
	}

	return in, nil
}

func handleTargets(targets []string) []string {
	if stringx.ContainsAnyOf(targets, connection.DiscoveryAll, connection.DiscoveryAuto) {
		return []string{
			connection.DiscoveryClusters,
			connection.DiscoveryNodes,
		}
	}
	return targets
}

// scopedConfig clones the base connection config for a discovered child asset,
// disabling further discovery and recording the scope (cluster or node) so the
// child connection resolves its resources to that single entity.
func scopedConfig(conf *inventory.Config, parentID uint32, scopeKey, scopeValue string) *inventory.Config {
	clone := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(parentID))
	if clone.Options == nil {
		clone.Options = map[string]string{}
	}
	clone.Options[scopeKey] = scopeValue
	return clone
}

func getMqlNutanix(runtime *plugin.Runtime) (*mqlNutanix, error) {
	res, err := CreateResource(runtime, "nutanix", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanix), nil
}
