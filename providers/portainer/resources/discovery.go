// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
	"go.mondoo.com/mql/utils/stringx"
)

// Discover expands a Portainer instance connection into one child asset per
// managed environment. The instance itself stays the connected (root) asset.
//
// In this phase the environment assets are informational: they carry the
// environment platform metadata and link back to the instance, but runtime
// scanning of their containers/workloads (which requires proxying the Docker
// or Kubernetes API through Portainer, or a direct connection to the
// underlying daemon) is intentionally left to a follow-up.
func Discover(runtime *plugin.Runtime) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.PortainerConnection)
	conf := conn.Asset().Connections[0]
	if conf.Discover == nil || len(conf.Discover.Targets) == 0 {
		return nil, nil
	}

	targets := conf.Discover.Targets
	endpoints, err := conn.Endpoints()
	if err != nil {
		return nil, err
	}

	instanceID := conn.InstanceKey()
	assets := []*inventory.Asset{}
	for _, e := range endpoints {
		if !matchesEnvironmentTargets(targets, e.Type) {
			continue
		}

		cfg := conf.Clone(inventory.WithoutDiscovery(), inventory.WithParentConnectionId(conn.ID()))
		// Clone preserves a nil options map, which an asset defined in an
		// inventory file without an options block carries; writing into it
		// would panic.
		if cfg.Options == nil {
			cfg.Options = map[string]string{}
		}
		cfg.Options[connection.OptionEnvironmentID] = strconv.FormatInt(e.ID, 10)
		cfg.Options[connection.OptionEnvironmentType] = strconv.FormatInt(e.Type, 10)

		assets = append(assets, &inventory.Asset{
			PlatformIds: []string{connection.NewEnvironmentPlatformID(instanceID, e.ID)},
			Name:        "Portainer environment " + e.Name,
			Platform:    connection.EnvironmentPlatform(e.Type),
			Connections: []*inventory.Config{cfg},
		})
	}

	return &inventory.Inventory{Spec: &inventory.InventorySpec{Assets: assets}}, nil
}

// matchesEnvironmentTargets reports whether an environment of the given type
// should be discovered for the requested targets. The "auto", "all" and
// "environments" aliases match every environment; the "docker", "kubernetes"
// and "edge" targets filter by environment type.
func matchesEnvironmentTargets(targets []string, envType int64) bool {
	if stringx.Contains(targets, connection.DiscoveryAuto) ||
		stringx.Contains(targets, connection.DiscoveryAll) ||
		stringx.Contains(targets, connection.DiscoveryEnvironments) {
		return true
	}
	if stringx.Contains(targets, connection.DiscoveryDocker) && connection.IsDockerEnvironment(envType) {
		return true
	}
	if stringx.Contains(targets, connection.DiscoveryKubernetes) && connection.IsKubernetesEnvironment(envType) {
		return true
	}
	if stringx.Contains(targets, connection.DiscoveryEdge) && connection.IsEdgeEnvironment(envType) {
		return true
	}
	return false
}
