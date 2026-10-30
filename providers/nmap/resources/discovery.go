// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/nmap/connection"
	"go.mondoo.com/mql/utils/stringx"
)

func Discover(runtime *plugin.Runtime, opts map[string]string) (*inventory.Inventory, error) {
	conn := runtime.Connection.(*connection.NmapConnection)
	if conn == nil || conn.Asset() == nil || len(conn.Asset().Connections) == 0 {
		return nil, nil
	}

	conf := conn.Asset().Connections[0]
	targets := handleTargets(conf.Discover.Targets)
	if !stringx.ContainsAnyOf(targets, connection.DiscoveryHosts, connection.DiscoveryAll, connection.DiscoveryAuto) {
		return nil, nil
	}

	// we only need to discover when networks are specified
	networkValue, ok := conf.Options["networks"]
	if !ok || networkValue == "" {
		return nil, nil
	}
	networks := splitNetworks(networkValue)
	assetList := []*inventory.Asset{}

	for i := range networks {
		network := networks[i]

		targetResource, err := runtime.CreateResource(runtime, "nmap.network", map[string]*llx.RawData{
			"target": llx.StringData(network),
		})
		if err != nil {
			return nil, err
		}
		hosts := targetResource.(*mqlNmapNetwork).GetHosts().Data
		for i := range hosts {
			entry := hosts[i]
			host := entry.(*mqlNmapHost)

			childOpts := map[string]string{}
			if ports, ok := conf.Options["ports"]; ok && ports != "" {
				childOpts["ports"] = ports
			}

			a := &inventory.Asset{
				Name: host.GetName().Data,
				Connections: []*inventory.Config{
					{
						Type:        "nmap",
						Host:        host.GetName().Data,
						Credentials: conf.Credentials,
						Options:     childOpts,
					},
				},
			}

			assetList = append(assetList, a)
		}
	}

	in := &inventory.Inventory{Spec: &inventory.InventorySpec{
		Assets: assetList,
	}}
	return in, nil
}

// splitNetworks parses the comma-separated "networks" discovery option into
// individual scan targets, trimming surrounding whitespace and dropping empty
// entries so a value like "10.0.0.0/24, 10.0.1.0/24" does not yield a target
// with a leading space (which nmap rejects).
func splitNetworks(value string) []string {
	parts := strings.Split(value, ",")
	networks := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			networks = append(networks, trimmed)
		}
	}
	return networks
}

func handleTargets(targets []string) []string {
	if stringx.Contains(targets, connection.DiscoveryAll) {
		return []string{
			connection.DiscoveryHosts,
		}
	}
	return targets
}
