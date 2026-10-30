// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	Family = "nutanix"

	DiscoveryAll      = "all"
	DiscoveryAuto     = "auto"
	DiscoveryClusters = "clusters"
	DiscoveryNodes    = "nodes"
)

const (
	platformIdPrismCentral = "//platformid.api.mondoo.app/runtime/nutanix/endpoint/"
	platformIdCluster      = "//platformid.api.mondoo.app/runtime/nutanix/cluster/"
	platformIdNode         = "//platformid.api.mondoo.app/runtime/nutanix/node/"
)

// ClusterID returns the cluster UUID this connection is scoped to, or "" when
// the connection targets Prism Central as a whole.
func (c *NutanixConnection) ClusterID() string {
	return c.Conf.Options["cluster-id"]
}

// NodeID returns the host UUID this connection is scoped to, or "" when the
// connection is not scoped to a single node.
func (c *NutanixConnection) NodeID() string {
	return c.Conf.Options["node-id"]
}

// PlatformInfo returns the platform for the asset this connection represents,
// derived from the scope encoded in the connection options.
func (c *NutanixConnection) PlatformInfo() *inventory.Platform {
	if id := c.NodeID(); id != "" {
		return NewNodePlatform(id)
	}
	if id := c.ClusterID(); id != "" {
		return NewClusterPlatform(id)
	}
	return NewPrismCentralPlatform(c.endpoint)
}

// PlatformIDs returns the stable platform identifiers for the asset this
// connection represents.
func (c *NutanixConnection) PlatformIDs() []string {
	if id := c.NodeID(); id != "" {
		return []string{NewNodeIdentifier(id)}
	}
	if id := c.ClusterID(); id != "" {
		return []string{NewClusterIdentifier(id)}
	}
	return []string{NewPrismCentralIdentifier(c.endpoint)}
}

func NewPrismCentralPlatform(endpoint string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"virtualization", "nutanix", "prism-central", endpoint},
	}
	PlatformByName("nutanix-prism-central").Apply(p)
	return p
}

func NewClusterPlatform(clusterId string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"virtualization", "nutanix", "cluster", clusterId},
	}
	PlatformByName("nutanix-cluster").Apply(p)
	return p
}

func NewNodePlatform(nodeId string) *inventory.Platform {
	p := &inventory.Platform{
		TechnologyUrlSegments: []string{"virtualization", "nutanix", "node", nodeId},
	}
	PlatformByName("nutanix-node").Apply(p)
	return p
}

func NewPrismCentralIdentifier(endpoint string) string {
	return platformIdPrismCentral + endpoint
}

func NewClusterIdentifier(clusterId string) string {
	return platformIdCluster + clusterId
}

func NewNodeIdentifier(nodeId string) string {
	return platformIdNode + nodeId
}
