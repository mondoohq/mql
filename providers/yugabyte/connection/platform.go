// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/yugabyte.json so the CLI and generated docs can list
// what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "yugabytedb", Title: "YugabyteDB", Family: []string{"yugabytedb"}, Kind: []string{"api"}, Runtime: []string{"yugabytedb"}},
}

var platformIdYugabyteCluster = "//platformid.api.mondoo.app/runtime/yugabytedb/cluster/"

// NewYugabyteClusterPlatform returns the platform for a YugabyteDB cluster
// asset, keyed by the cluster UUID.
func NewYugabyteClusterPlatform(clusterUUID, version string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "yugabytedb",
		Title:                 "YugabyteDB",
		Family:                []string{"yugabytedb"},
		Kind:                  "api",
		Runtime:               "yugabytedb",
		Version:               version,
		TechnologyUrlSegments: []string{"db", "yugabytedb", "cluster", clusterUUID},
	}
}

// NewYugabyteClusterIdentifier returns the stable platform id for a cluster.
func NewYugabyteClusterIdentifier(clusterUUID string) string {
	return platformIdYugabyteCluster + clusterUUID
}
