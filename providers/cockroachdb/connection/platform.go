// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Platforms is the static catalog of platforms this provider emits. The build
// exports it into dist/cockroachdb.json so the CLI and generated docs can list
// what the provider supports.
var Platforms = []*plugin.PlatformInfo{
	{Name: "cockroachdb", Title: "CockroachDB", Family: []string{"cockroachdb"}, Kind: []string{"api"}, Runtime: []string{"cockroachdb"}},
}

var platformIdCockroachdbCluster = "//platformid.api.mondoo.app/runtime/cockroachdb/cluster/"

// NewCockroachdbClusterPlatform returns the platform for a CockroachDB cluster
// asset, keyed by the cluster ID.
func NewCockroachdbClusterPlatform(clusterID, version string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "cockroachdb",
		Title:                 "CockroachDB",
		Family:                []string{"cockroachdb"},
		Kind:                  "api",
		Runtime:               "cockroachdb",
		Version:               version,
		TechnologyUrlSegments: []string{"db", "cockroachdb", "cluster", clusterID},
	}
}

// NewCockroachdbClusterIdentifier returns the stable platform id for a cluster.
func NewCockroachdbClusterIdentifier(clusterID string) string {
	return platformIdCockroachdbCluster + clusterID
}
