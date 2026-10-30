// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// OptionHost is the OpenSearch hostname or IP.
	OptionHost = "host"
	// OptionPort is the OpenSearch REST API port.
	OptionPort = "port"
	// OptionScheme is the connection scheme, http or https.
	OptionScheme = "scheme"
	// OptionTLSCA is the path to the trusted CA certificate.
	OptionTLSCA = "tls-ca"
	// OptionTLSInsecure skips TLS certificate validation when "true".
	OptionTLSInsecure = "tls-insecure"
)

var platformIdOpensearchCluster = "//platformid.api.mondoo.app/runtime/opensearch/cluster/"

// NewOpensearchClusterPlatform returns the platform for an OpenSearch cluster
// asset.
func NewOpensearchClusterPlatform(clusterID string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "opensearch",
		Title:                 "OpenSearch",
		Family:                []string{"opensearch"},
		Kind:                  "api",
		Runtime:               "opensearch",
		TechnologyUrlSegments: []string{"search", "opensearch", "cluster", clusterID},
	}
}

// NewOpensearchClusterIdentifier returns the stable platform id for a cluster,
// keyed by its UUID.
func NewOpensearchClusterIdentifier(clusterID string) string {
	return platformIdOpensearchCluster + clusterID
}
