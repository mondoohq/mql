// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// OptionHost is the Elasticsearch hostname or IP.
	OptionHost = "host"
	// OptionPort is the Elasticsearch REST API port.
	OptionPort = "port"
	// OptionScheme is the connection scheme, http or https.
	OptionScheme = "scheme"
	// OptionTLSCA is the path to the trusted CA certificate.
	OptionTLSCA = "tls-ca"
	// OptionTLSInsecure skips TLS certificate validation when "true".
	OptionTLSInsecure = "tls-insecure"
	// OptionAPIKey is the API key credential (base64 of id:api_key).
	OptionAPIKey = "api-key"
)

var platformIdElasticsearchCluster = "//platformid.api.mondoo.app/runtime/elasticsearch/cluster/"

// NewElasticsearchClusterPlatform returns the platform for an Elasticsearch
// cluster asset.
func NewElasticsearchClusterPlatform(clusterID string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "elasticsearch",
		Title:                 "Elasticsearch",
		Family:                []string{"elasticsearch"},
		Kind:                  "api",
		Runtime:               "elasticsearch",
		TechnologyUrlSegments: []string{"search", "elasticsearch", "cluster", clusterID},
	}
}

// NewElasticsearchClusterIdentifier returns the stable platform id for a
// cluster, keyed by its UUID.
func NewElasticsearchClusterIdentifier(clusterID string) string {
	return platformIdElasticsearchCluster + clusterID
}
