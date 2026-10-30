// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// OptionHost is the Cassandra hostname or IP.
	OptionHost = "host"
	// OptionPort is the Cassandra CQL native transport port.
	OptionPort = "port"
	// OptionTLS enables TLS when "true".
	OptionTLS = "tls"
	// OptionTLSCA is the path to the trusted CA certificate.
	OptionTLSCA = "tls-ca"
	// OptionTLSInsecure skips TLS certificate validation when "true".
	OptionTLSInsecure = "tls-insecure"
)

var platformIdCassandraCluster = "//platformid.api.mondoo.app/runtime/cassandra/cluster/"

// NewCassandraClusterPlatform returns the platform for a Cassandra cluster asset.
func NewCassandraClusterPlatform(clusterID string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "cassandra",
		Title:                 "Apache Cassandra",
		Family:                []string{"cassandra"},
		Kind:                  "api",
		Runtime:               "cassandra",
		TechnologyUrlSegments: []string{"db", "cassandra", "cluster", clusterID},
	}
}

// NewCassandraClusterIdentifier returns the stable platform id for a cluster.
func NewCassandraClusterIdentifier(clusterID string) string {
	return platformIdCassandraCluster + clusterID
}
