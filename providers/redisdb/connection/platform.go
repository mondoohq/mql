// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// OptionHost is the Redis/Valkey hostname or IP.
	OptionHost = "host"
	// OptionPort is the Redis/Valkey TCP port.
	OptionPort = "port"
	// OptionDatabase is the logical database index to select.
	OptionDatabase = "database"
	// OptionTLS enables TLS when "true".
	OptionTLS = "tls"
	// OptionTLSCA is the path to the trusted CA certificate.
	OptionTLSCA = "tls-ca"
	// OptionTLSCert is the path to the client certificate presented to a
	// server that requires one (tls-auth-clients yes).
	OptionTLSCert = "tls-cert"
	// OptionTLSKey is the path to the private key of OptionTLSCert.
	OptionTLSKey = "tls-key"
	// OptionTLSInsecure skips TLS certificate validation when "true".
	OptionTLSInsecure = "tls-insecure"
)

var platformIdRedisServer = "//platformid.api.mondoo.app/runtime/redisdb/server/"

// NewRedisServerPlatform returns the platform for a Redis/Valkey server asset.
func NewRedisServerPlatform(serverID, title string) *inventory.Platform {
	return &inventory.Platform{
		Name:                  "redisdb",
		Title:                 title,
		Family:                []string{"redisdb"},
		Kind:                  "api",
		Runtime:               "redisdb",
		TechnologyUrlSegments: []string{"db", "redisdb", "server", serverID},
	}
}

// NewRedisServerIdentifier returns the stable platform id for a server.
func NewRedisServerIdentifier(serverID string) string {
	return platformIdRedisServer + serverID
}
