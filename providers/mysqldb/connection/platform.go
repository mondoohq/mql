// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// DiscoveryAuto is the default discovery target. It returns the server
	// alone, because that is the asset the benchmarks and most policies apply
	// to. Per-database assets are opt-in through DiscoveryAll or
	// DiscoveryDatabases: emitting them by default turned a clean scan into one
	// scored asset and N "asset doesn't support any policies" errors.
	DiscoveryAuto = "auto"
	// DiscoveryAll discovers the server plus every schema as its own asset.
	DiscoveryAll = "all"
	// DiscoveryInstance discovers the server only.
	DiscoveryInstance = "instance"
	// DiscoveryDatabases discovers one asset per schema on the server.
	DiscoveryDatabases = "databases"
	// DiscoveryNone connects to the server only, without per-schema assets.
	DiscoveryNone = "none"
)

const (
	// OptionHost is the server hostname or IP address.
	OptionHost = "host"
	// OptionPort is the server TCP port.
	OptionPort = "port"
	// OptionDatabase is the default schema for the connection.
	OptionDatabase = "database"
	// OptionTLSMode selects the TLS mode (false/skip-verify/preferred/true).
	OptionTLSMode = "tls-mode"
	// OptionTLSCA is the path to the trusted CA certificate.
	OptionTLSCA = "tls-ca"
	// OptionTLSCert is the path to the client certificate.
	OptionTLSCert = "tls-cert"
	// OptionTLSKey is the path to the client private key.
	OptionTLSKey = "tls-key"
	// OptionTLSServerName is the name to verify in the server certificate.
	OptionTLSServerName = "tls-server-name"
	// OptionScopedDatabase marks a connection as scoped to a single discovered
	// schema, making the asset a mysqldb-database rather than the server.
	OptionScopedDatabase = "scoped-database"
)

var (
	platformIdMysqldbServer   = "//platformid.api.mondoo.app/runtime/mysqldb/server/"
	platformIdMysqldbDatabase = "/database/"
)

// NewMysqldbServerPlatform returns the platform for a server asset, keyed by
// the server UUID.
func NewMysqldbServerPlatform(serverID, flavor string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "mysqldb", "server", serverID},
	}
	PlatformByName("mysqldb").Apply(pf)
	if flavor != "" {
		pf.Labels = map[string]string{"mysqldb.mondoo.com/flavor": flavor}
	}
	return pf
}

// NewMysqldbDatabasePlatform returns the platform for a single-schema asset
// discovered under a server.
func NewMysqldbDatabasePlatform(serverID, database string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "mysqldb", "server", serverID, "database", database},
	}
	PlatformByName("mysqldb-database").Apply(pf)
	return pf
}

// NewMysqldbServerIdentifier returns the stable platform id for a server.
func NewMysqldbServerIdentifier(serverID string) string {
	return platformIdMysqldbServer + serverID
}

// NewMysqldbDatabaseIdentifier returns the stable platform id for a schema,
// qualified by its server so it is unique across servers.
func NewMysqldbDatabaseIdentifier(serverID, database string) string {
	return platformIdMysqldbServer + serverID + platformIdMysqldbDatabase + database
}
