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
	// DiscoveryAll discovers the server plus every connectable database as its own asset.
	DiscoveryAll = "all"
	// DiscoveryInstance discovers the PostgreSQL server only.
	DiscoveryInstance = "instance"
	// DiscoveryDatabases discovers one asset per connectable database on the server.
	DiscoveryDatabases = "databases"
	// DiscoveryNone connects to the server only, without per-database assets.
	DiscoveryNone = "none"
)

const (
	// OptionHost is the PostgreSQL hostname or IP address.
	OptionHost = "host"
	// OptionPort is the PostgreSQL TCP port.
	OptionPort = "port"
	// OptionDatabase is the database used for the server-level connection, and,
	// when a discovered asset is scoped to a single database, that database.
	OptionDatabase = "database"
	// OptionSSLMode selects the TLS mode (disable/allow/prefer/require/verify-ca/verify-full).
	OptionSSLMode = "sslmode"
	// OptionSSLRootCert is the path to the trusted CA certificate.
	OptionSSLRootCert = "sslrootcert"
	// OptionSSLCert is the path to the client certificate.
	OptionSSLCert = "sslcert"
	// OptionSSLKey is the path to the client private key.
	OptionSSLKey = "sslkey"
	// OptionScopedDatabase marks a connection as scoped to a single discovered
	// database, making the asset a postgresdb-database rather than the server.
	OptionScopedDatabase = "scoped-database"
)

var (
	platformIdPostgresdbServer   = "//platformid.api.mondoo.app/runtime/postgresdb/server/"
	platformIdPostgresdbDatabase = "/database/"
)

// NewPostgresServerPlatform returns the platform for a PostgreSQL server asset,
// keyed by the cluster system identifier.
func NewPostgresServerPlatform(systemID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "postgresdb", "server", systemID},
	}
	PlatformByName("postgresdb").Apply(pf)
	return pf
}

// NewPostgresDatabasePlatform returns the platform for a single-database asset
// discovered under a server.
func NewPostgresDatabasePlatform(systemID, database string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "postgresdb", "server", systemID, "database", database},
	}
	PlatformByName("postgresdb-database").Apply(pf)
	return pf
}

// NewPostgresServerIdentifier returns the stable platform id for a server.
func NewPostgresServerIdentifier(systemID string) string {
	return platformIdPostgresdbServer + systemID
}

// NewPostgresDatabaseIdentifier returns the stable platform id for a database,
// qualified by its server so it is unique across servers.
func NewPostgresDatabaseIdentifier(systemID, database string) string {
	return platformIdPostgresdbServer + systemID + platformIdPostgresdbDatabase + database
}
