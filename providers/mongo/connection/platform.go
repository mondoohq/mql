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
	// DiscoveryAll discovers the server plus every database as its own asset.
	DiscoveryAll = "all"
	// DiscoveryInstance discovers the server only.
	DiscoveryInstance = "instance"
	// DiscoveryDatabases discovers one asset per database on the server.
	DiscoveryDatabases = "databases"
	// DiscoveryNone connects to the server only, without per-database assets.
	DiscoveryNone = "none"
)

const (
	// OptionHost is the MongoDB hostname, IP, or mongodb:// connection string.
	OptionHost = "host"
	// OptionPort is the MongoDB TCP port.
	OptionPort = "port"
	// OptionAuthDB is the authentication database.
	OptionAuthDB = "auth-db"
	// OptionTLS enables TLS when "true".
	OptionTLS = "tls"
	// OptionTLSCA is the path to the trusted CA certificate.
	OptionTLSCA = "tls-ca"
	// OptionTLSInsecure skips TLS certificate validation when "true".
	OptionTLSInsecure = "tls-insecure"
	// OptionScopedDatabase marks a connection as scoped to a single database,
	// making the asset a mongo-database rather than the whole server.
	OptionScopedDatabase = "scoped-database"
)

var (
	platformIdMongoServer   = "//platformid.api.mondoo.app/runtime/mongo/server/"
	platformIdMongoDatabase = "/database/"
)

// NewMongoServerPlatform returns the platform for a MongoDB server asset.
func NewMongoServerPlatform(serverID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "mongo", "server", serverID},
	}
	PlatformByName("mongo").Apply(pf)
	return pf
}

// NewMongoDatabasePlatform returns the platform for a single-database asset
// discovered under a server.
func NewMongoDatabasePlatform(serverID, database string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "mongo", "server", serverID, "database", database},
	}
	PlatformByName("mongo-database").Apply(pf)
	return pf
}

// NewMongoServerIdentifier returns the stable platform id for a server.
func NewMongoServerIdentifier(serverID string) string {
	return platformIdMongoServer + serverID
}

// NewMongoDatabaseIdentifier returns the stable platform id for a database,
// qualified by its server so it is unique across servers.
func NewMongoDatabaseIdentifier(serverID, database string) string {
	return platformIdMongoServer + serverID + platformIdMongoDatabase + database
}
