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
	// DiscoveryAll discovers the instance plus every online database as its own asset.
	DiscoveryAll = "all"
	// DiscoveryInstance discovers the SQL Server instance only.
	DiscoveryInstance = "instance"
	// DiscoveryDatabases discovers one asset per online database on the instance.
	DiscoveryDatabases = "databases"
	// DiscoveryNone connects to the instance only, without per-database assets.
	DiscoveryNone = "none"
)

const (
	// OptionHost is the SQL Server hostname or IP address.
	OptionHost = "host"
	// OptionPort is the SQL Server TCP port.
	OptionPort = "port"
	// OptionInstance is the named instance to connect to.
	OptionInstance = "instance"
	// OptionDatabase marks a connection as scoped to a single database. When set,
	// the asset is a mssql-database rather than the whole instance.
	OptionDatabase = "database"
	// OptionAuth selects the authentication mode: sql, windows, kerberos, or azure.
	OptionAuth = "auth"
	// OptionEncrypt selects the TDS encryption mode: strict, mandatory, optional, or disable.
	OptionEncrypt = "encrypt"
	// OptionTrustServerCertificate skips TLS certificate validation when "true".
	OptionTrustServerCertificate = "trust-server-certificate"
)

var (
	platformIdMssqlInstance = "//platformid.api.mondoo.app/runtime/mssql/instance/"
	platformIdMssqlDatabase = "/database/"
)

// NewMssqlInstancePlatform returns the platform for a SQL Server instance asset.
func NewMssqlInstancePlatform(instanceID string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "mssql", "instance", instanceID},
	}
	PlatformByName("mssql").Apply(pf)
	return pf
}

// NewMssqlDatabasePlatform returns the platform for a single-database asset
// discovered under an instance.
func NewMssqlDatabasePlatform(instanceID, database string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"db", "mssql", "instance", instanceID, "database", database},
	}
	PlatformByName("mssql-database").Apply(pf)
	return pf
}

// NewMssqlInstanceIdentifier returns the stable platform id for an instance.
func NewMssqlInstanceIdentifier(instanceID string) string {
	return platformIdMssqlInstance + instanceID
}

// NewMssqlDatabaseIdentifier returns the stable platform id for a database,
// qualified by its instance so it is unique across instances.
func NewMssqlDatabaseIdentifier(instanceID, database string) string {
	return platformIdMssqlInstance + instanceID + platformIdMssqlDatabase + database
}
