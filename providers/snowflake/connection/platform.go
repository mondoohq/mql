// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

const (
	// DiscoveryAll discovers the account plus every database as its own asset.
	DiscoveryAll = "all"
	// DiscoveryAuto is the default discovery target; it behaves like DiscoveryAll.
	DiscoveryAuto = "auto"
	// DiscoveryDatabases discovers one asset per database in the account.
	DiscoveryDatabases = "databases"
	// DiscoveryNone connects to the account only, without per-database assets.
	DiscoveryNone = "none"
)

const (
	// OptionDatabase marks a connection as scoped to a single database. When set,
	// the asset is a snowflake-database rather than the account itself.
	OptionDatabase = "database"
)

var (
	platformIdSnowflakeAccount  = "//platformid.api.mondoo.app/runtime/snowflake/account/"
	platformIdSnowflakeDatabase = "/database/"
)

// NewSnowflakeAccountPlatform returns the platform for a Snowflake account asset.
func NewSnowflakeAccountPlatform(account string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "snowflake", "account", account},
	}
	PlatformByName("snowflake").Apply(pf)
	return pf
}

// NewSnowflakeDatabasePlatform returns the platform for a single-database asset
// discovered under an account.
func NewSnowflakeDatabasePlatform(account, database string) *inventory.Platform {
	pf := &inventory.Platform{
		TechnologyUrlSegments: []string{"saas", "snowflake", "account", account, "database", database},
	}
	PlatformByName("snowflake-database").Apply(pf)
	return pf
}

// NewSnowflakeAccountIdentifier returns the stable platform id for an account.
func NewSnowflakeAccountIdentifier(account string) string {
	return platformIdSnowflakeAccount + account
}

// NewSnowflakeDatabaseIdentifier returns the stable platform id for a database,
// qualified by its account so it is unique across accounts.
func NewSnowflakeDatabaseIdentifier(account, database string) string {
	return platformIdSnowflakeAccount + account + platformIdSnowflakeDatabase + database
}
