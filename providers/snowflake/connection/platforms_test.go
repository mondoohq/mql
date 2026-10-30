// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestPlatformCatalog(t *testing.T) {
	require.NotEmpty(t, Platforms)
	for _, pi := range Platforms {
		require.NotEmpty(t, pi.Name)
		assert.Same(t, pi, PlatformByName(pi.Name), pi.Name)

		p := &inventory.Platform{}
		pi.Apply(p)
		assert.True(t, pi.Consistent(p), pi.Name)
		assert.Equal(t, pi.Title, p.Title, pi.Name)
	}
}

func TestPlatformCatalogHasAccountAndDatabase(t *testing.T) {
	assert.NotNil(t, PlatformByName("snowflake"), "account platform")
	assert.NotNil(t, PlatformByName("snowflake-database"), "database platform")
}

func TestAccountPlatformAndIdentifier(t *testing.T) {
	pf := NewSnowflakeAccountPlatform("acme")
	assert.Equal(t, "snowflake", pf.Name)
	assert.Equal(t, []string{"saas", "snowflake", "account", "acme"}, pf.TechnologyUrlSegments)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/snowflake/account/acme",
		NewSnowflakeAccountIdentifier("acme"))
}

func TestDatabasePlatformAndIdentifier(t *testing.T) {
	pf := NewSnowflakeDatabasePlatform("acme", "SALES")
	assert.Equal(t, "snowflake-database", pf.Name)
	assert.Equal(t, []string{"saas", "snowflake", "account", "acme", "database", "SALES"}, pf.TechnologyUrlSegments)

	assert.Equal(t,
		"//platformid.api.mondoo.app/runtime/snowflake/account/acme/database/SALES",
		NewSnowflakeDatabaseIdentifier("acme", "SALES"))
}

// A database identifier is qualified by its account so the same database name in
// two accounts never collides into one asset.
func TestDatabaseIdentifierIsAccountQualified(t *testing.T) {
	assert.NotEqual(t,
		NewSnowflakeDatabaseIdentifier("acct-a", "SALES"),
		NewSnowflakeDatabaseIdentifier("acct-b", "SALES"))
}
