// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The regression this guards: an Elastic SAN volume group reports the vault
// URI, key name and key version as three separate fields, so the key identifier
// has to be assembled. Getting the join wrong yields a URI parseKeyVaultId
// rejects, and the encryption key of a customer-managed-key group reads as
// unresolvable — on the one resource where that reading is the point.
func TestElasticSanKeyVaultKeyId(t *testing.T) {
	t.Run("a pinned version is part of the key id", func(t *testing.T) {
		assert.Equal(t,
			"https://contoso.vault.azure.net/keys/san-cmk/abc123",
			elasticSanKeyVaultKeyId("https://contoso.vault.azure.net", "san-cmk", "abc123"))
	})

	// A group that pins no version follows the key, so a rotation takes effect
	// without an update to the group. The versionless identifier resolves to
	// whatever version is current, which is the version actually in force.
	t.Run("no version means the current version", func(t *testing.T) {
		assert.Equal(t,
			"https://contoso.vault.azure.net/keys/san-cmk",
			elasticSanKeyVaultKeyId("https://contoso.vault.azure.net", "san-cmk", ""))
	})

	t.Run("a trailing slash on the vault URI does not double up", func(t *testing.T) {
		assert.Equal(t,
			"https://contoso.vault.azure.net/keys/san-cmk",
			elasticSanKeyVaultKeyId("https://contoso.vault.azure.net/", "san-cmk", ""))
	})

	// A platform-key group reports no vault properties at all. Assembling an id
	// out of the empty halves would produce a reference that cannot resolve,
	// where the truthful answer is that there is no customer-managed key.
	t.Run("no key id without both halves", func(t *testing.T) {
		assert.Equal(t, "", elasticSanKeyVaultKeyId("", "", ""))
		assert.Equal(t, "", elasticSanKeyVaultKeyId("https://contoso.vault.azure.net", "", "abc123"))
		assert.Equal(t, "", elasticSanKeyVaultKeyId("", "san-cmk", "abc123"))
	})

	t.Run("both forms parse as key vault identifiers", func(t *testing.T) {
		versioned, err := parseKeyVaultId(elasticSanKeyVaultKeyId("https://contoso.vault.azure.net", "san-cmk", "abc123"))
		require.NoError(t, err)
		assert.Equal(t, "san-cmk", versioned.Name)
		assert.Equal(t, "abc123", versioned.Version)

		versionless, err := parseKeyVaultId(elasticSanKeyVaultKeyId("https://contoso.vault.azure.net", "san-cmk", ""))
		require.NoError(t, err)
		assert.Equal(t, "san-cmk", versionless.Name)
		assert.Equal(t, "", versionless.Version)
	})
}
