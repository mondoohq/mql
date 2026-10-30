// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/netapp/armnetapp/v11"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The regression this guards: NetApp reports the vault URI and the key name as
// two fields, so the key identifier has to be assembled. Getting the join wrong
// yields a URI that parseKeyVaultId rejects, and the encryption key of a
// customer-managed-key account reads as unresolvable.
func TestNetAppKeyVaultKeyId(t *testing.T) {
	str := func(s string) *string { return &s }

	t.Run("vault URI and key name are joined into a versionless key id", func(t *testing.T) {
		assert.Equal(t,
			"https://contoso.vault.azure.net/keys/netapp-cmk",
			netAppKeyVaultKeyId(str("https://contoso.vault.azure.net"), str("netapp-cmk")))
	})

	t.Run("a trailing slash on the vault URI does not double up", func(t *testing.T) {
		assert.Equal(t,
			"https://contoso.vault.azure.net/keys/netapp-cmk",
			netAppKeyVaultKeyId(str("https://contoso.vault.azure.net/"), str("netapp-cmk")))
	})

	// A platform-key account reports no vault at all. Assembling a key id out of
	// the empty halves would produce a reference that cannot resolve, where the
	// truthful answer is that there is no customer-managed key.
	t.Run("no key id without both halves", func(t *testing.T) {
		assert.Equal(t, "", netAppKeyVaultKeyId(nil, nil))
		assert.Equal(t, "", netAppKeyVaultKeyId(str("https://contoso.vault.azure.net"), nil))
		assert.Equal(t, "", netAppKeyVaultKeyId(nil, str("netapp-cmk")))
		assert.Equal(t, "", netAppKeyVaultKeyId(str(""), str("netapp-cmk")))
		assert.Equal(t, "", netAppKeyVaultKeyId(str("https://contoso.vault.azure.net"), str("")))
	})

	t.Run("the assembled id parses as a key vault identifier", func(t *testing.T) {
		parsed, err := parseKeyVaultId(netAppKeyVaultKeyId(
			str("https://contoso.vault.azure.net"), str("netapp-cmk")))
		require.NoError(t, err)
		assert.Equal(t, "contoso", parsed.Vault)
		assert.Equal(t, "keys", parsed.Type)
		assert.Equal(t, "netapp-cmk", parsed.Name)
		assert.Equal(t, "", parsed.Version)
	})
}

// NetApp reports the LDAP bind password location as a vault URI and a secret
// name. A wrong join yields an id parseKeyVaultId rejects, and the bind
// password secret of every LDAP-configured account reads as unresolvable.
func TestNetAppKeyVaultSecretId(t *testing.T) {
	str := func(s string) *string { return &s }

	// Synthetic: URI shape from the ARM BindPasswordAkvConfig docs; no target showed this.
	t.Run("vault URI and secret name are joined into a versionless secret id", func(t *testing.T) {
		assert.Equal(t,
			"https://contoso.vault.azure.net/secrets/ldap-bind",
			netAppKeyVaultSecretId(str("https://contoso.vault.azure.net/"), str("ldap-bind")))
	})

	// Synthetic: absent BindPasswordAkvConfig members; no target showed this.
	t.Run("no secret id without both halves", func(t *testing.T) {
		assert.Equal(t, "", netAppKeyVaultSecretId(nil, nil))
		assert.Equal(t, "", netAppKeyVaultSecretId(str("https://contoso.vault.azure.net"), nil))
		assert.Equal(t, "", netAppKeyVaultSecretId(nil, str("ldap-bind")))
		assert.Equal(t, "", netAppKeyVaultSecretId(str("https://contoso.vault.azure.net"), str("")))
	})

	// Synthetic: checks the join against the secret resource's id parser.
	t.Run("the assembled id parses as a key vault secret identifier", func(t *testing.T) {
		parsed, err := parseKeyVaultId(netAppKeyVaultSecretId(
			str("https://contoso.vault.azure.net"), str("ldap-bind")))
		require.NoError(t, err)
		assert.Equal(t, "contoso", parsed.Vault)
		assert.Equal(t, "secrets", parsed.Type)
		assert.Equal(t, "ldap-bind", parsed.Name)
		assert.Equal(t, "", parsed.Version)
	})
}

func TestNetAppMountTargetIps(t *testing.T) {
	str := func(s string) *string { return &s }

	t.Run("no mount targets is an empty list, never nil", func(t *testing.T) {
		res := netAppMountTargetIps(nil)
		require.NotNil(t, res)
		assert.Empty(t, res)
	})

	t.Run("nil entries and empty addresses are skipped", func(t *testing.T) {
		res := netAppMountTargetIps([]*armnetapp.MountTargetProperties{
			nil,
			{},
			{IPAddress: str("")},
			{IPAddress: str("10.0.1.4")},
		})
		assert.Equal(t, []any{"10.0.1.4"}, res)
	})

	t.Run("every address of a multi-target volume is reported", func(t *testing.T) {
		res := netAppMountTargetIps([]*armnetapp.MountTargetProperties{
			{IPAddress: str("10.0.1.4")},
			{IPAddress: str("10.0.2.4")},
		})
		assert.Equal(t, []any{"10.0.1.4", "10.0.2.4"}, res)
	})
}

// The regression this guards: the rule index builds the cache id. Two rules
// that both came back without one would land on the same id, and the runtime
// would serve the first rule's data for both -- so a volume with a permissive
// rule and a restrictive one could read as two copies of whichever came first.
func TestNetAppExportPolicyRuleKey(t *testing.T) {
	idx := func(i int32) *int32 { return &i }

	t.Run("the rule index is the key when the API supplies one", func(t *testing.T) {
		assert.Equal(t, "1", netAppExportPolicyRuleKey(&armnetapp.ExportPolicyRule{RuleIndex: idx(1)}, 0))
		assert.Equal(t, "7", netAppExportPolicyRuleKey(&armnetapp.ExportPolicyRule{RuleIndex: idx(7)}, 3))
	})

	// Index 0 is a real index, not an absent one, so it must not be confused
	// with the fallback.
	t.Run("index zero is an index", func(t *testing.T) {
		assert.Equal(t, "0", netAppExportPolicyRuleKey(&armnetapp.ExportPolicyRule{RuleIndex: idx(0)}, 5))
	})

	t.Run("rules with no index keep distinct keys", func(t *testing.T) {
		first := netAppExportPolicyRuleKey(&armnetapp.ExportPolicyRule{}, 0)
		second := netAppExportPolicyRuleKey(&armnetapp.ExportPolicyRule{}, 1)
		assert.NotEqual(t, first, second)
	})

	// The fallback is prefixed so a positional key can never collide with a
	// real index from a sibling rule.
	t.Run("a positional key cannot collide with a real index", func(t *testing.T) {
		positional := netAppExportPolicyRuleKey(&armnetapp.ExportPolicyRule{}, 2)
		indexed := netAppExportPolicyRuleKey(&armnetapp.ExportPolicyRule{RuleIndex: idx(2)}, 9)
		assert.NotEqual(t, positional, indexed)
	})

	t.Run("a nil rule falls back rather than panicking", func(t *testing.T) {
		assert.NotEmpty(t, netAppExportPolicyRuleKey(nil, 4))
	})
}
