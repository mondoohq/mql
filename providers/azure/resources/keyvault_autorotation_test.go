// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

// TestKeyVaultAutorotationDoesNotAliasAcrossVaults pins the defect directly: the
// rotation resource derived its cache key by parsing the key identifier and
// returning the bare key name, so a key called "cmk" in a production vault and a
// key called "cmk" in a staging vault were one resource. CreateResource returns
// the cached occupant of a key it has already seen, so the second vault's
// rotation row reported the first vault's answer -- a vault with rotation
// switched off reading "enabled: true".
//
// The list length stayed right and every row looked plausible, which is why this
// had to be pinned through the runtime cache rather than by comparing ids.
func TestKeyVaultAutorotationDoesNotAliasAcrossVaults(t *testing.T) {
	runtime := cacheIDTestRuntime()
	mk := func(kid string, enabled bool) *mqlAzureSubscriptionKeyVaultServiceKeyAutorotation {
		r, err := CreateResource(runtime, "azure.subscription.keyVaultService.key.autorotation",
			map[string]*llx.RawData{
				"kid":     llx.StringData(kid),
				"enabled": llx.BoolData(enabled),
			})
		require.NoError(t, err)
		return r.(*mqlAzureSubscriptionKeyVaultServiceKeyAutorotation)
	}

	rotating := mk("https://vault-prod.vault.azure.net/keys/cmk", true)
	notRotating := mk("https://vault-staging.vault.azure.net/keys/cmk", false)

	assert.NotEqual(t, rotating.MqlID(), notRotating.MqlID(),
		"the same key name in two vaults must not share a cache key")
	// The failure this guards: the unrotated key reporting the rotated key's answer.
	assert.False(t, notRotating.Enabled.Data)
	assert.True(t, rotating.Enabled.Data)

	// The name alone is what collided, so keep that visible -- it is the thing a
	// future refactor would be tempted to go back to.
	prod, err := parseKeyVaultId(rotating.Kid.Data)
	require.NoError(t, err)
	staging, err := parseKeyVaultId(notRotating.Kid.Data)
	require.NoError(t, err)
	require.Equal(t, prod.Name, staging.Name, "both keys are named cmk")
	assert.NotEqual(t, prod.Vault, staging.Vault, "only the vault tells them apart")
}

// Two keys in one vault were already distinct, and must stay so.
func TestKeyVaultAutorotationSeparatesKeysInOneVault(t *testing.T) {
	runtime := cacheIDTestRuntime()
	mk := func(kid string, enabled bool) *mqlAzureSubscriptionKeyVaultServiceKeyAutorotation {
		r, err := CreateResource(runtime, "azure.subscription.keyVaultService.key.autorotation",
			map[string]*llx.RawData{"kid": llx.StringData(kid), "enabled": llx.BoolData(enabled)})
		require.NoError(t, err)
		return r.(*mqlAzureSubscriptionKeyVaultServiceKeyAutorotation)
	}

	a := mk("https://vault.vault.azure.net/keys/signing", true)
	b := mk("https://vault.vault.azure.net/keys/encryption", false)
	assert.NotEqual(t, a.MqlID(), b.MqlID())
	assert.True(t, a.Enabled.Data)
	assert.False(t, b.Enabled.Data)
}

// The old id() returned parseKeyVaultId's error, which failed the whole resource
// rather than one field. A managed HSM identifier, or anything else the regex
// does not recognize, must still produce a row.
func TestKeyVaultAutorotationIDDoesNotDependOnParsing(t *testing.T) {
	runtime := cacheIDTestRuntime()
	for _, kid := range []string{
		"https://myhsm.managedhsm.azure.net/keys/cmk",
		"not-a-key-vault-identifier",
	} {
		r, err := CreateResource(runtime, "azure.subscription.keyVaultService.key.autorotation",
			map[string]*llx.RawData{"kid": llx.StringData(kid), "enabled": llx.BoolData(false)})
		require.NoError(t, err, "an unparseable identifier must not fail the resource: %q", kid)
		assert.Equal(t, kid, r.(*mqlAzureSubscriptionKeyVaultServiceKeyAutorotation).MqlID())
	}
}
