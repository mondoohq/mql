// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azsecrets"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

// The key and secret resources reached through a typed encryption-key accessor
// used to be built from the URI alone: enabled, expires, notBefore, created,
// updated and recoveryLevel were left unset (not null), and managed and tags
// were passed as invented literals. An unset field surfaces client-side as
// "primitive with no type information", and under MQL's three-valued logic
// `{ enabled && expires > time.now }` then passes over a key that is disabled or
// already expired. These tests pin both halves: real values when the key reads,
// explicit nulls when it does not.

func TestKeyVaultKeyArgs(t *testing.T) {
	kid := "https://v.vault.azure.net/keys/cmk/abc123"

	t.Run("unreadable key reports null attributes, never unset and never invented", func(t *testing.T) {
		args := keyVaultKeyArgs(kid, nil)

		assert.Equal(t, kid, args["kid"].Value)
		for _, field := range []string{"managed", "tags", "enabled", "created", "updated", "expires", "notBefore", "recoveryLevel"} {
			if assert.Contains(t, args, field, "every declared field must be present so it reads as null rather than unset") {
				assert.Equal(t, llx.NilData, args[field], "%s must be null, not a fabricated value", field)
			}
		}
	})

	t.Run("a managed, expiring key reports its real attributes", func(t *testing.T) {
		expires := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
		enabled := true
		managed := true
		recovery := "Recoverable+Purgeable"
		tagValue := "prod"

		args := keyVaultKeyArgs(kid, &azkeys.KeyBundle{
			Managed: &managed,
			Tags:    map[string]*string{"env": &tagValue},
			Attributes: &azkeys.KeyAttributes{
				Enabled:       &enabled,
				Expires:       &expires,
				RecoveryLevel: &recovery,
			},
		})

		assert.Equal(t, true, args["managed"].Value, "a certificate-backed key used to report managed: false as fact")
		assert.Equal(t, true, args["enabled"].Value)
		assert.Equal(t, "Recoverable+Purgeable", args["recoveryLevel"].Value)
		assert.Equal(t, map[string]any{"env": "prod"}, args["tags"].Value)
		assert.NotEqual(t, llx.NilData, args["expires"])
	})

	t.Run("a key with no attributes block still reports its identity", func(t *testing.T) {
		managed := false
		args := keyVaultKeyArgs(kid, &azkeys.KeyBundle{Managed: &managed})
		assert.Equal(t, false, args["managed"].Value)
		assert.Equal(t, llx.NilData, args["enabled"], "absent attributes are unknown, not false")
	})
}

func TestKeyVaultSecretArgs(t *testing.T) {
	id := "https://v.vault.azure.net/secrets/conn/abc123"

	t.Run("unreadable secret reports null attributes", func(t *testing.T) {
		args := keyVaultSecretArgs(id, nil)

		assert.Equal(t, id, args["id"].Value)
		for _, field := range []string{"tags", "contentType", "managed", "enabled", "created", "updated", "expires", "notBefore"} {
			if assert.Contains(t, args, field) {
				assert.Equal(t, llx.NilData, args[field], "%s must be null, not a fabricated value", field)
			}
		}
	})

	t.Run("a readable secret reports its metadata and never its value", func(t *testing.T) {
		enabled := false
		contentType := "text/plain"
		args := keyVaultSecretArgs(id, &azsecrets.Secret{
			ContentType: &contentType,
			Attributes:  &azsecrets.SecretAttributes{Enabled: &enabled},
		})

		assert.Equal(t, "text/plain", args["contentType"].Value)
		assert.Equal(t, false, args["enabled"].Value)
		assert.NotContains(t, args, "value", "the secret's value must never reach a field")
	})
}
