// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func expectedAccountID(apiKey string) string {
	sum := sha256.Sum256([]byte(apiKey))
	return hex.EncodeToString(sum[:])[:16]
}

func TestNewNextdnsConnection_AccountIDDerivation(t *testing.T) {
	// Ensure the environment never leaks a real key into the config-credential cases.
	t.Setenv("NEXTDNS_API_KEY", "")

	t.Run("account id is the truncated sha256 fingerprint of the key", func(t *testing.T) {
		conf := &inventory.Config{
			Credentials: []*vault.Credential{vault.NewPasswordCredential("", "secret-key")},
		}
		conn, err := NewNextdnsConnection(1, &inventory.Asset{}, conf)
		require.NoError(t, err)

		id := conn.AccountID()
		assert.Len(t, id, 16)
		assert.Equal(t, expectedAccountID("secret-key"), id)
	})

	t.Run("id is deterministic and distinct per key", func(t *testing.T) {
		mk := func(key string) string {
			conf := &inventory.Config{
				Credentials: []*vault.Credential{vault.NewPasswordCredential("", key)},
			}
			conn, err := NewNextdnsConnection(1, &inventory.Asset{}, conf)
			require.NoError(t, err)
			return conn.AccountID()
		}

		assert.Equal(t, mk("key-a"), mk("key-a"), "same key must yield the same account id")
		assert.NotEqual(t, mk("key-a"), mk("key-b"), "different keys must yield different account ids")
	})

	t.Run("config credential is preferred over the environment", func(t *testing.T) {
		t.Setenv("NEXTDNS_API_KEY", "env-key")
		conf := &inventory.Config{
			Credentials: []*vault.Credential{vault.NewPasswordCredential("", "config-key")},
		}
		conn, err := NewNextdnsConnection(1, &inventory.Asset{}, conf)
		require.NoError(t, err)
		assert.Equal(t, expectedAccountID("config-key"), conn.AccountID())
	})

	t.Run("falls back to the environment when no config credential is present", func(t *testing.T) {
		t.Setenv("NEXTDNS_API_KEY", "env-key")
		conn, err := NewNextdnsConnection(1, &inventory.Asset{}, &inventory.Config{})
		require.NoError(t, err)
		assert.Equal(t, expectedAccountID("env-key"), conn.AccountID())
	})

	t.Run("errors when no key is available anywhere", func(t *testing.T) {
		t.Setenv("NEXTDNS_API_KEY", "")
		_, err := NewNextdnsConnection(1, &inventory.Asset{}, &inventory.Config{})
		require.Error(t, err)
	})
}

func TestNextdnsConnection_ProfileID(t *testing.T) {
	t.Setenv("NEXTDNS_API_KEY", "some-key")

	t.Run("empty when the connection is account-scoped", func(t *testing.T) {
		conn, err := NewNextdnsConnection(1, &inventory.Asset{}, &inventory.Config{})
		require.NoError(t, err)
		assert.Equal(t, "", conn.ProfileID())
	})

	t.Run("returns the scoped profile option", func(t *testing.T) {
		conf := &inventory.Config{Options: map[string]string{OptionProfile: "abc123"}}
		conn, err := NewNextdnsConnection(1, &inventory.Asset{}, conf)
		require.NoError(t, err)
		assert.Equal(t, "abc123", conn.ProfileID())
	})
}
