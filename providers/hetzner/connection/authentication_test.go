// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestGetToken(t *testing.T) {
	t.Run("returns false when nothing is set", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "")
		conf := &inventory.Config{Options: map[string]string{}}
		got, ok := GetToken(conf)
		assert.False(t, ok)
		assert.Empty(t, got)
	})

	t.Run("falls back to env var", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "from-env")
		conf := &inventory.Config{Options: map[string]string{}}
		got, ok := GetToken(conf)
		assert.True(t, ok)
		assert.Equal(t, "from-env", got)
	})

	t.Run("flag option overrides env var", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "from-env")
		conf := &inventory.Config{Options: map[string]string{OPTION_TOKEN: "from-flag"}}
		got, ok := GetToken(conf)
		assert.True(t, ok)
		assert.Equal(t, "from-flag", got)
	})

	t.Run("password credential overrides env and flag", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "from-env")
		conf := &inventory.Config{
			Options:     map[string]string{OPTION_TOKEN: "from-flag"},
			Credentials: []*vault.Credential{vault.NewPasswordCredential("", "from-cred")},
		}
		got, ok := GetToken(conf)
		assert.True(t, ok)
		assert.Equal(t, "from-cred", got)
	})

	t.Run("empty option value falls through to env", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "from-env")
		conf := &inventory.Config{Options: map[string]string{OPTION_TOKEN: ""}}
		got, ok := GetToken(conf)
		assert.True(t, ok)
		assert.Equal(t, "from-env", got)
	})

	t.Run("unsupported credential type is ignored", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "from-env")
		conf := &inventory.Config{
			Options: map[string]string{},
			Credentials: []*vault.Credential{
				{Type: vault.CredentialType_private_key, Secret: []byte("nope")},
			},
		}
		got, ok := GetToken(conf)
		assert.True(t, ok)
		assert.Equal(t, "from-env", got)
	})

	t.Run("empty credential secret is skipped", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "from-env")
		conf := &inventory.Config{
			Options: map[string]string{},
			Credentials: []*vault.Credential{
				{Type: vault.CredentialType_password, Secret: nil},
			},
		}
		got, ok := GetToken(conf)
		assert.True(t, ok)
		assert.Equal(t, "from-env", got)
	})

	t.Run("later credential wins over earlier", func(t *testing.T) {
		t.Setenv(HCLOUD_TOKEN_VAR, "")
		conf := &inventory.Config{
			Options: map[string]string{},
			Credentials: []*vault.Credential{
				vault.NewPasswordCredential("", "first"),
				vault.NewPasswordCredential("", "second"),
			},
		}
		got, ok := GetToken(conf)
		require.True(t, ok)
		assert.Equal(t, "second", got)
	})
}

func TestGetEndpoint(t *testing.T) {
	t.Run("returns false when nothing is set", func(t *testing.T) {
		t.Setenv(HCLOUD_ENDPOINT_VAR, "")
		conf := &inventory.Config{Options: map[string]string{}}
		got, ok := GetEndpoint(conf)
		assert.False(t, ok)
		assert.Empty(t, got)
	})

	t.Run("env value", func(t *testing.T) {
		t.Setenv(HCLOUD_ENDPOINT_VAR, "https://api.example/")
		conf := &inventory.Config{Options: map[string]string{}}
		got, ok := GetEndpoint(conf)
		assert.True(t, ok)
		assert.Equal(t, "https://api.example/", got)
	})

	t.Run("flag option overrides env", func(t *testing.T) {
		t.Setenv(HCLOUD_ENDPOINT_VAR, "https://api.example/")
		conf := &inventory.Config{Options: map[string]string{OPTION_ENDPOINT: "https://override/"}}
		got, ok := GetEndpoint(conf)
		assert.True(t, ok)
		assert.Equal(t, "https://override/", got)
	})
}
