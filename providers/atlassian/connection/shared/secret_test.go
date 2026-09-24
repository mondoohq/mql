// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestSecret(t *testing.T) {
	const (
		option = "admin-token"
		envVar = "TEST_ATLASSIAN_ADMIN_TOKEN"
	)

	password := func(secret string) *vault.Credential {
		return &vault.Credential{Type: vault.CredentialType_password, Secret: []byte(secret)}
	}

	t.Run("reads a vault credential", func(t *testing.T) {
		// The hosted path: the runner resolves the vault reference and the token
		// never appears in the job's options.
		conf := &inventory.Config{Credentials: []*vault.Credential{password("from-vault")}}
		assert.Equal(t, "from-vault", Secret(conf, option, envVar))
	})

	t.Run("prefers the vault credential over the option", func(t *testing.T) {
		// An option travels in the job payload and is logged wherever options
		// are; a hosted scan has no reason to use one. When both are present the
		// credential is the one that was meant.
		conf := &inventory.Config{
			Options:     map[string]string{option: "from-option"},
			Credentials: []*vault.Credential{password("from-vault")},
		}
		assert.Equal(t, "from-vault", Secret(conf, option, envVar))
	})

	t.Run("reads the Password field when Secret is empty", func(t *testing.T) {
		// Both shapes reach providers. Reading only one is how a credential that
		// resolved fine looks empty.
		conf := &inventory.Config{Credentials: []*vault.Credential{
			{Type: vault.CredentialType_password, Password: "from-password-field"},
		}}
		assert.Equal(t, "from-password-field", Secret(conf, option, envVar))
	})

	t.Run("falls through to the option", func(t *testing.T) {
		conf := &inventory.Config{Options: map[string]string{option: "from-option"}}
		assert.Equal(t, "from-option", Secret(conf, option, envVar))
	})

	t.Run("falls through to the environment", func(t *testing.T) {
		t.Setenv(envVar, "from-env")
		assert.Equal(t, "from-env", Secret(&inventory.Config{}, option, envVar))
	})

	t.Run("skips a credential of the wrong type", func(t *testing.T) {
		// A private key handed to an Atlassian connection is a misconfiguration.
		// Skipping it rather than returning its bytes is what lets the option or
		// env still work, and the warning is what makes the mistake visible.
		conf := &inventory.Config{
			Options: map[string]string{option: "from-option"},
			Credentials: []*vault.Credential{
				{Type: vault.CredentialType_private_key, Secret: []byte("a-key")},
			},
		}
		assert.Equal(t, "from-option", Secret(conf, option, envVar))
	})

	t.Run("skips an empty credential rather than returning blank", func(t *testing.T) {
		conf := &inventory.Config{
			Options:     map[string]string{option: "from-option"},
			Credentials: []*vault.Credential{password("")},
		}
		assert.Equal(t, "from-option", Secret(conf, option, envVar))
	})

	t.Run("returns empty when nothing supplies it", func(t *testing.T) {
		assert.Empty(t, Secret(&inventory.Config{}, option, envVar))
	})

	t.Run("tolerates a nil config", func(t *testing.T) {
		t.Setenv(envVar, "from-env")
		assert.Equal(t, "from-env", Secret(nil, option, envVar))
	})
}
