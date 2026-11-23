// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// decodeSecretSummary runs a ListSecrets item through the SDK's own decoder,
// which is what turns the polymorphic generation context into a concrete type.
func decodeSecretSummary(t *testing.T, body string) vault.SecretSummary {
	t.Helper()
	var s vault.SecretSummary
	require.NoError(t, json.Unmarshal([]byte(body), &s))
	return s
}

func TestOciReadSecretGeneration(t *testing.T) {
	t.Run("passphrase with length", func(t *testing.T) {
		// Synthetic: passphrase generation context shape from the Vault API reference.
		s := decodeSecretSummary(t, `{"id":"s","secretGenerationContext":{"generationType":"PASSPHRASE","generationTemplate":"SECRETS_DEFAULT_PASSWORD","passphraseLength":32}}`)
		g := ociReadSecretGeneration(s.SecretGenerationContext)
		assert.Equal(t, "PASSPHRASE", g.Type)
		assert.Equal(t, "SECRETS_DEFAULT_PASSWORD", g.Template)
		require.NotNil(t, g.PassphraseLength)
		assert.Equal(t, int64(32), *g.PassphraseLength)
	})

	t.Run("passphrase without length", func(t *testing.T) {
		// Synthetic: a passphrase context that leaves the length to the service default.
		s := decodeSecretSummary(t, `{"id":"s","secretGenerationContext":{"generationType":"PASSPHRASE","generationTemplate":"DBAAS_DEFAULT_PASSWORD"}}`)
		g := ociReadSecretGeneration(s.SecretGenerationContext)
		assert.Equal(t, "PASSPHRASE", g.Type)
		assert.Nil(t, g.PassphraseLength)
	})

	t.Run("ssh key", func(t *testing.T) {
		// Synthetic: SSH key generation context shape from the Vault API reference.
		s := decodeSecretSummary(t, `{"id":"s","secretGenerationContext":{"generationType":"SSH_KEY","generationTemplate":"RSA_4096"}}`)
		g := ociReadSecretGeneration(s.SecretGenerationContext)
		assert.Equal(t, "SSH_KEY", g.Type)
		assert.Equal(t, "RSA_4096", g.Template)
		assert.Nil(t, g.PassphraseLength)
	})

	t.Run("bytes", func(t *testing.T) {
		// Synthetic: bytes generation context shape from the Vault API reference.
		s := decodeSecretSummary(t, `{"id":"s","secretGenerationContext":{"generationType":"BYTES","generationTemplate":"BYTES_512"}}`)
		g := ociReadSecretGeneration(s.SecretGenerationContext)
		assert.Equal(t, "BYTES", g.Type)
		assert.Equal(t, "BYTES_512", g.Template)
	})

	t.Run("no generation context", func(t *testing.T) {
		// Synthetic: a secret whose content was uploaded rather than generated.
		s := decodeSecretSummary(t, `{"id":"s"}`)
		g := ociReadSecretGeneration(s.SecretGenerationContext)
		assert.Empty(t, g.Type)
		assert.Empty(t, g.Template)
		assert.Nil(t, g.PassphraseLength)
	})
}
