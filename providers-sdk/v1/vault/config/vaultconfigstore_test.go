// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestVaultConfiguration(t *testing.T) {
	vCfgs := ClientVaultConfig{}

	vCfgs.Set("vault1cfg-key", vault.VaultConfiguration{
		Name: "vault1cfg-name",
	})

	cfg, err := vCfgs.Get("vault1cfg-key")
	require.NoError(t, err)
	assert.Equal(t, "vault1cfg-name", cfg.Name)

	vCfgs.Set("vault1cfg-key", vault.VaultConfiguration{
		Name: "vault1cfg-name2",
	})

	cfg, err = vCfgs.Get("vault1cfg-key")
	require.NoError(t, err)
	assert.Equal(t, "vault1cfg-name2", cfg.Name)

	s := &vault.Secret{
		Key:  "test",
		Data: vCfgs.SecretData(),
	}

	vCfgs2, err := NewClientVaultConfig(s)
	require.NoError(t, err)

	cfg, err = vCfgs2.Get("vault1cfg-key")
	require.NoError(t, err)
	assert.Equal(t, "vault1cfg-name2", cfg.Name)
}
