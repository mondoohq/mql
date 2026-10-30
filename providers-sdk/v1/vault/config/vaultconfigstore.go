// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"encoding/json"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

// ClientVaultConfig is the structured type where we store the client configuration for
// all user configured vaults. We use it to ensure the configuration is stored in structured
// format
type ClientVaultConfig map[string]vault.VaultConfiguration

func NewClientVaultConfig(secret *vault.Secret) (ClientVaultConfig, error) {
	var vCfg ClientVaultConfig
	err := json.Unmarshal(secret.Data, &vCfg)
	if err != nil {
		return nil, errors.Wrap(err, "corrupt vault configuration")
	}
	return vCfg, nil
}

func (avc ClientVaultConfig) Delete(key string) {
	delete(avc, key)
}

func (avc ClientVaultConfig) Set(key string, cfg vault.VaultConfiguration) {
	avc[key] = cfg
}

func (avc ClientVaultConfig) Get(key string) (vault.VaultConfiguration, error) {
	vCfg, ok := avc[key]
	if !ok {
		return vault.VaultConfiguration{}, errors.New("vault not found")
	}
	return vCfg, nil
}

// SecretData returns the marshaled data, it is compatible with vault.New
// In case the data structure cannot be marshalled, the function will panic
func (avc ClientVaultConfig) SecretData() []byte {
	data, err := json.Marshal(avc)
	if err != nil {
		panic(err)
	}
	return data
}
