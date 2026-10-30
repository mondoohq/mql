// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package keyring

import (
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func init() {
	vault.Register(vault.VaultType_KeyRing, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		return New(cfg.Name), nil
	})
	vault.Register(vault.VaultType_EncryptedFile, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		return NewEncryptedFile(cfg.Options["path"], cfg.Name, cfg.Options["password"]), nil
	})
	vault.Register(vault.VaultType_LinuxKernelKeyring, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		return NewLinuxKernelKeyring(cfg.Name), nil
	})
}
