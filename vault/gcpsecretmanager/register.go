// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package gcpsecretmanager

import (
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func init() {
	vault.Register(vault.VaultType_GCPSecretsManager, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		return New(cfg.Options["project-id"]), nil
	})
}
