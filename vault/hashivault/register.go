// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hashivault

import (
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func init() {
	vault.Register(vault.VaultType_HashiCorp, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		return New(
			cfg.Options["url"],
			cfg.Options["token"],
			// Empty is ignored, so an unset "mount" keeps the default.
			WithMount(cfg.Options["mount"]),
		), nil
	})
}
