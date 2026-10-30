// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
)

// Builder constructs a Vault from its configuration. Vault implementations
// register a Builder for the VaultType(s) they support via Register, typically
// from an init() function. This keeps the heavy implementation dependencies
// (cloud SDKs, keyring libraries, ...) out of this package and lets binaries
// opt into the backends they need by blank-importing the implementation.
type Builder func(cfg *VaultConfiguration) (Vault, error)

var (
	registryMu sync.RWMutex
	registry   = map[VaultType]Builder{}
)

// Register associates a Builder with a VaultType. It panics if the same
// VaultType is registered twice, mirroring the builtin-provider registration
// pattern. Call it from an implementation's init() function.
func Register(t VaultType, b Builder) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if _, exists := registry[t]; exists {
		panic("vault: Register called twice for vault type " + t.String())
	}
	registry[t] = b
}

// New instantiates a vault from the given configuration by looking up the
// registered Builder for the configured VaultType. The implementation must be
// linked into the binary (e.g. via go.mondoo.com/mql/vault/register or an
// individual implementation package) for its type to be available.
func New(cfg *VaultConfiguration) (Vault, error) {
	if cfg == nil {
		return nil, errors.New("vault configuration cannot be empty")
	}
	log.Debug().Str("vault-name", cfg.Name).Str("vault-type", cfg.Type.String()).Msg("initialize new vault")

	registryMu.RLock()
	b, ok := registry[cfg.Type]
	registryMu.RUnlock()
	if !ok {
		return nil, errors.Errorf("could not connect to vault: %s (%s)", cfg.Name, cfg.Type.String())
	}
	return b(cfg)
}
