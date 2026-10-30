// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package credentials_resolver

import (
	"context"
	"errors"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers-sdk/v1/vault/cache"
)

type resolver struct {
	vault vault.Vault
}

// New creates a new credentials resolver. The resolver allows for caching already resolved credentials
// in memory such that they are not retrieved from vault again.
func New(v vault.Vault, enableCaching bool) vault.Resolver {
	if enableCaching {
		return &resolver{vault: cache.New(v)}
	}
	return &resolver{vault: v}
}

// GetCredential retrieves the credential from vault via the secret id
func (c *resolver) GetCredential(cred *vault.Credential) (*vault.Credential, error) {
	if cred == nil {
		return nil, errors.New("cannot find credential with empty input")
	}

	info, _ := c.vault.About(context.Background(), &vault.Empty{})
	var name string
	if info != nil {
		name = info.Name
	}
	log.Debug().Str("secret-id", cred.SecretId).Str("vault", name).Msg("fetch secret from vault")
	// TODO: do we need to provide the encoding from outside or inside?
	secret, err := c.vault.Get(context.Background(), &vault.SecretID{
		Key: cred.SecretId,
	})
	if err != nil {
		return nil, err
	}

	retrievedCred, err := secret.Credential()
	if err != nil {
		return nil, err
	}

	// merge creds since user can provide additional credential_type, user
	if cred.User != "" {
		retrievedCred.User = cred.User
	}

	if cred.Type != vault.CredentialType_undefined {
		retrievedCred.Type = cred.Type
	}

	return retrievedCred, nil
}
