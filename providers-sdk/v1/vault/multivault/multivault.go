// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package multivault

import (
	"context"
	"errors"

	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/ranger-rpc/codes"
	"go.mondoo.com/ranger-rpc/status"
)

// New creates a new vault that can query multiple vaults. It is a
// read-only vault that allows the user to have a unified view for secrets
// located in e.g. and inmemory vault and in e.g. a keyring vault. The order
// matters. When a secret is requested, this implementation iterates over
// each vault and returns the first secret with the requested id
func New(vaults ...vault.Vault) *multiVault {
	return &multiVault{
		vaults: vaults,
	}
}

type multiVault struct {
	vaults []vault.Vault
}

func (v *multiVault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "Multi Vault"}, nil
}

func (m *multiVault) Set(ctx context.Context, secret *vault.Secret) (*vault.SecretID, error) {
	return nil, errors.New("this vault is read only")
}

func (m *multiVault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	if id == nil {
		return nil, errors.New("secret id is empty")
	}

	// iterate over each vault and return the first finding
	for i := range m.vaults {
		v := m.vaults[i]
		secret, err := v.Get(ctx, id)
		se, _ := status.FromError(err)
		// move to next vault if we could not find the secret
		if se != nil && se.Code() == codes.NotFound {
			continue
		} else if se != nil {
			return nil, err
		}
		return secret, nil
	}

	return nil, vault.NotFoundError
}

func (m *multiVault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	return nil, vault.NotImplementedError
}
