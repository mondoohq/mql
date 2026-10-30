// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inmemory

import (
	"context"
	"errors"

	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func init() {
	vault.Register(vault.VaultType_Memory, func(cfg *vault.VaultConfiguration) (vault.Vault, error) {
		return New(), nil
	})
}

type Option func(*inmemoryVault)

func WithSecretMap(secrets map[string]*vault.Secret) Option {
	return func(iv *inmemoryVault) {
		iv.secrets = secrets
	}
}

func New(opts ...Option) *inmemoryVault {
	iv := &inmemoryVault{
		secrets: map[string]*vault.Secret{},
	}

	for _, option := range opts {
		option(iv)
	}

	return iv
}

type inmemoryVault struct {
	secrets map[string]*vault.Secret
}

func (v *inmemoryVault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "In-Memory Vault"}, nil
}

func (v *inmemoryVault) Set(ctx context.Context, secret *vault.Secret) (*vault.SecretID, error) {
	if secret == nil {
		return nil, errors.New("secret is empty")
	}

	v.secrets[secret.Key] = secret
	return &vault.SecretID{
		Key: secret.Key,
	}, nil
}

func (v *inmemoryVault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	if id == nil {
		return nil, errors.New("secret id is empty")
	}

	s, ok := v.secrets[id.Key]
	if !ok {
		return nil, vault.NotFoundError
	}
	return s, nil
}

func (v *inmemoryVault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	if id == nil {
		return nil, errors.New("secret id is empty")
	}

	if _, ok := v.secrets[id.Key]; !ok {
		return nil, vault.NotFoundError
	}
	delete(v.secrets, id.Key)
	return &vault.Empty{}, nil
}
