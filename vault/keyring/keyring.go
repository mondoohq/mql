// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package keyring

import (
	"context"
	"errors"

	"github.com/99designs/keyring"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func New(serviceName string) *Vault {
	return &Vault{
		ServiceName: serviceName,
		fileDir:     "~/.mondoo/",
		filePasswordFunc: func(s string) (string, error) {
			// TODO: this only applies to cases where we have no real keychain available
			return "", errors.New("file-fallback is not supported")
		},
		// by default we do not allow a fallback to encrypted keys
		allowedBackends: []keyring.BackendType{
			// Windows
			keyring.WinCredBackend,
			// macOS
			keyring.KeychainBackend,
			// Linux
			keyring.SecretServiceBackend,
			keyring.KWalletBackend,
			// General
			keyring.PassBackend,
		},
	}
}

func NewEncryptedFile(path string, serviceName string, password string) *Vault {
	return &Vault{
		ServiceName: serviceName,
		fileDir:     path,
		filePasswordFunc: func(s string) (string, error) {
			return password, nil
		},
		allowedBackends: []keyring.BackendType{
			keyring.FileBackend,
		},
	}
}

func NewLinuxKernelKeyring(serviceName string) *Vault {
	return &Vault{
		ServiceName: serviceName,
		allowedBackends: []keyring.BackendType{
			keyring.KeyCtlBackend,
		},
		keyctlscope: "user",
	}
}

type Vault struct {
	ServiceName      string
	allowedBackends  []keyring.BackendType
	fileDir          string
	filePasswordFunc func(s string) (string, error)
	keyctlscope      string
}

func (v *Vault) About(context.Context, *vault.Empty) (*vault.VaultInfo, error) {
	return &vault.VaultInfo{Name: "Keyring Vault: " + v.ServiceName}, nil
}

func (v *Vault) open() (keyring.Keyring, error) {
	return keyring.Open(keyring.Config{
		ServiceName:      v.ServiceName,
		AllowedBackends:  v.allowedBackends,
		FileDir:          v.fileDir,
		FilePasswordFunc: v.filePasswordFunc,
		KeyCtlScope:      v.keyctlscope,
	})
}

func (v *Vault) Set(ctx context.Context, cred *vault.Secret) (*vault.SecretID, error) {
	ring, err := v.open()
	if err != nil {
		return nil, err
	}

	if cred.Encoding != vault.SecretEncoding_encoding_json && cred.Encoding != vault.SecretEncoding_encoding_undefined {
		return nil, errors.New("only json encoding is supported")
	}

	// TODO: store data as json encoding
	err = ring.Set(keyring.Item{
		Key:   cred.Key,
		Label: cred.Label,
		Data:  cred.Data,
	})

	return &vault.SecretID{
		Key: cred.Key,
	}, err
}

func (v *Vault) Get(ctx context.Context, id *vault.SecretID) (*vault.Secret, error) {
	if id == nil {
		return nil, errors.New("id cannot be nil")
	}
	log.Debug().Str("id", id.Key).Msg("get secret from keyring")
	ring, err := v.open()
	if err != nil {
		return nil, err
	}

	i, err := ring.Get(id.Key)
	if err != nil {
		log.Debug().Err(err).Msg("could not retrieve secret from keyring")
		return nil, vault.NotFoundError
	}

	return &vault.Secret{
		Key:      i.Key,
		Label:    i.Label,
		Data:     i.Data,
		Encoding: vault.SecretEncoding_encoding_json,
	}, nil
}

func (v *Vault) Delete(ctx context.Context, id *vault.SecretID) (*vault.Empty, error) {
	return nil, vault.NotImplementedError
}
