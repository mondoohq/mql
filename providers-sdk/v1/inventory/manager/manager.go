// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manager

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/logger"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
	"go.mondoo.com/mql/providers-sdk/v1/vault/credentials_resolver"
	"go.mondoo.com/mql/providers-sdk/v1/vault/inmemory"
	"go.mondoo.com/mql/providers-sdk/v1/vault/multivault"
	protobuf "google.golang.org/protobuf/proto"
)

var _ InventoryManager = (*inventoryManager)(nil)

type InventoryManager interface {
	// GetAssets returns all assets under management
	GetAssets() []*inventory.Asset
	// GetRelatedAssets returns a list of assets related to those under management
	GetRelatedAssets() []*inventory.Asset
	// Resolve will iterate over all assets and try to discover all nested assets. After this operation
	// GetAssets will return the fully resolved list of assets
	Resolve(ctx context.Context) map[*inventory.Asset]error
	// GetCredential returns a full credential including the secret from vault
	GetCredential(*vault.Credential) (*vault.Credential, error)
	// QuerySecretId runs the credential query to determine the secret id for an asset, the resulting credential
	// only returns a secret id
	QuerySecretId(a *inventory.Asset) (*vault.Credential, error)
	// GetVault returns the configured Vault
	GetVault() vault.Vault
	GetCredsResolver() vault.Resolver
}

type imOption func(*inventoryManager) error

// passes a pre-parsed asset inventory into the Inventory Manager
func WithInventory(inventory *inventory.Inventory, runtime llx.Runtime) imOption {
	return func(im *inventoryManager) error {
		logger.DebugDumpJSON("inventory-unresolved", inventory)
		return im.loadInventory(inventory, runtime)
	}
}

func WithCredentialQuery(query string, runtime llx.Runtime) imOption {
	return func(im *inventoryManager) error {
		return im.SetCredentialQuery(query, runtime)
	}
}

func WithVault(v vault.Vault) imOption {
	return func(im *inventoryManager) error {
		im.vault = v
		return nil
	}
}

func WithCachedCredsResolver() imOption {
	return func(im *inventoryManager) error {
		im.isCached = true
		return nil
	}
}

func NewManager(opts ...imOption) (*inventoryManager, error) {
	im := &inventoryManager{
		assetList: []*inventory.Asset{},
	}

	for _, option := range opts {
		if err := option(im); err != nil {
			return nil, err
		}
	}
	im.resetVault()

	return im, nil
}

type inventoryManager struct {
	isCached      bool
	assetList     []*inventory.Asset
	relatedAssets []*inventory.Asset
	// optional vault set by user
	vault vault.Vault
	// internal vault used to store embedded credentials
	inmemoryVault vault.Vault
	// wrapper vault to access the credentials
	accessVault           vault.Vault
	credentialQueryRunner *CredentialQueryRunner
}

// TODO: define what happens when we call load multiple times?
func (im *inventoryManager) loadInventory(inventory *inventory.Inventory, runtime llx.Runtime) error {
	err := inventory.PreProcess()
	if err != nil {
		return err
	}

	// all assets are copied
	im.assetList = append(im.assetList, inventory.Spec.Assets...)

	// palace all credentials in an in-memory vault
	secrets := map[string]*vault.Secret{}
	for i := range inventory.Spec.Credentials {
		cred := inventory.Spec.Credentials[i]

		secret, err := vault.NewSecret(cred, vault.SecretEncoding_encoding_proto)
		if err != nil {
			return err
		}

		secrets[secret.Key] = secret
	}

	if inventory.Spec.CredentialQuery != "" {
		err = im.SetCredentialQuery(inventory.Spec.CredentialQuery, runtime)
		if err != nil {
			return err
		}
	}

	// in-memory vault is used as fall-back store embedded credentials
	im.inmemoryVault = inmemory.New(inmemory.WithSecretMap(secrets))
	if inventory.Spec.Vault != nil {
		v, err := inventory.GetVault()
		if err != nil {
			return err
		}
		im.vault = v
	}

	// determine the vault to use for accessing credentials
	im.resetVault()

	return nil
}

func (im *inventoryManager) SetCredentialQuery(query string, runtime llx.Runtime) error {
	qr, err := NewCredentialQueryRunner(query, runtime)
	if err != nil {
		return err
	}
	im.credentialQueryRunner = qr
	return nil
}

func (im *inventoryManager) GetAssets() []*inventory.Asset {
	// TODO: do we need additional work to make this thread-safe
	return im.assetList
}

func (im *inventoryManager) GetRelatedAssets() []*inventory.Asset {
	return im.relatedAssets
}

// QuerySecretId provides an input and determines the credential information for an asset
// The credential will only include the reference to the secret and not include the actual secret
func (im *inventoryManager) QuerySecretId(a *inventory.Asset) (*vault.Credential, error) {
	if im.credentialQueryRunner == nil {
		log.Debug().Msg("no credential query set")
		return nil, nil
	}

	// this is where we get the vault configuration query and evaluate it against the asset data
	// if vault and secret function is set, run the additional handling
	return im.credentialQueryRunner.Run(a)
}

func (im *inventoryManager) Resolve(ctx context.Context) map[*inventory.Asset]error {
	// resolvedAssets := discovery.ResolveAssets(ctx, im.assetList, im.GetCredsResolver(), im.QuerySecretId)
	panic("NEED TO RESOLVE")

	// // TODO: iterate over all resolved assets and match them with the original list and try to find credentials for each asset
	// im.assetList = resolvedAssets.Assets
	// im.relatedAssets = resolvedAssets.RelatedAssets

	// log.Info().Int("resolved-assets", len(im.assetList)).Msg("resolved assets")
	// logger.DebugDumpJSON("inventory-resolved-assets", im.assetList)
	// return resolvedAssets.Errors
	return nil
}

func (im *inventoryManager) ResolveAsset(inventoryAsset *inventory.Asset) (*inventory.Asset, error) {
	creds := im.GetCredsResolver()

	// we clone the asset to make sure we do not modify the original asset
	clonedAsset := protobuf.Clone(inventoryAsset).(*inventory.Asset)

	for j := range clonedAsset.Connections {
		conn := clonedAsset.Connections[j]
		for k := range conn.Credentials {
			credential := conn.Credentials[k]
			if credential.SecretId == "" {
				continue
			}

			resolvedCredential, err := creds.GetCredential(credential)
			if err != nil {
				log.Debug().Str("secret-id", credential.SecretId).Err(err).Msg("could not fetch secret for motor connection")
				return nil, err
			}

			conn.Credentials[k] = resolvedCredential
		}
	}

	return clonedAsset, nil
}

func (im *inventoryManager) GetCredsResolver() vault.Resolver {
	return credentials_resolver.New(im.accessVault, im.isCached)
}

func (im *inventoryManager) GetCredential(cred *vault.Credential) (*vault.Credential, error) {
	return im.GetCredsResolver().GetCredential(cred)
}

func (im *inventoryManager) resetVault() {
	if im.vault != nil && im.inmemoryVault != nil {
		im.accessVault = multivault.New(im.vault, im.inmemoryVault)
	} else if im.vault != nil {
		im.accessVault = im.vault
	} else if im.inmemoryVault != nil {
		im.accessVault = im.inmemoryVault
	} else {
		im.accessVault = nil
	}
}

func (im *inventoryManager) GetVault() vault.Vault {
	return im.accessVault
}
