// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// keyVaultKeyURI builds the canonical Key Vault key identifier from the parts
// ARM reports on a resource's customer-managed-key settings.
//
// ARM returns the vault URI WITH a trailing slash
// ("https://myvault.vault.azure.net/"), so appending "/keys/" naively yields a
// doubled separator that parseKeyVaultId's regex rejects -- the key then reads
// as an error on exactly the resources that use a customer-managed key. Trim
// the separator rather than assuming ARM's shape.
//
// Returns "" when either required part is missing, which callers surface as a
// null reference rather than a broken URI.
func keyVaultKeyURI(vaultURI, keyName, keyVersion string) string {
	vaultURI = strings.TrimSuffix(strings.TrimSpace(vaultURI), "/")
	keyName = strings.TrimSpace(keyName)
	if vaultURI == "" || keyName == "" {
		return ""
	}
	uri := vaultURI + "/keys/" + keyName
	if keyVersion = strings.TrimSpace(keyVersion); keyVersion != "" {
		uri += "/" + keyVersion
	}
	return uri
}

// newKeyVaultKeyResource creates a typed azure.subscription.keyVaultService.key
// reference from a Key Vault key URI (e.g. https://myvault.vault.azure.net/keys/mykey/version).
// Returns nil resource if keyURI is empty.
func newKeyVaultKeyResource(runtime *plugin.Runtime, keyURI string) (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if keyURI == "" {
		return nil, nil
	}

	// Use NewResource so that if the key is already cached it gets reused, and
	// so initAzureSubscriptionKeyVaultServiceKey resolves the rest of the key.
	// The KID field is the canonical identifier for key vault keys.
	//
	// managed and tags used to be passed as literals here. Nothing had read
	// them, so a certificate-backed key reported managed: false and every key
	// reached this way reported no tags -- both as fact.
	mqlKey, err := NewResource(runtime, "azure.subscription.keyVaultService.key",
		map[string]*llx.RawData{
			"kid": llx.StringData(keyURI),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAzureSubscriptionKeyVaultServiceKey), nil
}

// newKeyVaultSecretResource creates a typed azure.subscription.keyVaultService.secret
// reference from a Key Vault secret URI (e.g. https://myvault.vault.azure.net/secrets/mysecret/version).
// Returns nil resource if secretURI is empty.
func newKeyVaultSecretResource(runtime *plugin.Runtime, secretURI string) (*mqlAzureSubscriptionKeyVaultServiceSecret, error) {
	if secretURI == "" {
		return nil, nil
	}

	// Use NewResource so that if the secret is already cached it gets reused, and
	// so initAzureSubscriptionKeyVaultServiceSecret resolves the rest of it.
	// The id field (the secret URI) is the canonical identifier for key vault secrets.
	mqlSecret, err := NewResource(runtime, "azure.subscription.keyVaultService.secret",
		map[string]*llx.RawData{
			"id": llx.StringData(secretURI),
		})
	if err != nil {
		return nil, err
	}
	return mqlSecret.(*mqlAzureSubscriptionKeyVaultServiceSecret), nil
}
