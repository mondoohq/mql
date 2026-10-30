// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsKeyRotateAction(t *testing.T) {
	action := func(t string) *azkeys.LifetimeActionType {
		v := azkeys.KeyRotationPolicyAction(t)
		return &azkeys.LifetimeActionType{Type: &v}
	}

	// nil wrapper -> false (guards a nil action.Action)
	assert.False(t, isKeyRotateAction(nil))
	// non-nil wrapper with a nil Type -> false
	assert.False(t, isKeyRotateAction(&azkeys.LifetimeActionType{}))
	// exact "Rotate" -> true
	assert.True(t, isKeyRotateAction(action("Rotate")))
	// different casing -> true (the SDK compares case-insensitively)
	assert.True(t, isKeyRotateAction(action("rotate")))
	// other action ("Notify") -> false
	assert.False(t, isKeyRotateAction(action("Notify")))
}

type azureIdTestCase struct {
	url      string
	expected keyvaultid
}

func TestAzureKeyvaultIdParser(t *testing.T) {
	testCases := []azureIdTestCase{
		{
			url: "https://superdupertestkey.vault.azure.net/certificates/testcertificate",
			expected: keyvaultid{
				BaseUrl: "https://superdupertestkey.vault.azure.net",
				Vault:   "superdupertestkey",
				Type:    "certificates",
				Name:    "testcertificate",
			},
		},
		{
			url: "https://superdupertestkey.vault.azure.net/certificates/testcertificate/c2fcb0ffb06d4cfead8240b4a06b7c63",
			expected: keyvaultid{
				BaseUrl: "https://superdupertestkey.vault.azure.net",
				Vault:   "superdupertestkey",
				Type:    "certificates",
				Name:    "testcertificate",
				Version: "c2fcb0ffb06d4cfead8240b4a06b7c63",
			},
		},
		{
			url: "https://superdupertestkey.vault.azure.net/secrets/testcertificate",
			expected: keyvaultid{
				BaseUrl: "https://superdupertestkey.vault.azure.net",
				Vault:   "superdupertestkey",
				Type:    "secrets",
				Name:    "testcertificate",
			},
		},
		{
			url: "https://superdupertestkey.vault.azure.net/secrets/Test",
			expected: keyvaultid{
				BaseUrl: "https://superdupertestkey.vault.azure.net",
				Vault:   "superdupertestkey",
				Type:    "secrets",
				Name:    "Test",
			},
		},
		{
			url: "https://superdupertestkey.vault.azure.net/keys/test",
			expected: keyvaultid{
				BaseUrl: "https://superdupertestkey.vault.azure.net",
				Vault:   "superdupertestkey",
				Type:    "keys",
				Name:    "test",
			},
		},
		{
			// Managed HSM key ID: the host is <name>.managedhsm.azure.net,
			// not <name>.vault.azure.net. The regex must accept it so the
			// reused key resource can resolve kty/keySize/curve for HSM keys.
			url: "https://myhsm.managedhsm.azure.net/keys/hsmkey",
			expected: keyvaultid{
				BaseUrl: "https://myhsm.managedhsm.azure.net",
				Vault:   "myhsm",
				Type:    "keys",
				Name:    "hsmkey",
			},
		},
		{
			url: "https://myhsm.managedhsm.azure.net/keys/hsmkey/9a8b7c6d5e4f",
			expected: keyvaultid{
				BaseUrl: "https://myhsm.managedhsm.azure.net",
				Vault:   "myhsm",
				Type:    "keys",
				Name:    "hsmkey",
				Version: "9a8b7c6d5e4f",
			},
		},
	}

	for i := range testCases {
		val, err := parseKeyVaultId(testCases[i].url)
		require.NoError(t, err, testCases[i].url)
		assert.Equal(t, testCases[i].expected, *val)
	}
}
