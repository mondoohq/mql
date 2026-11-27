// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	apps "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v5"
	"github.com/stretchr/testify/assert"
)

func TestImagePinnedByDigest(t *testing.T) {
	tag := "myacr.azurecr.io/api:1.2.3"
	digest := "myacr.azurecr.io/api@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	tagPlusDigest := "myacr.azurecr.io/api:1.2.3@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	empty := ""

	tests := []struct {
		name string
		in   *string
		want bool
	}{
		{"nil image", nil, false},
		{"empty string", &empty, false},
		{"tag-only reference", &tag, false},
		{"digest reference", &digest, true},
		{"tag plus digest", &tagPlusDigest, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, imagePinnedByDigest(tc.in))
		})
	}
}

func TestResourceGroupAndName(t *testing.T) {
	tests := []struct {
		name     string
		id       string
		leafKey  string
		wantRG   string
		wantLeaf string
	}{
		{
			name:     "managed environment",
			id:       "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.App/managedEnvironments/my-env",
			leafKey:  "managedEnvironments",
			wantRG:   "my-rg",
			wantLeaf: "my-env",
		},
		{
			name:     "container app",
			id:       "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.App/containerApps/my-app",
			leafKey:  "containerApps",
			wantRG:   "my-rg",
			wantLeaf: "my-app",
		},
		{
			name:     "leaf key absent from id",
			id:       "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/my-rg/providers/Microsoft.App/managedEnvironments/my-env",
			leafKey:  "containerApps",
			wantRG:   "my-rg",
			wantLeaf: "",
		},
		{
			name:     "case-insensitive resource group key",
			id:       "/subscriptions/00000000-0000-0000-0000-000000000000/resourcegroups/My-RG/providers/Microsoft.App/managedEnvironments/My-Env",
			leafKey:  "managedEnvironments",
			wantRG:   "My-RG",
			wantLeaf: "My-Env",
		},
		{
			name:     "malformed id",
			id:       "not-an-arm-id",
			leafKey:  "managedEnvironments",
			wantRG:   "",
			wantLeaf: "",
		},
		{
			name:     "empty id",
			id:       "",
			leafKey:  "managedEnvironments",
			wantRG:   "",
			wantLeaf: "",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rg, leaf := resourceGroupAndName(tc.id, tc.leafKey)
			assert.Equal(t, tc.wantRG, rg)
			assert.Equal(t, tc.wantLeaf, leaf)
		})
	}
}

func TestAcaSecretSourceOf(t *testing.T) {
	// Synthetic: a stored secret, a Key Vault reference read with the
	// system-assigned identity, and one read with a user-assigned identity.
	assert.Equal(t, acaSecretSource{}, acaSecretSourceOf(nil))
	stored := acaSecretSourceOf(&apps.Secret{Name: ptr("db-password")})
	assert.Empty(t, stored.keyVaultURL)
	assert.Empty(t, stored.identity)
	kvURL := "https://kv1.vault.azure.net/secrets/db-password"
	sys := acaSecretSourceOf(&apps.Secret{Name: ptr("db-password"), KeyVaultURL: &kvURL, Identity: ptr("system")})
	assert.Equal(t, kvURL, sys.keyVaultURL)
	assert.Equal(t, "system", sys.identity)
	uami := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/app"
	user := acaSecretSourceOf(&apps.Secret{Name: ptr("db-password"), KeyVaultURL: &kvURL, Identity: &uami})
	assert.Equal(t, uami, user.identity)
}

func TestAcaEnvironmentIDFromCertificateID(t *testing.T) {
	// Synthetic: ARM ID shapes of an environment certificate and a managed
	// certificate.
	env := "/subscriptions/s/resourceGroups/rg/providers/Microsoft.App/managedEnvironments/env1"
	assert.Equal(t, env, acaEnvironmentIDFromCertificateID(env+"/certificates/cert1"))
	assert.Empty(t, acaEnvironmentIDFromCertificateID(env+"/managedCertificates/mc1"))
	assert.Empty(t, acaEnvironmentIDFromCertificateID("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Web/certificates/c"))
	assert.Empty(t, acaEnvironmentIDFromCertificateID(""))
}
