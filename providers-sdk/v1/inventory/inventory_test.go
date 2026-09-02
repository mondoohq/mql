// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestInventoryParser(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/inventory.yaml")
	require.NoError(t, err)
	require.NotNil(t, inventory)

	assert.Equal(t, "mondoo-inventory", inventory.Metadata.Name)
	assert.Equal(t, "production", inventory.Metadata.Labels["environment"])
	assert.Equal(t, "{ id: 'secret-1' }", inventory.Spec.CredentialQuery)
}

// TestInventoryFromYAMLMarksRequestedNames pins the marker a `name:` in an inventory
// file carries into discovery. Providers name assets themselves during ParseCLI, so
// discovery cannot tell an authored name from a provider default without it.
func TestInventoryFromYAMLMarksRequestedNames(t *testing.T) {
	inv, err := InventoryFromYAML([]byte(`
spec:
  assets:
    - name: my-prod-host
      connections:
        - type: ssh
          host: 10.0.0.1
    - connections:
        - type: ssh
          host: 10.0.0.2
`))
	require.NoError(t, err)
	require.Len(t, inv.Spec.Assets, 2)

	assert.True(t, inv.Spec.Assets[0].NameOverride, "an authored name is a request")
	assert.False(t, inv.Spec.Assets[1].NameOverride, "no name, nothing to honor")
}

func TestPlatformMerge(t *testing.T) {
	base := &Platform{
		Name:                  "linux",
		Arch:                  "",
		Family:                []string{"unix"},
		Metadata:              map[string]string{"env": "prod"},
		TechnologyUrlSegments: []string{"a", "b", "c"},
		Version:               "",
	}

	incoming := &Platform{
		Name:                  "", // Should not override
		Arch:                  "amd64",
		Family:                []string{"gnu"}, // Should override (because of option)
		Metadata:              map[string]string{"region": "us-east-1"},
		TechnologyUrlSegments: []string{"x", "y", "z"},
		Version:               "1.0.0",
	}

	expected := &Platform{
		Name:   "linux",         // original
		Arch:   "amd64",         // merged in
		Family: []string{"gnu"}, // overridden (because we say so)
		Metadata: map[string]string{
			"env":    "prod",
			"region": "us-east-1", // merged map
		},
		Version:               "1.0.0", // merged in
		TechnologyUrlSegments: []string{"x", "y", "z"},
	}

	base.Merge(incoming)

	assert.Equal(t, expected.Name, base.Name)
	assert.Equal(t, expected.Arch, base.Arch)
	assert.Equal(t, expected.Family, base.Family)
	assert.Equal(t, expected.Version, base.Version)
	assert.Equal(t, expected.Metadata["env"], base.Metadata["env"])
	assert.Equal(t, expected.Metadata["region"], base.Metadata["region"])
	assert.Equal(t, expected.TechnologyUrlSegments, base.TechnologyUrlSegments)

	t.Run("cases", func(t *testing.T) {
		p := &Platform{
			Name:                  "terraform-plan",
			Title:                 "Terraform Plan",
			Family:                []string{"terraform"},
			Kind:                  "code",
			Runtime:               "terraform",
			TechnologyUrlSegments: []string{"iac", "terraform", "plan"},
		}

		expectTheSame := &Platform{
			Name:                  "terraform-plan",
			Title:                 "Terraform Plan",
			Family:                []string{"terraform"},
			Kind:                  "code",
			Runtime:               "terraform",
			TechnologyUrlSegments: []string{"iac", "terraform", "plan"},
		}

		t.Run("nil", func(t *testing.T) {
			p.Merge(nil)
			assert.Equal(t, expectTheSame, p)
		})

		t.Run("empty", func(t *testing.T) {
			p.Merge(&Platform{})
			assert.Equal(t, expectTheSame, p)
		})

	})
}

func TestPreprocess(t *testing.T) {
	t.Run("preprocess empty inventory", func(t *testing.T) {
		v1inventory := &Inventory{}
		err := v1inventory.PreProcess()
		require.NoError(t, err)
	})

	t.Run("normal inventory", func(t *testing.T) {
		inventory, err := InventoryFromFile("./testdata/inventory.yaml")
		require.NoError(t, err)

		// extract credentials into credential section
		err = inventory.PreProcess()
		require.NoError(t, err)

		// ensure that all assets have a valid secret reference
		err = inventory.Validate()
		require.NoError(t, err)

		// activate to debug the pre-process output
		//// write output for debugging, so that we can easily compare the result
		//data, err := inventory.ToYAML()
		//require.NoError(t, err)
		//
		//err = os.WriteFile("./testdata/inventory.parsed.yml", data, 0o700)
		//require.NoError(t, err)
	})

	t.Run("idempotent preprocess", func(t *testing.T) {
		v1inventory, err := InventoryFromFile("./testdata/k8s_mount.yaml")
		require.NoError(t, err)

		err = v1inventory.PreProcess()
		require.NoError(t, err)

		err = v1inventory.PreProcess()
		require.NoError(t, err)
	})

	t.Run("preprocess private key", func(t *testing.T) {
		v1inventory := &Inventory{
			Spec: &InventorySpec{
				Assets: []*Asset{
					{
						Name: "test",
						Connections: []*Config{
							{
								Type: "ssh",
								Credentials: []*vault.Credential{
									{
										PrivateKey: "./testdata/private_key_01",
									},
								},
							},
						},
					},
				},
			},
		}
		err := v1inventory.PreProcess()
		require.NoError(t, err)
		secretid := v1inventory.Spec.Assets[0].Connections[0].Credentials[0].SecretId
		assert.Equal(t, vault.CredentialType_private_key, v1inventory.Spec.Credentials[secretid].Type)
	})

	t.Run("preprocess pkcs12 credential with loading from file", func(t *testing.T) {
		v1inventory := &Inventory{
			Spec: &InventorySpec{
				Assets: []*Asset{
					{
						Name: "test",
						Connections: []*Config{
							{
								Type: "ms365",
								Credentials: []*vault.Credential{
									{
										Type:           vault.CredentialType_pkcs12,
										PrivateKeyPath: "./testdata/private_key_01",
									},
								},
							},
						},
					},
				},
			},
		}
		err := v1inventory.PreProcess()
		require.NoError(t, err)
		secretid := v1inventory.Spec.Assets[0].Connections[0].Credentials[0].SecretId
		assert.Equal(t, vault.CredentialType_pkcs12, v1inventory.Spec.Credentials[secretid].Type)
	})

	t.Run("preprocess pkcs12 credential with loading from file", func(t *testing.T) {
		v1inventory := &Inventory{
			Spec: &InventorySpec{
				Assets: []*Asset{
					{
						Name: "test",
						Connections: []*Config{
							{
								Type: "ms365",
								Credentials: []*vault.Credential{
									{
										Type:       vault.CredentialType_pkcs12,
										PrivateKey: "secretdata",
									},
								},
							},
						},
					},
				},
			},
		}
		err := v1inventory.PreProcess()
		require.NoError(t, err)
		secretid := v1inventory.Spec.Assets[0].Connections[0].Credentials[0].SecretId
		assert.Equal(t, vault.CredentialType_pkcs12, v1inventory.Spec.Credentials[secretid].Type)
	})

	t.Run("preprocess env", func(t *testing.T) {
		secret := "secretdata"
		os.Setenv("MY_CUSTOM_ENV", secret)
		v1inventory := &Inventory{
			Spec: &InventorySpec{
				Assets: []*Asset{
					{
						Name: "test",
						Connections: []*Config{
							{
								Type: "slack",
								Credentials: []*vault.Credential{
									{
										Type: vault.CredentialType_env,
										Env:  "MY_CUSTOM_ENV",
									},
								},
							},
						},
					},
				},
			},
		}
		err := v1inventory.PreProcess()
		require.NoError(t, err)
		secretid := v1inventory.Spec.Assets[0].Connections[0].Credentials[0].SecretId
		assert.Equal(t, vault.CredentialType_password, v1inventory.Spec.Credentials[secretid].Type)
		assert.Equal(t, secret, string(v1inventory.Spec.Credentials[secretid].Secret))
	})
}

func TestParseGCPInventory(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/gcp_inventory.yaml")
	require.NoError(t, err)

	// extract credentials into credential section
	err = inventory.PreProcess()
	require.NoError(t, err)

	assert.Equal(t, "gcp", inventory.Spec.Assets[0].Connections[0].Type)
	// ensure that all assets have a valid secret reference
	err = inventory.Validate()
	require.NoError(t, err)
}

func TestParseVsphereInventory(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/vsphere_inventory.yaml")
	require.NoError(t, err)

	// extract credentials into credential section
	err = inventory.PreProcess()
	require.NoError(t, err)

	// ensure that all assets have a valid secret reference
	err = inventory.Validate()
	require.NoError(t, err)

	// check that the password was pre-processed
	cred := inventory.Spec.Assets[0].Connections[0].Credentials[0]
	assert.Equal(t, "", cred.User)
	assert.Equal(t, "", cred.Password)
	assert.Equal(t, []byte{}, cred.Secret)

	secret := inventory.Spec.Credentials[cred.SecretId]
	assert.Equal(t, "root", secret.User)
	assert.Equal(t, "", secret.Password)
	assert.Equal(t, []byte("password1!"), secret.Secret)
}

func TestParseSshInventory(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/ssh_inventory.yaml")
	require.NoError(t, err)

	// extract credentials into credential section
	err = inventory.PreProcess()
	require.NoError(t, err)

	// ensure that all assets have a valid secret reference
	err = inventory.Validate()
	require.NoError(t, err)

	a := findAsset(inventory.Spec.Assets, "linux-with-password")
	require.NotNil(t, a)

	assert.Equal(t, vault.CredentialType_password, inventory.Spec.Credentials[a.Connections[0].Credentials[0].SecretId].Type)

	a = findAsset(inventory.Spec.Assets, "linux-ssh-agent")
	require.NotNil(t, a)
	assert.Equal(t, vault.CredentialType_ssh_agent, inventory.Spec.Credentials[a.Connections[0].Credentials[0].SecretId].Type)

	a = findAsset(inventory.Spec.Assets, "linux-identity-key")
	require.NotNil(t, a)
	assert.Equal(t, vault.CredentialType_private_key, inventory.Spec.Credentials[a.Connections[0].Credentials[0].SecretId].Type)
	// ensure we only have one credential
	assert.Len(t, a.Connections[0].Credentials, 1)

	a = findAsset(inventory.Spec.Assets, "linux-ssh-agent-and-key")
	require.NotNil(t, a)
	assert.Len(t, a.Connections[0].Credentials, 2)
	assert.Equal(t, vault.CredentialType_ssh_agent, inventory.Spec.Credentials[a.Connections[0].Credentials[0].SecretId].Type)
	assert.Equal(t, vault.CredentialType_private_key, inventory.Spec.Credentials[a.Connections[0].Credentials[1].SecretId].Type)
}

func TestParseVaultInventory(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/vault_inventory.yaml")
	require.NoError(t, err)

	// extract credentials into credential section
	err = inventory.PreProcess()
	require.NoError(t, err)

	// ensure that all assets have a valid secret reference
	err = inventory.Validate()
	require.NoError(t, err)
}

func TestNilPointer(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/no_metadata_inventory.yaml")
	require.NoError(t, err)

	assert.NotNil(t, inventory.Metadata)
	assert.NotNil(t, inventory.Metadata.Labels)
}

func TestMarkInsecure(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/ssh_inventory.yaml")
	require.NoError(t, err)

	// extract credentials into credential section
	err = inventory.PreProcess()
	require.NoError(t, err)

	// check that all assets have no insecure flag set
	for i := range inventory.Spec.Assets {
		a := inventory.Spec.Assets[i]
		for j := range a.Connections {
			assert.False(t, a.Connections[j].Insecure, a.Name)
		}
	}

	inventory.MarkConnectionsInsecure()

	// check that all connections are marked as insecure
	for i := range inventory.Spec.Assets {
		a := inventory.Spec.Assets[i]
		for j := range a.Connections {
			assert.True(t, a.Connections[j].Insecure, a.Name)
		}
	}
}

func TestAnnotations(t *testing.T) {
	inventory, err := InventoryFromFile("./testdata/annotations.yaml")
	require.NoError(t, err)

	err = inventory.PreProcess()
	require.NoError(t, err)

	a := findAsset(inventory.Spec.Assets, "asset-with-annotations")
	require.NotNil(t, a)

	assert.Equal(t, "myvalue", a.Annotations["mykey"])

}

func findAsset(assets []*Asset, id string) *Asset {
	for i := range assets {
		a := assets[i]
		if a.Id == id {
			return a
		}
	}
	return nil
}
