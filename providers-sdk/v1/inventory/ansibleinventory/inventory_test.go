// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ansibleinventory_test

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/inventory/ansibleinventory"
	"go.mondoo.com/mql/providers-sdk/v1/vault"
)

func TestValidInventory(t *testing.T) {
	assert.False(t, ansibleinventory.IsInventory([]byte{}))

	iniFile := `
[win]
172.16.2.5 
172.16.2.6 
	`
	assert.False(t, ansibleinventory.IsInventory([]byte(iniFile)))

	jsonFile := `
{
	"_meta": {
					"hostvars": {}
	},
	"ungrouped": {}
}
`
	assert.False(t, ansibleinventory.IsInventory([]byte(jsonFile)))

	jsonFile = `
{
	"all": {
		"children": [
				"local", 
				"ungrouped"
		]
	}
}
`
	assert.False(t, ansibleinventory.IsInventory([]byte(jsonFile)))

	jsonFile = `
all:
  hosts:
    ub2204:
      ansible_host: 34.69.247.108
      ansible_user: chris
      ansible_ssh_private_key_file: ~/.ssh/id_ed25519
`
	assert.False(t, ansibleinventory.IsInventory([]byte(jsonFile)))

	jsonFile = `
{
    "_meta": {
        "hostvars": {
            "ub2204": {
                "ansible_host": "34.69.247.108",
                "ansible_ssh_private_key_file": "~/.ssh/id_ed25519",
                "ansible_user": "chris"
            }
        }
    },
    "all": {
        "children": [
            "ungrouped"
        ]
    },
    "ungrouped": {
        "hosts": [
            "ub2204"
        ]
    }
}
`
	assert.True(t, ansibleinventory.IsInventory([]byte(jsonFile)))
}

func TestParseInventory(t *testing.T) {
	input, err := os.ReadFile("./testdata/empty.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)
	assert.Equal(t, inventory.All.Children, []string{"ungrouped"})
}

func TestParseInventoryUngrouped(t *testing.T) {
	input, err := os.ReadFile("./testdata/ungrouped.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)

	assert.Equal(t, []string{"ungrouped", "workers"}, inventory.All.Children)
	assert.Equal(t, ansibleinventory.Group{Hosts: []string{"34.244.38.44"}}, inventory.Groups["ungrouped"])
}

func TestFullInventory(t *testing.T) {
	input, err := os.ReadFile("./testdata/inventory.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)

	assert.Equal(t, []string{
		"api",
		"aws_ec2",
		"payment",
		"ungrouped",
		"web",
		"webservers",
	}, inventory.All.Children)

	assert.Equal(t, []string{"192.168.2.1", "192.168.2.2"}, inventory.Groups["api"].Hosts)
	assert.Equal(t, []string{"ec2-34-242-192-191.eu-west-1.compute.amazonaws.com"}, inventory.Groups["aws_ec2"].Hosts)
}

func sortHosts(hosts []*ansibleinventory.Host) {
	sort.SliceStable(hosts, func(i, j int) bool {
		return hosts[i].Alias < hosts[j].Alias
	})
}

func TestHostExtraction(t *testing.T) {
	input, err := os.ReadFile("./testdata/ungrouped.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)

	hosts := inventory.List()
	assert.Equal(t, 3, len(hosts))

	hosts = inventory.List("ungrouped")
	assert.Equal(t, 1, len(hosts))

	assert.Equal(t, []*ansibleinventory.Host{{
		Alias:      "34.244.38.44",
		Host:       "34.244.38.44",
		Port:       "2222",
		Connection: "ssh",
	}}, hosts)

	hosts = inventory.List("workers")
	assert.Equal(t, 2, len(hosts))

	// ensure order for equality check
	sortHosts(hosts)

	assert.Equal(t, []*ansibleinventory.Host{{
		Alias:      "34.244.38.46",
		Host:       "34.244.38.46",
		User:       "ec2-user",
		Port:       "22",
		Connection: "ssh",
	}, {
		Alias:      "34.255.178.16",
		Host:       "34.255.178.16",
		User:       "ec2-user",
		Identity:   "/Users/chartmann/.ssh/id_rsa",
		Connection: "ssh",
	}}, hosts)
}

// convert the ini via
// ansible-inventory -i integrations/ansibleinventory/testdata/local.ini --list > integrations/ansibleinventory/testdata/local.json
func TestHostConnectionLocal(t *testing.T) {
	input, err := os.ReadFile("./testdata/local.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)

	hosts := inventory.List()
	assert.Equal(t, 1, len(hosts))

	hosts = inventory.List("local")
	assert.Equal(t, 1, len(hosts))

	assert.Equal(t, []*ansibleinventory.Host{{
		Alias:      "127.0.0.1",
		Host:       "127.0.0.1",
		Connection: "local",
	}}, hosts)
}

// yq -y . integrations/ansibleinventory/testdata/local.json
func TestHostConnectionLocalYaml(t *testing.T) {
	input, err := os.ReadFile("./testdata/local.yaml")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)

	hosts := inventory.List()
	assert.Equal(t, 1, len(hosts))

	hosts = inventory.List("local")
	assert.Equal(t, 1, len(hosts))

	assert.Equal(t, []*ansibleinventory.Host{{
		Alias:      "127.0.0.1",
		Host:       "127.0.0.1",
		Connection: "local",
	}}, hosts)
}

// convert winrm.ini via
// ansible-inventory -i integrations/ansibleinventory/testdata/windows.ini --list > integrations/ansibleinventory/testdata/windows.json
func TestHostConnectionWinrm(t *testing.T) {
	input, err := os.ReadFile("./testdata/winrm.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)

	hosts := inventory.List()
	assert.Equal(t, 2, len(hosts))

	hosts = inventory.List("win")
	assert.Equal(t, 2, len(hosts))

	// ensure order for equality check
	sortHosts(hosts)

	assert.Equal(t, []*ansibleinventory.Host{{
		Alias:      "172.16.2.5",
		Host:       "172.16.2.5",
		User:       "vagrant",
		Password:   "password",
		Connection: "winrm",
	}, {
		Alias:      "172.16.2.6",
		Host:       "172.16.2.6",
		User:       "vagrant",
		Password:   "password",
		Connection: "winrm",
	}}, hosts)
}

func TestHostSSHPrivateKey(t *testing.T) {
	input, err := os.ReadFile("./testdata/ssh_private_key.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	inventory := ansibleinventory.Inventory{}
	err = inventory.Decode(input)
	assert.Nil(t, err)

	hosts := inventory.List()
	assert.Equal(t, 1, len(hosts))

	assert.Equal(t, []*ansibleinventory.Host{{
		Alias:      "instance1",
		Host:       "192.168.178.11",
		User:       "custom-user",
		Identity:   "/home/custom-user/.ssh/id_rsa",
		Connection: "ssh",
	}}, hosts)
}

func TestInventoryConversion(t *testing.T) {
	input, err := os.ReadFile("./testdata/inventory.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	ansibleInventory := ansibleinventory.Inventory{}
	err = ansibleInventory.Decode(input)
	assert.Nil(t, err)

	v1Inventory := ansibleInventory.ToV1Inventory()

	assert.Equal(t, 8, len(v1Inventory.Spec.Assets))
}

func TestInventoryWithUsernameConversion(t *testing.T) {
	input, err := os.ReadFile("./testdata/hosts.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	ansibleInventory := ansibleinventory.Inventory{}
	err = ansibleInventory.Decode(input)
	assert.Nil(t, err)

	v1Inventory := ansibleInventory.ToV1Inventory()
	assert.Equal(t, 2, len(v1Inventory.Spec.Assets))

	a := findAsset(v1Inventory.Spec.Assets, "instance1")
	assert.NotNil(t, a)
	assert.Equal(t, "104.154.55.51", a.Connections[0].Host)
	secretId := a.Connections[0].Credentials[0].SecretId
	cred := v1Inventory.Spec.Credentials[secretId]
	assert.Equal(t, "chris", cred.User)
	assert.Equal(t, vault.CredentialType_ssh_agent, cred.Type)

	a = findAsset(v1Inventory.Spec.Assets, "34.133.130.53")
	assert.NotNil(t, a)
	assert.Equal(t, "34.133.130.53", a.Connections[0].Host)
	secretId = a.Connections[0].Credentials[0].SecretId
	cred = v1Inventory.Spec.Credentials[secretId]
	assert.Equal(t, "chris", cred.User)
	assert.Equal(t, vault.CredentialType_ssh_agent, cred.Type)
}

func TestTagsAndGroups(t *testing.T) {
	input, err := os.ReadFile("./testdata/tags_groups.json")
	assert.Nil(t, err)
	assert.True(t, ansibleinventory.IsInventory(input))

	ansibleInventory := ansibleinventory.Inventory{}
	err = ansibleInventory.Decode(input)
	assert.Nil(t, err)

	hosts := ansibleInventory.List()
	assert.Equal(t, 1, len(hosts))

	assert.Equal(t, []*ansibleinventory.Host{{
		Alias:      "instance1",
		Host:       "192.168.178.11",
		User:       "custom-user",
		Identity:   "/home/custom-user/.ssh/id_rsa",
		Connection: "ssh",
		Labels:     []string{"ansible_host", "mondoo_agent"},
	}}, hosts)

	// convert to mondoo inventory
	v1Inventory := ansibleInventory.ToV1Inventory()
	assert.Equal(t, 1, len(v1Inventory.Spec.Assets))

	a := findAsset(v1Inventory.Spec.Assets, "instance1")
	assert.NotNil(t, a)
	assert.Equal(t, "192.168.178.11", a.Connections[0].Host)
	secretId := a.Connections[0].Credentials[0].SecretId
	cred := v1Inventory.Spec.Credentials[secretId]
	assert.Equal(t, "custom-user", cred.User)
	assert.Equal(t, vault.CredentialType_private_key, cred.Type)
	assert.Equal(t, "/home/custom-user/.ssh/id_rsa", cred.PrivateKeyPath)
}

func findAsset(assetList []*inventory.Asset, name string) *inventory.Asset {
	for i := range assetList {
		if assetList[i].Name == name {
			return assetList[i]
		}
	}
	return nil
}

func TestInventoryNamesAreMarkedAsRequested(t *testing.T) {
	input, err := os.ReadFile("./testdata/hosts.json")
	require.NoError(t, err)

	ansibleInventory := ansibleinventory.Inventory{}
	require.NoError(t, ansibleInventory.Decode(input))

	byName := map[string]*inventory.Asset{}
	for _, asset := range ansibleInventory.ToV1Inventory().Spec.Assets {
		byName[asset.Name] = asset
	}

	// instance1 is the ansible host key the operator wrote; 104.154.55.51 is only
	// what we connect to. The key is the name, and the marker is what stops a
	// provider's detect step replacing it once connected.
	instance := byName["instance1"]
	require.NotNil(t, instance)
	assert.Equal(t, "104.154.55.51", instance.Connections[0].Host)
	assert.True(t, instance.NameOverride)

	// a key with no ansible_host is still the operator's key
	direct := byName["34.133.130.53"]
	require.NotNil(t, direct)
	assert.True(t, direct.NameOverride)
}
