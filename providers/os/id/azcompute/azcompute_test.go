// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package azcompute

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/local"
	"go.mondoo.com/mql/providers/os/connection/mock"
	"go.mondoo.com/mql/providers/os/detector"
)

func TestCommandProviderLinux(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/metadata_linux.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	metadata := commandInstanceMetadata{conn: conn, platform: platform}
	ident, err := metadata.Identify()

	assert.Nil(t, err)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourcegroups/testresources/providers/microsoft.compute/virtualmachines/examplevmname", ident.InstanceID)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx", ident.AccountID)

	t.Run("raw metadata", func(t *testing.T) {
		raw, err := metadata.RawMetadata()
		assert.Nil(t, err)
		// Convert to JSON for readability
		jsonData, _ := json.MarshalIndent(raw, "", "  ")
		// Compare actual vs expected JSON output
		assert.JSONEq(t, expectedRawMetadata(true), string(jsonData))
	})
}

func TestCommandProviderWindows(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/metadata_windows.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	metadata := commandInstanceMetadata{conn: conn, platform: platform}
	ident, err := metadata.Identify()

	assert.Nil(t, err)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourcegroups/testresources/providers/microsoft.compute/virtualmachines/examplevmname", ident.InstanceID)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx", ident.AccountID)

	t.Run("raw metadata", func(t *testing.T) {
		raw, err := metadata.RawMetadata()
		assert.Nil(t, err)
		// Convert to JSON for readability
		jsonData, _ := json.MarshalIndent(raw, "", "  ")
		// Compare actual vs expected JSON output
		assert.JSONEq(t, expectedRawMetadata(true), string(jsonData))
	})
}

func TestCommandProviderLinuxNoLoadbalancerInformation(t *testing.T) {
	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/metadata_linux_no_loadbalancer_info.toml"))
	require.NoError(t, err)
	platform, ok := detector.DetectOS(conn)
	require.True(t, ok)

	metadata := commandInstanceMetadata{conn: conn, platform: platform}
	ident, err := metadata.Identify()

	assert.Nil(t, err)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourcegroups/testresources/providers/microsoft.compute/virtualmachines/examplevmname", ident.InstanceID)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx", ident.AccountID)

	t.Run("raw metadata", func(t *testing.T) {
		raw, err := metadata.RawMetadata()
		assert.Nil(t, err)
		// Convert to JSON for readability
		jsonData, _ := json.MarshalIndent(raw, "", "  ")
		// Compare actual vs expected JSON output
		assert.JSONEq(t, expectedRawMetadata(false), string(jsonData))
	})
}

func expectedRawMetadata(loadbalancer bool) string {
	loadbalancerData := ""
	if loadbalancer {
		loadbalancerData = expectedRawMetadataLoadbalancer()
	}
	return fmt.Sprintf(`{
  "instance": {
    "compute": {
      "additionalCapabilities": {
        "hibernationEnabled": "false"
      },
      "azEnvironment": "AzurePublicCloud",
      "customData": "",
      "evictionPolicy": "",
      "extendedLocation": {
        "name": "",
        "type": ""
      },
      "host": {
        "id": ""
      },
      "hostGroup": {
        "id": ""
      },
      "isHostCompatibilityLayerVm": "true",
      "licenseType": "",
      "location": "westus",
      "name": "afiune-metadata-test",
      "offer": "0001-com-ubuntu-server-focal",
      "osProfile": {
        "adminUsername": "azureuser",
        "computerName": "afiune-metadata-test",
        "disablePasswordAuthentication": "true"
      },
      "osType": "Linux",
      "placementGroupId": "",
      "plan": {
        "name": "",
        "product": "",
        "publisher": ""
      },
      "platformFaultDomain": "0",
      "platformSubFaultDomain": "",
      "platformUpdateDomain": "0",
      "priority": "",
      "provider": "Microsoft.Compute",
      "publicKeys": [
        {
          "keyData": "ssh-ed25519 abc afiune@mondoo.com",
          "path": "/home/azureuser/.ssh/authorized_keys"
        }
      ],
      "publisher": "canonical",
      "resourceGroupName": "TESTRESOURCES",
      "resourceId": "/subscriptions/xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx/resourceGroups/TestResources/providers/Microsoft.Compute/virtualMachines/examplevmname",
      "securityProfile": {
        "encryptionAtHost": "false",
        "secureBootEnabled": "true",
        "securityType": "TrustedLaunch",
        "virtualTpmEnabled": "true"
      },
      "sku": "20_04-lts-gen2",
      "storageProfile": {
        "dataDisks": [],
        "imageReference": {
          "communityGalleryImageId": "",
          "exactVersion": "20.04.202502181",
          "id": "",
          "offer": "0001-com-ubuntu-server-focal",
          "publisher": "canonical",
          "sharedGalleryImageId": "",
          "sku": "20_04-lts-gen2",
          "version": "latest"
        },
        "osDisk": {
          "caching": "ReadWrite",
          "createOption": "FromImage",
          "diffDiskSettings": {
            "option": ""
          },
          "diskSizeGB": "30",
          "encryptionSettings": {
            "diskEncryptionKey": {
              "secretUrl": "",
              "sourceVault": {
                "id": ""
              }
            },
            "enabled": "false",
            "keyEncryptionKey": {
              "keyUrl": "",
              "sourceVault": {
                "id": ""
              }
            }
          },
          "image": {
            "uri": ""
          },
          "managedDisk": {
            "id": "/subscriptions/3cd8b376-ada6-4c01-afc3-84d4b7d7da99/resourceGroups/TestResources/providers/Microsoft.Compute/disks/afiune-metadata-test_OsDisk_1_e60edeb6707048e88462fade01058529",
            "storageAccountType": "Premium_LRS"
          },
          "name": "afiune-metadata-test_OsDisk_1_e60edeb6707048e88462fade01058529",
          "osType": "Linux",
          "vhd": {
            "uri": ""
          },
          "writeAcceleratorEnabled": "false"
        },
        "resourceDisk": {
          "size": "34816"
        }
      },
      "subscriptionId": "xxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx",
      "tags": "",
      "tagsList": [],
      "userData": "",
      "version": "20.04.202502181",
      "virtualMachineScaleSet": {
        "id": ""
      },
      "vmId": "02b052e1-ef72-4d31-a135-94f0966cbef6",
      "vmScaleSetName": "",
      "vmSize": "Standard_B1s",
      "zone": ""
    },
    "network": {
      "interface": [
        {
          "ipv4": {
            "ipAddress": [
              {
                "privateIpAddress": "10.144.133.132",
                "publicIpAddress": ""
              }
            ],
            "subnet": [
              {
                "address": "10.144.133.128",
                "prefix": "26"
              }
            ]
          },
          "ipv6": {
            "ipAddress": []
          },
          "macAddress": "0011AAFFBB22"
        }
      ]
    }
  }%s
}`, loadbalancerData)
}

func expectedRawMetadataLoadbalancer() string {
	return `,
 "loadbalancer": {
    "loadbalancer": {
      "publicIpAddresses": [
        {
          "frontendIpAddress": "172.184.192.212",
          "privateIpAddress":"10.0.0.4"
        }
      ],
      "inboundRules": [],
      "outboundRules": []
    }
  }
`
}

func TestLocalHTTPMetadata(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "true", r.Header.Get("Metadata"))
		if strings.Contains(r.URL.Path, "/metadata/instance") {
			_, _ = w.Write([]byte(`{"compute":{"resourceId":"/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm","subscriptionId":"sub-123","tags":""}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	conn := local.NewConnection(0, &inventory.Config{}, &inventory.Asset{})
	require.Equal(t, "local", string(conn.Type()))

	md := commandInstanceMetadata{
		conn:        conn,
		platform:    &inventory.Platform{Name: "windows", Family: []string{"windows"}},
		imdsBaseURL: srv.URL,
	}
	ident, err := md.Identify()
	require.NoError(t, err)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/sub-123/resourcegroups/rg/providers/microsoft.compute/virtualmachines/vm", ident.InstanceID)
	assert.Equal(t, "//platformid.api.mondoo.app/runtime/azure/subscriptions/sub-123", ident.AccountID)
}

func TestLocalHTTPMetadataErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("boom"))
	}))
	defer srv.Close()

	md := commandInstanceMetadata{
		conn:        local.NewConnection(0, &inventory.Config{}, &inventory.Asset{}),
		platform:    &inventory.Platform{Name: "windows", Family: []string{"windows"}},
		imdsBaseURL: srv.URL,
	}
	_, err := md.Identify()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "HTTP 500")
}
