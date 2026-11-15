// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicebus/armservicebus/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateServiceBusNamespaceRawData(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	keySource := "Microsoft.KeyVault"
	tlsVersion := armservicebus.TLSVersionOne2

	ns := &armservicebus.SBNamespace{
		ID:       new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/ns1"),
		Name:     new("ns1"),
		Location: new("westeurope"),
		Tags:     map[string]*string{"env": new("prod")},
		Properties: &armservicebus.SBNamespaceProperties{
			CreatedAt:         &created,
			Status:            new("Active"),
			DisableLocalAuth:  new(true),
			MinimumTLSVersion: &tlsVersion,
			ZoneRedundant:     new(true),
			Encryption: &armservicebus.Encryption{
				KeySource:                       &keySource,
				RequireInfrastructureEncryption: new(true),
				KeyVaultProperties: []*armservicebus.KeyVaultProperties{
					{KeyName: new("cmk1")},
				},
			},
		},
	}

	raw, err := createServiceBusNamespaceRawData(azureTestRuntime(), ns)
	require.NoError(t, err)

	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/ns1", raw["id"].Value)
	assert.Equal(t, "ns1", raw["name"].Value)
	assert.Equal(t, "Active", raw["status"].Value)
	assert.Equal(t, true, raw["disableLocalAuth"].Value)
	assert.Equal(t, "1.2", raw["minimumTlsVersion"].Value)
	assert.Equal(t, true, raw["zoneRedundant"].Value)
	assert.Equal(t, "Microsoft.KeyVault", raw["cmkKeySource"].Value)
	assert.Equal(t, true, raw["requireInfrastructureEncryption"].Value)
	assert.Len(t, raw["cmkKeys"].Value, 1)
	assert.Equal(t, &created, raw["creationTime"].Value)
}

// A namespace whose properties omit the TLS floor reports an empty string, so
// a content check that requires "1.2" or "1.3" fails it rather than passing.
func TestCreateServiceBusNamespaceRawDataNoTLSVersion(t *testing.T) {
	ns := &armservicebus.SBNamespace{
		ID:         new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.ServiceBus/namespaces/ns2"),
		Name:       new("ns2"),
		Properties: &armservicebus.SBNamespaceProperties{},
	}

	raw, err := createServiceBusNamespaceRawData(azureTestRuntime(), ns)
	require.NoError(t, err)
	assert.Equal(t, "", raw["minimumTlsVersion"].Value)
}
