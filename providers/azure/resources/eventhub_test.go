// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/eventhub/armeventhub"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These exercise the mapping half of the two listers migrated onto listPaged.
// Splitting the map out of the pager walk is what makes them possible: before
// the split the only way to reach this code was through an ARM client and a
// live subscription.

func TestCreateEventHubNamespaceRawData(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	keySource := "Microsoft.KeyVault"
	tlsVersion := armeventhub.TLSVersionOne2
	publicAccess := armeventhub.PublicNetworkAccessDisabled

	ns := &armeventhub.EHNamespace{
		ID:       new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1"),
		Name:     new("ns1"),
		Location: new("westeurope"),
		Tags:     map[string]*string{"env": new("prod")},
		Properties: &armeventhub.EHNamespaceProperties{
			CreatedAt:              &created,
			Status:                 new("Active"),
			IsAutoInflateEnabled:   new(true),
			MaximumThroughputUnits: new(int32(12)),
			KafkaEnabled:           new(true),
			DisableLocalAuth:       new(true),
			MinimumTLSVersion:      &tlsVersion,
			PublicNetworkAccess:    &publicAccess,
			ZoneRedundant:          new(true),
			Encryption: &armeventhub.Encryption{
				KeySource:                       &keySource,
				RequireInfrastructureEncryption: new(true),
				KeyVaultProperties: []*armeventhub.KeyVaultProperties{
					{KeyName: new("cmk1")},
				},
			},
		},
	}

	raw, err := createEventHubNamespaceRawData(azureTestRuntime(), ns)
	require.NoError(t, err)

	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1", raw["id"].Value)
	assert.Equal(t, "ns1", raw["name"].Value)
	assert.Equal(t, "westeurope", raw["location"].Value)
	assert.Equal(t, "Active", raw["status"].Value)
	assert.Equal(t, true, raw["isAutoInflateEnabled"].Value)
	assert.Equal(t, int64(12), raw["maximumThroughputUnits"].Value)
	assert.Equal(t, true, raw["kafkaEnabled"].Value)
	assert.Equal(t, true, raw["disableLocalAuth"].Value)
	assert.Equal(t, "1.2", raw["minimumTlsVersion"].Value)
	assert.Equal(t, "Disabled", raw["publicNetworkAccess"].Value)
	assert.Equal(t, true, raw["zoneRedundant"].Value)
	assert.Equal(t, "Microsoft.KeyVault", raw["cmkKeySource"].Value)
	assert.Equal(t, true, raw["requireInfrastructureEncryption"].Value)
	assert.Len(t, raw["cmkKeys"].Value, 1)
	assert.Equal(t, &created, raw["creationTime"].Value)
}

// ARM omits the whole properties block on some rows. Dereferencing it panics,
// and a panic in an accessor ends the scan rather than the query.
func TestCreateEventHubNamespaceRawDataWithoutProperties(t *testing.T) {
	ns := &armeventhub.EHNamespace{ID: new("/subscriptions/s/x/ns1"), Name: new("ns1")}

	raw, err := createEventHubNamespaceRawData(azureTestRuntime(), ns)

	require.NoError(t, err)
	assert.Equal(t, "ns1", raw["name"].Value)
	assert.Equal(t, "", raw["status"].Value)
	assert.Equal(t, false, raw["kafkaEnabled"].Value)
	assert.Nil(t, raw["creationTime"].Value)
	assert.Nil(t, raw["requireInfrastructureEncryption"].Value)
}

// A nil entry inside KeyVaultProperties must be skipped, not dereferenced.
func TestCreateEventHubNamespaceRawDataSkipsNilKeyVaultProperties(t *testing.T) {
	ns := &armeventhub.EHNamespace{
		Name: new("ns1"),
		Properties: &armeventhub.EHNamespaceProperties{
			Encryption: &armeventhub.Encryption{
				KeyVaultProperties: []*armeventhub.KeyVaultProperties{
					nil,
					{KeyName: new("cmk1")},
					nil,
				},
			},
		},
	}

	raw, err := createEventHubNamespaceRawData(azureTestRuntime(), ns)

	require.NoError(t, err)
	assert.Len(t, raw["cmkKeys"].Value, 1)
}

func TestCreateEventHubRawData(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	status := armeventhub.EntityStatusActive

	raw := createEventHubRawData(&armeventhub.Eventhub{
		ID:   new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1/eventhubs/eh1"),
		Name: new("eh1"),
		Properties: &armeventhub.Properties{
			CreatedAt:              &created,
			PartitionCount:         new(int64(4)),
			MessageRetentionInDays: new(int64(7)),
			Status:                 &status,
			PartitionIDs:           []*string{new("0"), nil, new("1")},
		},
	})

	assert.Equal(t, "eh1", raw["name"].Value)
	assert.Equal(t, int64(4), raw["partitionCount"].Value)
	assert.Equal(t, int64(7), raw["messageRetentionInDays"].Value)
	assert.Equal(t, "Active", raw["status"].Value)
	// the nil partition id is skipped rather than dereferenced
	assert.Equal(t, []any{"0", "1"}, raw["partitionIds"].Value)
	assert.Equal(t, &created, raw["creationTime"].Value)
}

func TestCreateEventHubRawDataWithoutProperties(t *testing.T) {
	raw := createEventHubRawData(&armeventhub.Eventhub{Name: new("eh1")})

	assert.Equal(t, "eh1", raw["name"].Value)
	assert.Equal(t, int64(0), raw["partitionCount"].Value)
	assert.Equal(t, "", raw["status"].Value)
	assert.Nil(t, raw["creationTime"].Value)
}

func TestCreateEventHubConsumerGroupRawData(t *testing.T) {
	created := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

	raw := createEventHubConsumerGroupRawData(&armeventhub.ConsumerGroup{
		ID:   new("/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1/eventhubs/eh1/consumergroups/cg1"),
		Name: new("cg1"),
		Properties: &armeventhub.ConsumerGroupProperties{
			CreatedAt:    &created,
			UserMetadata: new("owner=platform"),
		},
	})

	assert.Equal(t, "/subscriptions/s/resourceGroups/rg/providers/Microsoft.EventHub/namespaces/ns1/eventhubs/eh1/consumergroups/cg1", raw["id"].Value)
	assert.Equal(t, "cg1", raw["name"].Value)
	assert.Equal(t, "owner=platform", raw["userMetadata"].Value)
	assert.Equal(t, &created, raw["creationTime"].Value)
}

// The $Default consumer group comes back with no properties block at all.
// Dereferencing it panics, and a panic in an accessor ends the scan rather than
// the query.
func TestCreateEventHubConsumerGroupRawDataWithoutProperties(t *testing.T) {
	raw := createEventHubConsumerGroupRawData(&armeventhub.ConsumerGroup{Name: new("$Default")})

	assert.Equal(t, "$Default", raw["name"].Value)
	assert.Equal(t, "", raw["userMetadata"].Value)
	// an absent creation time stays null rather than becoming the zero time
	assert.Nil(t, raw["creationTime"].Value)
}
