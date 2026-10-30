// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReplicationStatusToDict(t *testing.T) {
	t.Run("nil status reads null", func(t *testing.T) {
		assert.Nil(t, replicationStatusToDict(nil))
	})

	t.Run("status with unset oneof reads null", func(t *testing.T) {
		// An empty status object must not become an empty dict: that would
		// render as a version replicated nowhere rather than as unknown.
		assert.Nil(t, replicationStatusToDict(&secretmanagerpb.ReplicationStatus{}))
	})

	t.Run("automatic with CMEK reports the key version", func(t *testing.T) {
		got := replicationStatusToDict(&secretmanagerpb.ReplicationStatus{
			ReplicationStatus: &secretmanagerpb.ReplicationStatus_Automatic{
				Automatic: &secretmanagerpb.ReplicationStatus_AutomaticStatus{
					CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryptionStatus{
						KmsKeyVersionName: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3",
					},
				},
			},
		})

		require.NotNil(t, got)
		automatic, ok := got["automatic"].(map[string]any)
		require.True(t, ok, "automatic key must be present")
		cme, ok := automatic["customerManagedEncryption"].(map[string]any)
		require.True(t, ok)
		assert.Equal(t,
			"projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/3",
			cme["kmsKeyVersionName"])
		assert.NotContains(t, got, "userManaged")
	})

	t.Run("automatic without CMEK is Google-managed, not absent", func(t *testing.T) {
		// A Google-managed version still replicates automatically. The
		// discriminator must survive even though there is no key to report,
		// otherwise a Google-managed secret is indistinguishable from one whose
		// status could not be read.
		got := replicationStatusToDict(&secretmanagerpb.ReplicationStatus{
			ReplicationStatus: &secretmanagerpb.ReplicationStatus_Automatic{
				Automatic: &secretmanagerpb.ReplicationStatus_AutomaticStatus{},
			},
		})

		require.NotNil(t, got)
		automatic, ok := got["automatic"].(map[string]any)
		require.True(t, ok)
		assert.NotContains(t, automatic, "customerManagedEncryption")
	})

	t.Run("user managed reports every replica location", func(t *testing.T) {
		got := replicationStatusToDict(&secretmanagerpb.ReplicationStatus{
			ReplicationStatus: &secretmanagerpb.ReplicationStatus_UserManaged{
				UserManaged: &secretmanagerpb.ReplicationStatus_UserManagedStatus{
					Replicas: []*secretmanagerpb.ReplicationStatus_UserManagedStatus_ReplicaStatus{
						{
							Location: "us-east1",
							CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryptionStatus{
								KmsKeyVersionName: "key-east-v1",
							},
						},
						{Location: "europe-west1"},
					},
				},
			},
		})

		require.NotNil(t, got)
		userManaged, ok := got["userManaged"].(map[string]any)
		require.True(t, ok)
		replicas, ok := userManaged["replicas"].([]any)
		require.True(t, ok)
		require.Len(t, replicas, 2)

		first := replicas[0].(map[string]any)
		assert.Equal(t, "us-east1", first["location"])
		assert.Equal(t, "key-east-v1",
			first["customerManagedEncryption"].(map[string]any)["kmsKeyVersionName"])

		// A replica with no CMEK is Google-managed in that location. It must
		// still appear, or an audit counting protected replicas would miss it.
		second := replicas[1].(map[string]any)
		assert.Equal(t, "europe-west1", second["location"])
		assert.NotContains(t, second, "customerManagedEncryption")
	})

	t.Run("nil replica entries are skipped", func(t *testing.T) {
		got := replicationStatusToDict(&secretmanagerpb.ReplicationStatus{
			ReplicationStatus: &secretmanagerpb.ReplicationStatus_UserManaged{
				UserManaged: &secretmanagerpb.ReplicationStatus_UserManagedStatus{
					Replicas: []*secretmanagerpb.ReplicationStatus_UserManagedStatus_ReplicaStatus{
						nil,
						{Location: "us-central1"},
					},
				},
			},
		})

		replicas := got["userManaged"].(map[string]any)["replicas"].([]any)
		require.Len(t, replicas, 1)
		assert.Equal(t, "us-central1", replicas[0].(map[string]any)["location"])
	})

	t.Run("user managed with no replicas returns an empty list, not null", func(t *testing.T) {
		got := replicationStatusToDict(&secretmanagerpb.ReplicationStatus{
			ReplicationStatus: &secretmanagerpb.ReplicationStatus_UserManaged{
				UserManaged: &secretmanagerpb.ReplicationStatus_UserManagedStatus{},
			},
		})

		require.NotNil(t, got)
		replicas, ok := got["userManaged"].(map[string]any)["replicas"].([]any)
		require.True(t, ok)
		assert.Empty(t, replicas)
	})
}
