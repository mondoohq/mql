// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"cloud.google.com/go/secretmanager/apiv1/secretmanagerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSecretReplicationToDict_Automatic(t *testing.T) {
	r := &secretmanagerpb.Replication{
		Replication: &secretmanagerpb.Replication_Automatic_{
			Automatic: &secretmanagerpb.Replication_Automatic{},
		},
	}

	result, err := secretReplicationToDict(r)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "AUTOMATIC", result["type"])
	assert.Nil(t, result["replicas"])
	assert.Nil(t, result["customerManagedEncryption"])
}

func TestSecretReplicationToDict_AutomaticWithCMEK(t *testing.T) {
	r := &secretmanagerpb.Replication{
		Replication: &secretmanagerpb.Replication_Automatic_{
			Automatic: &secretmanagerpb.Replication_Automatic{
				CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryption{
					KmsKeyName: "projects/p/locations/global/keyRings/kr/cryptoKeys/key1",
				},
			},
		},
	}

	result, err := secretReplicationToDict(r)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "AUTOMATIC", result["type"])
	assert.Equal(t, "projects/p/locations/global/keyRings/kr/cryptoKeys/key1", result["customerManagedEncryption"])
}

func TestSecretReplicationToDict_UserManaged(t *testing.T) {
	r := &secretmanagerpb.Replication{
		Replication: &secretmanagerpb.Replication_UserManaged_{
			UserManaged: &secretmanagerpb.Replication_UserManaged{
				Replicas: []*secretmanagerpb.Replication_UserManaged_Replica{
					{Location: "us-east1"},
					{Location: "europe-west1"},
				},
			},
		},
	}

	result, err := secretReplicationToDict(r)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "USER_MANAGED", result["type"])
	replicas, ok := result["replicas"].([]any)
	require.True(t, ok)
	require.Len(t, replicas, 2)
	r0 := replicas[0].(map[string]any)
	assert.Equal(t, "us-east1", r0["location"])
	assert.Nil(t, r0["customerManagedEncryption"])
	r1 := replicas[1].(map[string]any)
	assert.Equal(t, "europe-west1", r1["location"])
}

func TestSecretReplicationToDict_UserManagedWithCMEK(t *testing.T) {
	r := &secretmanagerpb.Replication{
		Replication: &secretmanagerpb.Replication_UserManaged_{
			UserManaged: &secretmanagerpb.Replication_UserManaged{
				Replicas: []*secretmanagerpb.Replication_UserManaged_Replica{
					{
						Location: "us-east1",
						CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryption{
							KmsKeyName: "projects/p/locations/us-east1/keyRings/kr/cryptoKeys/key-a",
						},
					},
					{
						Location: "eu-west1",
						CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryption{
							KmsKeyName: "projects/p/locations/eu-west1/keyRings/kr/cryptoKeys/key-b",
						},
					},
				},
			},
		},
	}

	result, err := secretReplicationToDict(r)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "USER_MANAGED", result["type"])
	replicas, ok := result["replicas"].([]any)
	require.True(t, ok)
	require.Len(t, replicas, 2)
	r0 := replicas[0].(map[string]any)
	assert.Equal(t, "us-east1", r0["location"])
	assert.Equal(t, "projects/p/locations/us-east1/keyRings/kr/cryptoKeys/key-a", r0["customerManagedEncryption"])
	r1 := replicas[1].(map[string]any)
	assert.Equal(t, "eu-west1", r1["location"])
	assert.Equal(t, "projects/p/locations/eu-west1/keyRings/kr/cryptoKeys/key-b", r1["customerManagedEncryption"])
}

func TestSecretReplicationToDict_Nil(t *testing.T) {
	r := &secretmanagerpb.Replication{}

	result, err := secretReplicationToDict(r)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestExtractCustomerManagedEncryptionKeys(t *testing.T) {
	t.Run("top-level CMEK", func(t *testing.T) {
		s := &secretmanagerpb.Secret{
			CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryption{
				KmsKeyName: "projects/p/locations/global/keyRings/kr/cryptoKeys/key1",
			},
		}
		keys := extractCustomerManagedEncryptionKeys(s)
		assert.Equal(t, []any{"projects/p/locations/global/keyRings/kr/cryptoKeys/key1"}, keys)
	})

	t.Run("automatic replication CMEK", func(t *testing.T) {
		s := &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{
						CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryption{
							KmsKeyName: "projects/p/locations/global/keyRings/kr/cryptoKeys/key2",
						},
					},
				},
			},
		}
		keys := extractCustomerManagedEncryptionKeys(s)
		assert.Equal(t, []any{"projects/p/locations/global/keyRings/kr/cryptoKeys/key2"}, keys)
	})

	t.Run("user-managed replication with multiple CMEK keys", func(t *testing.T) {
		s := &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_UserManaged_{
					UserManaged: &secretmanagerpb.Replication_UserManaged{
						Replicas: []*secretmanagerpb.Replication_UserManaged_Replica{
							{
								Location: "us-east1",
								CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryption{
									KmsKeyName: "projects/p/locations/us-east1/keyRings/kr/cryptoKeys/key-a",
								},
							},
							{
								Location: "eu-west1",
								CustomerManagedEncryption: &secretmanagerpb.CustomerManagedEncryption{
									KmsKeyName: "projects/p/locations/eu-west1/keyRings/kr/cryptoKeys/key-b",
								},
							},
							{Location: "asia-east1"},
						},
					},
				},
			},
		}
		keys := extractCustomerManagedEncryptionKeys(s)
		assert.Equal(t, []any{
			"projects/p/locations/us-east1/keyRings/kr/cryptoKeys/key-a",
			"projects/p/locations/eu-west1/keyRings/kr/cryptoKeys/key-b",
		}, keys)
	})

	t.Run("no CMEK anywhere", func(t *testing.T) {
		s := &secretmanagerpb.Secret{
			Replication: &secretmanagerpb.Replication{
				Replication: &secretmanagerpb.Replication_Automatic_{
					Automatic: &secretmanagerpb.Replication_Automatic{},
				},
			},
		}
		assert.Nil(t, extractCustomerManagedEncryptionKeys(s))
	})

	t.Run("nil replication", func(t *testing.T) {
		s := &secretmanagerpb.Secret{}
		assert.Nil(t, extractCustomerManagedEncryptionKeys(s))
	})
}

func TestTimestampToString(t *testing.T) {
	t.Run("nil timestamp", func(t *testing.T) {
		assert.Equal(t, "", timestampToString(nil))
	})

	t.Run("valid timestamp", func(t *testing.T) {
		ts := timestamppb.New(time.Date(2024, 6, 15, 10, 30, 0, 0, time.UTC))
		result := timestampToString(ts)
		assert.Equal(t, "2024-06-15T10:30:00Z", result)
	})
}

func TestDurationToString(t *testing.T) {
	t.Run("nil duration", func(t *testing.T) {
		assert.Equal(t, "", durationToString(nil))
	})

	t.Run("valid duration", func(t *testing.T) {
		d := &durationpb.Duration{Seconds: 86400}
		assert.Equal(t, "86400s", durationToString(d))
	})

	t.Run("zero duration", func(t *testing.T) {
		d := &durationpb.Duration{Seconds: 0}
		assert.Equal(t, "0s", durationToString(d))
	})
}

func TestSecretManagerRegionalAddressing(t *testing.T) {
	assert.Equal(t, "", secretManagerEndpoint(""), "the global endpoint is the client default")
	assert.Equal(t, "secretmanager.us-central1.rep.googleapis.com:443", secretManagerEndpoint("us-central1"))

	assert.Equal(t, "projects/p", secretManagerParent("p", ""))
	assert.Equal(t, "projects/p/locations/europe-west4", secretManagerParent("p", "europe-west4"))

	assert.Equal(t, "", secretLocationFromName("projects/p/secrets/s"))
	assert.Equal(t, "", secretLocationFromName("projects/p/secrets/s/versions/1"))
	assert.Equal(t, "us-east1", secretLocationFromName("projects/p/locations/us-east1/secrets/s"))
	assert.Equal(t, "us-east1", secretLocationFromName("projects/p/locations/us-east1/secrets/s/versions/3"))
	assert.Equal(t, "", secretLocationFromName(""))
}
