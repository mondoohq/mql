// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"cloud.google.com/go/container/apiv1/containerpb"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNodeTaintID(t *testing.T) {
	// Kubernetes taints are uniquely identified by (key, value, effect). A node
	// pool may carry siblings that share any one or two of those — collisions
	// here silently drop taints from the runtime cache.
	cases := []struct {
		name string
		want string
		got  string
	}{
		{
			name: "happy path",
			want: "pool1/taints/dedicated/team-a/NoSchedule",
			got:  nodeTaintID("pool1", "dedicated", "team-a", "NoSchedule"),
		},
		{
			name: "same key, different value",
			want: "pool1/taints/dedicated/team-b/NoSchedule",
			got:  nodeTaintID("pool1", "dedicated", "team-b", "NoSchedule"),
		},
		{
			name: "same key & value, different effect",
			want: "pool1/taints/dedicated/team-a/PreferNoSchedule",
			got:  nodeTaintID("pool1", "dedicated", "team-a", "PreferNoSchedule"),
		},
	}
	seen := make(map[string]string, len(cases))
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.got)
			if prev, exists := seen[tc.got]; exists {
				t.Fatalf("id collision: %q produced by both %q and %q", tc.got, prev, tc.name)
			}
			seen[tc.got] = tc.name
		})
	}
}

func TestBuildGKENotificationConfig(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		result, err := buildGKENotificationConfig(nil, "parent", nil)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("nil pubsub returns nil", func(t *testing.T) {
		nc := &containerpb.NotificationConfig{Pubsub: nil}
		result, err := buildGKENotificationConfig(nil, "parent", nc)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestGkeRbacInsecureBindings(t *testing.T) {
	t.Run("nil config defaults to secure (both false)", func(t *testing.T) {
		unauth, auth := gkeRbacInsecureBindings(nil)
		assert.False(t, unauth)
		assert.False(t, auth)
	})
	t.Run("flags are surfaced", func(t *testing.T) {
		trueVal, falseVal := true, false
		cfg := &containerpb.RBACBindingConfig{
			EnableInsecureBindingSystemUnauthenticated: &trueVal,
			EnableInsecureBindingSystemAuthenticated:   &falseVal,
		}
		unauth, auth := gkeRbacInsecureBindings(cfg)
		assert.True(t, unauth)
		assert.False(t, auth)
	})
}

func TestNewGkeDatabaseEncryption(t *testing.T) {
	t.Run("no configuration", func(t *testing.T) {
		got := newGkeDatabaseEncryption(nil)
		assert.Equal(t, gkeDatabaseEncryption{}, got)
	})

	t.Run("encrypted with a Cloud KMS key", func(t *testing.T) {
		got := newGkeDatabaseEncryption(&containerpb.DatabaseEncryption{
			State:        containerpb.DatabaseEncryption_ENCRYPTED,
			KeyName:      "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k",
			CurrentState: containerpb.DatabaseEncryption_CURRENT_STATE_ENCRYPTED.Enum(),
		})
		assert.Equal(t, "ENCRYPTED", got.state)
		assert.Equal(t, "CURRENT_STATE_ENCRYPTED", got.currentState)
		assert.Equal(t, "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k", got.keyName)
		assert.Equal(t, map[string]any{
			"state":        "ENCRYPTED",
			"keyName":      "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k",
			"currentState": "CURRENT_STATE_ENCRYPTED",
		}, got.dict)
	})

	t.Run("requested but failed", func(t *testing.T) {
		got := newGkeDatabaseEncryption(&containerpb.DatabaseEncryption{
			State:        containerpb.DatabaseEncryption_ENCRYPTED,
			KeyName:      "projects/p/locations/us-central1/keyRings/r/cryptoKeys/k",
			CurrentState: containerpb.DatabaseEncryption_CURRENT_STATE_ENCRYPTION_ERROR.Enum(),
		})
		assert.Equal(t, "ENCRYPTED", got.state)
		assert.Equal(t, "CURRENT_STATE_ENCRYPTION_ERROR", got.currentState)
	})

	t.Run("not encrypted", func(t *testing.T) {
		got := newGkeDatabaseEncryption(&containerpb.DatabaseEncryption{
			State:        containerpb.DatabaseEncryption_DECRYPTED,
			CurrentState: containerpb.DatabaseEncryption_CURRENT_STATE_DECRYPTED.Enum(),
		})
		assert.Equal(t, "DECRYPTED", got.state)
		assert.Equal(t, "CURRENT_STATE_DECRYPTED", got.currentState)
		assert.Empty(t, got.keyName)
	})

	t.Run("no current state reported", func(t *testing.T) {
		got := newGkeDatabaseEncryption(&containerpb.DatabaseEncryption{
			State: containerpb.DatabaseEncryption_DECRYPTED,
		})
		assert.Equal(t, "DECRYPTED", got.state)
		assert.Empty(t, got.currentState)
		require.Contains(t, got.dict, "currentState")
	})
}
