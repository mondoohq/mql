// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLookupStorage_Hit(t *testing.T) {
	f := newFakePVE(t)
	f.route("/storage", []map[string]any{
		{"storage": "local", "type": "dir", "content": "iso,vztmpl"},
		{"storage": "pbs", "type": "pbs", "content": "backup", "shared": 1, "encryption-key": "autogen"},
	})
	conn := f.conn()

	s, found, err := conn.LookupStorage("pbs")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "pbs", s.Storage)
	require.Equal(t, "backup", s.Content)
	require.Equal(t, 1, s.Shared)
	require.Equal(t, "autogen", s.EncryptionKey)
}

// TestLookupStorage_NormalizesEnabled pins that the index carries the same
// normalized Enabled the direct listing does, rather than the raw cluster
// config shape where every storage reads as disabled.
func TestLookupStorage_NormalizesEnabled(t *testing.T) {
	f := newFakePVE(t)
	f.route("/storage", []map[string]any{
		{"storage": "on", "disable": 0},
		{"storage": "off", "disable": 1},
	})
	conn := f.conn()

	on, found, err := conn.LookupStorage("on")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 1, on.Enabled)

	off, found, err := conn.LookupStorage("off")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, 0, off.Enabled)
}

func TestLookupStorage_Miss(t *testing.T) {
	f := newFakePVE(t)
	f.route("/storage", []map[string]any{{"storage": "local", "type": "dir"}})
	conn := f.conn()

	s, found, err := conn.LookupStorage("removed-pool")
	require.NoError(t, err)
	require.False(t, found)
	require.Equal(t, StorageInfo{}, s)
}

func TestLookupStorage_EmptyName(t *testing.T) {
	f := newFakePVE(t)
	f.route("/storage", []map[string]any{{"storage": "local", "type": "dir"}})
	conn := f.conn()

	_, found, err := conn.LookupStorage("")
	require.NoError(t, err)
	require.False(t, found)
}

// TestLookupStorage_ErrorMemoized pins that an unreadable storage listing
// fails every lookup with the same error and is not retried per item.
func TestLookupStorage_ErrorMemoized(t *testing.T) {
	f := newFakePVE(t)
	f.errorRoute("/storage", 403, "Permission check failed")
	conn := f.conn()

	for range 3 {
		_, found, err := conn.LookupStorage("local")
		require.Error(t, err)
		require.False(t, found)
	}

	var attempts int
	for _, path := range f.requests {
		if path == "/storage" {
			attempts++
		}
	}
	require.Equal(t, 1, attempts, "a failed storage listing must not be retried per lookup")
}

func TestLookupStorage_IndexesOnce(t *testing.T) {
	f := newFakePVE(t)
	f.route("/storage", []map[string]any{
		{"storage": "local", "type": "dir"},
		{"storage": "local-lvm", "type": "lvmthin"},
	})
	conn := f.conn()

	for _, name := range []string{"local", "local-lvm", "local", "gone"} {
		_, _, err := conn.LookupStorage(name)
		require.NoError(t, err)
	}

	var calls int
	for _, path := range f.requests {
		if path == "/storage" {
			calls++
		}
	}
	require.Equal(t, 1, calls, "storage listing must be fetched once per connection")
}
