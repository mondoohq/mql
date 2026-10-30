// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLookupNode_Hit(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes", []map[string]any{
		{"node": "pve1", "status": "online"},
		{"node": "pve2", "status": "offline"},
	})
	f.route("/cluster/status", []map[string]any{
		{"type": "cluster", "name": "prod"},
		{"type": "node", "name": "pve1", "ip": "10.0.0.11"},
		{"type": "node", "name": "pve2", "ip": "10.0.0.12"},
	})
	conn := f.conn()

	n, found, err := conn.LookupNode("pve2")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "pve2", n.Name)
	require.Equal(t, "offline", n.Status)
	require.Equal(t, "10.0.0.12", n.IP)
}

func TestLookupNode_Miss(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes", []map[string]any{{"node": "pve1", "status": "online"}})
	f.route("/cluster/status", []map[string]any{})
	conn := f.conn()

	// A node name that is no longer in the cluster must report "not found"
	// rather than an error, so the caller can render the reference as null.
	n, found, err := conn.LookupNode("decommissioned")
	require.NoError(t, err)
	require.False(t, found)
	require.Equal(t, NodeDetail{}, n)
}

func TestLookupNode_EmptyName(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes", []map[string]any{{"node": "pve1", "status": "online"}})
	f.route("/cluster/status", []map[string]any{})
	conn := f.conn()

	_, found, err := conn.LookupNode("")
	require.NoError(t, err)
	require.False(t, found)
}

// TestLookupNode_StandaloneHostHasNoClusterStatus pins that a host with no
// cluster membership still resolves. /cluster/status is unavailable there, and
// treating that as fatal would make every node reference on a standalone host
// fail instead of simply reporting no address.
func TestLookupNode_StandaloneHostHasNoClusterStatus(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes", []map[string]any{{"node": "pve", "status": "online"}})
	f.errorRoute("/cluster/status", 501, "no cluster")
	conn := f.conn()

	n, found, err := conn.LookupNode("pve")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, "online", n.Status)
	require.Empty(t, n.IP)
}

// TestLookupNode_ErrorMemoized pins that an unreadable node listing fails
// every lookup with the same error and is not retried per item.
func TestLookupNode_ErrorMemoized(t *testing.T) {
	f := newFakePVE(t)
	f.errorRoute("/nodes", 403, "Permission check failed")
	conn := f.conn()

	for range 3 {
		_, found, err := conn.LookupNode("pve1")
		require.Error(t, err)
		require.False(t, found)
	}

	var attempts int
	for _, path := range f.requests {
		if path == "/nodes" {
			attempts++
		}
	}
	require.Equal(t, 1, attempts, "a failed node listing must not be retried per lookup")
}

// TestLookupNode_IndexesOnce is the property the whole index exists for: node
// references hang off every guest and every Ceph daemon, so resolving them
// must not re-list the cluster once per item.
func TestLookupNode_IndexesOnce(t *testing.T) {
	f := newFakePVE(t)
	f.route("/nodes", []map[string]any{
		{"node": "pve1", "status": "online"},
		{"node": "pve2", "status": "online"},
	})
	f.route("/cluster/status", []map[string]any{
		{"type": "node", "name": "pve1", "ip": "10.0.0.11"},
	})
	conn := f.conn()

	for _, name := range []string{"pve1", "pve2", "pve1", "gone", "pve2"} {
		_, _, err := conn.LookupNode(name)
		require.NoError(t, err)
	}

	var nodeCalls, statusCalls int
	for _, path := range f.requests {
		switch path {
		case "/nodes":
			nodeCalls++
		case "/cluster/status":
			statusCalls++
		}
	}
	require.Equal(t, 1, nodeCalls, "node listing must be fetched once per connection")
	require.Equal(t, 1, statusCalls, "cluster status must be fetched once per connection")
}
