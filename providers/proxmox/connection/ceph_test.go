// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// cephReadyServer wires the two routes the availability probe needs: a
// healthy ceph status and a node list to pick the query node from.
func cephReadyServer(t *testing.T) *fakePVE {
	t.Helper()
	f := newFakePVE(t)
	f.route("/cluster/ceph/status", map[string]any{
		"health": map[string]any{"status": "HEALTH_OK"},
	})
	f.route("/nodes", []map[string]any{
		{"node": "pve0", "status": "offline"},
		{"node": "pve1", "status": "online"},
	})
	return f
}

func TestCephAvailable_NotConfigured(t *testing.T) {
	f := newFakePVE(t)
	// PVE dies with "configuration not initialized" when pveceph was never
	// run, which surfaces as a 500.
	f.errorRoute("/cluster/ceph/status", http.StatusInternalServerError,
		"rados_connect failed - No such file or directory")

	available, node, err := f.conn().CephAvailable()
	require.NoError(t, err, "a cluster without ceph is not an error")
	require.False(t, available)
	require.Empty(t, node)
}

func TestCephAvailable_PermissionDeniedIsAnError(t *testing.T) {
	// The whole point of separating these: a token that cannot read ceph
	// must not be reported as a cluster that has no ceph, or every ceph
	// policy check passes vacuously.
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		f := newFakePVE(t)
		f.errorRoute("/cluster/ceph/status", status, "Permission check failed")

		available, _, err := f.conn().CephAvailable()
		require.Error(t, err, "status %d must surface as an error", status)
		require.False(t, available)
	}
}

func TestCephAvailable_PicksFirstOnlineNode(t *testing.T) {
	f := cephReadyServer(t)

	available, node, err := f.conn().CephAvailable()
	require.NoError(t, err)
	require.True(t, available)
	require.Equal(t, "pve1", node, "offline nodes cannot answer ceph queries")
}

func TestCephAvailable_NoOnlineNodeIsAnError(t *testing.T) {
	f := newFakePVE(t)
	f.route("/cluster/ceph/status", map[string]any{})
	f.route("/nodes", []map[string]any{{"node": "pve0", "status": "offline"}})

	_, _, err := f.conn().CephAvailable()
	require.Error(t, err)
}

func TestCephProbeRunsOnce(t *testing.T) {
	f := cephReadyServer(t)
	conn := f.conn()

	for range 3 {
		_, _, err := conn.CephAvailable()
		require.NoError(t, err)
	}

	var probes int
	for _, path := range f.requests {
		if path == "/cluster/ceph/status" {
			probes++
		}
	}
	require.Equal(t, 1, probes, "the availability probe must be memoized")
}

func TestCephListsAreEmptyWithoutCeph(t *testing.T) {
	f := newFakePVE(t)
	f.errorRoute("/cluster/ceph/status", http.StatusInternalServerError, "not initialized")
	conn := f.conn()

	mons, err := conn.GetCephMonitors()
	require.NoError(t, err)
	require.Empty(t, mons)

	pools, err := conn.GetCephPools()
	require.NoError(t, err)
	require.Empty(t, pools)

	osds, err := conn.GetCephOSDs()
	require.NoError(t, err)
	require.Empty(t, osds)

	rules, err := conn.GetCephCrushRules()
	require.NoError(t, err)
	require.Empty(t, rules)

	// No per-node ceph route should have been attempted at all.
	for _, path := range f.requests {
		require.NotContains(t, path, "/ceph/mon")
		require.NotContains(t, path, "/ceph/pool")
	}
}

func TestGetCephMonitors(t *testing.T) {
	f := cephReadyServer(t)
	f.route("/nodes/pve1/ceph/mon", []map[string]any{
		{
			"name": "pve1", "host": "pve1", "addr": "10.0.0.1:6789/0",
			"quorum": 1, "rank": 0, "state": "running",
			"service": 1, "direxists": 1,
			"ceph_version_short": "19.2.0",
		},
		{
			"name": "pve2", "host": "pve2", "quorum": 0, "state": "stopped",
		},
	})

	mons, err := f.conn().GetCephMonitors()
	require.NoError(t, err)
	require.Len(t, mons, 2)
	require.True(t, mons[0].Quorum.Bool())
	require.Equal(t, "10.0.0.1:6789/0", mons[0].Addr)
	require.Equal(t, "19.2.0", mons[0].CephVersionShort)
	require.NotNil(t, mons[0].Rank)
	require.Equal(t, 0, *mons[0].Rank)
	require.False(t, mons[1].Quorum.Bool())
	require.Nil(t, mons[1].Rank, "an omitted rank must stay null, not read as rank 0")
}

func TestGetCephPools(t *testing.T) {
	f := cephReadyServer(t)
	f.route("/nodes/pve1/ceph/pool", []map[string]any{
		{
			"pool": 2, "pool_name": "vm-data", "type": "replicated",
			"size": 3, "min_size": 2, "pg_num": 128,
			"pg_autoscale_mode": "on", "crush_rule": 0,
			"crush_rule_name": "replicated_rule",
			"bytes_used":      1234567, "percent_used": 0.42,
			"application_metadata": map[string]any{"rbd": map[string]any{}},
		},
	})

	pools, err := f.conn().GetCephPools()
	require.NoError(t, err)
	require.Len(t, pools, 1)
	require.Equal(t, "vm-data", pools[0].PoolName)
	require.Equal(t, 3, pools[0].Size)
	require.Equal(t, 2, pools[0].MinSize)
	require.Equal(t, "replicated_rule", pools[0].CrushRuleName)
	require.InDelta(t, 0.42, pools[0].PercentUsed, 0.0001)
	require.Contains(t, pools[0].ApplicationMetadata, "rbd")
}

func TestGetCephConfig(t *testing.T) {
	f := cephReadyServer(t)
	f.route("/nodes/pve1/ceph/cfg/db", []map[string]any{
		{
			"section": "global", "name": "auth_cluster_required",
			"value": "cephx", "mask": "", "level": "advanced",
			"can_update_at_runtime": 0,
		},
	})

	entries, err := f.conn().GetCephConfig()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	require.Equal(t, "global", entries[0].Section)
	require.Equal(t, "cephx", entries[0].Value)
	require.False(t, entries[0].CanUpdateAtRuntime.Bool())
}

func TestGetCephCrushRules(t *testing.T) {
	f := cephReadyServer(t)
	f.route("/nodes/pve1/ceph/rules", []map[string]any{
		{"name": "replicated_rule"},
		{"name": "ssd_only"},
	})

	rules, err := f.conn().GetCephCrushRules()
	require.NoError(t, err)
	require.Equal(t, []string{"replicated_rule", "ssd_only"}, rules)
}

func TestGetCephFileSystems(t *testing.T) {
	f := cephReadyServer(t)
	f.route("/nodes/pve1/ceph/fs", []map[string]any{
		{
			"name": "cephfs", "metadata_pool": "cephfs_metadata",
			"data_pool":  "cephfs_data",
			"data_pools": []string{"cephfs_data", "cephfs_data_ec"},
		},
	})

	systems, err := f.conn().GetCephFileSystems()
	require.NoError(t, err)
	require.Len(t, systems, 1)
	require.Equal(t, "cephfs_metadata", systems[0].MetadataPool)
	require.Equal(t, []string{"cephfs_data", "cephfs_data_ec"}, systems[0].DataPools)
}

// ---------------------------------------------------------------------------
// CRUSH tree flattening
// ---------------------------------------------------------------------------

//go:fix inline
func intPtr(v int) *int { return new(v) }

func TestFlattenCephCrushTree(t *testing.T) {
	root := CephCrushNode{
		ID: -1, Name: "default", Type: "root",
		Children: []CephCrushNode{
			{
				ID: -3, Name: "pve1", Type: "host",
				Children: []CephCrushNode{
					{
						ID: 0, Name: "osd.0", Type: "osd", Status: "up",
						In: new(1), DeviceClass: "ssd", CrushWeight: 0.5,
						Reweight: 1, TotalSpace: 1000, BytesUsed: 250,
						PercentUsed: 25,
					},
					{
						ID: 1, Name: "osd.1", Type: "osd", Status: "down",
						In: new(0), DeviceClass: "hdd",
					},
				},
			},
			{
				ID: -5, Name: "pve2", Type: "host",
				Children: []CephCrushNode{
					{ID: 2, Name: "osd.2", Type: "osd", Status: "up", In: new(1)},
				},
			},
		},
	}

	osds := FlattenCephCrushTree(root)
	require.Len(t, osds, 3, "only osd leaves are returned; buckets are not OSDs")

	require.Equal(t, 0, osds[0].ID)
	require.Equal(t, "pve1", osds[0].Host, "leaves inherit the enclosing host bucket")
	require.Equal(t, "up", osds[0].Status)
	require.Equal(t, "ssd", osds[0].DeviceClass)
	require.InDelta(t, 25.0, osds[0].PercentUsed, 0.0001)

	require.Equal(t, "pve1", osds[1].Host)
	require.Equal(t, "down", osds[1].Status)
	require.Equal(t, 0, *osds[1].In)

	require.Equal(t, "pve2", osds[2].Host)
}

func TestFlattenCephCrushTree_ExplicitHostWins(t *testing.T) {
	root := CephCrushNode{
		Type: "root",
		Children: []CephCrushNode{{
			Name: "bucket-name", Type: "host",
			Children: []CephCrushNode{
				{ID: 7, Name: "osd.7", Type: "osd", Host: "real-host"},
			},
		}},
	}

	osds := FlattenCephCrushTree(root)
	require.Len(t, osds, 1)
	require.Equal(t, "real-host", osds[0].Host)
}

func TestFlattenCephCrushTree_MissingStateStaysNull(t *testing.T) {
	root := CephCrushNode{
		Type:     "root",
		Children: []CephCrushNode{{ID: 4, Name: "osd.4", Type: "osd"}},
	}

	osds := FlattenCephCrushTree(root)
	require.Len(t, osds, 1)
	require.Empty(t, osds[0].Status)
	require.Nil(t, osds[0].In, "an absent `in` must not read as out")
}

func TestFlattenCephCrushTree_Empty(t *testing.T) {
	require.Empty(t, FlattenCephCrushTree(CephCrushNode{}))
}

// ---------------------------------------------------------------------------
// OSD metadata merge
// ---------------------------------------------------------------------------

func cephOSDTreeRoute(f *fakePVE) {
	f.route("/nodes/pve1/ceph/osd", map[string]any{
		"root": map[string]any{
			"id": -1, "name": "default", "type": "root",
			"children": []map[string]any{{
				"id": -3, "name": "pve1", "type": "host",
				"children": []map[string]any{
					{"id": 0, "name": "osd.0", "type": "osd", "status": "up", "in": 1, "device_class": "ssd"},
					{"id": 1, "name": "osd.1", "type": "osd", "status": "up", "in": 1, "device_class": "ssd"},
				},
			}},
		},
	})
}

func TestGetCephOSDs_MergesMetadata(t *testing.T) {
	f := cephReadyServer(t)
	cephOSDTreeRoute(f)
	f.route("/cluster/ceph/metadata", map[string]any{
		"osd": []map[string]any{
			{
				"id": 0, "hostname": "pve1", "ceph_version_short": "19.2.0",
				"ceph_release": "squid", "osd_objectstore": "bluestore",
				"devices": "sdb", "front_addr": "10.0.0.1:6800/1",
				"back_addr": "10.10.0.1:6801/1", "osd_data": "/var/lib/ceph/osd/ceph-0",
			},
			// no metadata entry for osd.1
		},
		"node": map[string]any{"pve1": map[string]any{"version": "19.2.0"}},
	})

	osds, err := f.conn().GetCephOSDs()
	require.NoError(t, err)
	require.Len(t, osds, 2)

	require.Equal(t, "bluestore", osds[0].ObjectStore)
	require.Equal(t, "squid", osds[0].CephRelease)
	require.Equal(t, "sdb", osds[0].Devices)
	require.Equal(t, "10.10.0.1:6801/1", osds[0].BackAddr)

	// The tree stays the source of record: an OSD with no metadata entry is
	// still reported, just without the enrichment columns.
	require.Equal(t, 1, osds[1].ID)
	require.Equal(t, "up", osds[1].Status)
	require.Empty(t, osds[1].ObjectStore)
}

func TestGetCephOSDs_MetadataFailureKeepsInventory(t *testing.T) {
	f := cephReadyServer(t)
	cephOSDTreeRoute(f)
	f.errorRoute("/cluster/ceph/metadata", http.StatusForbidden, "Permission check failed")

	osds, err := f.conn().GetCephOSDs()
	require.NoError(t, err, "metadata is enrichment; losing it must not drop the OSD list")
	require.Len(t, osds, 2)
	require.Equal(t, "ssd", osds[0].DeviceClass)
	require.Empty(t, osds[0].CephVersionShort)
}

func TestGetCephOSDs_TreeFailureIsAnError(t *testing.T) {
	f := cephReadyServer(t)
	f.errorRoute("/nodes/pve1/ceph/osd", http.StatusInternalServerError, "boom")

	_, err := f.conn().GetCephOSDs()
	require.Error(t, err, "losing the tree means losing the inventory, which must not be silent")
}

func TestGetCephNodeVersions(t *testing.T) {
	f := cephReadyServer(t)
	f.route("/cluster/ceph/metadata", map[string]any{
		"node": map[string]any{"pve1": map[string]any{"version": "19.2.0"}},
	})

	versions, err := f.conn().GetCephNodeVersions()
	require.NoError(t, err)
	require.Contains(t, versions, "pve1")
}

func TestGetCephStatusPassesThroughRawReport(t *testing.T) {
	f := cephReadyServer(t)

	status, err := f.conn().GetCephStatus()
	require.NoError(t, err)
	health, ok := status["health"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "HEALTH_OK", health["status"])
}
