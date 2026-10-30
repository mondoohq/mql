// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseVolumeContentType(t *testing.T) {
	tests := []struct {
		volid string
		want  string
	}{
		// directory-backed storages name the class in the first segment
		{"local:iso/debian-12.iso", "iso"},
		{"local:vztmpl/debian-12-standard.tar.zst", "vztmpl"},
		{"local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst", "backup"},
		{"local:snippets/user-data.yaml", "snippets"},
		// PVE writes backups under "dump" on directory storages
		{"local:dump/vzdump-lxc-200-2024_01_01-00_00_00.tar.zst", "backup"},
		// guest disks on a directory storage live under the owning VMID
		{"local:100/vm-100-disk-0.qcow2", "images"},
		{"local:9999/vm-9999-disk-1.raw", "images"},
		// block-backed storages have no directory component at all
		{"local-lvm:vm-100-disk-0", "images"},
		{"ceph-rbd:vm-101-disk-0", "images"},
		// PBS volumes keep the backup prefix
		{"pbs:backup/vm/100/2024-01-01T00:00:00Z", "backup"},
		// unparseable inputs report nothing rather than guessing
		{"", ""},
		{"local:", ""},
		{"no-colon-at-all", ""},
		{"local:mystery/thing", ""},
	}

	for _, tc := range tests {
		t.Run(tc.volid, func(t *testing.T) {
			require.Equal(t, tc.want, ParseVolumeContentType(tc.volid))
		})
	}
}

func TestStorageContentTypePrefersAPIValue(t *testing.T) {
	// When the plugin reports the class, it wins over anything derived from
	// the volume id.
	v := StorageContent{VolID: "local:100/vm-100-disk-0.qcow2", Content: "rootdir"}
	require.Equal(t, "rootdir", v.ContentType())

	// With no reported class, the volid is the fallback.
	v = StorageContent{VolID: "local:iso/debian.iso"}
	require.Equal(t, "iso", v.ContentType())
}

func TestStorageHoldsBackups(t *testing.T) {
	require.True(t, storageHoldsBackups(StorageInfo{Enabled: 1, Content: "images,backup,iso"}))
	require.True(t, storageHoldsBackups(StorageInfo{Enabled: 1, Content: "backup"}))
	require.True(t, storageHoldsBackups(StorageInfo{Enabled: 1, Content: "images, backup"}))
	require.False(t, storageHoldsBackups(StorageInfo{Enabled: 1, Content: "images,iso"}))
	// a disabled storage cannot be serving anything
	require.False(t, storageHoldsBackups(StorageInfo{Enabled: 0, Content: "backup"}))
	// "backup" must match as a whole class, not as a substring
	require.False(t, storageHoldsBackups(StorageInfo{Enabled: 1, Content: "backupsomething"}))
}

func nodeListServer(t *testing.T) *fakePVE {
	t.Helper()
	f := newFakePVE(t)
	f.route("/nodes", []map[string]any{
		{"node": "pve1", "status": "online"},
		{"node": "pve2", "status": "online"},
		{"node": "pve3", "status": "offline"},
	})
	return f
}

func TestStorageNodes_SharedListedOnce(t *testing.T) {
	f := nodeListServer(t)
	// A shared storage holds one copy. Listing it from every node would
	// report each volume once per node.
	nodes, err := f.conn().StorageNodes(StorageInfo{Storage: "pbs", Shared: 1})
	require.NoError(t, err)
	require.Len(t, nodes, 1)
}

func TestStorageNodes_LocalListedPerNode(t *testing.T) {
	f := nodeListServer(t)
	// A local storage holds an independent copy per node.
	nodes, err := f.conn().StorageNodes(StorageInfo{Storage: "local", Shared: 0})
	require.NoError(t, err)
	require.Equal(t, []string{"pve1", "pve2"}, nodes, "offline nodes cannot be listed")
}

func TestStorageNodes_RespectsNodeRestriction(t *testing.T) {
	f := nodeListServer(t)
	nodes, err := f.conn().StorageNodes(StorageInfo{Storage: "local", Nodes: "pve2, pve3"})
	require.NoError(t, err)
	require.Equal(t, []string{"pve2"}, nodes,
		"the restriction narrows the candidates, and pve3 is offline")
}

func TestGetStorageContentTagsOrigin(t *testing.T) {
	f := nodeListServer(t)
	f.route("/nodes/pve1/storage/local/content", []map[string]any{
		{
			"volid": "local:backup/vzdump-qemu-100-2024_01_01-00_00_00.vma.zst",
			"ctime": 1704067200, "size": 1073741824, "vmid": 100,
			// Proxmox is Perl and sends 1, not JSON true. Using the real
			// wire format here is the point: a plain bool field decodes this
			// as false and the test would still pass.
			"format": "vma.zst", "protected": 1, "encrypted": "ab:cd",
			"verification": map[string]any{"state": "ok", "upid": "UPID:..."},
		},
	})

	content, err := f.conn().GetStorageContent("pve1", "local")
	require.NoError(t, err)
	require.Len(t, content, 1)
	require.Equal(t, "pve1", content[0].Node, "the listing node must be recorded")
	require.Equal(t, "local", content[0].Storage)
	require.Equal(t, "backup", content[0].ContentType())
	require.Equal(t, int64(1704067200), content[0].CTime)
	require.True(t, content[0].Protected.Bool())
	require.Equal(t, "ab:cd", content[0].Encrypted)
	require.Equal(t, "ok", content[0].Verification["state"])
}

func TestListStorageContent_SkipsUnreachableNode(t *testing.T) {
	f := nodeListServer(t)
	f.route("/nodes/pve1/storage/local/content", []map[string]any{
		{"volid": "local:iso/a.iso"},
	})
	f.errorRoute("/nodes/pve2/storage/local/content", http.StatusInternalServerError, "storage offline")

	// One unreachable node must not hide the volumes the others report.
	content, err := f.conn().ListStorageContent(StorageInfo{Storage: "local", Enabled: 1})
	require.NoError(t, err)
	require.Len(t, content, 1)
	require.Equal(t, "local:iso/a.iso", content[0].VolID)
}

func TestListStorageContent_SkipsDisabledStorage(t *testing.T) {
	f := nodeListServer(t)
	content, err := f.conn().ListStorageContent(StorageInfo{Storage: "local", Enabled: 0})
	require.NoError(t, err)
	require.Empty(t, content)
	for _, path := range f.requests {
		require.NotContains(t, path, "/content")
	}
}

func TestGetBackupsForGuest(t *testing.T) {
	f := nodeListServer(t)
	f.route("/storage", []map[string]any{
		{"storage": "pbs", "content": "backup", "shared": 1},
		// an image-only storage must not be swept for backups
		{"storage": "local-lvm", "content": "images", "shared": 0},
	})
	f.route("/nodes/pve1/storage/pbs/content", []map[string]any{
		{"volid": "pbs:backup/vm/100/2024-01-01T00:00:00Z", "vmid": 100, "ctime": 1704067200},
		{"volid": "pbs:backup/vm/100/2024-02-01T00:00:00Z", "vmid": 100, "ctime": 1706745600},
		{"volid": "pbs:backup/ct/200/2024-01-01T00:00:00Z", "vmid": 200, "ctime": 1704067200},
		// an orphan with no owning guest must not be indexed under VMID 0
		{"volid": "pbs:backup/vm/0/stray", "vmid": 0, "ctime": 1704067200},
	})
	conn := f.conn()

	vm100, err := conn.GetBackupsForGuest(100)
	require.NoError(t, err)
	require.Len(t, vm100, 2)

	ct200, err := conn.GetBackupsForGuest(200)
	require.NoError(t, err)
	require.Len(t, ct200, 1)

	none, err := conn.GetBackupsForGuest(999)
	require.NoError(t, err)
	require.Empty(t, none)

	for _, path := range f.requests {
		require.NotContains(t, path, "local-lvm", "image-only storages must be skipped")
	}
}

func TestGetBackupsForGuest_SweepsOnce(t *testing.T) {
	f := nodeListServer(t)
	f.route("/storage", []map[string]any{{"storage": "pbs", "content": "backup", "shared": 1}})
	f.route("/nodes/pve1/storage/pbs/content", []map[string]any{
		{"volid": "pbs:backup/vm/100/a", "vmid": 100, "ctime": 1704067200},
	})
	conn := f.conn()

	for _, vmid := range []int{100, 101, 102, 100} {
		_, err := conn.GetBackupsForGuest(vmid)
		require.NoError(t, err)
	}

	var sweeps int
	for _, path := range f.requests {
		if path == "/nodes/pve1/storage/pbs/content" {
			sweeps++
		}
	}
	require.Equal(t, 1, sweeps, "asking every guest must not re-sweep every storage")
}
