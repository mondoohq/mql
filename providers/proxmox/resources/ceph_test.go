// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"go.mondoo.com/mql/providers/proxmox/connection"
)

func TestCephDataPools(t *testing.T) {
	tests := []struct {
		name string
		fs   connection.CephFS
		want []any
	}{
		{
			name: "full list preferred",
			fs: connection.CephFS{
				DataPool:  "cephfs_data",
				DataPools: []string{"cephfs_data", "cephfs_data_ec"},
			},
			want: []any{"cephfs_data", "cephfs_data_ec"},
		},
		{
			// Older releases report only the first data pool. Falling back
			// keeps a single-pool CephFS from looking like it has none.
			name: "falls back to the singular field",
			fs:   connection.CephFS{DataPool: "cephfs_data"},
			want: []any{"cephfs_data"},
		},
		{
			name: "neither reported",
			fs:   connection.CephFS{},
			want: []any{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := cephDataPools(tc.fs)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("index %d: got %v, want %v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// The same Ceph config key can be set more than once with different masks
// (e.g. a global default plus a per-device-class override). If the mask were
// left out of the cache key the two entries would collide and the second
// would silently return the first one's value.
func TestCephConfigEntryKeyIncludesMask(t *testing.T) {
	global := cephConfigEntryKey("osd", "osd_memory_target", "")
	masked := cephConfigEntryKey("osd", "osd_memory_target", "class:ssd")

	if global == masked {
		t.Fatalf("masked and unmasked entries share cache key %q", global)
	}
	if want := "proxmox.ceph.configEntry/osd/osd_memory_target/"; global != want {
		t.Errorf("got %q, want %q", global, want)
	}
}

func TestCephConfigEntryKeyDistinguishesSections(t *testing.T) {
	a := cephConfigEntryKey("global", "auth_cluster_required", "")
	b := cephConfigEntryKey("mon", "auth_cluster_required", "")
	if a == b {
		t.Fatalf("entries in different sections share cache key %q", a)
	}
}
