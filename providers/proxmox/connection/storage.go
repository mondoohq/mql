// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"sync"
)

// ---------------------------------------------------------------------------
// Storage pools
// ---------------------------------------------------------------------------

type StorageInfo struct {
	Storage string `json:"storage"`
	Type    string `json:"type"`
	Content string `json:"content"`
	Path    string `json:"path"`
	Enabled int    `json:"enabled"`
	// Disable is the cluster /storage config key (1 = disabled); /nodes/<n>/storage
	// uses "enabled" instead. GetStorages normalizes Enabled from Disable.
	Disable  int     `json:"disable"`
	Shared   int     `json:"shared"`
	Total    int64   `json:"total"`
	Used     int64   `json:"used"`
	Avail    int64   `json:"avail"`
	UsedFrac float64 `json:"used_fraction"`
	// EncryptionKey carries the PBS encryption-key field. The value is
	// either an explicit key fingerprint or the literal "autogen" when
	// Proxmox manages the key. An empty string means encryption is off.
	EncryptionKey string `json:"encryption-key"`
	// Nodes is the comma-separated node restriction from the storage config.
	// Empty means the storage is available on every node.
	Nodes string `json:"nodes"`
	// Active reports whether the storage is currently reachable. Only the
	// per-node /nodes/<n>/storage endpoint returns it.
	Active int `json:"active"`
}

func (c *PveConnection) GetStorages() ([]StorageInfo, error) {
	var storages []StorageInfo
	if err := c.apiGet("/storage", &storages); err != nil {
		return nil, fmt.Errorf("failed to get storages: %w", err)
	}
	normalizeClusterStorageEnabled(storages)
	return storages, nil
}

// normalizeClusterStorageEnabled derives Enabled from the cluster /storage
// "disable" config key. That endpoint reports config (disable), not the runtime
// "enabled" key that /nodes/<n>/storage returns, so without this every
// cluster-level storage reads as enabled=false. Enabled is only inferred when
// the response didn't already provide it, so an endpoint returning both keys
// keeps its explicit value.
func normalizeClusterStorageEnabled(storages []StorageInfo) {
	for i := range storages {
		if storages[i].Disable != 0 {
			storages[i].Enabled = 0
		} else if storages[i].Enabled == 0 {
			storages[i].Enabled = 1
		}
	}
}

// ---------------------------------------------------------------------------
// Storage index
// ---------------------------------------------------------------------------

// storageIndex memoizes the cluster's storage listing, keyed by storage name.
// Every guest disk, mount point, and stored volume names the pool it sits on,
// so resolving those references per item would re-list every storage once per
// item. The error is memoized alongside the value so an unreadable listing
// fails once instead of on every lookup.
type storageIndex struct {
	once   sync.Once
	byName map[string]StorageInfo
	err    error
}

// LookupStorage returns the storage with the given name. The boolean result
// is false when the cluster has no such storage, which lets callers report a
// dangling reference as null instead of fabricating a blank storage.
func (c *PveConnection) LookupStorage(name string) (StorageInfo, bool, error) {
	c.storages.once.Do(c.buildStorageIndex)
	if c.storages.err != nil {
		return StorageInfo{}, false, c.storages.err
	}
	s, ok := c.storages.byName[name]
	return s, ok, nil
}

func (c *PveConnection) buildStorageIndex() {
	storages, err := c.GetStorages()
	if err != nil {
		c.storages.err = fmt.Errorf("failed to index storages: %w", err)
		return
	}
	index := make(map[string]StorageInfo, len(storages))
	for _, s := range storages {
		index[s.Storage] = s
	}
	c.storages.byName = index
}

// ---------------------------------------------------------------------------
// Resource pools
// ---------------------------------------------------------------------------

type PoolInfo struct {
	PoolID  string `json:"poolid"`
	Comment string `json:"comment"`
}

func (c *PveConnection) GetPools() ([]PoolInfo, error) {
	var pools []PoolInfo
	if err := c.apiGet("/pools", &pools); err != nil {
		return nil, fmt.Errorf("failed to get pools: %w", err)
	}
	return pools, nil
}
