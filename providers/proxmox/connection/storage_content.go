// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
)

// StorageContent is one volume stored on a Proxmox storage: a backup archive,
// an ISO image, a container template, a guest disk, or a snippet.
type StorageContent struct {
	VolID string `json:"volid"`
	// Content is the volume class. PVE returns it on most storage plugins but
	// does not guarantee it, so ContentType() falls back to the volid.
	Content   string  `json:"content"`
	Format    string  `json:"format"`
	Size      int64   `json:"size"`
	Used      int64   `json:"used"`
	CTime     int64   `json:"ctime"`
	VMID      int     `json:"vmid"`
	Notes     string  `json:"notes"`
	Parent    string  `json:"parent"`
	Protected PveBool `json:"protected"`
	// Encrypted is the PBS encryption marker: either a key fingerprint or the
	// literal "1". Empty when the volume is not encrypted.
	Encrypted string `json:"encrypted"`
	// Verification is the last PBS verification result, with `state` (`ok` or
	// `failed`) and `upid`. Absent on non-PBS storages.
	Verification map[string]any `json:"verification"`

	// Node is the node the volume was listed from. Local storages hold a
	// separate copy per node, so this distinguishes them.
	Node string `json:"-"`
	// Storage is the storage the volume lives on.
	Storage string `json:"-"`
}

// ContentType returns the volume class, preferring what the API reported and
// falling back to the volid when the storage plugin omitted it.
func (s StorageContent) ContentType() string {
	if s.Content != "" {
		return s.Content
	}
	return ParseVolumeContentType(s.VolID)
}

// knownContentDirs are the directory names Proxmox uses inside a storage for
// each content class. A volid segment matching one of these names the class
// directly.
var knownContentDirs = map[string]string{
	"backup":   "backup",
	"dump":     "backup",
	"iso":      "iso",
	"template": "vztmpl",
	"vztmpl":   "vztmpl",
	"snippets": "snippets",
	"images":   "images",
	"rootdir":  "rootdir",
	"private":  "rootdir",
}

// ParseVolumeContentType derives a volume's content class from its volume id.
//
// A volid is `<storage>:<path>`. Directory-backed storages put the class in
// the first path segment (`local:iso/debian.iso`) except for guest disks,
// which live under the owning VMID (`local:100/vm-100-disk-0.qcow2`).
// Block-backed storages have no path segment at all
// (`local-lvm:vm-100-disk-0`), and always hold guest disks.
func ParseVolumeContentType(volid string) string {
	_, path, found := strings.Cut(volid, ":")
	if !found || path == "" {
		return ""
	}
	segment, rest, hasSlash := strings.Cut(path, "/")
	if !hasSlash || rest == "" {
		// No directory component: a block-backed guest volume.
		return "images"
	}
	if class, ok := knownContentDirs[segment]; ok {
		return class
	}
	if _, err := strconv.Atoi(segment); err == nil {
		// A numeric segment is the owning VMID, so this is a guest disk.
		return "images"
	}
	return ""
}

// GetStorageContent lists the volumes on one storage as seen from one node.
func (c *PveConnection) GetStorageContent(node, storage string) ([]StorageContent, error) {
	var content []StorageContent
	path := fmt.Sprintf("/nodes/%s/storage/%s/content", node, storage)
	if err := c.apiGet(path, &content); err != nil {
		return nil, fmt.Errorf("failed to list content of storage %s on node %s: %w", storage, node, err)
	}
	for i := range content {
		content[i].Node = node
		content[i].Storage = storage
	}
	return content, nil
}

// StorageNodes returns the nodes a storage should be listed from.
//
// A shared storage holds one copy visible from every node, so it is listed
// from a single node; listing it from all of them would report each volume
// once per node. A local storage holds an independent copy per node, so every
// candidate node is listed. The storage's own `nodes` restriction narrows the
// candidates when set.
func (c *PveConnection) StorageNodes(s StorageInfo) ([]string, error) {
	online, err := c.onlineNodes()
	if err != nil {
		return nil, err
	}
	candidates := online
	if s.Nodes != "" {
		restricted := map[string]bool{}
		for n := range strings.SplitSeq(s.Nodes, ",") {
			restricted[strings.TrimSpace(n)] = true
		}
		candidates = nil
		for _, n := range online {
			if restricted[n] {
				candidates = append(candidates, n)
			}
		}
	}
	if s.Shared == 1 && len(candidates) > 1 {
		return candidates[:1], nil
	}
	return candidates, nil
}

func (c *PveConnection) onlineNodes() ([]string, error) {
	nodes, err := c.GetNodes()
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %w", err)
	}
	var online []string
	for _, n := range nodes {
		if n.Status == "online" {
			online = append(online, n.Node)
		}
	}
	return online, nil
}

// ListStorageContent lists every volume on one storage across the nodes that
// should serve it. A node that cannot answer is logged and skipped: a single
// unreachable node must not hide the volumes the others do report.
func (c *PveConnection) ListStorageContent(s StorageInfo) ([]StorageContent, error) {
	if s.Enabled == 0 {
		return nil, nil
	}
	nodes, err := c.StorageNodes(s)
	if err != nil {
		return nil, err
	}
	var out []StorageContent
	for _, node := range nodes {
		content, err := c.GetStorageContent(node, s.Storage)
		if err != nil {
			log.Warn().Err(err).Str("storage", s.Storage).Str("node", node).
				Msg("proxmox: could not list storage content")
			continue
		}
		out = append(out, content...)
	}
	return out, nil
}

// backupIndex memoizes the cluster-wide backup listing so that asking every
// guest for its backups costs one sweep instead of one sweep per guest.
type backupIndex struct {
	once   sync.Once
	byVMID map[int][]StorageContent
	err    error
}

// GetBackupsForGuest returns every backup volume owned by a guest, across all
// storages that hold backups. The underlying sweep runs once per connection.
func (c *PveConnection) GetBackupsForGuest(vmid int) ([]StorageContent, error) {
	c.backups.once.Do(c.buildBackupIndex)
	if c.backups.err != nil {
		return nil, c.backups.err
	}
	return c.backups.byVMID[vmid], nil
}

func (c *PveConnection) buildBackupIndex() {
	storages, err := c.GetStorages()
	if err != nil {
		c.backups.err = err
		return
	}
	index := map[int][]StorageContent{}
	for _, s := range storages {
		if !storageHoldsBackups(s) {
			continue
		}
		content, err := c.ListStorageContent(s)
		if err != nil {
			c.backups.err = err
			return
		}
		for _, v := range content {
			if v.ContentType() != "backup" || v.VMID == 0 {
				continue
			}
			index[v.VMID] = append(index[v.VMID], v)
		}
	}
	c.backups.byVMID = index
}

// storageHoldsBackups reports whether a storage is configured to accept backup
// archives, so the sweep skips storages that cannot hold any.
func storageHoldsBackups(s StorageInfo) bool {
	if s.Enabled == 0 {
		return false
	}
	for class := range strings.SplitSeq(s.Content, ",") {
		if strings.TrimSpace(class) == "backup" {
			return true
		}
	}
	return false
}
