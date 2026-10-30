// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
)

// Ceph routes come in two shapes. `/cluster/ceph/*` answers for the whole
// cluster, while `/nodes/{node}/ceph/*` is nominally per-node but reads the
// shared mon map, so any node that runs Ceph returns the same cluster-wide
// answer. We therefore resolve one Ceph-capable node once and reuse it for
// every list, instead of fanning out across the cluster.

// cephProbe memoizes whether this cluster runs Ceph at all, plus the node
// used to answer the cluster-wide Ceph routes.
type cephProbe struct {
	once      sync.Once
	available bool
	node      string
	status    map[string]any
	err       error
}

// CephAvailable reports whether the cluster has Ceph configured, along with
// the node used to serve Ceph queries.
//
// A cluster with no Ceph is a normal, expected state, not a failure: PVE
// answers the Ceph routes with a 5xx when `pveceph` was never initialized.
// That case yields (false, nil). A permission failure is NOT folded into
// that answer — it returns an error, so a token that merely lacks Sys.Audit
// can never be mistaken for a cluster without Ceph.
func (c *PveConnection) CephAvailable() (bool, string, error) {
	c.ceph.once.Do(c.probeCeph)
	return c.ceph.available, c.ceph.node, c.ceph.err
}

func (c *PveConnection) probeCeph() {
	var status map[string]any
	err := c.apiGet("/cluster/ceph/status", &status)
	if err != nil {
		var apiErr *APIError
		if errors.As(err, &apiErr) && (apiErr.StatusCode == 401 || apiErr.StatusCode == 403) {
			c.ceph.err = fmt.Errorf("failed to query ceph status: %w", err)
			return
		}
		// Any other API error means Ceph is not set up on this cluster (PVE
		// dies with "pveceph configuration not initialized" -> 500) or the
		// route does not exist on this release. Both are "no Ceph here".
		log.Debug().Err(err).Msg("proxmox: ceph not available on this cluster")
		return
	}

	node, err := c.firstOnlineNode()
	if err != nil {
		c.ceph.err = err
		return
	}

	c.ceph.available = true
	c.ceph.node = node
	c.ceph.status = status
}

func (c *PveConnection) firstOnlineNode() (string, error) {
	nodes, err := c.GetNodes()
	if err != nil {
		return "", fmt.Errorf("failed to list nodes for ceph queries: %w", err)
	}
	for _, n := range nodes {
		if n.Status == "online" {
			return n.Node, nil
		}
	}
	return "", errors.New("no online node available to answer ceph queries")
}

// GetCephStatus returns the raw `/cluster/ceph/status` payload, or nil when
// the cluster does not run Ceph.
func (c *PveConnection) GetCephStatus() (map[string]any, error) {
	available, _, err := c.CephAvailable()
	if err != nil || !available {
		return nil, err
	}
	return c.ceph.status, nil
}

// cephGet runs a cluster-wide Ceph route against the resolved Ceph node and
// unmarshals into result. It reports ok=false when the cluster has no Ceph,
// leaving result untouched.
func (c *PveConnection) cephGet(route string, result any) (bool, error) {
	available, node, err := c.CephAvailable()
	if err != nil || !available {
		return false, err
	}
	path := fmt.Sprintf("/nodes/%s/ceph/%s", node, route)
	if err := c.apiGet(path, result); err != nil {
		return false, fmt.Errorf("failed to get ceph %s: %w", route, err)
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Monitors, managers, metadata servers
// ---------------------------------------------------------------------------

// CephDaemon covers the shared shape of the mon, mgr, and mds listings. Not
// every field is populated for every daemon type; MDS adds Rank, FSName, and
// StandbyReplay, and MON adds Rank and Quorum.
type CephDaemon struct {
	Name             string  `json:"name"`
	Host             string  `json:"host"`
	Addr             string  `json:"addr"`
	State            string  `json:"state"`
	Service          PveBool `json:"service"`
	DirExists        PveBool `json:"direxists"`
	CephVersion      string  `json:"ceph_version"`
	CephVersionShort string  `json:"ceph_version_short"`

	// mon + mds
	Rank *int `json:"rank"`
	// mon only
	Quorum PveBool `json:"quorum"`
	// mds only
	FSName        string  `json:"fs_name"`
	StandbyReplay PveBool `json:"standby_replay"`
}

func (c *PveConnection) GetCephMonitors() ([]CephDaemon, error) {
	var mons []CephDaemon
	_, err := c.cephGet("mon", &mons)
	return mons, err
}

func (c *PveConnection) GetCephManagers() ([]CephDaemon, error) {
	var mgrs []CephDaemon
	_, err := c.cephGet("mgr", &mgrs)
	return mgrs, err
}

func (c *PveConnection) GetCephMetadataServers() ([]CephDaemon, error) {
	var mds []CephDaemon
	_, err := c.cephGet("mds", &mds)
	return mds, err
}

// ---------------------------------------------------------------------------
// Pools
// ---------------------------------------------------------------------------

type CephPool struct {
	Pool                int            `json:"pool"`
	PoolName            string         `json:"pool_name"`
	Type                string         `json:"type"`
	Size                int            `json:"size"`
	MinSize             int            `json:"min_size"`
	PGNum               int            `json:"pg_num"`
	PGNumFinal          int            `json:"pg_num_final"`
	PGNumMin            int            `json:"pg_num_min"`
	PGAutoscaleMode     string         `json:"pg_autoscale_mode"`
	CrushRule           int            `json:"crush_rule"`
	CrushRuleName       string         `json:"crush_rule_name"`
	BytesUsed           int64          `json:"bytes_used"`
	PercentUsed         float64        `json:"percent_used"`
	TargetSize          int64          `json:"target_size"`
	TargetSizeRatio     float64        `json:"target_size_ratio"`
	ApplicationMetadata map[string]any `json:"application_metadata"`
	AutoscaleStatus     map[string]any `json:"autoscale_status"`
}

func (c *PveConnection) GetCephPools() ([]CephPool, error) {
	var pools []CephPool
	_, err := c.cephGet("pool", &pools)
	return pools, err
}

// ---------------------------------------------------------------------------
// File systems
// ---------------------------------------------------------------------------

type CephFS struct {
	Name           string   `json:"name"`
	MetadataPool   string   `json:"metadata_pool"`
	MetadataPoolID int      `json:"metadata_pool_id"`
	DataPool       string   `json:"data_pool"`
	DataPools      []string `json:"data_pools"`
	DataPoolIDs    []int    `json:"data_pool_ids"`
}

func (c *PveConnection) GetCephFileSystems() ([]CephFS, error) {
	var fs []CephFS
	_, err := c.cephGet("fs", &fs)
	return fs, err
}

// ---------------------------------------------------------------------------
// Config database
// ---------------------------------------------------------------------------

type CephConfigEntry struct {
	Section            string  `json:"section"`
	Name               string  `json:"name"`
	Value              string  `json:"value"`
	Mask               string  `json:"mask"`
	Level              string  `json:"level"`
	CanUpdateAtRuntime PveBool `json:"can_update_at_runtime"`
}

func (c *PveConnection) GetCephConfig() ([]CephConfigEntry, error) {
	var entries []CephConfigEntry
	_, err := c.cephGet("cfg/db", &entries)
	return entries, err
}

// ---------------------------------------------------------------------------
// CRUSH rules
// ---------------------------------------------------------------------------

type cephCrushRule struct {
	Name string `json:"name"`
}

func (c *PveConnection) GetCephCrushRules() ([]string, error) {
	var rules []cephCrushRule
	if _, err := c.cephGet("rules", &rules); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.Name)
	}
	return names, nil
}

// ---------------------------------------------------------------------------
// OSDs
// ---------------------------------------------------------------------------

// CephCrushNode is one entry in the CRUSH tree returned by
// `/nodes/{node}/ceph/osd`. Buckets (root, host) carry negative ids and hold
// children; the leaves with type "osd" are the daemons themselves.
type CephCrushNode struct {
	ID          int             `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Status      string          `json:"status"`
	In          *int            `json:"in"`
	DeviceClass string          `json:"device_class"`
	CrushWeight float64         `json:"crush_weight"`
	Reweight    float64         `json:"reweight"`
	Host        string          `json:"host"`
	TotalSpace  int64           `json:"total_space"`
	BytesUsed   int64           `json:"bytes_used"`
	PercentUsed float64         `json:"percent_used"`
	Children    []CephCrushNode `json:"children"`
}

type cephOSDTree struct {
	Root  CephCrushNode `json:"root"`
	Flags string        `json:"flags"`
}

// CephOSD merges the CRUSH tree view of an OSD (up/in, device class, usage)
// with the daemon metadata from `/cluster/ceph/metadata` (version, object
// store, backing devices).
type CephOSD struct {
	ID          int
	Name        string
	Host        string
	Status      string
	In          *int
	DeviceClass string
	CrushWeight float64
	Reweight    float64
	TotalSpace  int64
	BytesUsed   int64
	PercentUsed float64

	// from metadata
	CephVersion      string
	CephVersionShort string
	CephRelease      string
	ObjectStore      string
	Devices          string
	DeviceIDs        string
	DevicePaths      string
	FrontAddr        string
	BackAddr         string
	OSDData          string
}

// CephOSDMetadata is one entry of the `osd` array in /cluster/ceph/metadata.
type CephOSDMetadata struct {
	ID               int    `json:"id"`
	Hostname         string `json:"hostname"`
	CephVersion      string `json:"ceph_version"`
	CephVersionShort string `json:"ceph_version_short"`
	CephRelease      string `json:"ceph_release"`
	ObjectStore      string `json:"osd_objectstore"`
	Devices          string `json:"devices"`
	DeviceIDs        string `json:"device_ids"`
	DevicePaths      string `json:"device_paths"`
	FrontAddr        string `json:"front_addr"`
	BackAddr         string `json:"back_addr"`
	OSDData          string `json:"osd_data"`
}

type cephMetadata struct {
	OSD  []CephOSDMetadata `json:"osd"`
	Node map[string]any    `json:"node"`
}

// GetCephOSDs returns every OSD in the cluster. The CRUSH tree is the source
// of record for which OSDs exist and their up/in state; metadata only
// enriches entries that are already present in the tree.
func (c *PveConnection) GetCephOSDs() ([]CephOSD, error) {
	var tree cephOSDTree
	ok, err := c.cephGet("osd", &tree)
	if err != nil || !ok {
		return nil, err
	}

	osds := FlattenCephCrushTree(tree.Root)

	meta, err := c.getCephMetadata()
	if err != nil {
		// Metadata is enrichment only. Losing it costs the version and
		// device columns, not the OSD inventory, so report the OSDs we
		// already resolved rather than failing the whole list.
		log.Warn().Err(err).Msg("proxmox: could not read ceph metadata; OSD version and device fields will be empty")
		return osds, nil
	}
	byID := make(map[int]CephOSDMetadata, len(meta.OSD))
	for _, m := range meta.OSD {
		byID[m.ID] = m
	}
	for i := range osds {
		m, found := byID[osds[i].ID]
		if !found {
			continue
		}
		osds[i].CephVersion = m.CephVersion
		osds[i].CephVersionShort = m.CephVersionShort
		osds[i].CephRelease = m.CephRelease
		osds[i].ObjectStore = m.ObjectStore
		osds[i].Devices = m.Devices
		osds[i].DeviceIDs = m.DeviceIDs
		osds[i].DevicePaths = m.DevicePaths
		osds[i].FrontAddr = m.FrontAddr
		osds[i].BackAddr = m.BackAddr
		osds[i].OSDData = m.OSDData
		if osds[i].Host == "" {
			osds[i].Host = m.Hostname
		}
	}
	return osds, nil
}

func (c *PveConnection) getCephMetadata() (*cephMetadata, error) {
	available, _, err := c.CephAvailable()
	if err != nil || !available {
		return nil, err
	}
	var meta cephMetadata
	if err := c.apiGet("/cluster/ceph/metadata", &meta); err != nil {
		return nil, fmt.Errorf("failed to get ceph metadata: %w", err)
	}
	return &meta, nil
}

// GetCephNodeVersions returns the Ceph version installed on each node, keyed
// by node name, or nil when the cluster does not run Ceph.
func (c *PveConnection) GetCephNodeVersions() (map[string]any, error) {
	meta, err := c.getCephMetadata()
	if err != nil || meta == nil {
		return nil, err
	}
	return meta.Node, nil
}

// FlattenCephCrushTree walks a CRUSH bucket tree and returns every OSD leaf.
// Leaves inherit the name of the nearest enclosing host bucket when they do
// not carry a `host` of their own.
func FlattenCephCrushTree(root CephCrushNode) []CephOSD {
	var out []CephOSD
	var walk func(n CephCrushNode, host string)
	walk = func(n CephCrushNode, host string) {
		if n.Type == "host" && n.Name != "" {
			host = n.Name
		}
		if n.Type == "osd" {
			h := n.Host
			if h == "" {
				h = host
			}
			out = append(out, CephOSD{
				ID:          n.ID,
				Name:        n.Name,
				Host:        h,
				Status:      n.Status,
				In:          n.In,
				DeviceClass: n.DeviceClass,
				CrushWeight: n.CrushWeight,
				Reweight:    n.Reweight,
				TotalSpace:  n.TotalSpace,
				BytesUsed:   n.BytesUsed,
				PercentUsed: n.PercentUsed,
			})
		}
		for _, child := range n.Children {
			walk(child, host)
		}
	}
	walk(root, "")
	return out
}
