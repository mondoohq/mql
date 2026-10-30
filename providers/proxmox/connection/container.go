// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
)

// ---------------------------------------------------------------------------
// Container listing
// ---------------------------------------------------------------------------

// ContainerInfo describes an LXC container as returned by /cluster/resources.
// The shape mirrors VMInfo, but container-specific config (unprivileged,
// features, hostname) only appears in the per-container config endpoint.
type ContainerInfo struct {
	VMID      int       `json:"vmid"`
	Name      string    `json:"name"`
	Node      string    `json:"node"`
	Status    string    `json:"status"`
	Type      string    `json:"type"`
	CPU       float64   `json:"cpu"`
	MaxCPU    PveNumber `json:"maxcpu"`
	Mem       int64     `json:"mem"`
	MaxMem    int64     `json:"maxmem"`
	Disk      int64     `json:"disk"`
	MaxDisk   int64     `json:"maxdisk"`
	DiskRead  int64     `json:"diskread"`
	DiskWrite int64     `json:"diskwrite"`
	NetIn     int64     `json:"netin"`
	NetOut    int64     `json:"netout"`
	Uptime    int64     `json:"uptime"`
	Template  PveBool   `json:"template"`
	Tags      string    `json:"tags"`
}

func (c *PveConnection) GetAllContainers() ([]ContainerInfo, error) {
	var resources []ContainerInfo
	if err := c.apiGet("/cluster/resources?type=vm", &resources); err != nil {
		return nil, fmt.Errorf("failed to list containers: %w", err)
	}
	var containers []ContainerInfo
	for _, r := range resources {
		if r.Type == "lxc" {
			containers = append(containers, r)
		}
	}
	return containers, nil
}

// nodeLXCEntry is the shape returned by /nodes/<node>/lxc. The row carries
// `cpus` where /cluster/resources carries `maxcpu`, and no node, so it is
// decoded into this intermediate type and copied across. `cpus` is a quoted
// fractional value when it comes from `cpulimit`, which PveNumber absorbs.
type nodeLXCEntry struct {
	VMID      PveNumber `json:"vmid"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CPU       float64   `json:"cpu"`
	MaxCPU    PveNumber `json:"cpus"`
	Mem       int64     `json:"mem"`
	MaxMem    int64     `json:"maxmem"`
	Disk      int64     `json:"disk"`
	MaxDisk   int64     `json:"maxdisk"`
	DiskRead  int64     `json:"diskread"`
	DiskWrite int64     `json:"diskwrite"`
	NetIn     int64     `json:"netin"`
	NetOut    int64     `json:"netout"`
	Uptime    int64     `json:"uptime"`
	Template  PveBool   `json:"template"`
	Tags      string    `json:"tags"`
}

// GetNodeContainers hits the per-node /nodes/<node>/lxc endpoint directly so
// that `proxmox.nodes { containers }` doesn't fan out into one full
// cluster-resources fetch per node.
func (c *PveConnection) GetNodeContainers(node string) ([]ContainerInfo, error) {
	var entries []nodeLXCEntry
	path := fmt.Sprintf("/nodes/%s/lxc", node)
	if err := c.apiGet(path, &entries); err != nil {
		return nil, fmt.Errorf("failed to list containers on node %s: %w", node, err)
	}
	out := make([]ContainerInfo, 0, len(entries))
	for _, e := range entries {
		vmid := int(e.VMID.Int())
		if vmid <= 0 || float64(vmid) != e.VMID.Float() {
			return nil, fmt.Errorf("invalid VMID %v on node %s", e.VMID.Float(), node)
		}
		out = append(out, ContainerInfo{
			VMID:      vmid,
			Name:      e.Name,
			Node:      node,
			Status:    e.Status,
			Type:      "lxc",
			CPU:       e.CPU,
			MaxCPU:    e.MaxCPU,
			Mem:       e.Mem,
			MaxMem:    e.MaxMem,
			Disk:      e.Disk,
			MaxDisk:   e.MaxDisk,
			DiskRead:  e.DiskRead,
			DiskWrite: e.DiskWrite,
			NetIn:     e.NetIn,
			NetOut:    e.NetOut,
			Uptime:    e.Uptime,
			Template:  e.Template,
			Tags:      e.Tags,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Container configuration
// ---------------------------------------------------------------------------

func (c *PveConnection) GetContainerConfig(node string, vmid int) (map[string]any, error) {
	var config map[string]any
	path := fmt.Sprintf("/nodes/%s/lxc/%d/config", node, vmid)
	if err := c.apiGet(path, &config); err != nil {
		return nil, fmt.Errorf("failed to get config for container %d: %w", vmid, err)
	}
	return config, nil
}

// ---------------------------------------------------------------------------
// Container snapshots
// ---------------------------------------------------------------------------

func (c *PveConnection) GetContainerSnapshots(node string, vmid int) ([]SnapshotInfo, error) {
	var snapshots []SnapshotInfo
	path := fmt.Sprintf("/nodes/%s/lxc/%d/snapshot", node, vmid)
	if err := c.apiGet(path, &snapshots); err != nil {
		return nil, fmt.Errorf("failed to get snapshots for container %d: %w", vmid, err)
	}
	var filtered []SnapshotInfo
	for _, s := range snapshots {
		if s.Name != "current" {
			filtered = append(filtered, s)
		}
	}
	return filtered, nil
}

// ---------------------------------------------------------------------------
// Container firewall rules
// ---------------------------------------------------------------------------

func (c *PveConnection) GetContainerFirewallRules(node string, vmid int) ([]FirewallRule, error) {
	var rules []FirewallRule
	path := fmt.Sprintf("/nodes/%s/lxc/%d/firewall/rules", node, vmid)
	if err := c.apiGet(path, &rules); err != nil {
		return nil, fmt.Errorf("failed to get firewall rules for container %d: %w", vmid, err)
	}
	return rules, nil
}
