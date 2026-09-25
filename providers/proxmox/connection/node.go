// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"sync"
)

// ---------------------------------------------------------------------------
// Node listing
// ---------------------------------------------------------------------------

type NodeInfo struct {
	Node   string `json:"node"`
	Status string `json:"status"`
}

func (c *PveConnection) GetNodes() ([]NodeInfo, error) {
	var nodes []NodeInfo
	return nodes, c.apiGet("/nodes", &nodes)
}

// ---------------------------------------------------------------------------
// Node index
// ---------------------------------------------------------------------------

// NodeDetail is one node as the index reports it: the /nodes row joined with
// the address the cluster status advertises for that node.
type NodeDetail struct {
	Name   string
	Status string
	// IP is the address from the cluster status. It is empty on a
	// standalone host, which has no cluster membership row at all.
	IP string
}

// nodeIndex memoizes the cluster's node listing, keyed by node name. Node
// references hang off every guest, every Ceph daemon, and every storage
// volume, so resolving them per item would re-list the cluster once per
// item. Building the map once turns that fan-out into a single pair of
// calls. The error is memoized alongside the value so a token that cannot
// read /nodes fails once instead of on every lookup.
type nodeIndex struct {
	once   sync.Once
	byName map[string]NodeDetail
	err    error
}

// LookupNode returns the node with the given name. The boolean result is
// false when the cluster has no such node, which lets callers report a
// dangling reference as null instead of fabricating a blank node.
func (c *PveConnection) LookupNode(name string) (NodeDetail, bool, error) {
	c.nodes.once.Do(c.buildNodeIndex)
	if c.nodes.err != nil {
		return NodeDetail{}, false, c.nodes.err
	}
	n, ok := c.nodes.byName[name]
	return n, ok, nil
}

func (c *PveConnection) buildNodeIndex() {
	nodes, err := c.GetNodes()
	if err != nil {
		c.nodes.err = fmt.Errorf("failed to index nodes: %w", err)
		return
	}
	// The advertised address lives in the cluster status, not the nodes
	// list. A standalone host has no cluster status to read, so a failure
	// here leaves the addresses empty rather than failing every lookup.
	addrs := map[string]string{}
	if entries, statusErr := c.GetClusterStatus(); statusErr == nil {
		for _, e := range entries {
			if e.Type == "node" {
				addrs[e.Name] = e.IP
			}
		}
	}
	index := make(map[string]NodeDetail, len(nodes))
	for _, n := range nodes {
		index[n.Node] = NodeDetail{Name: n.Node, Status: n.Status, IP: addrs[n.Node]}
	}
	c.nodes.byName = index
}

// ---------------------------------------------------------------------------
// Node status (detailed)
// ---------------------------------------------------------------------------

type NodeStatus struct {
	// CPU
	CPUInfo struct {
		Model   string `json:"model"`
		Sockets int    `json:"sockets"`
		Cores   int    `json:"cores"`
		CPUs    int    `json:"cpus"`
		// Flags is space-separated as returned by /proc/cpuinfo. Older
		// PVE versions may omit the field entirely.
		Flags string `json:"flags"`
	} `json:"cpuinfo"`
	CPU float64 `json:"cpu"`
	// Memory
	Memory struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
		Free  int64 `json:"free"`
	} `json:"memory"`
	Swap struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
		Free  int64 `json:"free"`
	} `json:"swap"`
	// System
	KVersion string   `json:"kversion"`
	PVEVer   string   `json:"pveversion"`
	Uptime   int64    `json:"uptime"`
	LoadAvg  []string `json:"loadavg"`
	// BootInfo reports the firmware the node booted through and, on EFI,
	// whether Secure Boot is on. It does not name the kernel the node boots
	// next; no status field does.
	BootInfo struct {
		Mode       string  `json:"mode"`
		SecureBoot PveBool `json:"secureboot"`
	} `json:"boot-info"`
}

func (c *PveConnection) GetNodeStatus(node string) (*NodeStatus, error) {
	var status NodeStatus
	path := fmt.Sprintf("/nodes/%s/status", node)
	if err := c.apiGet(path, &status); err != nil {
		return nil, fmt.Errorf("failed to get status for node %s: %w", node, err)
	}
	return &status, nil
}

// ---------------------------------------------------------------------------
// Node network interfaces
// ---------------------------------------------------------------------------

type NetworkIface struct {
	Iface       string `json:"iface"`
	Type        string `json:"type"`
	Active      int    `json:"active"`
	Method      string `json:"method"`
	Address     string `json:"address"`
	Netmask     string `json:"netmask"`
	Gateway     string `json:"gateway"`
	BridgePorts string `json:"bridge_ports"`
	CIDR        string `json:"cidr"`
	Autostart   int    `json:"autostart"`
	Comments    string `json:"comments"`
}

func (c *PveConnection) GetNodeNetworks(node string) ([]NetworkIface, error) {
	var ifaces []NetworkIface
	path := fmt.Sprintf("/nodes/%s/network", node)
	if err := c.apiGet(path, &ifaces); err != nil {
		return nil, fmt.Errorf("failed to get networks for node %s: %w", node, err)
	}
	return ifaces, nil
}

// ---------------------------------------------------------------------------
// Node DNS
// ---------------------------------------------------------------------------

type DNSConfig struct {
	Search string `json:"search"`
	DNS1   string `json:"dns1"`
	DNS2   string `json:"dns2"`
	DNS3   string `json:"dns3"`
}

func (c *PveConnection) GetNodeDNS(node string) (*DNSConfig, error) {
	var dns DNSConfig
	path := fmt.Sprintf("/nodes/%s/dns", node)
	if err := c.apiGet(path, &dns); err != nil {
		return nil, fmt.Errorf("failed to get DNS for node %s: %w", node, err)
	}
	return &dns, nil
}

// ---------------------------------------------------------------------------
// Node services (systemd)
// ---------------------------------------------------------------------------

type ServiceInfo struct {
	Name          string `json:"name"`
	State         string `json:"state"`
	Description   string `json:"desc"`
	UnitFileState string `json:"unit-file-state"`
}

func (c *PveConnection) GetNodeServices(node string) ([]ServiceInfo, error) {
	var services []ServiceInfo
	path := fmt.Sprintf("/nodes/%s/services", node)
	if err := c.apiGet(path, &services); err != nil {
		return nil, fmt.Errorf("failed to get services for node %s: %w", node, err)
	}
	return services, nil
}

// ---------------------------------------------------------------------------
// Node time/timezone
// ---------------------------------------------------------------------------

type TimeInfo struct {
	Timezone  string `json:"timezone"`
	Localtime int64  `json:"localtime"`
	Time      int64  `json:"time"`
}

func (c *PveConnection) GetNodeTime(node string) (*TimeInfo, error) {
	var t TimeInfo
	path := fmt.Sprintf("/nodes/%s/time", node)
	if err := c.apiGet(path, &t); err != nil {
		return nil, fmt.Errorf("failed to get time for node %s: %w", node, err)
	}
	return &t, nil
}

// ---------------------------------------------------------------------------
// Node certificates
// ---------------------------------------------------------------------------

type CertInfo struct {
	Filename      string   `json:"filename"`
	Fingerprint   string   `json:"fingerprint"`
	Issuer        string   `json:"issuer"`
	NotAfter      int64    `json:"notafter"`
	NotBefore     int64    `json:"notbefore"`
	PublicKeyBits int      `json:"public-key-bits"`
	PublicKeyType string   `json:"public-key-type"`
	San           []string `json:"san"`
	Subject       string   `json:"subject"`
}

func (c *PveConnection) GetNodeCertificates(node string) ([]CertInfo, error) {
	var certs []CertInfo
	path := fmt.Sprintf("/nodes/%s/certificates/info", node)
	if err := c.apiGet(path, &certs); err != nil {
		return nil, fmt.Errorf("failed to get certificates for node %s: %w", node, err)
	}
	return certs, nil
}

// ---------------------------------------------------------------------------
// Node subscription
// ---------------------------------------------------------------------------

type SubscriptionInfo struct {
	Status      string `json:"status"`
	ServerID    string `json:"serverid"`
	ProductName string `json:"productname"`
	RegDate     string `json:"regdate"`
	NextDueDate string `json:"nextduedate"`
	Level       string `json:"level"`
	Key         string `json:"key"`
}

func (c *PveConnection) GetNodeSubscription(node string) (*SubscriptionInfo, error) {
	var sub SubscriptionInfo
	path := fmt.Sprintf("/nodes/%s/subscription", node)
	if err := c.apiGet(path, &sub); err != nil {
		return nil, fmt.Errorf("failed to get subscription for node %s: %w", node, err)
	}
	return &sub, nil
}

// ---------------------------------------------------------------------------
// Node APT repositories
// ---------------------------------------------------------------------------

type AptRepoInfo struct {
	Digest string `json:"digest"`
	Files  []struct {
		Path         string `json:"path"`
		FileType     string `json:"file-type"`
		Repositories []struct {
			Types      []string `json:"Types"`
			URIs       []string `json:"URIs"`
			Suites     []string `json:"Suites"`
			Components []string `json:"Components"`
			Enabled    bool     `json:"Enabled"`
			Comment    string   `json:"Comment"`
			// PVE serializes Signed-By and the other deb822 options as an
			// array of {Key, Values}. Older API versions and one-line
			// sources don't return Options at all.
			Options []struct {
				Key    string   `json:"Key"`
				Values []string `json:"Values"`
			} `json:"Options"`
		} `json:"repositories"`
	} `json:"files"`
	Infos []struct {
		Index   string `json:"index"`
		Kind    string `json:"kind"`
		Message string `json:"message"`
	} `json:"infos"`
}

func (c *PveConnection) GetNodeRepositories(node string) (*AptRepoInfo, error) {
	var info AptRepoInfo
	path := fmt.Sprintf("/nodes/%s/apt/repositories", node)
	if err := c.apiGet(path, &info); err != nil {
		return nil, fmt.Errorf("failed to get repositories for node %s: %w", node, err)
	}
	return &info, nil
}

// ---------------------------------------------------------------------------
// Node APT updates
// ---------------------------------------------------------------------------

type NodeUpdateInfo struct {
	Package    string `json:"Package"`
	OldVersion string `json:"OldVersion"`
	NewVersion string `json:"Version"`
	Section    string `json:"Section"`
	Priority   string `json:"Priority"`
	Title      string `json:"Title"`
	Origin     string `json:"Origin"`
}

func (c *PveConnection) GetNodeUpdates(node string) ([]NodeUpdateInfo, error) {
	var updates []NodeUpdateInfo
	path := fmt.Sprintf("/nodes/%s/apt/update", node)
	if err := c.apiGet(path, &updates); err != nil {
		return nil, fmt.Errorf("failed to get updates for node %s: %w", node, err)
	}
	return updates, nil
}

// ---------------------------------------------------------------------------
// Node firewall rules
// ---------------------------------------------------------------------------

func (c *PveConnection) GetNodeFirewallRules(node string) ([]FirewallRule, error) {
	var rules []FirewallRule
	path := fmt.Sprintf("/nodes/%s/firewall/rules", node)
	if err := c.apiGet(path, &rules); err != nil {
		return nil, fmt.Errorf("failed to get firewall rules for node %s: %w", node, err)
	}
	return rules, nil
}

// ---------------------------------------------------------------------------
// Node storage
// ---------------------------------------------------------------------------

func (c *PveConnection) GetNodeStorage(node string) ([]StorageInfo, error) {
	var storages []StorageInfo
	path := fmt.Sprintf("/nodes/%s/storage", node)
	if err := c.apiGet(path, &storages); err != nil {
		return nil, fmt.Errorf("failed to get storage for node %s: %w", node, err)
	}
	return storages, nil
}
