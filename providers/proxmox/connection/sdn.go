// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import "fmt"

// ---------------------------------------------------------------------------
// SDN zones
// ---------------------------------------------------------------------------

type SDNZone struct {
	Zone       string `json:"zone"`
	Type       string `json:"type"` // simple, vlan, qinq, vxlan, evpn
	IPAM       string `json:"ipam"`
	MTU        int    `json:"mtu"`
	Nodes      string `json:"nodes"` // comma-separated; empty = all
	DNS        string `json:"dns"`
	DNSZone    string `json:"dnszone"`
	ReverseDNS string `json:"reversedns"`
	Pending    int    `json:"pending"`
	State      string `json:"state"`
}

func (c *PveConnection) GetSDNZones() ([]SDNZone, error) {
	var zones []SDNZone
	if err := c.apiGet("/cluster/sdn/zones", &zones); err != nil {
		return nil, fmt.Errorf("failed to get SDN zones: %w", err)
	}
	return zones, nil
}

// ---------------------------------------------------------------------------
// SDN vnets
// ---------------------------------------------------------------------------

type SDNVNet struct {
	VNet      string `json:"vnet"`
	Zone      string `json:"zone"`
	Alias     string `json:"alias"`
	Tag       int    `json:"tag"`
	VLANAware int    `json:"vlanaware"`
	Type      string `json:"type"`
}

func (c *PveConnection) GetSDNVNets() ([]SDNVNet, error) {
	var vnets []SDNVNet
	if err := c.apiGet("/cluster/sdn/vnets", &vnets); err != nil {
		return nil, fmt.Errorf("failed to get SDN vnets: %w", err)
	}
	return vnets, nil
}

// ---------------------------------------------------------------------------
// SDN subnets — scoped under a vnet
// ---------------------------------------------------------------------------

type SDNSubnet struct {
	ID            string `json:"id"`     // e.g. "myzone-10.0.0.0-24"
	Subnet        string `json:"subnet"` // CIDR
	CIDR          string `json:"cidr"`
	Gateway       string `json:"gateway"`
	SNAT          int    `json:"snat"`
	DNSZonePrefix string `json:"dnszoneprefix"`
	VNet          string `json:"vnet"`
}

func (c *PveConnection) GetSDNSubnets(vnet string) ([]SDNSubnet, error) {
	var subnets []SDNSubnet
	path := fmt.Sprintf("/cluster/sdn/vnets/%s/subnets", vnet)
	if err := c.apiGet(path, &subnets); err != nil {
		return nil, fmt.Errorf("failed to get SDN subnets for vnet %s: %w", vnet, err)
	}
	return subnets, nil
}

// ---------------------------------------------------------------------------
// SDN vnet firewall — scoped under a vnet
// ---------------------------------------------------------------------------

// GetSDNVNetFirewallRules lists the firewall rules attached to an SDN vnet.
// The vnet firewall arrived in a later Proxmox release than the SDN itself and
// needs SDN.Audit on the vnet, so the second return value reports whether the
// scope could be read at all.
func (c *PveConnection) GetSDNVNetFirewallRules(vnet string) ([]FirewallRule, bool, error) {
	var rules []FirewallRule
	path := fmt.Sprintf("/cluster/sdn/vnets/%s/firewall/rules", vnet)
	readable, err := c.getIfAvailable(path, &rules)
	if err != nil {
		return nil, false, err
	}
	return rules, readable, nil
}

// GetSDNVNetFirewallOptions reads the firewall options of an SDN vnet. Unlike
// the other scopes these carry `policy_forward` and `log_level_forward`, since
// a vnet filters traffic crossing between guests rather than entering one.
func (c *PveConnection) GetSDNVNetFirewallOptions(vnet string) (map[string]any, bool, error) {
	var opts map[string]any
	path := fmt.Sprintf("/cluster/sdn/vnets/%s/firewall/options", vnet)
	readable, err := c.getIfAvailable(path, &opts)
	if err != nil {
		return nil, false, err
	}
	return opts, readable, nil
}
