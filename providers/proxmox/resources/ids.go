// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/providers/proxmox/connection"
)

// id() methods + Internal-struct declarations for resources whose
// cache key can't be derived from their own public fields.
//
// Sub-resources that need a parent identifier in their cache key
// (vm.network, vm.disk, vm.snapshot, vm.update, vm.serialPort,
// container.network, container.mountPoint, node.update, network, dns,
// service, certificate, subscription, repository, lvm.volumeGroup,
// lvm.thinPool, node.disk.smart) set `__id` directly in their
// CreateResource args. Those resources do NOT need entries here — the
// runtime uses the supplied __id and never calls id().

// --- Globally unique by their `id` field ---

func (r *mqlProxmoxClusterHaResource) id() (string, error) {
	return "proxmox.cluster.haResource/" + r.Id.Data, nil
}

func (r *mqlProxmoxStorage) id() (string, error) {
	return "proxmox.storage/" + r.Id.Data, nil
}

func (r *mqlProxmoxPool) id() (string, error) {
	return "proxmox.pool/" + r.Id.Data, nil
}

func (r *mqlProxmoxUser) id() (string, error) {
	return "proxmox.user/" + r.Id.Data, nil
}

func (r *mqlProxmoxToken) id() (string, error) {
	return "proxmox.token/" + r.Id.Data, nil
}

func (r *mqlProxmoxRole) id() (string, error) {
	return "proxmox.role/" + r.Id.Data, nil
}

func (r *mqlProxmoxClusterHaGroup) id() (string, error) {
	return "proxmox.cluster.haGroup/" + r.Id.Data, nil
}

func (r *mqlProxmoxBackupJob) id() (string, error) {
	return "proxmox.backup.job/" + r.Id.Data, nil
}

func (r *mqlProxmoxReplicationJob) id() (string, error) {
	return "proxmox.replication.job/" + r.Id.Data, nil
}

func (r *mqlProxmoxSdnZone) id() (string, error) {
	return "proxmox.sdn.zone/" + r.Zone.Data, nil
}

func (r *mqlProxmoxSdnVnet) id() (string, error) {
	return "proxmox.sdn.vnet/" + r.Vnet.Data, nil
}

func (r *mqlProxmoxSdnSubnet) id() (string, error) {
	return "proxmox.sdn.subnet/" + r.Id.Data, nil
}

// --- Internal structs whose fields are read elsewhere ---
//
// Firewall rules don't have a unique scalar id of their own; the
// scope + position + tuple makes one. IPset entries keep a fetcher
// closure so the parent ipset can lazy-load its entries.

type mqlProxmoxFirewallRuleInternal struct {
	scope string // e.g. "cluster", "node/pve1", "vm/100", "ct/200"
}

func (r *mqlProxmoxFirewallRule) id() (string, error) {
	return fmt.Sprintf("proxmox.firewall.rule/%s/%d/%s/%s/%s/%s",
		r.scope, r.Pos.Data, r.Type.Data, r.Action.Data, r.Source.Data, r.Dest.Data), nil
}

type mqlProxmoxFirewallIpsetInternal struct {
	entriesScope string
	fetcherName  string
	fetcher      func(name string) ([]connection.IPSetEntry, error)
}

type mqlProxmoxFirewallIpsetEntryInternal struct {
	scope   string // e.g. "cluster/myset", "vm/100/myset"
	ipsetID string
}
