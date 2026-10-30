// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// vsphereInventory indexes hosts, VMs, datastores, and clusters by encoded
// moid for cross-reference resolution. Built once per scan and cached on the
// singleton vsphere resource (see mqlVsphereInternal), since a query like
// `vsphere.vms { host datastores }` over N VMs would otherwise rebuild the
// index 2N times.
type vsphereInventory struct {
	hosts        map[string]*mqlVsphereHost
	vms          map[string]*mqlVsphereVm
	datastores   map[string]*mqlVsphereDatastore
	clusters     map[string]*mqlVsphereCluster
	dvPortGroups map[string]*mqlVsphereVswitchPortgroup
	kmsClusters  map[string]*mqlVsphereKmsCluster // keyed by clusterId
}

// mqlVsphereInternal extends mqlVspherePermissionInternal (already declared in
// vsphere.go); the codegen embeds both fields into the generated resource
// struct. The mutex serializes the first-build race; only successful builds
// are memoized so a transient error doesn't pin a partial inventory in place.
type mqlVsphereInternal struct {
	inventoryMu sync.Mutex
	inventory   *vsphereInventory

	// tagIndex maps a vAPI tag ID to its shared vsphere.tag resource so the
	// per-object tagRefs accessors resolve against the same instances as the
	// root vsphere.tags list (built once, guarded by tagIndexMu).
	tagIndexMu sync.Mutex
	tagIndex   map[string]*mqlVsphereTag
}

func loadVsphereInventory(runtime *plugin.Runtime) (*vsphereInventory, error) {
	res, err := CreateResource(runtime, "vsphere", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	v := res.(*mqlVsphere)
	// Hold the mutex across the build so concurrent callers serialize on the
	// first builder rather than each running their own redundant build (the
	// thundering-herd shape that double-checked locking would allow). Only
	// memoize on success — a transient sub-fetch error must not pin a partial
	// inventory in place, since that would permanently break cross-reference
	// resolution until provider restart.
	v.inventoryMu.Lock()
	defer v.inventoryMu.Unlock()
	if v.inventory != nil {
		return v.inventory, nil
	}
	inv, err := buildVsphereInventory(v)
	if err != nil {
		return nil, err
	}
	v.inventory = inv
	return inv, nil
}

func buildVsphereInventory(v *mqlVsphere) (*vsphereInventory, error) {
	dcs := v.GetDatacenters()
	if dcs.Error != nil {
		return nil, dcs.Error
	}
	inv := &vsphereInventory{
		hosts:        map[string]*mqlVsphereHost{},
		vms:          map[string]*mqlVsphereVm{},
		datastores:   map[string]*mqlVsphereDatastore{},
		clusters:     map[string]*mqlVsphereCluster{},
		dvPortGroups: map[string]*mqlVsphereVswitchPortgroup{},
		kmsClusters:  map[string]*mqlVsphereKmsCluster{},
	}
	if kms := v.GetKmsClusters(); kms.Error == nil {
		for _, c := range kms.Data {
			cluster := c.(*mqlVsphereKmsCluster)
			inv.kmsClusters[cluster.ClusterId.Data] = cluster
		}
	}
	for _, d := range dcs.Data {
		dc := d.(*mqlVsphereDatacenter)
		hosts := dc.GetHosts()
		if hosts.Error != nil {
			return nil, hosts.Error
		}
		for _, h := range hosts.Data {
			host := h.(*mqlVsphereHost)
			inv.hosts[host.Moid.Data] = host
		}
		vms := dc.GetVms()
		if vms.Error != nil {
			return nil, vms.Error
		}
		for _, vm := range vms.Data {
			m := vm.(*mqlVsphereVm)
			inv.vms[m.Moid.Data] = m
		}
		datastores := dc.GetDatastores()
		if datastores.Error != nil {
			return nil, datastores.Error
		}
		for _, ds := range datastores.Data {
			s := ds.(*mqlVsphereDatastore)
			inv.datastores[s.Moid.Data] = s
		}
		clusters := dc.GetClusters()
		if clusters.Error != nil {
			return nil, clusters.Error
		}
		for _, c := range clusters.Data {
			cl := c.(*mqlVsphereCluster)
			inv.clusters[cl.Moid.Data] = cl
		}
		pgs := dc.GetDistributedPortGroups()
		if pgs.Error != nil {
			return nil, pgs.Error
		}
		for _, p := range pgs.Data {
			pg := p.(*mqlVsphereVswitchPortgroup)
			inv.dvPortGroups[pg.Moid.Data] = pg
		}
	}
	return inv, nil
}

// resolveHosts maps a slice of HostSystem refs to their MQL resources, dropping
// refs that aren't in inventory (e.g. hosts the caller doesn't have read
// access to).
func (inv *vsphereInventory) resolveHosts(refs []types.ManagedObjectReference) []any {
	out := make([]any, 0, len(refs))
	for _, r := range refs {
		if h, ok := inv.hosts[r.Encode()]; ok {
			out = append(out, h)
		}
	}
	return out
}

func (inv *vsphereInventory) resolveVms(refs []types.ManagedObjectReference) []any {
	out := make([]any, 0, len(refs))
	for _, r := range refs {
		if v, ok := inv.vms[r.Encode()]; ok {
			out = append(out, v)
		}
	}
	return out
}

func (inv *vsphereInventory) resolveDatastores(refs []types.ManagedObjectReference) []any {
	out := make([]any, 0, len(refs))
	for _, r := range refs {
		if d, ok := inv.datastores[r.Encode()]; ok {
			out = append(out, d)
		}
	}
	return out
}

// host resolves the ESXi host the VM is currently running on against
// vsphere.datacenters[].hosts. Null when the VM is unregistered or the host
// isn't visible in inventory.
func (v *mqlVsphereVm) host() (*mqlVsphereHost, error) {
	if v.vm == nil || v.vm.Runtime.Host == nil {
		v.Host.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if h, ok := inv.hosts[v.vm.Runtime.Host.Encode()]; ok {
		return h, nil
	}
	v.Host.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// datastores resolves the VM's backing datastores against
// vsphere.datacenters[].datastores.
func (v *mqlVsphereVm) datastores() ([]any, error) {
	if v.vm == nil {
		return []any{}, nil
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return inv.resolveDatastores(v.vm.Datastore), nil
}

// cluster resolves the host's parent cluster against
// vsphere.datacenters[].clusters. Null for standalone hosts (whose parent is a
// ComputeResource, not a ClusterComputeResource).
func (v *mqlVsphereHost) cluster() (*mqlVsphereCluster, error) {
	if v.host == nil || v.host.Parent == nil || v.host.Parent.Type != "ClusterComputeResource" {
		v.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if c, ok := inv.clusters[v.host.Parent.Encode()]; ok {
		return c, nil
	}
	v.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// datastores resolves the host's mounted datastores against
// vsphere.datacenters[].datastores.
func (v *mqlVsphereHost) datastores() ([]any, error) {
	if v.host == nil {
		return []any{}, nil
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return inv.resolveDatastores(v.host.Datastore), nil
}

// hosts resolves the hosts that have this datastore mounted against
// vsphere.datacenters[].hosts. Datastore.Host carries DatastoreHostMount; we
// use its Key (the host moid).
func (v *mqlVsphereDatastore) hosts() ([]any, error) {
	if v.ds == nil {
		return []any{}, nil
	}
	refs := make([]types.ManagedObjectReference, 0, len(v.ds.Host))
	for _, h := range v.ds.Host {
		refs = append(refs, h.Key)
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return inv.resolveHosts(refs), nil
}

// vms resolves the VMs whose files reside on this datastore against
// vsphere.datacenters[].vms.
func (v *mqlVsphereDatastore) vms() ([]any, error) {
	if v.ds == nil {
		return []any{}, nil
	}
	inv, err := loadVsphereInventory(v.MqlRuntime)
	if err != nil {
		return nil, err
	}
	return inv.resolveVms(v.ds.Vm), nil
}
