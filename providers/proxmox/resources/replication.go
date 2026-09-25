// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// mqlProxmoxReplicationJobInternal caches the guest kind so that vm() and
// container() can return null for the wrong type without each one paging
// through /cluster/resources independently.
type mqlProxmoxReplicationJobInternal struct {
	kindOnce  sync.Once
	guestKind string // "qemu", "lxc", or "" when the vmid isn't found
	kindErr   error
}

func (r *mqlProxmox) replicationJobs() ([]any, error) {
	conn := proxmoxConn(r)
	jobs, err := conn.GetReplicationJobs()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(jobs))
	for i, j := range jobs {
		res, err := CreateResource(r.MqlRuntime, "proxmox.replication.job", map[string]*llx.RawData{
			"id":        llx.StringData(j.ID),
			"vmid":      llx.IntData(int64(j.VMID)),
			"schedule":  llx.StringData(j.Schedule),
			"source":    llx.StringData(j.Source),
			"target":    llx.StringData(j.Target),
			"type":      llx.StringData(j.Type),
			"comment":   llx.StringData(j.Comment),
			"rate":      llx.IntData(j.Rate.Ceil()),
			"disabled":  llx.BoolData(j.Disable == 1),
			"removeJob": llx.StringData(j.RemoveJob),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxReplicationJob) sourceNode() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Source.Data, &r.SourceNode)
}

func (r *mqlProxmoxReplicationJob) targetNode() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Target.Data, &r.TargetNode)
}

// ensureGuestKind reads /cluster/resources once to determine whether this
// job's vmid is a QEMU VM or an LXC container. The accessors below use
// the result to return the right typed resource and null for the other —
// matching the .lr contract that only one of vm()/container() is set.
func (r *mqlProxmoxReplicationJob) ensureGuestKind() (string, error) {
	r.kindOnce.Do(func() {
		conn := r.MqlRuntime.Connection.(*connection.PveConnection)
		vms, vmErr := conn.GetAllVMs()
		if vmErr == nil {
			for _, vm := range vms {
				if int64(vm.VMID) == r.Vmid.Data {
					r.guestKind = "qemu"
					return
				}
			}
		}
		cts, ctErr := conn.GetAllContainers()
		if ctErr == nil {
			for _, ct := range cts {
				if int64(ct.VMID) == r.Vmid.Data {
					r.guestKind = "lxc"
					return
				}
			}
		}
		// Treat "deleted guest" as the success path: only bubble the
		// API errors up if BOTH lookups failed, because either listing
		// returning cleanly is enough to authoritatively answer "not
		// found." A transient VM-listing failure should not poison the
		// answer when the container listing definitively said "not me."
		if vmErr != nil && ctErr != nil {
			r.kindErr = vmErr
		}
	})
	return r.guestKind, r.kindErr
}

func (r *mqlProxmoxReplicationJob) vm() (*mqlProxmoxVm, error) {
	kind, err := r.ensureGuestKind()
	if err != nil {
		return nil, err
	}
	if kind != "qemu" {
		r.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.vm", map[string]*llx.RawData{
		"id": llx.IntData(r.Vmid.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxVm), nil
}

func (r *mqlProxmoxReplicationJob) container() (*mqlProxmoxContainer, error) {
	kind, err := r.ensureGuestKind()
	if err != nil {
		return nil, err
	}
	if kind != "lxc" {
		r.Container.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.container", map[string]*llx.RawData{
		"id": llx.IntData(r.Vmid.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxContainer), nil
}
