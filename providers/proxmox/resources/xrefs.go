// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// ---------------------------------------------------------------------------
// vm.disk / container.mountPoint / storage.volume → storage
// ---------------------------------------------------------------------------

func (r *mqlProxmoxVmVirtualDisk) storageRef() (*mqlProxmoxStorage, error) {
	return resolveStorageRef(r.MqlRuntime, r.Storage.Data, &r.StorageRef)
}

func (r *mqlProxmoxContainerMountPoint) storageRef() (*mqlProxmoxStorage, error) {
	return resolveStorageRef(r.MqlRuntime, r.Storage.Data, &r.StorageRef)
}

func (r *mqlProxmoxStorageVolume) storageRef() (*mqlProxmoxStorage, error) {
	return resolveStorageRef(r.MqlRuntime, r.Storage.Data, &r.StorageRef)
}

// resolveStorageRef turns a storage name into a storage resource. The name is
// checked against the connection's storage index first: a name the cluster no
// longer configures is reported as null rather than handed to NewResource,
// whose init would otherwise build a storage with every field unset.
func resolveStorageRef(runtime *plugin.Runtime, storageID string, slot *plugin.TValue[*mqlProxmoxStorage]) (*mqlProxmoxStorage, error) {
	if storageID == "" {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn, ok := runtime.Connection.(*connection.PveConnection)
	if !ok {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	_, found, err := conn.LookupStorage(storageID)
	if err != nil {
		return nil, err
	}
	if !found {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "proxmox.storage", map[string]*llx.RawData{
		"id": llx.StringData(storageID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxStorage), nil
}

// ---------------------------------------------------------------------------
// vm / container / storage.volume / ceph daemons → node
// ---------------------------------------------------------------------------

func (r *mqlProxmoxVm) nodeRef() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Node.Data, &r.NodeRef)
}

func (r *mqlProxmoxContainer) nodeRef() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Node.Data, &r.NodeRef)
}

func (r *mqlProxmoxStorageVolume) nodeRef() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Node.Data, &r.NodeRef)
}

func (r *mqlProxmoxCephMonitor) node() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Host.Data, &r.Node)
}

func (r *mqlProxmoxCephManager) node() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Host.Data, &r.Node)
}

func (r *mqlProxmoxCephMetadataServer) node() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Host.Data, &r.Node)
}

func (r *mqlProxmoxCephOsd) node() (*mqlProxmoxNode, error) {
	return resolveNodeRef(r.MqlRuntime, r.Host.Data, &r.Node)
}

// resolveNodeRef turns a node name into a node resource. Node names are
// cluster-unique, so the name alone identifies the host. The name is checked
// against the connection's node index first, which both keeps the whole fleet
// of guests and daemons down to a single node listing and lets a name the
// cluster no longer knows be reported as null instead of a blank node.
func resolveNodeRef(runtime *plugin.Runtime, name string, slot *plugin.TValue[*mqlProxmoxNode]) (*mqlProxmoxNode, error) {
	if name == "" {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn, ok := runtime.Connection.(*connection.PveConnection)
	if !ok {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	_, found, err := conn.LookupNode(name)
	if err != nil {
		return nil, err
	}
	if !found {
		slot.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "proxmox.node", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxNode), nil
}

// ---------------------------------------------------------------------------
// token → owner user
// ---------------------------------------------------------------------------

func (r *mqlProxmoxToken) owner() (*mqlProxmoxUser, error) {
	// Token id shape is `user@realm!tokenid`. Anything else is a token
	// the API would have refused to create, so treat unparseable ids as
	// "no resolvable owner" rather than failing the whole query.
	bang := strings.LastIndex(r.Id.Data, "!")
	if bang <= 0 {
		r.Owner.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	ownerID := r.Id.Data[:bang]
	res, err := NewResource(r.MqlRuntime, "proxmox.user", map[string]*llx.RawData{
		"id": llx.StringData(ownerID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxUser), nil
}

// ---------------------------------------------------------------------------
// user → groupRefs
// ---------------------------------------------------------------------------

func (r *mqlProxmoxUser) groupRefs() ([]any, error) {
	out := make([]any, 0, len(r.cachedGroups))
	for _, g := range r.cachedGroups {
		if g == "" {
			continue
		}
		res, err := NewResource(r.MqlRuntime, "proxmox.group", map[string]*llx.RawData{
			"id": llx.StringData(g),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
