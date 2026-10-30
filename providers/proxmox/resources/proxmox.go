// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

func proxmoxConn(r *mqlProxmox) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

func (r *mqlProxmox) id() (string, error) {
	return "proxmox", nil
}

func (r *mqlProxmox) about() (any, error) {
	return proxmoxConn(r).GetVersion()
}

func (r *mqlProxmox) cluster() (*mqlProxmoxCluster, error) {
	conn := proxmoxConn(r)
	entries, err := conn.GetClusterStatus()
	if err != nil {
		return nil, err
	}
	var name string
	var version, quorate, nodeCount int
	foundCluster := false
	for _, e := range entries {
		if e.Type == "cluster" {
			name = e.Name
			version = e.Version
			quorate = e.Quorate
			nodeCount = e.Nodes
			foundCluster = true
			break
		}
	}
	// Standalone node (no corosync cluster): treat as single-node quorate
	if !foundCluster {
		for _, e := range entries {
			if e.Type == "node" {
				name = e.Name
				nodeCount = 1
				quorate = 1
				break
			}
		}
	}
	res, err := CreateResource(r.MqlRuntime, "proxmox.cluster", map[string]*llx.RawData{
		"name":      llx.StringData(name),
		"version":   llx.IntData(int64(version)),
		"quorate":   llx.BoolData(quorate == 1),
		"nodeCount": llx.IntData(int64(nodeCount)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxCluster), nil
}

func (r *mqlProxmox) vms() ([]any, error) {
	conn := proxmoxConn(r)
	vms, err := conn.GetAllVMs()
	if err != nil {
		return nil, err
	}
	return vmInfoToResources(r.MqlRuntime, vms)
}

func (r *mqlProxmox) nodes() ([]any, error) {
	conn := proxmoxConn(r)
	nodes, err := conn.GetNodes()
	if err != nil {
		return nil, err
	}
	clusterEntries, _ := conn.GetClusterStatus()
	nodeIPs := make(map[string]string)
	for _, e := range clusterEntries {
		if e.Type == "node" {
			nodeIPs[e.Name] = e.IP
		}
	}
	list := make([]any, len(nodes))
	for i, n := range nodes {
		res, err := CreateResource(r.MqlRuntime, "proxmox.node", map[string]*llx.RawData{
			"name":   llx.StringData(n.Node),
			"status": llx.StringData(n.Status),
			"ip":     llx.StringData(nodeIPs[n.Node]),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlProxmoxNode).nodeName = n.Node
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) storages() ([]any, error) {
	conn := proxmoxConn(r)
	storages, err := conn.GetStorages()
	if err != nil {
		return nil, err
	}
	return storageInfoToResources(r.MqlRuntime, storages, "")
}

func (r *mqlProxmox) pools() ([]any, error) {
	conn := proxmoxConn(r)
	pools, err := conn.GetPools()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(pools))
	for i, p := range pools {
		res, err := CreateResource(r.MqlRuntime, "proxmox.pool", map[string]*llx.RawData{
			"id":      llx.StringData(p.PoolID),
			"comment": llx.StringData(p.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) users() ([]any, error) {
	conn := proxmoxConn(r)
	users, err := conn.GetUsers()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(users))
	for i, u := range users {
		groups := splitProxmoxGroups(u.Groups)
		realm := ""
		if parts := strings.SplitN(u.UserID, "@", 2); len(parts) == 2 {
			realm = parts[1]
		}
		res, err := CreateResource(r.MqlRuntime, "proxmox.user", map[string]*llx.RawData{
			"id":             llx.StringData(u.UserID),
			"email":          llx.StringData(u.Email),
			"enable":         llx.BoolData(u.Enable == 1),
			"expire":         llx.IntData(u.Expire),
			"firstname":      llx.StringData(u.Firstname),
			"lastname":       llx.StringData(u.Lastname),
			"realm":          llx.StringData(realm),
			"realmType":      llx.StringData(u.RealmType),
			"tfaLockedUntil": llx.IntData(u.TFALockedUntil),
		})
		if err != nil {
			return nil, err
		}
		// The user-listing endpoint already returned every token for
		// this user; cache them so tokens() doesn't refetch one
		// /access/users/<id>/token per user.
		mqlUser := res.(*mqlProxmoxUser)
		tokens := make([]any, 0, len(u.Tokens))
		for _, t := range u.Tokens {
			fullID := u.UserID + "!" + t.TokenID
			tok, err := CreateResource(r.MqlRuntime, "proxmox.token", map[string]*llx.RawData{
				"id":      llx.StringData(fullID),
				"comment": llx.StringData(t.Comment),
				"expire":  llx.IntData(t.Expire),
				"privsep": llx.BoolData(t.Privsep == 1),
			})
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, tok)
		}
		mqlUser.cachedTokens = tokens
		mqlUser.cachedTokensSet = true
		mqlUser.cachedGroups = groups
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) roles() ([]any, error) {
	conn := proxmoxConn(r)
	roles, err := conn.GetRoles()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(roles))
	for i, role := range roles {
		var privs []any
		if role.Privs != "" {
			for _, p := range strings.Split(role.Privs, ",") {
				privs = append(privs, p)
			}
		}
		res, err := CreateResource(r.MqlRuntime, "proxmox.role", map[string]*llx.RawData{
			"id":      llx.StringData(role.RoleID),
			"privs":   llx.ArrayData(privs, "\x02"),
			"special": llx.BoolData(role.Special == 1),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}
