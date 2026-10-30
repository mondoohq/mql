// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// ---------------------------------------------------------------------------
// Fencing and HA shutdown policy
// ---------------------------------------------------------------------------

func (r *mqlProxmoxCluster) fencingMode() (string, error) {
	return r.clusterOptionString("fencing")
}

func (r *mqlProxmoxCluster) haShutdownPolicy() (string, error) {
	// /cluster/options serializes the `ha` block as a property string whose
	// only member is shutdown_policy.
	props, found, err := r.clusterOptionProps("ha", "")
	if err != nil || !found {
		return "", err
	}
	return props["shutdown_policy"], nil
}

// ---------------------------------------------------------------------------
// Cluster-wide second-factor configuration
// ---------------------------------------------------------------------------

// webauthnProps reads the `webauthn` block. A cluster that never configured
// WebAuthn has no relying party at all, which is why the sub-settings report
// empty rather than a guessed hostname.
func (r *mqlProxmoxCluster) webauthnProps() (map[string]string, bool, error) {
	return r.clusterOptionProps("webauthn", "")
}

func (r *mqlProxmoxCluster) webauthnRelyingParty() (string, error) {
	props, _, err := r.webauthnProps()
	if err != nil {
		return "", err
	}
	return props["rp"], nil
}

func (r *mqlProxmoxCluster) webauthnId() (string, error) {
	props, _, err := r.webauthnProps()
	if err != nil {
		return "", err
	}
	return props["id"], nil
}

func (r *mqlProxmoxCluster) webauthnOrigin() (string, error) {
	props, _, err := r.webauthnProps()
	if err != nil {
		return "", err
	}
	return props["origin"], nil
}

func (r *mqlProxmoxCluster) webauthnAllowSubdomains() (bool, error) {
	props, found, err := r.webauthnProps()
	if err != nil {
		return false, err
	}
	if !found {
		r.WebauthnAllowSubdomains.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	if v := connection.PropBool(props, "allow-subdomains"); v != nil {
		return *v, nil
	}
	// Proxmox accepts subdomains unless told otherwise, so an unset flag is
	// the permissive state rather than the restrictive one.
	return true, nil
}

func (r *mqlProxmoxCluster) u2fAppId() (string, error) {
	props, found, err := r.clusterOptionProps("u2f", "")
	if err != nil || !found {
		return "", err
	}
	return props["appid"], nil
}

func (r *mqlProxmoxCluster) u2fOrigin() (string, error) {
	props, found, err := r.clusterOptionProps("u2f", "")
	if err != nil || !found {
		return "", err
	}
	return props["origin"], nil
}

// ---------------------------------------------------------------------------
// Guests no backup job covers
// ---------------------------------------------------------------------------

func (r *mqlProxmoxCluster) guestsWithoutBackup() ([]any, error) {
	guests, readable, err := clusterConn(r).GetGuestsNotBackedUp()
	if err != nil {
		return nil, err
	}
	if !readable {
		// Reporting an empty list here would tell an audit that every guest
		// is covered, which is exactly what could not be established.
		r.GuestsWithoutBackup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	list := make([]any, len(guests))
	for i, g := range guests {
		res, err := CreateResource(r.MqlRuntime, "proxmox.cluster.guestWithoutBackup", map[string]*llx.RawData{
			// A VMID is cluster-unique, but the kind is carried too so the key
			// stays stable if Proxmox ever reports the same id under both.
			"__id": llx.StringData(fmt.Sprintf("proxmox.cluster.guestWithoutBackup/%s/%d", g.Type, g.VMID)),
			"vmid": llx.IntData(int64(g.VMID)),
			"name": llx.StringData(g.Name),
			"type": llx.StringData(g.Type),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxClusterGuestWithoutBackup) vm() (*mqlProxmoxVm, error) {
	if r.Type.Data != "qemu" {
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

func (r *mqlProxmoxClusterGuestWithoutBackup) container() (*mqlProxmoxContainer, error) {
	if r.Type.Data != "lxc" {
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
