// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

type mqlProxmoxVmInternal struct {
	configOnce sync.Once
	vmConfig   map[string]interface{}
	configErr  error
	osInfoOnce sync.Once
	osInfo     *connection.OsInfo
	osInfoErr  error
}

func vmConn(r *mqlProxmoxVm) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

func (r *mqlProxmoxVm) id() (string, error) {
	return fmt.Sprintf("proxmox.vm/%d", r.Id.Data), nil
}

func (r *mqlProxmoxVm) ensureConfig() {
	r.configOnce.Do(func() {
		r.vmConfig, r.configErr = vmConn(r).GetVMConfig(r.Node.Data, int(r.Id.Data))
	})
}

// cfgStr reads a key out of the VM config. A failed config read is reported
// as an error rather than an empty value: "the key is absent" and "we never
// got to see the config" are different answers and an audit has to be able to
// tell them apart.
func (r *mqlProxmoxVm) cfgStr(key string) (string, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return "", r.configErr
	}
	if v, ok := r.vmConfig[key]; ok {
		return fmt.Sprintf("%v", v), nil
	}
	return "", nil
}

// cfgBool reads a boolean-ish key out of the VM config. PVE writes flags as
// 1/0, so an absent key means the flag is off. A failed config read is an
// error, not an off flag.
func (r *mqlProxmoxVm) cfgBool(key string) (bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return false, r.configErr
	}
	v, ok := r.vmConfig[key]
	if !ok {
		return false, nil
	}
	switch val := v.(type) {
	case bool:
		return val, nil
	case float64:
		return val == 1, nil
	case string:
		return val == "1" || val == "true", nil
	}
	return false, nil
}

func (r *mqlProxmoxVm) config() (any, error) {
	r.ensureConfig()
	return r.vmConfig, r.configErr
}

func (r *mqlProxmoxVm) osType() (string, error)  { return r.cfgStr("ostype") }
func (r *mqlProxmoxVm) machine() (string, error) { return r.cfgStr("machine") }

// bios falls back to seabios, which is what PVE boots a VM with when the key
// is absent from the config. That default only holds for a config we actually
// read; a failed read is reported as an error instead.
func (r *mqlProxmoxVm) bios() (string, error) {
	b, err := r.cfgStr("bios")
	if err != nil {
		return "", err
	}
	if b == "" {
		b = "seabios"
	}
	return b, nil
}

func (r *mqlProxmoxVm) bootOrder() (string, error) { return r.cfgStr("boot") }

// agent reads the `agent` line, which is a property string whose positional
// value is `enabled`: `1`, `enabled=1`, and `1,fstrim_cloned_disks=1` all
// mean the agent is on. Comparing the whole line against "1" reports every
// agent configured with an option as disabled.
func (r *mqlProxmoxVm) agent() (bool, error) {
	props, found, err := r.cfgProps("agent", "enabled")
	if err != nil || !found {
		return false, err
	}
	if v := connection.PropBool(props, "enabled"); v != nil {
		return *v, nil
	}
	return false, nil
}

func (r *mqlProxmoxVm) protection() (bool, error)    { return r.cfgBool("protection") }
func (r *mqlProxmoxVm) description() (string, error) { return r.cfgStr("description") }
func (r *mqlProxmoxVm) lock() (string, error)        { return r.cfgStr("lock") }
func (r *mqlProxmoxVm) hookscript() (string, error)  { return r.cfgStr("hookscript") }
func (r *mqlProxmoxVm) args() (string, error)        { return r.cfgStr("args") }
func (r *mqlProxmoxVm) vga() (string, error)         { return r.cfgStr("vga") }

// --- Cloud-init ---

func (r *mqlProxmoxVm) ciuser() (string, error)       { return r.cfgStr("ciuser") }
func (r *mqlProxmoxVm) sshkeys() (string, error)      { return r.cfgStr("sshkeys") }
func (r *mqlProxmoxVm) searchDomain() (string, error) { return r.cfgStr("searchdomain") }
func (r *mqlProxmoxVm) nameserver() (string, error)   { return r.cfgStr("nameserver") }

// cipasswordSet only reports whether the key is present in the VM
// config; the password value itself is intentionally never read or
// surfaced through this resource. Audits should focus on whether a
// password is configured, not on what it is.
func (r *mqlProxmoxVm) cipasswordSet() (bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return false, r.configErr
	}
	v, ok := r.vmConfig["cipassword"]
	if !ok {
		return false, nil
	}
	// PVE returns the raw value; a non-empty string means a password is set.
	switch val := v.(type) {
	case string:
		return val != "", nil
	default:
		return v != nil, nil
	}
}

func (r *mqlProxmoxVm) ciCustom() (any, error) {
	// `cicustom` is serialized as comma-delimited key=storage:snippets/file
	// pairs (e.g. `user=local:snippets/u.yaml,network=local:snippets/n.yaml`).
	val, err := r.cfgStr("cicustom")
	if err != nil {
		return nil, err
	}
	out := map[string]any{}
	if val == "" {
		return out, nil
	}
	for _, part := range strings.Split(val, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		out[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
	}
	return out, nil
}

func (r *mqlProxmoxVm) serialPorts() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	var list []any
	for key, val := range r.vmConfig {
		if !isSerialPortKey(key) {
			continue
		}
		target := fmt.Sprintf("%v", val)
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.serialPort", map[string]*llx.RawData{
			"__id":   llx.StringData(fmt.Sprintf("proxmox.vm.serialPort/%d/%s", r.Id.Data, key)),
			"id":     llx.StringData(key),
			"target": llx.StringData(target),
		})
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// isSerialPortKey matches serial0..serial3 — the only valid slot names
// in PVE. Anything else (`serialport` style typos, future slots) is
// ignored so the audit sees exactly the ports PVE actually exposes.
func isSerialPortKey(key string) bool {
	if !strings.HasPrefix(key, "serial") {
		return false
	}
	suffix := key[len("serial"):]
	if len(suffix) != 1 {
		return false
	}
	return suffix[0] >= '0' && suffix[0] <= '3'
}

func (r *mqlProxmoxVm) tags() ([]any, error) {
	tagStr, err := r.cfgStr("tags")
	if err != nil {
		return nil, err
	}
	if tagStr == "" {
		return []any{}, nil
	}
	parts := strings.Split(tagStr, ";")
	result := make([]any, len(parts))
	for i, p := range parts {
		result[i] = p
	}
	return result, nil
}

func (r *mqlProxmoxVm) pool() (*mqlProxmoxPool, error) {
	id, err := r.cfgStr("pool")
	if err != nil {
		return nil, err
	}
	if id == "" {
		r.Pool.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.pool", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxPool), nil
}

func (r *mqlProxmoxVm) networks() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	var list []any
	for key, val := range r.vmConfig {
		if !isNetSlotKey(key) {
			continue
		}
		valStr := fmt.Sprintf("%v", val)
		net := parseVMNetworkConfig(key, valStr)
		net["__id"] = llx.StringData(fmt.Sprintf("proxmox.vm.network/%d/%s", r.Id.Data, key))
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.network", net)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlProxmoxVm) disks() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	prefixes := []string{"scsi", "virtio", "ide", "sata", "efidisk", "tpmstate"}
	var list []any
	for key, val := range r.vmConfig {
		isDisk := false
		for _, p := range prefixes {
			if strings.HasPrefix(key, p) {
				isDisk = true
				break
			}
		}
		if !isDisk {
			continue
		}
		valStr := fmt.Sprintf("%v", val)
		if !strings.Contains(valStr, ":") {
			continue
		}
		disk := parseVMDiskConfig(key, valStr)
		disk["__id"] = llx.StringData(fmt.Sprintf("proxmox.vm.virtualDisk/%d/%s", r.Id.Data, key))
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.virtualDisk", disk)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlProxmoxVm) snapshots() ([]any, error) {
	conn := vmConn(r)
	snaps, err := conn.GetVMSnapshots(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	list := make([]any, len(snaps))
	for i, s := range snaps {
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.snapshot", map[string]*llx.RawData{
			"__id":        llx.StringData(fmt.Sprintf("proxmox.vm.snapshot/vm/%d/%s", r.Id.Data, s.Name)),
			"name":        llx.StringData(s.Name),
			"description": llx.StringData(s.Description),
			"parent":      llx.StringData(s.Parent),
			"snaptime":    llx.IntData(s.Snaptime),
			"vmstate":     llx.BoolData(s.VMState == 1),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxVm) firewallRules() ([]any, error) {
	conn := vmConn(r)
	rules, err := conn.GetVMFirewallRules(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	return firewallRulesToResources(r.MqlRuntime, rules, fmt.Sprintf("vm/%d", r.Id.Data))
}

func (r *mqlProxmoxVm) updates() ([]any, error) {
	if r.Status.Data != "running" {
		return []any{}, nil
	}
	conn := vmConn(r)
	vmid := int(r.Id.Data)
	r.osInfoOnce.Do(func() {
		r.osInfo, r.osInfoErr = conn.GetOsInfo(r.Node.Data, vmid)
	})
	if r.osInfoErr != nil {
		if errors.Is(r.osInfoErr, connection.ErrQGANotRunning) {
			// Without the guest agent we can't enumerate updates; return an
			// empty list rather than failing the field, so iterating
			// `vms { updates }` doesn't error on the first agent-less VM
			// (consistent with the Windows-update path). Warn so operators can
			// still see which VMs are agent-less.
			log.Warn().Int("vmid", vmid).Msg("guest agent not reachable, returning empty updates list")
			return []any{}, nil
		}
		return nil, r.osInfoErr
	}
	updates, err := conn.GetUpdates(r.Node.Data, vmid, r.osInfo)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(updates))
	for i, u := range updates {
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.update", map[string]*llx.RawData{
			"__id":             llx.StringData(fmt.Sprintf("proxmox.vm.update/%d/%s", r.Id.Data, u.Name)),
			"name":             llx.StringData(u.Name),
			"installedVersion": llx.StringData(u.InstalledVersion),
			"newVersion":       llx.StringData(u.NewVersion),
			"upgradable":       llx.BoolData(u.Upgradable),
			"severity":         llx.StringData(u.Severity),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// --- User tokens ---
//
// When the user came from the cluster-wide listing the tokens are
// already populated in cachedTokens (see proxmox.users()), so we
// short-circuit. The per-user /access/users/<id>/token fetch is
// reserved for the init path that resolves a single user by id
// (e.g. an ACL grant pointing at a user we haven't enumerated).
//
// No sync.Once is needed for the cached-read path: cachedTokens and
// cachedTokensSet are written synchronously inside proxmox.users()
// before the resource is published to the runtime, so by the time
// any caller can invoke tokens() the writes have happened-before in
// the same goroutine that returned the resource list.
func (r *mqlProxmoxUser) tokens() ([]any, error) {
	if r.cachedTokensSet {
		return r.cachedTokens, nil
	}
	conn := r.MqlRuntime.Connection.(*connection.PveConnection)
	tokens, err := conn.GetUserTokens(r.Id.Data)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(tokens))
	for i, t := range tokens {
		fullID := r.Id.Data + "!" + t.TokenID
		res, err := CreateResource(r.MqlRuntime, "proxmox.token", map[string]*llx.RawData{
			"id":      llx.StringData(fullID),
			"comment": llx.StringData(t.Comment),
			"expire":  llx.IntData(t.Expire),
			"privsep": llx.BoolData(t.Privsep == 1),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}
