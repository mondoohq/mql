// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

type mqlProxmoxContainerInternal struct {
	configOnce sync.Once
	ctConfig   map[string]any
	configErr  error
}

func ctConn(r *mqlProxmoxContainer) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

func (r *mqlProxmoxContainer) id() (string, error) {
	return fmt.Sprintf("proxmox.container/%d", r.Id.Data), nil
}

func containerInfoToResources(runtime *plugin.Runtime, cts []connection.ContainerInfo) ([]any, error) {
	list := make([]any, len(cts))
	for i, ct := range cts {
		res, err := CreateResource(runtime, "proxmox.container", map[string]*llx.RawData{
			"id":        llx.IntData(int64(ct.VMID)),
			"name":      llx.StringData(ct.Name),
			"node":      llx.StringData(ct.Node),
			"status":    llx.StringData(ct.Status),
			"cpu":       llx.FloatData(ct.CPU),
			"maxcpu":    llx.IntData(int64(ct.MaxCPU)),
			"mem":       llx.IntData(ct.Mem),
			"maxmem":    llx.IntData(ct.MaxMem),
			"disk":      llx.IntData(ct.Disk),
			"maxdisk":   llx.IntData(ct.MaxDisk),
			"diskread":  llx.IntData(ct.DiskRead),
			"diskwrite": llx.IntData(ct.DiskWrite),
			"netin":     llx.IntData(ct.NetIn),
			"netout":    llx.IntData(ct.NetOut),
			"uptime":    llx.IntData(ct.Uptime),
			"template":  llx.BoolData(ct.Template == 1),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmox) containers() ([]any, error) {
	conn := proxmoxConn(r)
	cts, err := conn.GetAllContainers()
	if err != nil {
		return nil, err
	}
	return containerInfoToResources(r.MqlRuntime, cts)
}

func (r *mqlProxmoxNode) containers() ([]any, error) {
	conn := nodeConn(r)
	cts, err := conn.GetNodeContainers(r.Name.Data)
	if err != nil {
		return nil, err
	}
	return containerInfoToResources(r.MqlRuntime, cts)
}

func (r *mqlProxmoxContainer) ensureConfig() {
	r.configOnce.Do(func() {
		r.ctConfig, r.configErr = ctConn(r).GetContainerConfig(r.Node.Data, int(r.Id.Data))
	})
}

// cfgStr reads a key out of the container config. A failed config read is
// reported as an error rather than an empty value: "the key is absent" and
// "we never got to see the config" are different answers and an audit has to
// be able to tell them apart.
func (r *mqlProxmoxContainer) cfgStr(key string) (string, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return "", r.configErr
	}
	if v, ok := r.ctConfig[key]; ok {
		return fmt.Sprintf("%v", v), nil
	}
	return "", nil
}

// cfgBool reads a boolean-ish key out of the container config. PVE writes
// flags as 1/0, so an absent key means the flag is off. A failed config read
// is an error, not an off flag.
func (r *mqlProxmoxContainer) cfgBool(key string) (bool, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return false, r.configErr
	}
	v, ok := r.ctConfig[key]
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

func (r *mqlProxmoxContainer) config() (any, error) {
	r.ensureConfig()
	return r.ctConfig, r.configErr
}

func (r *mqlProxmoxContainer) osType() (string, error)       { return r.cfgStr("ostype") }
func (r *mqlProxmoxContainer) hostname() (string, error)     { return r.cfgStr("hostname") }
func (r *mqlProxmoxContainer) unprivileged() (bool, error)   { return r.cfgBool("unprivileged") }
func (r *mqlProxmoxContainer) protection() (bool, error)     { return r.cfgBool("protection") }
func (r *mqlProxmoxContainer) onboot() (bool, error)         { return r.cfgBool("onboot") }
func (r *mqlProxmoxContainer) description() (string, error)  { return r.cfgStr("description") }
func (r *mqlProxmoxContainer) cmode() (string, error)        { return r.cfgStr("cmode") }
func (r *mqlProxmoxContainer) searchDomain() (string, error) { return r.cfgStr("searchdomain") }
func (r *mqlProxmoxContainer) nameserver() (string, error)   { return r.cfgStr("nameserver") }

// swap is configured in MB; convert to bytes for consistency with the
// other size fields on the resource.
func (r *mqlProxmoxContainer) swap() (int64, error) {
	val, err := r.cfgStr("swap")
	if err != nil {
		return 0, err
	}
	if val == "" {
		return 0, nil
	}
	mb, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, nil
	}
	return mb * 1024 * 1024, nil
}

func (r *mqlProxmoxContainer) cpuLimit() (float64, error) {
	val, err := r.cfgStr("cpulimit")
	if err != nil {
		return 0, err
	}
	if val == "" {
		return 0, nil
	}
	limit, err := strconv.ParseFloat(val, 64)
	if err != nil {
		return 0, nil
	}
	return limit, nil
}

func (r *mqlProxmoxContainer) cpuUnits() (int64, error) {
	val, err := r.cfgStr("cpuunits")
	if err != nil {
		return 0, err
	}
	if val == "" {
		return 0, nil
	}
	units, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, nil
	}
	return units, nil
}

// rawLxc surfaces the user-injected `lxc.<key>: <value>` lines. PVE
// stores the field as one logical newline-delimited string; split it
// and trim so audits can iterate one override at a time.
func (r *mqlProxmoxContainer) rawLxc() ([]any, error) {
	val, err := r.cfgStr("lxc")
	if err != nil {
		return nil, err
	}
	if val == "" {
		return []any{}, nil
	}
	lines := parseRawLxcLines(val)
	out := make([]any, len(lines))
	for i, line := range lines {
		out[i] = line
	}
	return out, nil
}

// parseRawLxcLines splits a multi-line `lxc` config value into its
// individual `lxc.<key>: <value>` lines. PVE uses `\n` as the line
// delimiter inside JSON; some older API responses use the literal
// two-character sequence `\\n`. Handle both, drop blank lines and the
// commented-out form `#lxc.cap.drop = ...`.
func parseRawLxcLines(raw string) []string {
	// Normalize the literal-backslash form first.
	raw = strings.ReplaceAll(raw, "\\n", "\n")
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, line)
	}
	return out
}

func (r *mqlProxmoxContainer) features() ([]any, error) {
	val, err := r.cfgStr("features")
	if err != nil {
		return nil, err
	}
	if val == "" {
		return []any{}, nil
	}
	// features line is comma-separated; an enabled flag is written as
	// `keyctl=1` or `nesting=1` and a parameter-style flag like
	// `mount=nfs;cifs`. We surface the keys whose value isn't "0" since
	// "feature is enabled" is what audits care about.
	var out []any
	for _, part := range strings.Split(val, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		key := strings.TrimSpace(kv[0])
		v := strings.TrimSpace(kv[1])
		if key == "" || v == "0" {
			continue
		}
		out = append(out, key)
	}
	return out, nil
}

func (r *mqlProxmoxContainer) tags() ([]any, error) {
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

// pool resolves the guest's resource pool. Membership is recorded on the pool,
// not in the guest config, so it is read from the cluster resource listing.
func (r *mqlProxmoxContainer) pool() (*mqlProxmoxPool, error) {
	id, err := ctConn(r).GuestPool(int(r.Id.Data))
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

func (r *mqlProxmoxContainer) networks() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	var list []any
	for key, val := range r.ctConfig {
		if !isNetSlotKey(key) {
			continue
		}
		valStr := fmt.Sprintf("%v", val)
		net := parseContainerNetworkConfig(key, valStr)
		net["__id"] = llx.StringData(fmt.Sprintf("proxmox.container.network/%d/%s", r.Id.Data, key))
		res, err := CreateResource(r.MqlRuntime, "proxmox.container.network", net)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlProxmoxContainer) mountPoints() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	var list []any
	// rootfs is the root mount; mp0..mp254 are extra mounts.
	for key, val := range r.ctConfig {
		if key != "rootfs" && !strings.HasPrefix(key, "mp") {
			continue
		}
		if strings.HasPrefix(key, "mp") {
			// Exclude memory pool keys (mpregion etc. don't exist but be defensive)
			rest := key[2:]
			if rest == "" {
				continue
			}
			allDigit := true
			for _, c := range rest {
				if c < '0' || c > '9' {
					allDigit = false
					break
				}
			}
			if !allDigit {
				continue
			}
		}
		valStr := fmt.Sprintf("%v", val)
		mp := parseContainerMountPoint(key, valStr)
		mp["__id"] = llx.StringData(fmt.Sprintf("proxmox.container.mountPoint/%d/%s", r.Id.Data, key))
		res, err := CreateResource(r.MqlRuntime, "proxmox.container.mountPoint", mp)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *mqlProxmoxContainer) snapshots() ([]any, error) {
	conn := ctConn(r)
	snaps, err := conn.GetContainerSnapshots(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	list := make([]any, len(snaps))
	for i, s := range snaps {
		// Container snapshots share the proxmox.vm.snapshot resource
		// type with VM snapshots, so the cache key needs a scope prefix
		// to keep VM <id> and container <id> from colliding when they
		// happen to use the same VMID for unrelated guests.
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.snapshot", map[string]*llx.RawData{
			"__id":        llx.StringData(fmt.Sprintf("proxmox.vm.snapshot/ct/%d/%s", r.Id.Data, s.Name)),
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

func (r *mqlProxmoxContainer) firewallRules() ([]any, error) {
	conn := ctConn(r)
	rules, err := conn.GetContainerFirewallRules(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	return firewallRulesToResources(r.MqlRuntime, rules, fmt.Sprintf("ct/%d", r.Id.Data))
}
