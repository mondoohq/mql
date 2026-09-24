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

type mqlProxmoxClusterInternal struct {
	optionsOnce    sync.Once
	clusterOptions map[string]any
	optionsErr     error
}

func clusterConn(r *mqlProxmoxCluster) *connection.PveConnection {
	return r.MqlRuntime.Connection.(*connection.PveConnection)
}

func (r *mqlProxmoxCluster) ensureOptions() (map[string]any, error) {
	r.optionsOnce.Do(func() {
		r.clusterOptions, r.optionsErr = clusterConn(r).GetClusterOptions()
	})
	return r.clusterOptions, r.optionsErr
}

func (r *mqlProxmoxCluster) id() (string, error) {
	return "proxmox.cluster/" + r.Name.Data, nil
}

func (r *mqlProxmoxCluster) haResources() ([]any, error) {
	conn := clusterConn(r)
	ha, err := conn.GetHAResources()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(ha))
	for i, h := range ha {
		res, err := CreateResource(r.MqlRuntime, "proxmox.cluster.haResource", map[string]*llx.RawData{
			"id":          llx.StringData(h.SID),
			"type":        llx.StringData(h.Type),
			"status":      llx.StringData(h.Status),
			"node":        llx.StringData(h.Node),
			"maxRestart":  llx.IntData(int64(h.MaxRestart)),
			"maxRelocate": llx.IntData(int64(h.MaxRelocate)),
			"state":       llx.StringData(h.State),
			"group":       llx.StringData(h.Group),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxCluster) firewallRules() ([]any, error) {
	conn := clusterConn(r)
	rules, err := conn.GetClusterFirewallRules()
	if err != nil {
		return nil, err
	}
	return firewallRulesToResources(r.MqlRuntime, rules, "cluster")
}

func (r *mqlProxmoxCluster) haGroups() ([]any, error) {
	conn := clusterConn(r)
	groups, err := conn.GetHAGroups()
	if err != nil {
		return nil, err
	}
	list := make([]any, len(groups))
	for i, g := range groups {
		res, err := CreateResource(r.MqlRuntime, "proxmox.cluster.haGroup", map[string]*llx.RawData{
			"id":         llx.StringData(g.Group),
			"nodes":      llx.StringData(g.Nodes),
			"restricted": llx.BoolData(g.Restricted == 1),
			"noFailback": llx.BoolData(g.NoFailback == 1),
			"comment":    llx.StringData(g.Comment),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

func (r *mqlProxmoxCluster) options() (any, error) {
	return r.ensureOptions()
}

// ---------------------------------------------------------------------------
// Typed views over /cluster/options
// ---------------------------------------------------------------------------

// clusterOptionString reads a string-coerced value from cluster.options; if
// the key isn't present or the fetch failed, returns "" with no error so an
// audit can still proceed against partially-readable clusters.
func (r *mqlProxmoxCluster) clusterOptionString(key string) (string, error) {
	opts, err := r.ensureOptions()
	if err != nil || opts == nil {
		return "", err
	}
	v, ok := opts[key]
	if !ok || v == nil {
		return "", nil
	}
	return fmt.Sprintf("%v", v), nil
}

// clusterOptionProps reads a structured setting out of cluster.options.
//
// /cluster/options hands back datacenter.cfg as Proxmox parsed it, and the
// structured settings (`migration`, `ha`, `webauthn`, `u2f`, `crs`, ...)
// arrive as JSON objects rather than the property strings they are written
// as. Both shapes are accepted so a value is never flattened through `%v` into
// `map[...]` text that no longer parses. found is false when the key is
// absent.
func (r *mqlProxmoxCluster) clusterOptionProps(key, defaultKey string) (map[string]string, bool, error) {
	opts, err := r.ensureOptions()
	if err != nil || opts == nil {
		return nil, false, err
	}
	return optionProps(opts[key], defaultKey)
}

func optionProps(v any, defaultKey string) (map[string]string, bool, error) {
	switch val := v.(type) {
	case nil:
		return nil, false, nil
	case map[string]any:
		out := make(map[string]string, len(val))
		for k, item := range val {
			if item == nil {
				continue
			}
			out[k] = connection.PropertyValueString(item)
		}
		return out, true, nil
	case string:
		if val == "" {
			return nil, false, nil
		}
		return connection.ParsePropertyString(val, defaultKey), true, nil
	}
	return nil, false, fmt.Errorf("unexpected cluster option value of type %T", v)
}

func (r *mqlProxmoxCluster) migrationPolicy() (string, error) {
	// `migration` is `type=secure,network=10.0.0.0/24`, with `type` as the
	// positional default key.
	props, found, err := r.clusterOptionProps("migration", "type")
	if err != nil || !found {
		return "", err
	}
	return props["type"], nil
}

func (r *mqlProxmoxCluster) migrationNetwork() (string, error) {
	props, found, err := r.clusterOptionProps("migration", "type")
	if err != nil || !found {
		return "", err
	}
	return props["network"], nil
}

func (r *mqlProxmoxCluster) consoleViewer() (string, error) {
	return r.clusterOptionString("console")
}

func (r *mqlProxmoxCluster) bandwidthLimits() (any, error) {
	opts, err := r.ensureOptions()
	if err != nil || opts == nil {
		return map[string]any{}, err
	}
	raw, ok := opts["bwlimit"]
	if !ok || raw == nil {
		return map[string]any{}, nil
	}
	// `bwlimit` is serialized as a comma-delimited key=value string when
	// the user sets multiple limits, e.g. `default=10000,restore=20000`.
	// Convert it into a dict so MQL can index by operation name.
	str, isStr := raw.(string)
	if !isStr {
		return raw, nil
	}
	out := map[string]any{}
	for _, part := range strings.Split(str, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		// values are KB/s as numeric strings; carry them as int64 when
		// they parse, otherwise leave the raw string for audits to inspect.
		if n, err := strconv.ParseInt(strings.TrimSpace(kv[1]), 10, 64); err == nil {
			out[kv[0]] = n
		} else {
			out[kv[0]] = kv[1]
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// haResource cross-references
// ---------------------------------------------------------------------------

// parseHAResourceSID parses ids like "vm:100" or "ct:200" into their pieces.
// HA configs occasionally drop the prefix and just carry the numeric VMID,
// in which case `kind` is the resource's `type` and `id` is the parsed int.
func parseHAResourceSID(sid, typ string) (kind string, id int64, ok bool) {
	if colon := strings.Index(sid, ":"); colon > 0 {
		kind = sid[:colon]
		parsed, err := strconv.ParseInt(sid[colon+1:], 10, 64)
		if err != nil {
			return "", 0, false
		}
		return kind, parsed, true
	}
	parsed, err := strconv.ParseInt(sid, 10, 64)
	if err != nil {
		return "", 0, false
	}
	return typ, parsed, true
}

func (r *mqlProxmoxClusterHaResource) vm() (*mqlProxmoxVm, error) {
	kind, id, ok := parseHAResourceSID(r.Id.Data, r.Type.Data)
	if !ok || kind != "vm" {
		r.Vm.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.vm", map[string]*llx.RawData{
		"id": llx.IntData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxVm), nil
}

func (r *mqlProxmoxClusterHaResource) container() (*mqlProxmoxContainer, error) {
	kind, id, ok := parseHAResourceSID(r.Id.Data, r.Type.Data)
	if !ok || kind != "ct" {
		r.Container.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.container", map[string]*llx.RawData{
		"id": llx.IntData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxContainer), nil
}

func (r *mqlProxmoxClusterHaResource) groupRef() (*mqlProxmoxClusterHaGroup, error) {
	if r.Group.Data == "" {
		r.GroupRef.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "proxmox.cluster.haGroup", map[string]*llx.RawData{
		"id": llx.StringData(r.Group.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxClusterHaGroup), nil
}
