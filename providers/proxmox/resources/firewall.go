// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// firewallOptionsToResource turns the raw options dict into a typed
// proxmox.firewall.options resource. Cluster/node/guest scopes share
// the same shape — keys absent from a given scope simply read as the
// zero value, which matches Proxmox semantics.
func firewallOptionsToResource(runtime *plugin.Runtime, opts map[string]any, scope string) (any, error) {
	intOrBool := func(v any) bool {
		switch val := v.(type) {
		case bool:
			return val
		case float64:
			return val == 1
		case string:
			return val == "1" || val == "true"
		}
		return false
	}
	str := func(v any) string {
		if v == nil {
			return ""
		}
		return fmt.Sprintf("%v", v)
	}

	res, err := CreateResource(runtime, "proxmox.firewall.options", map[string]*llx.RawData{
		"__id":        llx.StringData("proxmox.firewall.options/" + scope),
		"scope":       llx.StringData(scope),
		"enable":      llx.BoolData(intOrBool(opts["enable"])),
		"policyIn":    llx.StringData(str(opts["policy_in"])),
		"policyOut":   llx.StringData(str(opts["policy_out"])),
		"logLevelIn":  llx.StringData(str(opts["log_level_in"])),
		"logLevelOut": llx.StringData(str(opts["log_level_out"])),
		"dhcp":        llx.BoolData(intOrBool(opts["dhcp"])),
		"ndp":         llx.BoolData(intOrBool(opts["ndp"])),
		"macfilter":   llx.BoolData(intOrBool(opts["macfilter"])),
		"ipfilter":    llx.BoolData(intOrBool(opts["ipfilter"])),
		"radv":        llx.BoolData(intOrBool(opts["radv"])),
		// Only the vnet scope carries a forward policy; every other scope
		// leaves these empty rather than claiming a default it has no say in.
		"policyForward":   llx.StringData(str(opts["policy_forward"])),
		"logLevelForward": llx.StringData(str(opts["log_level_forward"])),
		"config":          llx.DictData(opts),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// ipSetsToResources converts a list of IPSetInfo to proxmox.firewall.ipset.
// fetcher returns the entries for a given ipset name, allowing the same
// helper to serve cluster, VM, and container scopes.
func ipSetsToResources(
	runtime *plugin.Runtime,
	sets []connection.IPSetInfo,
	scope string,
	fetcher func(name string) ([]connection.IPSetEntry, error),
) ([]any, error) {
	list := make([]any, 0, len(sets))
	for _, s := range sets {
		res, err := CreateResource(runtime, "proxmox.firewall.ipset", map[string]*llx.RawData{
			"__id":    llx.StringData("proxmox.firewall.ipset/" + scope + "/" + s.Name),
			"scope":   llx.StringData(scope),
			"name":    llx.StringData(s.Name),
			"comment": llx.StringData(s.Comment),
		})
		if err != nil {
			return nil, err
		}
		mqlSet := res.(*mqlProxmoxFirewallIpset)
		mqlSet.entriesScope = scope + "/" + s.Name
		mqlSet.fetcher = fetcher
		mqlSet.fetcherName = s.Name
		list = append(list, res)
	}
	return list, nil
}

func aliasesToResources(runtime *plugin.Runtime, aliases []connection.AliasInfo, scope string) ([]any, error) {
	list := make([]any, len(aliases))
	for i, a := range aliases {
		ipver := int64(a.IPVer)
		if ipver == 0 {
			// Default to IPv4 when the API doesn't report a version.
			ipver = 4
		}
		res, err := CreateResource(runtime, "proxmox.firewall.alias", map[string]*llx.RawData{
			"__id":      llx.StringData("proxmox.firewall.alias/" + scope + "/" + a.Name),
			"scope":     llx.StringData(scope),
			"name":      llx.StringData(a.Name),
			"cidr":      llx.StringData(a.CIDR),
			"comment":   llx.StringData(a.Comment),
			"ipVersion": llx.IntData(ipver),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// Cluster-scope wiring
// ---------------------------------------------------------------------------

func (r *mqlProxmoxCluster) firewallOptions() (*mqlProxmoxFirewallOptions, error) {
	conn := clusterConn(r)
	opts, err := conn.GetClusterFirewallOptions()
	if err != nil {
		return nil, err
	}
	res, err := firewallOptionsToResource(r.MqlRuntime, opts, "cluster")
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxFirewallOptions), nil
}

func (r *mqlProxmoxCluster) ipsets() ([]any, error) {
	conn := clusterConn(r)
	sets, err := conn.GetClusterIPSets()
	if err != nil {
		return nil, err
	}
	return ipSetsToResources(r.MqlRuntime, sets, "cluster",
		func(name string) ([]connection.IPSetEntry, error) {
			return conn.GetClusterIPSetEntries(name)
		})
}

func (r *mqlProxmoxCluster) aliases() ([]any, error) {
	conn := clusterConn(r)
	aliases, err := conn.GetClusterAliases()
	if err != nil {
		return nil, err
	}
	return aliasesToResources(r.MqlRuntime, aliases, "cluster")
}

// ---------------------------------------------------------------------------
// Node-scope wiring
// ---------------------------------------------------------------------------

func (r *mqlProxmoxNode) firewallOptions() (*mqlProxmoxFirewallOptions, error) {
	conn := nodeConn(r)
	opts, err := conn.GetNodeFirewallOptions(r.Name.Data)
	if err != nil {
		return nil, err
	}
	res, err := firewallOptionsToResource(r.MqlRuntime, opts, "node/"+r.Name.Data)
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxFirewallOptions), nil
}

// ---------------------------------------------------------------------------
// VM-scope wiring
// ---------------------------------------------------------------------------

func (r *mqlProxmoxVm) firewallOptions() (*mqlProxmoxFirewallOptions, error) {
	conn := vmConn(r)
	opts, err := conn.GetVMFirewallOptions(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	res, err := firewallOptionsToResource(r.MqlRuntime, opts, fmt.Sprintf("vm/%d", r.Id.Data))
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxFirewallOptions), nil
}

func (r *mqlProxmoxVm) ipsets() ([]any, error) {
	conn := vmConn(r)
	sets, err := conn.GetVMIPSets(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	node := r.Node.Data
	vmid := int(r.Id.Data)
	return ipSetsToResources(r.MqlRuntime, sets, fmt.Sprintf("vm/%d", vmid),
		func(name string) ([]connection.IPSetEntry, error) {
			return conn.GetVMIPSetEntries(node, vmid, name)
		})
}

func (r *mqlProxmoxVm) aliases() ([]any, error) {
	conn := vmConn(r)
	aliases, err := conn.GetVMAliases(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	return aliasesToResources(r.MqlRuntime, aliases, fmt.Sprintf("vm/%d", r.Id.Data))
}

// ---------------------------------------------------------------------------
// Container-scope wiring
// ---------------------------------------------------------------------------

func (r *mqlProxmoxContainer) firewallOptions() (*mqlProxmoxFirewallOptions, error) {
	conn := ctConn(r)
	opts, err := conn.GetContainerFirewallOptions(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	res, err := firewallOptionsToResource(r.MqlRuntime, opts, fmt.Sprintf("ct/%d", r.Id.Data))
	if err != nil {
		return nil, err
	}
	return res.(*mqlProxmoxFirewallOptions), nil
}

func (r *mqlProxmoxContainer) ipsets() ([]any, error) {
	conn := ctConn(r)
	sets, err := conn.GetContainerIPSets(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	node := r.Node.Data
	vmid := int(r.Id.Data)
	return ipSetsToResources(r.MqlRuntime, sets, fmt.Sprintf("ct/%d", vmid),
		func(name string) ([]connection.IPSetEntry, error) {
			return conn.GetContainerIPSetEntries(node, vmid, name)
		})
}

func (r *mqlProxmoxContainer) aliases() ([]any, error) {
	conn := ctConn(r)
	aliases, err := conn.GetContainerAliases(r.Node.Data, int(r.Id.Data))
	if err != nil {
		return nil, err
	}
	return aliasesToResources(r.MqlRuntime, aliases, fmt.Sprintf("ct/%d", r.Id.Data))
}

// ---------------------------------------------------------------------------
// IPset entries — resolved through the parent's fetcher closure
// ---------------------------------------------------------------------------

func (r *mqlProxmoxFirewallIpset) entries() ([]any, error) {
	if r.fetcher == nil {
		return []any{}, nil
	}
	entries, err := r.fetcher(r.fetcherName)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(entries))
	for i, e := range entries {
		res, err := CreateResource(r.MqlRuntime, "proxmox.firewall.ipset.entry", map[string]*llx.RawData{
			"__id":    llx.StringData("proxmox.firewall.ipset.entry/" + r.entriesScope + "/" + e.CIDR),
			"cidr":    llx.StringData(e.CIDR),
			"comment": llx.StringData(e.Comment),
			"nomatch": llx.BoolData(e.NoMatch == 1),
		})
		if err != nil {
			return nil, err
		}
		// The fetcher closure and scope still need to be reachable from
		// the parent for any further drill-down; the cache key is
		// already correct via __id above.
		mqlEntry := res.(*mqlProxmoxFirewallIpsetEntry)
		mqlEntry.scope = r.entriesScope
		mqlEntry.ipsetID = r.fetcherName
		list[i] = res
	}
	return list, nil
}
