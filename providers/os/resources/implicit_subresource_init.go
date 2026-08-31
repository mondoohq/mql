// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Codegen synthesizes an implicit singular field for every sub-resource, so a
// query can name `nftables.table` as a static path even though the schema only
// declares the plural `nftables.tables` list. Naming the singular form builds
// the sub-resource standalone: it never sees the parent that would have filled
// it in, so its id is empty or garbage and every field stays unset. The runtime
// then reports "provider returned no data and no error for a field" and the
// query yields nulls, which a check reads as a real answer rather than as a
// failure.
//
// The inits below refuse that instantiation, following the `logrotate.entry`
// model of erroring out instead of handing back a husk. Each one keeps the fast
// path for arguments that already carry the sub-resource's identity, so the
// parent listers and the typed accessors that resolve through NewResource are
// unaffected.

// errSubResourceNeedsParent reports that a sub-resource cannot stand on its own
// and names the parent collection to query instead.
func errSubResourceNeedsParent(resource string, parent string) error {
	return fmt.Errorf("%s cannot be initialized on its own, it only exists as part of %s", resource, parent)
}

// hasStringArgs reports whether every named argument is present and holds a
// non-empty string. An argument that is absent, null, or empty cannot identify
// a sub-resource, which is exactly the state a standalone instantiation lands in.
func hasStringArgs(args map[string]*llx.RawData, names ...string) bool {
	for _, name := range names {
		raw, ok := args[name]
		if !ok || raw == nil {
			return false
		}
		s, ok := raw.Value.(string)
		if !ok || s == "" {
			return false
		}
	}
	return true
}

func initNftablesTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "family", "name") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("nftables.table", "nftables.tables")
}

func initNftablesChain(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "family", "table", "name") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("nftables.chain", "nftables.chains")
}

func initNftablesRule(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "family", "table", "chain") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("nftables.rule", "nftables.rules")
}

func initNftablesSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "family", "table", "name") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("nftables.set", "nftables.sets")
}

func initIptablesTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "name") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("iptables.table", "iptables.tables")
}

func initIptablesChain(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "table", "name") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("iptables.chain", "iptables.tables")
}

func initIptablesEntry(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "chain") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("iptables.entry", "iptables.input, iptables.output, iptables.forward, or iptables.tables")
}

func initLsblkEntry(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "name") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("lsblk.entry", "lsblk.list")
}

func initJournaldConfigSection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "name") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("journald.config.section", "journald.config.sections")
}

func initModprobeBlacklist(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "file") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("modprobe.blacklist", "modprobe.blacklists")
}

func initModprobeAlias(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "file") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("modprobe.alias", "modprobe.aliases")
}

func initModprobeInstall(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "file") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("modprobe.install", "modprobe.installs")
}

func initModprobeOption(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "file") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("modprobe.option", "modprobe.options")
}

func initModprobeRemove(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "file") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("modprobe.remove", "modprobe.removes")
}

func initModprobeSoftdep(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if hasStringArgs(args, "file") {
		return args, nil, nil
	}
	return nil, nil, errSubResourceNeedsParent("modprobe.softdep", "modprobe.softdeps")
}
