// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/proxmox/connection"
)

// vmInfoToResources converts a slice of VMInfo to MQL resources.
func vmInfoToResources(runtime *plugin.Runtime, vms []connection.VMInfo) ([]any, error) {
	list := make([]any, len(vms))
	for i, vm := range vms {
		res, err := CreateResource(runtime, "proxmox.vm", map[string]*llx.RawData{
			"id":        llx.IntData(int64(vm.VMID)),
			"name":      llx.StringData(vm.Name),
			"node":      llx.StringData(vm.Node),
			"status":    llx.StringData(vm.Status),
			"cpu":       llx.FloatData(vm.CPU),
			"maxcpu":    llx.IntData(int64(vm.MaxCPU)),
			"mem":       llx.IntData(vm.Mem),
			"maxmem":    llx.IntData(vm.MaxMem),
			"disk":      llx.IntData(vm.Disk),
			"maxdisk":   llx.IntData(vm.MaxDisk),
			"diskread":  llx.IntData(vm.DiskRead),
			"diskwrite": llx.IntData(vm.DiskWrite),
			"netin":     llx.IntData(vm.NetIn),
			"netout":    llx.IntData(vm.NetOut),
			"uptime":    llx.IntData(vm.Uptime),
			"template":  llx.BoolData(vm.Template == 1),
		})
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// storageInfoToResources converts a slice of StorageInfo to MQL resources.
//
// node is empty for the cluster-wide /storage listing and names the node for
// /nodes/<n>/storage. The two views of one storage are different records: the
// node view carries that node's usage and activity, the cluster view carries
// the configuration (path, node restriction, encryption key). A local storage
// such as `local-lvm` also exists once per node with independent usage. Keying
// every view on the storage name alone made them share one cache entry, so
// whichever listing ran first answered for all of them.
func storageInfoToResources(runtime *plugin.Runtime, storages []connection.StorageInfo, node string) ([]any, error) {
	list := make([]any, len(storages))
	for i, s := range storages {
		var usagePct float64
		// Prefer UsedFrac (pre-computed by Proxmox); fall back to manual calculation
		if s.UsedFrac > 0 {
			usagePct = s.UsedFrac * 100.0
		} else if s.Total > 0 {
			usagePct = float64(s.Used) / float64(s.Total) * 100.0
		}
		args := map[string]*llx.RawData{
			"id":            llx.StringData(s.Storage),
			"type":          llx.StringData(s.Type),
			"content":       llx.StringData(s.Content),
			"path":          llx.StringData(s.Path),
			"nodes":         llx.StringData(s.Nodes),
			"enabled":       llx.BoolData(s.Enabled != 0),
			"shared":        llx.BoolData(s.Shared != 0),
			"total":         llx.IntData(s.Total),
			"used":          llx.IntData(s.Used),
			"available":     llx.IntData(s.Avail),
			"usagePercent":  llx.FloatData(usagePct),
			"encrypted":     llx.BoolData(s.EncryptionKey != ""),
			"encryptionKey": llx.StringData(s.EncryptionKey),
		}
		if node != "" {
			args["__id"] = llx.StringData(nodeStorageCacheKey(node, s.Storage))
		}
		res, err := CreateResource(runtime, "proxmox.storage", args)
		if err != nil {
			return nil, err
		}
		list[i] = res
	}
	return list, nil
}

// nodeStorageCacheKey is the cache key of a storage as one node reports it.
// The cluster-wide view keeps the `proxmox.storage/<name>` key from id(), which
// is also what references to a storage by name resolve to.
func nodeStorageCacheKey(node, storage string) string {
	return "proxmox.storage/node/" + node + "/" + storage
}

// firewallRulesToResources converts firewall rules to MQL resources.
// scope identifies the owner (e.g. "cluster", "node/pve1", "vm/100") to
// prevent cache-key collisions when identical rules exist at different levels.
func firewallRulesToResources(runtime *plugin.Runtime, rules []connection.FirewallRule, scope string) ([]any, error) {
	list := make([]any, len(rules))
	for i, rule := range rules {
		res, err := CreateResource(runtime, "proxmox.firewall.rule", map[string]*llx.RawData{
			// Set __id explicitly: `scope` is an Internal-struct field assigned
			// after CreateResource returns, but the cache key is computed inside
			// CreateResource. Deriving it from id() there would bake an empty
			// scope segment, so two identical rules in different scopes (e.g.
			// vm/100 and vm/101) would collide and alias to the first.
			"__id": llx.StringData(fmt.Sprintf("proxmox.firewall.rule/%s/%d/%s/%s/%s/%s",
				scope, rule.Pos, rule.Type, rule.Action, rule.Source, rule.Dest)),
			"pos":     llx.IntData(int64(rule.Pos)),
			"type":    llx.StringData(rule.Type),
			"action":  llx.StringData(rule.Action),
			"comment": llx.StringData(rule.Comment),
			"dest":    llx.StringData(rule.Dest),
			"dport":   llx.StringData(rule.Dport),
			"enable":  llx.BoolData(rule.Enable == 1),
			"iface":   llx.StringData(rule.Iface),
			"log":     llx.StringData(rule.Log),
			"macro":   llx.StringData(rule.Macro),
			"proto":   llx.StringData(rule.Proto),
			"source":  llx.StringData(rule.Source),
			"sport":   llx.StringData(rule.Sport),
		})
		if err != nil {
			return nil, err
		}
		res.(*mqlProxmoxFirewallRule).scope = scope
		list[i] = res
	}
	return list, nil
}

// parseVMNetworkConfig parses a Proxmox VM network config value.
// Format: virtio=AA:BB:CC:DD:EE:FF,bridge=vmbr0,firewall=1,tag=100
func parseVMNetworkConfig(id, val string) map[string]*llx.RawData {
	model, mac, bridge := "", "", ""
	firewall := false
	tag := int64(0)

	for i, part := range strings.Split(val, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "bridge":
			bridge = kv[1]
		case "firewall":
			firewall = kv[1] == "1"
		case "tag":
			fmt.Sscanf(kv[1], "%d", &tag)
		default:
			// First part is model=macaddr (e.g. virtio=BC:24:11:AA:BB:CC)
			if i == 0 && looksLikeMAC(kv[1]) {
				model = kv[0]
				mac = kv[1]
			}
		}
	}

	return map[string]*llx.RawData{
		"id":         llx.StringData(id),
		"model":      llx.StringData(model),
		"macAddress": llx.StringData(mac),
		"bridge":     llx.StringData(bridge),
		"tag":        llx.IntData(tag),
		"firewall":   llx.BoolData(firewall),
	}
}

// parseVMDiskConfig parses a Proxmox VM disk config value.
func parseVMDiskConfig(id, val string) map[string]*llx.RawData {
	storage, format, cache := "", "", ""
	size := int64(0)
	iothread := false
	backup := true

	parts := strings.Split(val, ",")
	if len(parts) > 0 {
		if idx := strings.Index(parts[0], ":"); idx >= 0 {
			storage = parts[0][:idx]
		}
	}
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "size":
			size = parseSizeToBytes(kv[1])
		case "format":
			format = kv[1]
		case "cache":
			cache = kv[1]
		case "iothread":
			iothread = kv[1] == "1"
		case "backup":
			backup = kv[1] != "0"
		}
	}

	return map[string]*llx.RawData{
		"id":       llx.StringData(id),
		"storage":  llx.StringData(storage),
		"size":     llx.IntData(size),
		"format":   llx.StringData(format),
		"cache":    llx.StringData(cache),
		"iothread": llx.BoolData(iothread),
		"backup":   llx.BoolData(backup),
	}
}

func looksLikeMAC(s string) bool {
	return len(s) == 17 && strings.Count(s, ":") == 5
}

// isNetSlotKey reports whether a VM/CT config key is one of the
// `netN` interface slots. A naive `HasPrefix("net")` match would
// also catch the `netin`/`netout` traffic counters returned by the
// listing endpoint, so insist on a non-empty all-digit suffix.
func isNetSlotKey(key string) bool {
	if !strings.HasPrefix(key, "net") {
		return false
	}
	rest := key[len("net"):]
	if rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// parseContainerNetworkConfig parses a Proxmox LXC network config value.
// Format: name=eth0,bridge=vmbr0,firewall=1,gw=192.168.1.1,hwaddr=AA:..,
//
//	ip=dhcp,ip6=auto,tag=10,type=veth
func parseContainerNetworkConfig(id, val string) map[string]*llx.RawData {
	name, mac, bridge, ip, gw, ip6, gw6 := "", "", "", "", "", "", ""
	firewall := false
	tag := int64(0)

	for _, part := range strings.Split(val, ",") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "name":
			name = kv[1]
		case "hwaddr":
			mac = kv[1]
		case "bridge":
			bridge = kv[1]
		case "firewall":
			firewall = kv[1] == "1"
		case "tag":
			fmt.Sscanf(kv[1], "%d", &tag)
		case "ip":
			ip = kv[1]
		case "gw":
			gw = kv[1]
		case "ip6":
			ip6 = kv[1]
		case "gw6":
			gw6 = kv[1]
		}
	}

	return map[string]*llx.RawData{
		"id":         llx.StringData(id),
		"name":       llx.StringData(name),
		"macAddress": llx.StringData(mac),
		"bridge":     llx.StringData(bridge),
		"tag":        llx.IntData(tag),
		"firewall":   llx.BoolData(firewall),
		"ip":         llx.StringData(ip),
		"gw":         llx.StringData(gw),
		"ip6":        llx.StringData(ip6),
		"gw6":        llx.StringData(gw6),
	}
}

// parseContainerMountPoint parses a Proxmox LXC mount-point config value.
// Format: local-lvm:vm-100-disk-0,size=8G,mp=/data,backup=1,ro=0,acl=1,replicate=1
// rootfs uses the same format minus mp=.
func parseContainerMountPoint(id, val string) map[string]*llx.RawData {
	storage, mountPath := "", ""
	size := int64(0)
	// In PVE only rootfs is backed up by default; additional mount points
	// (mp0..mp254) are EXCLUDED from vzdump unless backup=1 is set explicitly.
	// (This differs from QEMU disks, where a drive is included unless backup=0.)
	backup := id == "rootfs"
	replicate := true
	readonly := false
	aclEnabled := false

	parts := strings.Split(val, ",")
	if len(parts) > 0 {
		if idx := strings.Index(parts[0], ":"); idx >= 0 {
			storage = parts[0][:idx]
		}
	}
	for _, part := range parts[1:] {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "size":
			size = parseSizeToBytes(kv[1])
		case "mp":
			mountPath = kv[1]
		case "backup":
			backup = kv[1] != "0"
		case "replicate":
			replicate = kv[1] != "0"
		case "ro":
			readonly = kv[1] == "1"
		case "acl":
			aclEnabled = kv[1] == "1"
		}
	}
	if id == "rootfs" && mountPath == "" {
		mountPath = "/"
	}

	return map[string]*llx.RawData{
		"id":         llx.StringData(id),
		"storage":    llx.StringData(storage),
		"size":       llx.IntData(size),
		"mountPath":  llx.StringData(mountPath),
		"backup":     llx.BoolData(backup),
		"replicate":  llx.BoolData(replicate),
		"readonly":   llx.BoolData(readonly),
		"aclEnabled": llx.BoolData(aclEnabled),
	}
}

func parseSizeToBytes(s string) int64 {
	s = strings.TrimSpace(s)
	multiplier := int64(1)
	if strings.HasSuffix(s, "T") {
		multiplier = 1024 * 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "T")
	} else if strings.HasSuffix(s, "G") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSuffix(s, "G")
	} else if strings.HasSuffix(s, "M") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "M")
	} else if strings.HasSuffix(s, "K") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "K")
	}
	var val float64
	fmt.Sscanf(s, "%f", &val)
	return int64(val * float64(multiplier))
}
