// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"sort"
	"strings"

	"go.mondoo.com/mql/llx"
)

// ---------------------------------------------------------------------------
// VM PCI passthrough
// ---------------------------------------------------------------------------

// pciHostKey reports whether a VM config key like `hostpci3` is a valid
// passthrough slot. PVE caps at hostpci15.
func pciHostKey(key string) bool {
	if !strings.HasPrefix(key, "hostpci") {
		return false
	}
	rest := key[len("hostpci"):]
	if rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	// Reject `hostpci99` style keys so we only surface what PVE accepts.
	switch rest {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		"10", "11", "12", "13", "14", "15":
		return true
	}
	return false
}

// parseHostPCIConfig pulls the audit-relevant knobs out of a `hostpci<n>`
// config value. Two leading forms are accepted: a direct PCI address
// (`0000:01:00.0`, with optional `.func` suffix), or a `mapping=<name>`
// reference. The remaining comma-separated key=value pairs are the
// per-device tuning knobs PVE documents.
func parseHostPCIConfig(slot, val string) map[string]*llx.RawData {
	var address, mapping, mdev string
	var pciExpress, romBar, xVga bool
	for i, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		key := kv[0]
		var value string
		if len(kv) == 2 {
			value = kv[1]
		}
		// First token may carry no `=` — it's the bare address.
		if i == 0 && len(kv) == 1 {
			address = key
			continue
		}
		switch key {
		case "host":
			// `host=<addr>` is the explicit form of the bare address above
			if address == "" {
				address = value
			}
		case "mapping":
			mapping = value
		case "pcie", "pcie-express":
			// PVE accepts both forms; either means "expose as PCI Express"
			pciExpress = value == "1"
		case "rombar":
			romBar = value == "1"
		case "x-vga":
			xVga = value == "1"
		case "mdev":
			mdev = value
		}
	}
	return map[string]*llx.RawData{
		"__id":       llx.StringData("proxmox.vm.pciDevice/" + slot),
		"slot":       llx.StringData(slot),
		"address":    llx.StringData(address),
		"mapping":    llx.StringData(mapping),
		"pciExpress": llx.BoolData(pciExpress),
		"romBar":     llx.BoolData(romBar),
		"xVga":       llx.BoolData(xVga),
		"mdev":       llx.StringData(mdev),
		"raw":        llx.StringData(val),
	}
}

func (r *mqlProxmoxVm) pciDevices() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	// Sort keys so the returned list is deterministic across runs;
	// Proxmox returns the config as a map without ordering guarantees.
	keys := make([]string, 0)
	for k := range r.vmConfig {
		if pciHostKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	list := make([]any, 0, len(keys))
	for _, k := range keys {
		valStr := fmt.Sprintf("%v", r.vmConfig[k])
		args := parseHostPCIConfig(k, valStr)
		// Disambiguate cache key by VM so two VMs don't collide on `hostpci0`.
		args["__id"] = llx.StringData(fmt.Sprintf("proxmox.vm.pciDevice/%d/%s", r.Id.Data, k))
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.pciDevice", args)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// VM USB passthrough
// ---------------------------------------------------------------------------

func usbVMKey(key string) bool {
	if !strings.HasPrefix(key, "usb") {
		return false
	}
	rest := key[len("usb"):]
	switch rest {
	case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
		"10", "11", "12", "13", "14":
		return true
	}
	return false
}

// parseVMUsbConfig extracts the target form (vendor:product / bus path /
// device path / `spice`) and the usb3 flag from a `usb<n>` line. PVE
// emits the target either bare (`host=...`) or as `spice` on its own.
func parseVMUsbConfig(slot, val string) map[string]*llx.RawData {
	var target string
	var usb3 bool
	for _, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		key := kv[0]
		var value string
		if len(kv) == 2 {
			value = kv[1]
		}
		switch {
		case key == "host" && len(kv) == 2:
			target = value
		case key == "spice" && len(kv) == 1:
			target = "spice"
		case key == "usb3" && len(kv) == 2:
			usb3 = value == "1"
		default:
			// Bare token with no `=`: PVE accepts host paths directly.
			if len(kv) == 1 && target == "" {
				target = key
			}
		}
	}
	return map[string]*llx.RawData{
		"slot":   llx.StringData(slot),
		"target": llx.StringData(target),
		"usb3":   llx.BoolData(usb3),
		"raw":    llx.StringData(val),
	}
}

func (r *mqlProxmoxVm) usbDevices() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	keys := make([]string, 0)
	for k := range r.vmConfig {
		if usbVMKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	list := make([]any, 0, len(keys))
	for _, k := range keys {
		valStr := fmt.Sprintf("%v", r.vmConfig[k])
		args := parseVMUsbConfig(k, valStr)
		args["__id"] = llx.StringData(fmt.Sprintf("proxmox.vm.usbDevice/%d/%s", r.Id.Data, k))
		res, err := CreateResource(r.MqlRuntime, "proxmox.vm.usbDevice", args)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}

// ---------------------------------------------------------------------------
// Container host-device passthrough
// ---------------------------------------------------------------------------

// devContainerKey recognizes `dev0`..`dev255`. PVE accepts up to 256
// devNN slots; only the all-digit suffix in that range counts.
func devContainerKey(key string) bool {
	if !strings.HasPrefix(key, "dev") {
		return false
	}
	rest := key[len("dev"):]
	if rest == "" {
		return false
	}
	for _, c := range rest {
		if c < '0' || c > '9' {
			return false
		}
	}
	// Reject single-leading-zero forms (`dev01`) so PVE's own canonical
	// rendering is the only one that matches.
	if len(rest) > 1 && rest[0] == '0' {
		return false
	}
	var n int
	for _, c := range rest {
		n = n*10 + int(c-'0')
		if n > 255 {
			return false
		}
	}
	return true
}

func parseContainerDeviceConfig(slot, val string) map[string]*llx.RawData {
	var path, mode string
	var uid, gid int64
	for i, part := range strings.Split(val, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if i == 0 && len(kv) == 1 {
			path = kv[0]
			continue
		}
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "path":
			if path == "" {
				path = kv[1]
			}
		case "uid":
			fmt.Sscanf(kv[1], "%d", &uid)
		case "gid":
			fmt.Sscanf(kv[1], "%d", &gid)
		case "mode":
			mode = kv[1]
		}
	}
	return map[string]*llx.RawData{
		"slot": llx.StringData(slot),
		"path": llx.StringData(path),
		"uid":  llx.IntData(uid),
		"gid":  llx.IntData(gid),
		"mode": llx.StringData(mode),
	}
}

func (r *mqlProxmoxContainer) passthroughDevices() ([]any, error) {
	r.ensureConfig()
	if r.configErr != nil {
		return nil, r.configErr
	}
	keys := make([]string, 0)
	for k := range r.ctConfig {
		if devContainerKey(k) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	list := make([]any, 0, len(keys))
	for _, k := range keys {
		valStr := fmt.Sprintf("%v", r.ctConfig[k])
		args := parseContainerDeviceConfig(k, valStr)
		args["__id"] = llx.StringData(fmt.Sprintf("proxmox.container.passthroughDevice/%d/%s", r.Id.Data, k))
		res, err := CreateResource(r.MqlRuntime, "proxmox.container.passthroughDevice", args)
		if err != nil {
			return nil, err
		}
		list = append(list, res)
	}
	return list, nil
}
