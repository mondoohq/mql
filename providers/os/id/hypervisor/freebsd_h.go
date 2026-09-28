// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"strings"
)

// freebsdHypervisorCommand prints the kernel's guest detection followed by the
// SMBIOS strings the loader exports, in the same order Linux reads their DMI
// counterparts (product_name, sys_vendor, board_vendor, bios_vendor,
// product_version). kenv -q prints nothing for a variable that is not set.
// The guest line carries a prefix so that a failed sysctl cannot shift an
// SMBIOS string into its place.
const freebsdHypervisorCommand = `echo "vm_guest=$(sysctl -n kern.vm_guest 2>/dev/null)"; ` +
	"kenv -q smbios.system.product; kenv -q smbios.system.maker; " +
	"kenv -q smbios.planar.maker; kenv -q smbios.bios.vendor; " +
	"kenv -q smbios.system.version; true"

// freebsdVMGuests maps the values of FreeBSD's kern.vm_guest to hypervisor
// names. `none` (bare metal) and `generic` (a hypervisor the kernel does not
// recognize) are left out, so neither names a hypervisor.
var freebsdVMGuests = map[string]string{
	"kvm":       "KVM",
	"vmware":    "VMware",
	"hv":        "Hyper-V",
	"xen":       "Xen",
	"bhyve":     "bhyve",
	"parallels": "Parallels",
	"vbox":      "VirtualBox",
}

// detectFreebsdHypervisor detects the hypervisor on FreeBSD.
func (h *hyper) detectFreebsdHypervisor() (string, bool) {
	out, err := h.RunCommand(freebsdHypervisorCommand)
	if err != nil {
		return "", false
	}
	return parseFreebsdHypervisor(out)
}

// parseFreebsdHypervisor reads the output of freebsdHypervisorCommand.
//
// kern.vm_guest decides whether this is a guest at all, as the CPU hypervisor
// flag does on Linux. The SMBIOS strings are then matched first, since they
// name the platform where the kernel only names the hypervisor family: an EC2
// Nitro instance reports `kvm` but its SMBIOS maker is `Amazon EC2`, which is
// what Linux reports for the same instance.
func parseFreebsdHypervisor(out string) (string, bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	guest, found := strings.CutPrefix(strings.TrimSpace(lines[0]), "vm_guest=")
	if !found || guest == "" || guest == "none" {
		return "", false
	}

	for _, smbios := range lines[1:] {
		if strings.TrimSpace(smbios) == "" {
			continue
		}
		if name, ok := mapHypervisor(smbios); ok {
			return name, true
		}
	}

	name, ok := freebsdVMGuests[guest]
	return name, ok
}
