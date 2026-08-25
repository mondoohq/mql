// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"io"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/providers/os/connection/shared"
	"go.mondoo.com/mql/v13/providers/os/resources/powershell"
)

// list of known hypervisors
var knownHypervisors = map[string]string{
	"vmware":                   "VMware",
	"virtualbox":               "VirtualBox",
	"kvm":                      "KVM",
	"qemu":                     "QEMU",
	"rhev":                     "RHEV Hypervisor",
	"hyper-v":                  "Hyper-V",
	"xen":                      "Xen",
	"parallels":                "Parallels",
	"bhyve":                    "bhyve",
	"proxmox":                  "Proxmox VE",
	"openvz":                   "OpenVZ",
	"virtuozzo":                "Virtuozzo",
	"powervm":                  "IBM PowerVM",
	"applevirtual":             "Apple Virtualization",
	"apple virtual":            "Apple Virtualization",
	"nutanix":                  "Nutanix Acropolis",
	"openshift virtualization": "OpenShift Virtualization",
	"red hat":                  "OpenShift Virtualization",

	// AWS Nitro. systemd-detect-virt reports exactly "amazon" for Nitro and
	// "xen" for the older Xen-based instance families, so the two are already
	// distinguishable; the DMI vendor fields read "Amazon EC2" on Nitro and
	// "Xen" on Xen, which keeps them disjoint on that path too. One substring
	// therefore covers both Nitro detection routes without shadowing "xen".
	"amazon": "AWS Nitro System",
}

// hyper is a helper struct to avoid passing the connection and platform
// as function arguments.
type hyper struct {
	connection shared.Connection
	platform   *inventory.Platform
}

// Hypervisor returns the hypervisor of the system. Not cached here; the os.hypervisor
// resource memoizes it per connection via plugin.GetOrCompute.
func Hypervisor(conn shared.Connection, pf *inventory.Platform) (hypervisor string, ok bool) {
	if !pf.IsFamily(inventory.FAMILY_UNIX) && !pf.IsFamily(inventory.FAMILY_WINDOWS) {
		log.Debug().Msg("your platform is not supported for hypervisor detection")
		return
	}

	hype := &hyper{conn, pf}

	if pf.IsFamily(inventory.FAMILY_LINUX) {
		return hype.detectLinuxHypervisor()
	}
	if pf.IsFamily(inventory.FAMILY_DARWIN) {
		return hype.detectDarwinHypervisor()
	}
	if pf.IsFamily(inventory.FAMILY_WINDOWS) && conn.Capabilities().Has(shared.Capability_File) {
		return hype.detectWindowsHypervisor()
	}

	return
}

// mapHypervisor maps known hypervisors to their names.
func mapHypervisor(info string) (string, bool) {
	// make sure it is lower case
	info = strings.ToLower(info)

	for key, value := range knownHypervisors {
		if strings.Contains(info, key) {
			return value, true
		}
	}
	return "", false
}

// runCommand is a wrapper around connection.RunCommand that helps execute commands
// and read the standard output for unix and windows systems.
func (h *hyper) RunCommand(commandString string) (string, error) {
	if h.platform.IsFamily(inventory.FAMILY_WINDOWS) {
		commandString = powershell.Encode(commandString)
	}
	cmd, err := h.connection.RunCommand(commandString)
	if err != nil {
		return "", err
	}

	data, err := io.ReadAll(cmd.Stdout)
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(data)), nil
}
