// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"bytes"
	"regexp"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/spf13/afero"
)

// List of Desktop Management Interface (DMI) files that might contain information
// related to the presence of a virtualization platform.
var dmiFilesSlice = []string{
	"/sys/class/dmi/id/product_name",
	"/sys/class/dmi/id/sys_vendor",
	"/sys/class/dmi/id/board_vendor",
	"/sys/class/dmi/id/bios_vendor",
	"/sys/class/dmi/id/product_version",
}

// detectLinuxHypervisor detects the hypervisor on Linux.
func (h *hyper) detectLinuxHypervisor() (hypervisor string, ok bool) {
	detectors := []func() (string, bool){
		h.detectDMIVendor,
		h.detectDMIDecode,
		// systemd-detect-virt doesn't know about OpenShift Virtualization,
		// we will leave this detector as our last resource
		h.detectSystemdDetectVirt,
	}
	if h.detectLinuxGuest() {
		for _, detectFn := range detectors {
			hypervisor, ok = detectFn()
			if ok {
				break
			}
		}
	}
	return
}

// x86CPUFlagsLine matches the "flags" line /proc/cpuinfo carries on x86. Other
// architectures list CPU features under a different label ("Features" on
// arm64), so its absence means the CPUID-based check below cannot apply.
var x86CPUFlagsLine = regexp.MustCompile(`(?m)^flags\s*:`)

// detectLinuxGuest reports whether the system runs as a virtual machine guest.
//
// On x86 the answer is the CPUID "hypervisor" bit, which the kernel exposes as
// a flag in /proc/cpuinfo. That bit does not exist on other architectures: an
// arm64 guest under Apple Virtualization.framework, KVM or EC2 Graviton lists
// no such flag. There the gate falls back to "systemd-detect-virt --vm", which
// uses the checks systemd implements for that architecture (DMI, the SMBIOS
// "virtual machine" bit, device tree) and needs no root. "--vm" leaves
// container detection out, so a container on a physical host does not open
// the gate.
func (h *hyper) detectLinuxGuest() bool {
	content, err := afero.ReadFile(h.connection.FileSystem(), "/proc/cpuinfo")
	if err != nil {
		return false
	}
	if bytes.Contains(content, []byte("hypervisor")) {
		return true
	}
	if x86CPUFlagsLine.Match(content) {
		return false
	}
	return h.detectSystemdVM()
}

// detectSystemdVM reports whether "systemd-detect-virt --vm" names a virtual
// machine. It prints "none" on a physical host.
func (h *hyper) detectSystemdVM() bool {
	out, err := h.RunCommand("systemd-detect-virt --vm")
	if err != nil {
		return false
	}
	out = strings.TrimSpace(out)
	return out != "" && out != "none"
}

// detectSystemdDetectVirt runs "systemd-detect-virt" to identify the hypervisor.
func (h *hyper) detectSystemdDetectVirt() (string, bool) {
	systemdVirt, err := h.RunCommand("systemd-detect-virt")
	if err != nil {
		return "", false
	}
	return mapHypervisor(systemdVirt)
}

// detectDMIVendor checks known VM vendors in DMI data.
//
// This approach was inspired on systemd's work for a similar purpose.
// https://github.com/systemd/systemd/blob/main/src/basic/virt.c#L163
func (h *hyper) detectDMIVendor() (string, bool) {
	for _, f := range dmiFilesSlice {
		content, err := afero.ReadFile(h.connection.FileSystem(), f)
		if err != nil {
			continue
		}
		if name, ok := mapHypervisor(string(content)); ok {
			log.Debug().Str("file", f).Msg("os.id.hypervisor> found in dmi data")
			return name, true
		}
	}

	return "", false
}

// detectDMIDecode runs "dmidecode" and extracts hypervisor information.
func (h *hyper) detectDMIDecode() (string, bool) {
	productName, err := h.RunCommand("dmidecode -s system-product-name")
	if err != nil {
		return "", false
	}
	return mapHypervisor(productName)
}
