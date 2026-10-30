// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"slices"
	"strings"
)

// detectDarwinHypervisor detects the hypervisor on Darwin.
func (h *hyper) detectDarwinHypervisor() (hypervisor string, ok bool) {
	value, err := h.RunCommand("sysctl -n machdep.cpu.features")
	if err != nil {
		return
	}
	if strings.Contains(value, "VMM") {
		return h.detectDarwinIOReg()
	}

	// This setting can be only "0" or "1"
	value, err = h.RunCommand("sysctl -n kern.hv_vmm_present")
	if err != nil {
		return
	}
	if value == "1" {
		return h.detectDarwinIOReg()
	}

	// Look at the model identifier
	return h.detectDarwinModelIdentifier()
}

// detectDarwinIOReg uses ioreg to detect virtualization.
func (h *hyper) detectDarwinIOReg() (string, bool) {
	stdout, err := h.RunCommand("ioreg -lw0")
	if err != nil {
		return "", false
	}
	return mapHypervisor(stdout)
}

// detectDarwinModelIdentifier uses system_profiler to detect virtualization.
//
// Only the model fields are matched, never the whole hardware profile. The
// profile of a physical Mac carries the vendor name in several unrelated
// places ("Chip: Apple M4 Pro"), and matching against all of it made every
// Apple Silicon Mac report the "apple" key and come back as Apple
// Virtualization. A guest names its hypervisor in the model itself --
// "Apple Virtual Machine 1", "VMware Virtual Platform", "VirtualBox" -- so
// those two lines carry the whole signal.
func (h *hyper) detectDarwinModelIdentifier() (string, bool) {
	stdout, err := h.RunCommand("system_profiler SPHardwareDataType")
	if err != nil {
		return "", false
	}
	return mapHypervisor(darwinHardwareModel(stdout))
}

// darwinHardwareModelKeys are the SPHardwareDataType labels whose values name
// the machine. A hypervisor announces itself in one of them or not at all.
var darwinHardwareModelKeys = []string{"Model Name", "Model Identifier"}

// darwinHardwareModel returns the model values from SPHardwareDataType output,
// joined by a newline so a key cannot match across two of them.
func darwinHardwareModel(stdout string) string {
	var models []string
	for line := range strings.SplitSeq(stdout, "\n") {
		label, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		label = strings.TrimSpace(label)
		if slices.Contains(darwinHardwareModelKeys, label) {
			models = append(models, strings.TrimSpace(value))
		}
	}
	return strings.Join(models, "\n")
}
