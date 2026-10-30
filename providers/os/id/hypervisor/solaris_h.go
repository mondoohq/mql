// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"strings"
)

// solarisHypervisorCommand lists the virtual environments the system runs in.
// virtinfo ships with Solaris 11; on a host without it the command fails and
// no hypervisor is reported.
const solarisHypervisorCommand = "virtinfo -c current list -H -o name"

// The Oracle virtualization environments virtinfo names that mapHypervisor
// does not know. A non-global zone is left out: it is a container on the same
// kernel, not a hypervisor.
var solarisVirtEnvironments = map[string]string{
	"logical-domain": "Oracle VM Server for SPARC",
	"kernel-zone":    "Oracle Solaris Kernel Zones",
}

// detectSolarisHypervisor detects the hypervisor on Solaris.
func (h *hyper) detectSolarisHypervisor() (string, bool) {
	out, err := h.RunCommand(solarisHypervisorCommand)
	if err != nil {
		return "", false
	}
	return parseSolarisHypervisor(out)
}

// parseSolarisHypervisor reads the environments of the current class, one per
// line (kvm, vmware, logical-domain, kernel-zone, non-global-zone, ...).
func parseSolarisHypervisor(out string) (string, bool) {
	for line := range strings.SplitSeq(out, "\n") {
		env := strings.TrimSpace(line)
		if env == "" || env == "non-global-zone" {
			continue
		}
		if name, ok := solarisVirtEnvironments[env]; ok {
			return name, true
		}
		if name, ok := mapHypervisor(env); ok {
			return name, true
		}
	}
	return "", false
}
