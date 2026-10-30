// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package hypervisor

import (
	"strconv"
	"strings"
)

// aixHypervisorCommand prints the partition number and name of the LPAR.
const aixHypervisorCommand = "uname -L"

// detectAixHypervisor detects the hypervisor on AIX.
func (h *hyper) detectAixHypervisor() (string, bool) {
	out, err := h.RunCommand(aixHypervisorCommand)
	if err != nil {
		return "", false
	}
	return parseAixHypervisor(out)
}

// parseAixHypervisor reads uname -L, which prints the partition number and
// name (25 aix73-00000000-00000000) inside a logical partition and -1 NULL on
// a system that is not partitioned. Logical partitions run on IBM PowerVM.
func parseAixHypervisor(out string) (string, bool) {
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", false
	}
	n, err := strconv.Atoi(fields[0])
	if err != nil || n < 1 {
		return "", false
	}
	return knownHypervisors["powervm"], true
}
