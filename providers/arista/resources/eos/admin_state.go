// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package eos

import "strings"

// AdminState is whether a top-level configuration block exists on the device
// and whether it is administratively shut down.
//
// The two are separate questions and collapsing them loses the answer. A
// feature that is not configured at all is not the same as one configured and
// then shut down, and neither is the same as one that is up.
type AdminState struct {
	// Configured is true when the block is present in the running-config.
	Configured bool
	// Shutdown is true only when the block explicitly says so. Both the MLAG
	// and BGP blocks default to running, and EOS omits a default from the
	// running-config, so the absence of a shutdown line means the feature is
	// up. Reading absence as "shut down" reports a healthy device as down.
	Shutdown bool
}

// ParseBlockAdminState reports the admin state of the top-level block whose
// header equals header, or begins with it when header ends in a space (which
// is how `router bgp <asn>` is matched without knowing the AS number).
func ParseBlockAdminState(runningConfig, header string) AdminState {
	state := AdminState{}

	EachTopLevelBlock(runningConfig, func(blockHeader, body string) {
		if strings.HasSuffix(header, " ") {
			if !strings.HasPrefix(blockHeader, header) {
				return
			}
		} else if blockHeader != header {
			return
		}
		state.Configured = true

		for line := range strings.SplitSeq(body, "\n") {
			switch strings.TrimSpace(line) {
			case "shutdown":
				state.Shutdown = true
			case "no shutdown", "default shutdown":
				state.Shutdown = false
			}
		}
	})

	return state
}
