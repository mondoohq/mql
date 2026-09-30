// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ids

import (
	"slices"
	"strings"
)

const (
	IdDetector_Hostname     = "hostname"
	IdDetector_MachineID    = "machine-id"
	IdDetector_SerialNumber = "serialnumber"
	IdDetector_BiosUUID     = "bios-uuid"
	IdDetector_CloudDetect  = "cloud-detect"
	IdDetector_AwsEcs       = "aws-ecs"
	IdDetector_WindowsADSID = "windows-ad-sid"
	// IdDetector_CrowdStrikeAID identifies a host by the agent ID of its
	// CrowdStrike Falcon sensor. Opt-in: it is never part of the defaults.
	IdDetector_CrowdStrikeAID = "crowdstrike-aid"
	// IdDetector_IntuneDevice identifies a Windows device by its Microsoft
	// Intune device ID, scoped by its Entra tenant. Opt-in: it is never part of
	// the defaults.
	IdDetector_IntuneDevice = "intune-device"

	// IdDetector_PlatformID = "transport-platform-id" // TODO: how does this work?

	// IdDetector_Default is not a detector. In a list of detectors it stands
	// for the detectors the connection uses when none are requested, so
	// `default,crowdstrike-aid` adds one detector to the defaults instead of
	// replacing them.
	IdDetector_Default = "default"
)

// Parse splits a comma-separated list of id detectors, as the id-detector
// flag takes it, trimming whitespace and dropping empty entries. A single
// name yields a one-element list.
func Parse(raw string) []string {
	var res []string
	for _, name := range strings.Split(raw, ",") {
		if name = strings.TrimSpace(name); name != "" {
			res = append(res, name)
		}
	}
	return res
}

// HasDefault reports whether the list asks for the default detectors, which
// an empty list does implicitly.
func HasDefault(detectors []string) bool {
	return len(detectors) == 0 || slices.Contains(detectors, IdDetector_Default)
}

// ExpandDefault replaces IdDetector_Default in the list with the given
// default detectors, and returns the defaults for an empty list. Order is
// kept and each detector appears once.
func ExpandDefault(detectors []string, defaults []string) []string {
	if len(detectors) == 0 {
		return slices.Clone(defaults)
	}
	res := make([]string, 0, len(detectors)+len(defaults))
	for _, d := range detectors {
		if d == IdDetector_Default {
			for _, def := range defaults {
				if !slices.Contains(res, def) {
					res = append(res, def)
				}
			}
			continue
		}
		if !slices.Contains(res, d) {
			res = append(res, d)
		}
	}
	return res
}
