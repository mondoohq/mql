// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package ids

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

	// IdDetector_PlatformID = "transport-platform-id" // TODO: how does this work?
)
