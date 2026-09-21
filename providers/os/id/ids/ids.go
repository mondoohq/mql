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

	// IdDetector_MountPath derives an identifier from the directory a
	// filesystem connection reads. It is the last resort for a target that
	// carries no machine identity of its own, such as an extracted container
	// root filesystem, and it is never combined with a detector that found one.
	IdDetector_MountPath = "mount-path"

	// IdDetector_PlatformID = "transport-platform-id" // TODO: how does this work?
)
