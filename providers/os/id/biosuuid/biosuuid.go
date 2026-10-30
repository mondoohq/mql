// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package biosuuid

import (
	"slices"
	"strings"

	"github.com/cockroachdb/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

// knownSentinels are SMBIOS UUID values that indicate the UUID is not set or not usable.
var knownSentinels = []string{
	"not settable",
	"not available",
	"not specified",
	"not present",
	"none",
	"default string",
	"to be filled by o.e.m.",
}

// allZerosUUID is the nil UUID that indicates no UUID was assigned.
const allZerosUUID = "00000000-0000-0000-0000-000000000000"

// isValidUUID checks that the UUID is not empty, not a known sentinel, and not the nil UUID.
func isValidUUID(uuid string) bool {
	uuid = strings.ToLower(strings.TrimSpace(uuid))
	if len(uuid) == 0 {
		return false
	}
	if uuid == allZerosUUID {
		return false
	}
	return !slices.Contains(knownSentinels, uuid)
}

// BiosUUID returns the BIOS UUID (SMBIOS System UUID) for the platform.
// This is preferred over SerialNumber for VMs, as some hypervisors (e.g., OpenStack)
// pass through the host's serial number to VMs, making it non-unique.
// The BIOS UUID is typically unique per VM instance.
func BiosUUID(conn shared.Connection, p *inventory.Platform) (string, error) {
	mgr, err := smbios.ResolveManager(conn, p)
	if err != nil {
		return "", errors.Wrap(err, "cannot determine platform BIOS UUID")
	}
	if mgr == nil {
		return "", errors.New("cannot determine platform BIOS UUID")
	}

	info, err := mgr.Info()
	if err != nil {
		return "", errors.Wrap(err, "cannot determine platform BIOS UUID")
	}

	uuid := info.SysInfo.UUID
	if !isValidUUID(uuid) {
		return "", nil
	}

	return strings.ToLower(uuid), nil
}
