// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package serialnumber

import (
	"slices"
	"strings"

	"github.com/pkg/errors"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/shared"
	"go.mondoo.com/mql/providers/os/resources/smbios"
)

// knownSentinels are SMBIOS serial number values that indicate the serial is not
// set or not usable. OEMs frequently ship hardware (and many hypervisors ship VMs)
// with these placeholder strings left in the DMI fields, so they are not unique and
// must not be used as a platform identifier.
var knownSentinels = []string{
	"system serial number",
	"base board serial number",
	"chassis serial number",
	"to be filled by o.e.m.",
	"default string",
	"not specified",
	"not available",
	"not applicable",
	"not present",
	"not settable",
	"none",
	"oem",
	"invalid",
	"0",
	"00000000",
}

// isValidSerialNumber checks that the serial is not empty and not a known placeholder.
// It expects a pre-trimmed value.
func isValidSerialNumber(serial string) bool {
	if len(serial) == 0 {
		return false
	}
	return !slices.Contains(knownSentinels, strings.ToLower(serial))
}

func SerialNumber(conn shared.Connection, p *inventory.Platform) (string, error) {
	mgr, err := smbios.ResolveManager(conn, p)
	if err != nil {
		return "", errors.Wrap(err, "cannot determine platform serial number")
	}
	if mgr == nil {
		return "", errors.New("cannot determine platform serial number")
	}

	info, err := mgr.Info()
	if err != nil {
		return "", errors.New("cannot determine platform serial number")
	}

	// A placeholder or empty serial returns ("", nil) — not an error — so the
	// caller (gatherPlatformInfo) treats it the same as "no serial available"
	// and falls through to the next ID strategy, rather than building a
	// non-unique platform ID from an OEM default. This matches biosuuid.BiosUUID.
	serial := strings.TrimSpace(info.SysInfo.SerialNumber)
	if !isValidSerialNumber(serial) {
		return "", nil
	}

	return serial, nil
}
