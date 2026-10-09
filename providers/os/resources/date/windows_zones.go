// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package date

import "strings"

//go:generate go run ./gen -release release-48-2 -out windows_zones.gen.go

// WindowsZoneToIANA returns the IANA name for a Windows time zone ID, such as
// "Europe/Berlin" for "W. Europe Standard Time", using the Unicode CLDR
// mapping in windows_zones.gen.go. It reports false for an ID CLDR does not
// map.
func WindowsZoneToIANA(id string) (string, bool) {
	iana, ok := windowsZoneToIANA[strings.TrimSpace(id)]
	return iana, ok
}
