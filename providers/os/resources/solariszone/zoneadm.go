// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package solariszone parses the output of the Oracle Solaris and illumos
// zone administration tools, zoneadm and zonecfg.
package solariszone

import (
	"fmt"
	"strconv"
	"strings"
)

// Zone is one row of `zoneadm list -cp`.
type Zone struct {
	// ID is the numeric zone ID, nil when the zone is not running ("-").
	ID    *int64
	Name  string
	State string
	Path  string
	UUID  string
	Brand string
	// IPType is "shared" or "exclusive". zoneadm prints "excl" for an
	// exclusive-IP zone; it is normalized to the zonecfg spelling.
	IPType string
}

// ParseZoneadmList parses the parseable output of `zoneadm list -cp`:
//
//	zoneid:zonename:state:zonepath:uuid:brand:ip-type[:...]
//
// Oracle Solaris 11.4 appends further columns (r/w and file-mac-profile),
// which are ignored. A colon or backslash inside a field is escaped with a
// backslash.
func ParseZoneadmList(out string) ([]Zone, error) {
	var zones []Zone
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := splitEscaped(line, ':')
		if len(f) < 7 {
			return nil, fmt.Errorf("unexpected zoneadm list line: %q", line)
		}
		z := Zone{
			Name:   f[1],
			State:  f[2],
			Path:   f[3],
			UUID:   f[4],
			Brand:  f[5],
			IPType: f[6],
		}
		if z.Name == "" {
			return nil, fmt.Errorf("zoneadm list line without a zone name: %q", line)
		}
		if f[0] != "-" && f[0] != "" {
			id, err := strconv.ParseInt(f[0], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("invalid zone ID in zoneadm list line %q: %w", line, err)
			}
			z.ID = &id
		}
		if z.IPType == "excl" {
			z.IPType = "exclusive"
		}
		zones = append(zones, z)
	}
	return zones, nil
}

// splitEscaped splits s at every sep that is not escaped with a backslash,
// and removes the escaping backslashes.
func splitEscaped(s string, sep byte) []string {
	var res []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
		case c == sep:
			res = append(res, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(res, cur.String())
}
