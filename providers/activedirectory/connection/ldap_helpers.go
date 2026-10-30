// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// windowsEpochDelta is the number of 100-nanosecond intervals between
// the Windows FILETIME epoch (1601-01-01) and the Unix epoch (1970-01-01).
const windowsEpochDelta = 116444736000000000

// filetimeNeverExpires is the AD sentinel meaning "never expires".
const filetimeNeverExpires = 0x7FFFFFFFFFFFFFFF

// pagedSearchPageSize is the number of entries per page for LDAP paged results.
const pagedSearchPageSize = 1000

// functionalLevels maps AD domainFunctionality / forestFunctionality integer
// strings to human-readable Windows Server version names.
var functionalLevels = map[string]string{
	"0": "2000",
	"1": "2003Interim",
	"2": "2003",
	"3": "2008",
	"4": "2008R2",
	"5": "2012",
	"6": "2012R2",
	"7": "2016",
}

// FunctionalLevelName converts a numeric functional level string to its
// human-readable name. Unknown levels are returned verbatim.
func FunctionalLevelName(level string) string {
	if name, ok := functionalLevels[level]; ok {
		return name
	}
	return level
}

// DecodeSID converts a raw binary Windows Security Identifier to its
// canonical string form (e.g. S-1-5-21-...).
//
// Binary layout:
//
//	[0]      Revision (1 byte)
//	[1]      Sub-authority count (1 byte)
//	[2..7]   Identifier authority (6 bytes, big-endian)
//	[8..]    Sub-authorities (4 bytes each, little-endian)
func DecodeSID(raw []byte) (string, error) {
	if len(raw) < 8 {
		return "", fmt.Errorf("SID too short: %d bytes", len(raw))
	}

	revision := raw[0]
	subAuthorityCount := int(raw[1])

	expectedLen := 8 + 4*subAuthorityCount
	if len(raw) < expectedLen {
		return "", fmt.Errorf("SID truncated: have %d bytes, need %d", len(raw), expectedLen)
	}

	// Identifier authority is big-endian 48-bit value in bytes [2..7].
	var identifierAuthority uint64
	for i := 2; i < 8; i++ {
		identifierAuthority = (identifierAuthority << 8) | uint64(raw[i])
	}

	var b strings.Builder
	fmt.Fprintf(&b, "S-%d-%d", revision, identifierAuthority)

	for i := range subAuthorityCount {
		offset := 8 + 4*i
		subAuth := binary.LittleEndian.Uint32(raw[offset : offset+4])
		fmt.Fprintf(&b, "-%d", subAuth)
	}

	return b.String(), nil
}

// FileTimeToTime converts an Active Directory FILETIME value (100-nanosecond
// intervals since 1601-01-01 UTC) to a Go time.Time.
//
// Sentinel values (≤ 0 and 0x7FFFFFFFFFFFFFFF / never-expires) return
// the zero time.
func FileTimeToTime(ft int64) time.Time {
	if ft <= 0 || ft == filetimeNeverExpires {
		return time.Time{}
	}
	// Convert from Windows 100ns ticks to Unix nanoseconds.
	unixNano := (ft - windowsEpochDelta) * 100
	return time.Unix(0, unixNano).UTC()
}

// DurationToMinutes converts an AD negative 100-nanosecond duration to minutes.
// AD stores durations such as lockoutDuration as negative 100ns intervals.
func DurationToMinutes(d int64) int {
	if d == 0 {
		return 0
	}
	return int(-(d / (10_000_000 * 60)))
}

// DurationToDays converts an AD negative 100-nanosecond duration to days.
func DurationToDays(d int64) int {
	if d == 0 {
		return 0
	}
	return int(-(d / (10_000_000 * 86400)))
}

// PagedSearch executes an LDAP search request using the paged results control
// (RFC 2696) with a page size of 1000, accumulating all entries across pages.
// Caller-supplied controls on req.Controls are preserved alongside the paging control.
func PagedSearch(conn *ldap.Conn, req *ldap.SearchRequest) ([]*ldap.Entry, error) {
	var allEntries []*ldap.Entry
	pagingControl := ldap.NewControlPaging(pagedSearchPageSize)
	extraControls := req.Controls // preserve caller-supplied controls (e.g. SD flags)

	for {
		controls := make([]ldap.Control, 0, len(extraControls)+1)
		controls = append(controls, extraControls...)
		controls = append(controls, pagingControl)
		req.Controls = controls

		resp, err := conn.Search(req)
		if err != nil {
			return allEntries, fmt.Errorf("paged search failed: %w", err)
		}

		allEntries = append(allEntries, resp.Entries...)

		// Find the paging response control to get the cookie for the next page.
		var cookie []byte
		for _, ctrl := range resp.Controls {
			if pc, ok := ctrl.(*ldap.ControlPaging); ok {
				cookie = pc.Cookie
				break
			}
		}

		// Empty or missing cookie means we've received the last page.
		if len(cookie) == 0 {
			break
		}
		pagingControl.SetCookie(cookie)
	}

	return allEntries, nil
}

// GetStringAttr safely returns the first value of the named attribute,
// or an empty string if the attribute is absent.
func GetStringAttr(entry *ldap.Entry, name string) string {
	if entry == nil {
		return ""
	}
	return entry.GetAttributeValue(name)
}

// GetStringSliceAttr returns all values of a multi-valued attribute.
func GetStringSliceAttr(entry *ldap.Entry, name string) []string {
	if entry == nil {
		return nil
	}
	return entry.GetAttributeValues(name)
}

// GetIntAttr parses the first value of the named attribute as an int64.
func GetIntAttr(entry *ldap.Entry, name string) (int64, error) {
	s := GetStringAttr(entry, name)
	if s == "" {
		return 0, fmt.Errorf("attribute %q is empty or missing", name)
	}
	return strconv.ParseInt(s, 10, 64)
}

// GetBinaryAttr returns the raw binary value of the named attribute.
func GetBinaryAttr(entry *ldap.Entry, name string) []byte {
	if entry == nil {
		return nil
	}
	return entry.GetRawAttributeValue(name)
}
