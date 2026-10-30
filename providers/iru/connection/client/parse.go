// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import (
	"strconv"
	"strings"
	"time"
)

// timeLayouts covers every timestamp shape the Iru API is known to emit.
// The device detail endpoint is inconsistent: the listing and library
// endpoints use RFC3339 ("2026-07-22T18:07:24.422285Z"), while the device
// detail sections use a space separator with a numeric offset
// ("2026-02-18 14:42:04.395339+00:00") and installed profiles use a space
// separator with a spaced offset ("2026-02-18 14:42:41 +0000").
var timeLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02 15:04:05.999999-07:00",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05 -0700",
	"2006-01-02 15:04:05",
}

// ParseTime parses an Iru timestamp, returning nil on empty or unparseable
// input so callers can hand the result straight to llx.TimeDataPtr and get
// a null field rather than the zero time.
func ParseTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	for _, layout := range timeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// ParseBool interprets the several truthy spellings the Iru API uses. The
// device detail endpoint returns booleans as the strings "True"/"False",
// and some fields use "Yes"/"No" or "enabled"/"disabled"; the JSON boolean
// endpoints decode straight to bool and never reach this helper.
func ParseBool(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "enabled", "on", "1":
		return true
	default:
		return false
	}
}

// ParseInt parses an integer that the API sometimes serializes as a string
// (for example hardware core counts), returning 0 when the value is empty
// or non-numeric.
func ParseInt(s string) int64 {
	n, _ := ParseIntOK(s)
	return n
}

// ParseIntOK is ParseInt that also reports whether the input was well-formed.
// An empty string is treated as a legitimate absent value (0, ok), so callers
// can warn on a genuinely unexpected non-numeric value while staying quiet on
// a field the API simply didn't populate.
func ParseIntOK(s string) (int64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return n, true
}

// ParseMemoryBytes converts a human-readable memory string like
// "32 GB LPDDR5" to bytes using binary units (1 GB = 1024^3, matching how
// Apple reports installed memory). It returns 0 when the string has no
// recognizable "<number> <unit>" prefix.
func ParseMemoryBytes(s string) int64 {
	fields := strings.Fields(s)
	if len(fields) < 2 {
		return 0
	}
	val, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0
	}
	var mult float64
	switch strings.ToUpper(fields[1]) {
	case "KB":
		mult = 1 << 10
	case "MB":
		mult = 1 << 20
	case "GB":
		mult = 1 << 30
	case "TB":
		mult = 1 << 40
	default:
		return 0
	}
	return int64(val * mult)
}
