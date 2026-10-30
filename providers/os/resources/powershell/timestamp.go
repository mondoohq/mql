// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"regexp"
	"strconv"
	"time"
)

// Date(ms) or Date(ms+hhmm): the offset only says which zone the value was
// local to, ms is always since the unix epoch in UTC.
var powershellTimestamp = regexp.MustCompile(`Date\((-?\d+)(?:[+-]\d{4})?\)`)

func PSJsonTimestamp(date string) *time.Time {
	// extract unix seconds
	m := powershellTimestamp.FindStringSubmatch(date)
	if len(m) > 0 {
		i, err := strconv.ParseInt(m[1], 10, 64)
		if err != nil {
			return nil
		}

		// UnixMilli rather than time.Unix(0, i*int64(time.Millisecond)): the
		// regex captures an unbounded run of digits, and that multiplication
		// overflows int64 past ~year 2262, wrapping to a confident-looking wrong
		// date instead of the nil callers check for.
		tm := time.UnixMilli(i)
		return &tm
	}
	return nil
}
