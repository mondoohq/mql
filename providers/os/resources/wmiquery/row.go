// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wmiquery

import (
	"fmt"
	"math"
	"strconv"
	"time"
)

// Row is one WMI object: the properties a query read, as COM returned them.
// Scalars are Go values of the width WMI chose (int32, uint16, string, bool,
// ...), 64-bit integers and datetimes arrive as strings, arrays as []any, and
// NULL as nil. The accessors convert. A value of another type reads as absent:
// a mismatch between what WMI sends and what a caller expects is never a
// panic.
type Row map[string]any

// String returns a string property, or "" when it is NULL, missing or not a
// string.
func (r Row) String(name string) string {
	s, _ := r[name].(string)
	return s
}

// StringPtr is String for callers that tell NULL apart from "": nil when the
// property is NULL, missing or not a string.
func (r Row) StringPtr(name string) *string {
	s, ok := r[name].(string)
	if !ok {
		return nil
	}
	return &s
}

// Int64 returns an integer property of any width. WMI sends 64-bit integers
// as decimal strings, which are parsed. ok is false when the property is NULL,
// missing or not an integer.
func (r Row) Int64(name string) (int64, bool) {
	return toInt64(r[name])
}

// Int64s returns an integer array property, such as ChassisTypes, whatever
// width its elements have. ok is false when the property is NULL, missing, not
// an array, or holds anything but integers.
func (r Row) Int64s(name string) ([]int64, bool) {
	values, ok := r[name].([]any)
	if !ok {
		return nil, false
	}
	res := make([]int64, len(values))
	for i, v := range values {
		n, ok := toInt64(v)
		if !ok {
			return nil, false
		}
		res[i] = n
	}
	return res, true
}

// Time returns a CIM_DATETIME property. ok is false when the property is
// NULL, missing or not a valid datetime, e.g. one with wildcard fields.
func (r Row) Time(name string) (time.Time, bool) {
	s, ok := r[name].(string)
	if !ok {
		return time.Time{}, false
	}
	return parseCIMDatetime(s)
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		if n > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case uint:
		if uint64(n) > math.MaxInt64 {
			return 0, false
		}
		return int64(n), true
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	}
	return 0, false
}

// parseCIMDatetime parses yyyymmddHHMMSS.mmmmmm followed by a sign and the
// UTC offset in minutes (20240115000000.000000+060), the form WMI sends a
// datetime in. The offset is rewritten as hours and minutes for time.Parse.
func parseCIMDatetime(s string) (time.Time, bool) {
	if len(s) == 25 {
		mins, err := strconv.Atoi(s[22:])
		if err != nil {
			return time.Time{}, false
		}
		s = s[:22] + fmt.Sprintf("%02d%02d", mins/60, mins%60)
	}
	t, err := time.Parse("20060102150405.000000-0700", s)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}
