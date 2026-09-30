// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package powershell

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
)

// ErrNoOutput is returned by UnmarshalList for empty output.
var ErrNoOutput = errors.New("powershell: the command produced no output")

// UnmarshalList decodes the JSON a PowerShell pipeline produces for a list of
// T, in every shape Windows PowerShell 5.1's ConvertTo-Json uses for one:
//
//   - an array, for two or more elements;
//   - a bare object, for exactly one element. Piping into ConvertTo-Json
//     unrolls the collection, so `@(...) | ConvertTo-Json` does not help;
//     only `ConvertTo-Json -InputObject @(...)` keeps a one-element array;
//   - {"value":[...],"Count":n}, which a list held in a calculated property
//     serializes as;
//   - null, {} or [], for no elements.
//
// A plain []T decode fails on the second shape and reports an empty list for
// the third, so a host with exactly one disk, service, group or package broke
// or under-reported its resource. No elements decode to an empty, non-nil
// slice.
//
// Empty output is an error, not an empty list: for most lists (services,
// users, processes) it means the command failed, and an empty list would let
// every check over it pass vacuously. A caller whose command legitimately
// prints nothing checks for that itself.
func UnmarshalList[T any](data []byte) ([]T, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, ErrNoOutput
	}
	if bytes.Equal(data, []byte("null")) {
		return []T{}, nil
	}

	switch data[0] {
	case '[':
		var list []T
		if err := json.Unmarshal(data, &list); err != nil {
			return nil, err
		}
		if list == nil {
			list = []T{}
		}
		return list, nil
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return nil, err
		}
		if len(fields) == 0 {
			return []T{}, nil
		}
		// A wrapper has only "value" (any casing) and optionally "Count". Any
		// other key makes the object a single element, even one that happens
		// to have a Value property.
		if v, hasCount, ok := wrapperValue(fields); ok {
			if len(v) > 0 && v[0] == '[' {
				return UnmarshalList[T](v)
			}
			if len(v) == 0 || bytes.Equal(v, []byte("null")) {
				return []T{}, nil
			}
			// With a Count the object is unambiguously a wrapper, so a
			// non-array value is its one element. Without a Count it may be
			// an element whose only property is Value, decoded below.
			if hasCount {
				var one T
				if err := json.Unmarshal(v, &one); err != nil {
					return nil, err
				}
				return []T{one}, nil
			}
		}
		var one T
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, err
		}
		return []T{one}, nil
	default:
		var one T
		if err := json.Unmarshal(data, &one); err != nil {
			return nil, err
		}
		return []T{one}, nil
	}
}

// wrapperValue returns the trimmed "value" of a {"value":…,"Count":n} wrapper
// and whether it has a Count, and false when the object has any other key.
func wrapperValue(fields map[string]json.RawMessage) (value json.RawMessage, hasCount bool, ok bool) {
	for k, v := range fields {
		switch {
		case strings.EqualFold(k, "value"):
			value, ok = bytes.TrimSpace(v), true
		case strings.EqualFold(k, "count"):
			hasCount = true
		default:
			return nil, false, false
		}
	}
	return value, hasCount, ok
}
