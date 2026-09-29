// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"bytes"
	"encoding/json"
	"strings"
)

// psUnwrapList normalizes the shapes PowerShell produces for a list into a
// plain JSON array.
//
// The same payload can carry more than one of them: a list held in an ordinary
// property serializes as [...], while the same list produced by a
// Select-Object calculated property serializes as {"value":[...],"Count":n},
// and a single element is sometimes flattened out of its array entirely. A
// plain []T tag decodes the wrapped shape to empty, which reports "no key
// protectors" on a protected volume and "no security services running" on a
// host running Credential Guard.
//
// A nil result means the value was absent, which callers keep distinct from a
// list that is present and empty.
func psUnwrapList(data []byte) ([]byte, error) {
	data = bytes.TrimSpace(data)
	if len(data) == 0 || bytes.Equal(data, []byte("null")) {
		return nil, nil
	}

	switch data[0] {
	case '[':
		return data, nil
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return nil, err
		}
		// An object is only a wrapper when it actually carries a "value"
		// holding an array. Testing for the key rather than assuming it keeps
		// a single flattened object element (a lone key protector, say) from
		// being mistaken for a wrapper and decoded to nothing.
		if v, ok := psLookupField(fields, "value"); ok {
			v = bytes.TrimSpace(v)
			if len(v) == 0 || bytes.Equal(v, []byte("null")) {
				return nil, nil
			}
			if v[0] == '[' {
				return v, nil
			}
		}
		if len(fields) == 0 {
			// A calculated property that yields nothing serializes as {}
			// rather than as null.
			return nil, nil
		}
		return psWrapElement(data), nil
	default:
		return psWrapElement(data), nil
	}
}

// psLookupField finds a field by name without regard to case. PowerShell is
// inconsistent about the casing of the wrapper's "value" key, and a
// map[string]json.RawMessage lookup is exact where a struct tag would not be.
func psLookupField(fields map[string]json.RawMessage, name string) (json.RawMessage, bool) {
	if v, ok := fields[name]; ok {
		return v, true
	}
	for k, v := range fields {
		if strings.EqualFold(k, name) {
			return v, true
		}
	}
	return nil, false
}

// psWrapElement turns a single flattened element back into a one-element array.
func psWrapElement(data []byte) []byte {
	out := make([]byte, 0, len(data)+2)
	out = append(out, '[')
	out = append(out, data...)
	return append(out, ']')
}

// PSString decodes a value PowerShell means as a string.
//
// Two object shapes stand in for one. A calculated property whose expression
// yields nothing serializes as an empty object rather than as null, which
// decodes to "". And Get-Content attaches PSPath, PSChildName and other note
// properties to the strings it returns, which ConvertTo-Json in Windows
// PowerShell 5.1 writes as {"value":"...","PSPath":...}; that decodes to the
// value. A plain string field fails the whole decode on either shape.
type PSString string

func (s *PSString) UnmarshalJSON(data []byte) error {
	data = bytes.TrimSpace(data)
	if len(data) > 0 && data[0] == '{' {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(data, &fields); err != nil {
			return err
		}
		v, ok := psLookupField(fields, "value")
		if !ok {
			*s = ""
			return nil
		}
		data = bytes.TrimSpace(v)
	}
	if len(data) == 0 || data[0] != '"' {
		*s = ""
		return nil
	}
	var v string
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	*s = PSString(v)
	return nil
}

// StringPtr returns the string, or nil when s is nil.
func (s *PSString) StringPtr() *string {
	if s == nil {
		return nil
	}
	str := string(*s)
	return &str
}

// PSInt64Array decodes a list of integers out of any of the shapes PowerShell
// produces for one. See psUnwrapList for why a plain []int64 tag is not enough.
type PSInt64Array []int64

func (a *PSInt64Array) UnmarshalJSON(data []byte) error {
	list, err := psUnwrapList(data)
	if err != nil {
		return err
	}
	if list == nil {
		*a = nil
		return nil
	}

	var out []int64
	if err := json.Unmarshal(list, &out); err != nil {
		return err
	}
	*a = out
	return nil
}
