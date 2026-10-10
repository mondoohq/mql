// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package aix

import (
	"strconv"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// The helpers below turn AIX attribute values into MQL data: a value that is
// not set, or not of the field's type, is null rather than a zero value.

// ParseBool reads a boolean attribute: AIX writes true, false, yes, no, on
// and off.
func ParseBool(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "on":
		return true, true
	case "false", "no", "off":
		return false, true
	}
	return false, false
}

// IntData is an integer attribute, null when unset or not a number.
func IntData(v string, ok bool) *llx.RawData {
	if !ok {
		return llx.IntDataPtr[int64](nil)
	}
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil {
		return llx.IntDataPtr[int64](nil)
	}
	return llx.IntData(n)
}

// BoolData is a boolean attribute, null when unset or not a boolean.
func BoolData(v string, ok bool) *llx.RawData {
	if !ok {
		return llx.BoolDataPtr(nil)
	}
	b, valid := ParseBool(v)
	if !valid {
		return llx.BoolDataPtr(nil)
	}
	return llx.BoolData(b)
}

// StringData is a string attribute, null when unset.
func StringData(v string, ok bool) *llx.RawData {
	if !ok {
		return llx.StringDataPtr(nil)
	}
	return llx.StringData(v)
}

// StringMap turns attributes into the map an MQL map[string]string holds.
func StringMap(attrs map[string]string) map[string]any {
	res := make(map[string]any, len(attrs))
	for k, v := range attrs {
		res[k] = v
	}
	return res
}

// IntField returns an integer attribute for a computed field, marking the
// field null when the attribute is unset or not a number.
func IntField(tv *plugin.TValue[int64], v string, ok bool) (int64, error) {
	if ok {
		if n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64); err == nil {
			return n, nil
		}
	}
	tv.State = plugin.StateIsSet | plugin.StateIsNull
	return 0, nil
}

// BoolField returns a boolean attribute for a computed field, marking the
// field null when the attribute is unset or not a boolean.
func BoolField(tv *plugin.TValue[bool], v string, ok bool) (bool, error) {
	if ok {
		if b, valid := ParseBool(v); valid {
			return b, nil
		}
	}
	tv.State = plugin.StateIsSet | plugin.StateIsNull
	return false, nil
}

// StringField returns a string attribute for a computed field, marking
// the field null when the attribute is unset.
func StringField(tv *plugin.TValue[string], v string, ok bool) (string, error) {
	if !ok {
		tv.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return v, nil
}
