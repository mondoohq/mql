// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

// normalizeMultiSz strips the Windows API artifact where an empty REG_MULTI_SZ
// value (raw bytes: \0\0) is parsed as []string{""} instead of []string{}.
func normalizeMultiSz(entries []string) []string {
	if len(entries) == 1 && entries[0] == "" {
		return []string{}
	}
	return entries
}

// derived from "golang.org/x/sys/windows/registry"
// see https://github.com/golang/sys/blob/master/windows/registry/value.go#L17-L31
const (
	NONE                       = 0
	SZ                         = 1
	EXPAND_SZ                  = 2
	BINARY                     = 3
	DWORD                      = 4
	DWORD_BIG_ENDIAN           = 5
	LINK                       = 6
	MULTI_SZ                   = 7
	RESOURCE_LIST              = 8
	FULL_RESOURCE_DESCRIPTOR   = 9
	RESOURCE_REQUIREMENTS_LIST = 10
	QWORD                      = 11
)

type RegistryKeyItem struct {
	Key   string
	Value RegistryKeyValue
}

func (k RegistryKeyItem) Kind() string {
	switch k.Value.Kind {
	case NONE:
		return "bone"
	case SZ:
		return "string"
	case EXPAND_SZ:
		return "expandstring"
	case BINARY:
		return "binary"
	case DWORD:
		return "dword"
	case DWORD_BIG_ENDIAN:
		return "dword"
	case LINK:
		return "link"
	case MULTI_SZ:
		return "multistring"
	case RESOURCE_LIST:
		return "<unsupported>"
	case FULL_RESOURCE_DESCRIPTOR:
		return "<unsupported>"
	case RESOURCE_REQUIREMENTS_LIST:
		return "<unsupported>"
	case QWORD:
		return "qword"
	}
	return "<unsupported>"
}

func (k RegistryKeyItem) GetRawValue() any {
	switch k.Value.Kind {
	case NONE:
		return nil
	case SZ:
		return k.Value.String
	case EXPAND_SZ:
		return k.Value.String
	case BINARY:
		return binaryToDict(k.Value.Binary)
	case DWORD:
		return k.Value.Number
	case DWORD_BIG_ENDIAN:
		return nil
	case LINK:
		return nil
	case MULTI_SZ:
		return convert.SliceAnyToInterface(k.Value.MultiString)
	case RESOURCE_LIST:
		return nil
	case FULL_RESOURCE_DESCRIPTOR:
		return nil
	case RESOURCE_REQUIREMENTS_LIST:
		return nil
	case QWORD:
		return k.Value.Number
	}
	return nil
}

// binaryToDict converts REG_BINARY data into a value an llx dict can carry.
// Dicts only hold JSON-native types, so handing a []byte straight to the client
// fails with "unsupported child type: []uint8" and takes the whole key read down
// with it, not just the one binary value.
func binaryToDict(data []byte) any {
	if data == nil {
		return nil
	}
	res := make([]any, len(data))
	for i := range data {
		res[i] = int64(data[i])
	}
	return res
}

// String returns a string representation of the registry key value
func (k RegistryKeyItem) String() string {
	return k.Value.String // conversion to string is handled in UnmarshalJSON
}

type RegistryKeyValue struct {
	Kind        int
	Binary      []byte
	Number      int64
	String      string
	MultiString []string
}

type RegistryKeyChild struct {
	Name       string
	Path       string
	Properties []string
}

// registryValueKinds maps the type names reg.exe prints in the second column of
// `reg query` output onto the numeric kinds used everywhere else. reg.exe is the
// only source of a value's type that survives PowerShell's Constrained Language
// Mode, where RegistryKey.GetValueKind() cannot be invoked at all.
var registryValueKinds = map[string]int{
	"REG_NONE":                       NONE,
	"REG_SZ":                         SZ,
	"REG_EXPAND_SZ":                  EXPAND_SZ,
	"REG_BINARY":                     BINARY,
	"REG_DWORD":                      DWORD,
	"REG_DWORD_LITTLE_ENDIAN":        DWORD,
	"REG_DWORD_BIG_ENDIAN":           DWORD_BIG_ENDIAN,
	"REG_LINK":                       LINK,
	"REG_MULTI_SZ":                   MULTI_SZ,
	"REG_RESOURCE_LIST":              RESOURCE_LIST,
	"REG_FULL_RESOURCE_DESCRIPTOR":   FULL_RESOURCE_DESCRIPTOR,
	"REG_RESOURCE_REQUIREMENTS_LIST": RESOURCE_REQUIREMENTS_LIST,
	"REG_QWORD":                      QWORD,
	"REG_QWORD_LITTLE_ENDIAN":        QWORD,
}

// resolveRegistryValueKind determines a value's kind from what the collection
// script managed to report: the reg.exe type name when there is one, otherwise
// the numeric kind from RegistryKey.GetValueKind().
//
// When neither is available it returns an error instead of defaulting to NONE.
// Defaulting is what made this a silent-data-loss bug: under Constrained
// Language Mode GetValueKind() is refused for every value, a missing kind
// decoded as NONE, and NONE discards the data. Value names still enumerated, so
// a fully readable key reported every one of its values as empty and denylist
// style checks passed on data that was never read.
func resolveRegistryValueKind(typeName string, kind *int) (int, error) {
	if typeName != "" {
		resolved, ok := registryValueKinds[strings.ToUpper(typeName)]
		if !ok {
			return NONE, fmt.Errorf("unknown registry value type %q", typeName)
		}
		return resolved, nil
	}
	if kind != nil {
		return *kind, nil
	}
	return NONE, errors.New("could not determine the registry value type: reg.exe reported no type for this value and RegistryKey.GetValueKind() returned nothing (it is refused under PowerShell Constrained Language Mode)")
}

type keyKindRaw struct {
	// Kind is the numeric value kind from RegistryKey.GetValueKind(). It is
	// absent whenever the collection script could not invoke that method.
	Kind *int
	// Type is the reg.exe type name, e.g. REG_DWORD.
	Type string
	Data any
}

func (k *RegistryKeyValue) UnmarshalJSON(b []byte) error {
	var raw keyKindRaw

	// try to unmarshal the type
	err := json.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	kind, err := resolveRegistryValueKind(raw.Type, raw.Kind)
	if err != nil {
		return err
	}
	k.Kind = kind

	if raw.Data == nil {
		return nil
	}

	// see https://learn.microsoft.com/en-us/powershell/scripting/samples/working-with-registry-entries?view=powershell-7
	switch kind {
	case NONE:
		// ignore
	case SZ: // Any string value
		value, ok := raw.Data.(string)
		if !ok {
			return fmt.Errorf("registry key value is not a string: %v", raw.Data)
		}
		k.String = value
	case EXPAND_SZ: // A string that can contain environment variables that are dynamically expanded
		value, ok := raw.Data.(string)
		if !ok {
			return fmt.Errorf("registry key value is not a string: %v", raw.Data)
		}
		k.String = value
	case BINARY: // Binary data
		rawData, ok := raw.Data.([]any)
		if !ok {
			return fmt.Errorf("registry key value is not a byte array: %v", raw.Data)
		}
		data := make([]byte, len(rawData))
		for i, v := range rawData {
			val, ok := v.(float64)
			if !ok {
				return fmt.Errorf("registry key value is not a byte array: %v", raw.Data)
			}
			data[i] = byte(val)
		}
		k.Binary = data
	case DWORD: // A number that is a valid UInt32
		data, ok := raw.Data.(float64)
		if !ok {
			return fmt.Errorf("registry key value is not a number: %v", raw.Data)
		}
		number := int64(data)
		// string fallback
		k.Number = number
		k.String = strconv.FormatInt(number, 10)
	case DWORD_BIG_ENDIAN:
		log.Warn().Msg("DWORD_BIG_ENDIAN for registry key is not supported")
	case LINK:
		log.Warn().Msg("LINK for registry key is not supported")
	case MULTI_SZ: // A multiline string
		switch value := raw.Data.(type) {
		case string:
			k.String = value
			if value != "" {
				k.MultiString = []string{value}
			}
		case []any:
			if len(value) > 0 {
				var multiString []string
				for _, v := range value {
					multiString = append(multiString, v.(string))
				}
				multiString = normalizeMultiSz(multiString)
				if len(multiString) > 0 {
					// NOTE: this is to be consistent with the output before we moved to multi-datatype support for registry keys
					k.String = strings.Join(multiString, " ")
					k.MultiString = multiString
				}
			}
		}
	case RESOURCE_LIST:
		log.Warn().Msg("RESOURCE_LIST for registry key is not supported")
	case FULL_RESOURCE_DESCRIPTOR:
		log.Warn().Msg("FULL_RESOURCE_DESCRIPTOR for registry key is not supported")
	case RESOURCE_REQUIREMENTS_LIST:
		log.Warn().Msg("RESOURCE_REQUIREMENTS_LIST for registry key is not supported")
	case QWORD: // A number that is a valid UInt64
		data, ok := raw.Data.(float64)
		if !ok {
			return fmt.Errorf("registry key value is not a number: %v", raw.Data)
		}
		number := int64(data)
		// string fallback
		k.Number = number
		k.String = strconv.FormatInt(number, 10)
	}
	return nil
}
