// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

// decodeRawRegistryValue decodes a registry value as Windows stores it, the
// kind and raw data RegQueryValueEx returns, into the same RegistryKeyValue
// the PowerShell path decodes for that value (RegistryKeyValue.UnmarshalJSON).
//
// The native reader and the PowerShell script are two readings of one value,
// and every value kind must come out the same on both, or a query gives a
// different answer depending on how the host is reached. Keeping the native
// decoding here, free of any Windows API, lets a test feed both decoders the
// same value on every platform.
//
// A value whose data does not fit its kind (a DWORD that is not 4 bytes) gets
// Err, which fails that value alone, as the PowerShell decoder does.
func decodeRawRegistryValue(kind uint32, data []byte) RegistryKeyValue {
	v := RegistryKeyValue{Kind: int(kind)}
	switch kind {
	case SZ, EXPAND_SZ, LINK:
		// REG_EXPAND_SZ stays unexpanded: it is what is configured, and the
		// PowerShell script reads it the same way.
		v.String = utf16String(data)
	case MULTI_SZ:
		entries := normalizeMultiSz(utf16Strings(data))
		v.MultiString = entries
		if len(entries) > 0 {
			// NOTE: this is to be consistent with the output before we moved to multi-datatype support for registry keys
			v.String = strings.Join(entries, " ")
		}
	case BINARY, RESOURCE_LIST, FULL_RESOURCE_DESCRIPTOR, RESOURCE_REQUIREMENTS_LIST:
		v.Binary = append([]byte{}, data...)
	case DWORD, DWORD_BIG_ENDIAN:
		if len(data) != 4 {
			v.Err = fmt.Errorf("registry %s value is %d bytes long, not 4", kindName(kind), len(data))
			return v
		}
		if kind == DWORD {
			v.Number = int64(binary.LittleEndian.Uint32(data))
		} else {
			v.Number = int64(binary.BigEndian.Uint32(data))
		}
		v.String = strconv.FormatInt(v.Number, 10)
	case QWORD:
		if len(data) != 8 {
			v.Err = fmt.Errorf("registry QWORD value is %d bytes long, not 8", len(data))
			return v
		}
		v.Number = int64(binary.LittleEndian.Uint64(data))
		v.String = strconv.FormatInt(v.Number, 10)
	case NONE:
		// no typed data; the PowerShell decoder discards it too
	}
	return v
}

func kindName(kind uint32) string {
	if kind == DWORD_BIG_ENDIAN {
		return "DWORD_BIG_ENDIAN"
	}
	return "DWORD"
}

// utf16Units reinterprets little-endian UTF-16 data; a trailing odd byte is
// dropped, as Windows does.
func utf16Units(data []byte) []uint16 {
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[2*i:])
	}
	return units
}

// utf16String decodes a string value up to its first NUL, as
// golang.org/x/sys/windows/registry does for REG_SZ.
func utf16String(data []byte) string {
	units := utf16Units(data)
	for i, u := range units {
		if u == 0 {
			units = units[:i]
			break
		}
	}
	return string(utf16.Decode(units))
}

// utf16Strings decodes a REG_MULTI_SZ value: NUL-separated strings, ended by
// an extra NUL. It splits the way golang.org/x/sys/windows/registry does, so
// an empty value decodes as []string{""}, which normalizeMultiSz turns into
// []string{}. A last string without its NUL is kept, as .NET's
// RegistryKey.GetValue keeps it, so the PowerShell path reads it too.
func utf16Strings(data []byte) []string {
	units := utf16Units(data)
	if len(units) == 0 {
		return nil
	}
	if units[len(units)-1] == 0 {
		units = units[:len(units)-1]
	}
	res := make([]string, 0, 5)
	from := 0
	for i, u := range units {
		if u == 0 {
			res = append(res, string(utf16.Decode(units[from:i])))
			from = i + 1
		}
	}
	if from < len(units) {
		res = append(res, string(utf16.Decode(units[from:])))
	}
	return res
}
