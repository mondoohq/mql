// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package registry

import (
	"encoding/binary"
	"encoding/json"
	"testing"
	"unicode/utf16"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// utf16z encodes strings the way Windows stores REG_SZ (one string) and
// REG_MULTI_SZ (several): UTF-16LE, each ended by NUL, a multi-string ended by
// one more NUL.
func utf16z(multi bool, strs ...string) []byte {
	var units []uint16
	for _, s := range strs {
		units = append(units, utf16.Encode([]rune(s))...)
		units = append(units, 0)
	}
	if multi {
		units = append(units, 0)
	}
	out := make([]byte, 2*len(units))
	for i, u := range units {
		binary.LittleEndian.PutUint16(out[2*i:], u)
	}
	return out
}

// TestRegistryValueEquivalence decodes one value of every kind the way each
// path sees it (the native reader: the stored bytes; the PowerShell script:
// the JSON it emits for that value) and asserts both decode to the same
// value. A difference here is a query that answers differently depending on
// how the host is reached.
func TestRegistryValueEquivalence(t *testing.T) {
	le32 := func(v uint32) []byte { b := make([]byte, 4); binary.LittleEndian.PutUint32(b, v); return b }
	be32 := func(v uint32) []byte { b := make([]byte, 4); binary.BigEndian.PutUint32(b, v); return b }
	le64 := func(v uint64) []byte { b := make([]byte, 8); binary.LittleEndian.PutUint64(b, v); return b }

	tests := []struct {
		name string
		kind uint32
		raw  []byte
		// psJSON is the value object the collection script emits.
		psJSON string
	}{
		{"REG_SZ", SZ, utf16z(false, "hello"), `{"data":"hello","type":"REG_SZ","kind":null}`},
		{"REG_SZ empty", SZ, utf16z(false, ""), `{"data":"","type":"REG_SZ","kind":null}`},
		// The script reads REG_EXPAND_SZ unexpanded, as it is stored.
		{"REG_EXPAND_SZ", EXPAND_SZ, utf16z(false, `%SystemRoot%\system32\logfiles\firewall\domainfw.log`),
			`{"data":"%SystemRoot%\\system32\\logfiles\\firewall\\domainfw.log","type":"REG_EXPAND_SZ","kind":null}`},
		{"REG_DWORD", DWORD, le32(42), `{"data":42,"type":"REG_DWORD","kind":null}`},
		{"REG_DWORD max", DWORD, le32(0xFFFFFFFF), `{"data":4294967295,"type":"REG_DWORD","kind":null}`},
		{"REG_QWORD", QWORD, le64(5000000000), `{"data":5000000000,"type":"REG_QWORD","kind":null}`},
		// Get-ItemProperty returns a REG_QWORD at or above 2^63 as UInt64.
		{"REG_QWORD above 2^63", QWORD, le64(0x8000000000000001), `{"data":9223372036854775809,"type":"REG_QWORD","kind":null}`},
		{"REG_MULTI_SZ", MULTI_SZ, utf16z(true, "alpha", "beta"), `{"data":["alpha","beta"],"type":"REG_MULTI_SZ","kind":null}`},
		{"REG_MULTI_SZ single", MULTI_SZ, utf16z(true, "alpha"), `{"data":"alpha","type":"REG_MULTI_SZ","kind":null}`},
		{"REG_MULTI_SZ empty", MULTI_SZ, utf16z(true), `{"data":[],"type":"REG_MULTI_SZ","kind":null}`},
		{"REG_BINARY", BINARY, []byte{0xde, 0xad, 0xbe, 0xef}, `{"data":[222,173,190,239],"type":"REG_BINARY","kind":null}`},
		// .NET returns REG_DWORD_BIG_ENDIAN as its raw bytes.
		{"REG_DWORD_BIG_ENDIAN", DWORD_BIG_ENDIAN, be32(42), `{"data":[0,0,0,42],"type":"REG_DWORD_BIG_ENDIAN","kind":null}`},
		// .NET returns no data for REG_LINK and the resource lists; the
		// script emits the hex reg.exe prints (as observed on Server 2022).
		{"REG_LINK", LINK, []byte{0x41, 0, 0x42, 0}, `{"data":null,"hex":"41004200","type":"REG_LINK","kind":null}`},
		{"REG_RESOURCE_LIST", RESOURCE_LIST, []byte{1, 0, 0, 0, 5}, `{"data":null,"hex":"0100000005","type":"REG_RESOURCE_LIST","kind":null}`},
		{"REG_FULL_RESOURCE_DESCRIPTOR", FULL_RESOURCE_DESCRIPTOR, []byte{2, 3}, `{"data":null,"hex":"0203","type":"REG_FULL_RESOURCE_DESCRIPTOR","kind":null}`},
		// Byte arrays decode too, should a PowerShell version return them.
		{"REG_RESOURCE_LIST as bytes", RESOURCE_LIST, []byte{1, 0, 0, 0, 5}, `{"data":[1,0,0,0,5],"type":"REG_RESOURCE_LIST","kind":null}`},
		{"REG_NONE", NONE, []byte{1, 2}, `{"data":[1,2],"type":"REG_NONE","kind":null}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			native := RegistryKeyItem{Key: "v", Value: decodeRawRegistryValue(tt.kind, tt.raw)}
			require.NoError(t, native.Value.Err)

			var ps RegistryKeyItem
			require.NoError(t, json.Unmarshal([]byte(`{"key":"v","value":`+tt.psJSON+`}`), &ps))
			require.NoError(t, ps.Value.Err)

			assert.Equal(t, native.Value.Kind, ps.Value.Kind, "kind")
			assert.Equal(t, native.Kind(), ps.Kind(), "type name")
			assert.Equal(t, native.String(), ps.String(), "value")
			assert.Equal(t, native.GetRawValue(), ps.GetRawValue(), "data")
			assert.Equal(t, native.Value.Number, ps.Value.Number, "number")
		})
	}
}

// REG_RESOURCE_REQUIREMENTS_LIST is the one kind the paths cannot agree on:
// .NET returns no data for it and reg.exe prints it as REG_NONE, so over
// PowerShell it reads as an empty value of kind none. The native path reads
// it as stored.
func TestResourceRequirementsListOverPowerShell(t *testing.T) {
	native := RegistryKeyItem{Key: "v", Value: decodeRawRegistryValue(RESOURCE_REQUIREMENTS_LIST, []byte{9})}
	assert.Equal(t, "resourcerequirementslist", native.Kind())
	assert.Equal(t, []any{int64(9)}, native.GetRawValue())

	var ps RegistryKeyItem
	require.NoError(t, json.Unmarshal([]byte(`{"key":"v","value":{"data":null,"hex":null,"type":"REG_NONE","kind":null}}`), &ps))
	assert.Equal(t, "none", ps.Kind())
	assert.Nil(t, ps.GetRawValue())
}

// A value whose data does not fit its kind fails that value alone, on both
// paths, rather than the whole key.
func TestDecodeRawRegistryValueMalformed(t *testing.T) {
	v := decodeRawRegistryValue(DWORD, []byte{1, 2})
	require.Error(t, v.Err)
	v = decodeRawRegistryValue(QWORD, []byte{1, 2, 3, 4})
	require.Error(t, v.Err)
	v = decodeRawRegistryValue(DWORD_BIG_ENDIAN, nil)
	require.Error(t, v.Err)

	var ps RegistryKeyItem
	require.NoError(t, json.Unmarshal([]byte(`{"key":"v","value":{"data":[1,2],"type":"REG_DWORD_BIG_ENDIAN","kind":null}}`), &ps))
	assert.Error(t, ps.Value.Err)

	// data that is not a byte array fails the value, not the key
	ps = RegistryKeyItem{}
	require.NoError(t, json.Unmarshal([]byte(`{"key":"v","value":{"data":"garbled","type":"REG_DWORD_BIG_ENDIAN","kind":null}}`), &ps))
	assert.Error(t, ps.Value.Err)
	ps = RegistryKeyItem{}
	require.NoError(t, json.Unmarshal([]byte(`{"key":"v","value":{"data":[1,256],"type":"REG_LINK","kind":null}}`), &ps))
	assert.Error(t, ps.Value.Err)
}

// A REG_MULTI_SZ whose last string lacks its NUL keeps that string, as .NET
// reads it for the PowerShell path.
func TestUTF16StringsUnterminated(t *testing.T) {
	units := func(s string) []byte {
		var out []byte
		for _, u := range utf16.Encode([]rune(s)) {
			out = binary.LittleEndian.AppendUint16(out, u)
		}
		return out
	}
	assert.Equal(t, []string{"a", "b"}, utf16Strings(utf16z(true, "a", "b")))
	assert.Equal(t, []string{"a", "", "b"}, utf16Strings(utf16z(true, "a", "", "b")))
	assert.Equal(t, []string{"a", "b"}, utf16Strings(units("a\x00b")))
	assert.Equal(t, []string{"a", "b"}, utf16Strings(units("a\x00b\x00")))
	assert.Equal(t, []string{"ab"}, utf16Strings(units("ab")))
	assert.Nil(t, utf16Strings(nil))
}

// The collection script reads REG_EXPAND_SZ unexpanded: with
// DoNotExpandEnvironmentNames, and from reg.exe's printed data where language
// mode refuses the method call.
func TestGetRegistryKeyItemScriptReadsExpandStringUnexpanded(t *testing.T) {
	script := GetRegistryKeyItemScript(`HKEY_LOCAL_MACHINE\SOFTWARE\Example`)
	assert.Contains(t, script, `$reg.GetValue($fetchKeyValue, $null, 'DoNotExpandEnvironmentNames')`)
	assert.Contains(t, script, `$regData[$matches[1]] = $matches[3]`)
	assert.Contains(t, script, `if ($printed -ne $null) { $data = $printed }`)
	assert.Contains(t, script, `"hex" = $hex;`)
}
