// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package windows

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPSInt64Array(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  PSInt64Array
	}{
		{name: "bare array", input: `[1,2]`, want: PSInt64Array{1, 2}},
		{name: "bare and empty", input: `[]`, want: PSInt64Array{}},
		// The shape a Select-Object calculated property produces. A plain
		// []int64 tag decodes it to empty, which reports "no security
		// services running" on a host running Credential Guard.
		{name: "wrapped by Count", input: `{"value":[1,2],"Count":2}`, want: PSInt64Array{1, 2}},
		{name: "wrapped and empty", input: `{"value":[],"Count":0}`, want: PSInt64Array{}},
		{name: "wrapped with capital Value", input: `{"Value":[3],"Count":1}`, want: PSInt64Array{3}},
		// A one-element list PowerShell flattened out of its array.
		{name: "single flattened element", input: `2`, want: PSInt64Array{2}},
		{name: "absent", input: `null`, want: nil},
		// A calculated property yielding nothing serializes as {} rather than
		// as null.
		{name: "empty object", input: `{}`, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var got PSInt64Array
			require.NoError(t, json.Unmarshal([]byte(tc.input), &got))
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestPSInt64ArrayDistinguishesAbsentFromEmpty(t *testing.T) {
	// An absent property has to stay distinguishable from a present but empty
	// list: the first is "unknown", the second is "none configured", and an
	// audit reads them differently.
	var absent PSInt64Array
	require.NoError(t, json.Unmarshal([]byte(`null`), &absent))
	assert.Nil(t, absent)

	var empty PSInt64Array
	require.NoError(t, json.Unmarshal([]byte(`[]`), &empty))
	assert.NotNil(t, empty)
	assert.Len(t, empty, 0)
}

func TestPSUnwrapListRejectsGarbage(t *testing.T) {
	var got PSInt64Array
	assert.Error(t, json.Unmarshal([]byte(`{"value":[1,`), &got))
}

// psGetContentString is the shape Windows PowerShell 5.1 gives a Get-Content
// result in ConvertTo-Json: the string plus the note properties Get-Content
// attaches (key names captured from a Windows 11 host, PSDrive and PSProvider
// trimmed).
const psGetContentString = `{"value":"<Package/>\r\n",` +
	`"PSPath":"Microsoft.PowerShell.Core\\FileSystem::C:\\Program Files\\WindowsApps\\App\\AppxManifest.xml",` +
	`"PSParentPath":"Microsoft.PowerShell.Core\\FileSystem::C:\\Program Files\\WindowsApps\\App",` +
	`"PSChildName":"AppxManifest.xml","PSDrive":{"Name":"C","Root":"C:\\"},` +
	`"PSProvider":{"Name":"FileSystem"},"ReadCount":1}`

func TestPSString(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  PSString
	}{
		{name: "plain string", input: `"<Package/>"`, want: "<Package/>"},
		{name: "Get-Content string in PowerShell 5.1", input: psGetContentString, want: "<Package/>\r\n"},
		{name: "wrapper with lower-case key", input: `{"Value":"x"}`, want: "x"},
		{name: "wrapper holding null", input: `{"value":null}`, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got PSString
			require.NoError(t, json.Unmarshal([]byte(tt.input), &got))
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPSStringNullStaysAbsent(t *testing.T) {
	var got struct {
		S *PSString `json:"S"`
	}
	require.NoError(t, json.Unmarshal([]byte(`{"S":null}`), &got))
	assert.Nil(t, got.S)
	assert.Nil(t, got.S.StringPtr())
}

// Objects that carry no string value keep decoding to "": an empty calculated
// property serializes as {} (a DNS server that has never scavenged).
func TestPSStringObjectWithoutStringValue(t *testing.T) {
	for _, in := range []string{`{}`, `{"PSPath":"x"}`, `{"value":1}`, `[]`} {
		got := PSString("prior")
		require.NoError(t, json.Unmarshal([]byte(in), &got), in)
		assert.Equal(t, PSString(""), got, in)
	}
}
