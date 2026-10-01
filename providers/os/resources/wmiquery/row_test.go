// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package wmiquery

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRowString(t *testing.T) {
	r := Row{"Caption": "Microsoft Windows Server 2022", "Model": nil, "OSType": int32(18)}

	assert.Equal(t, "Microsoft Windows Server 2022", r.String("Caption"))
	require.NotNil(t, r.StringPtr("Caption"))
	assert.Equal(t, "Microsoft Windows Server 2022", *r.StringPtr("Caption"))

	// NULL, missing and non-string values read as absent
	for _, name := range []string{"Model", "NoSuchProperty", "OSType"} {
		assert.Equal(t, "", r.String(name), name)
		assert.Nil(t, r.StringPtr(name), name)
	}

	empty := Row{"SMBIOSAssetTag": ""}
	require.NotNil(t, empty.StringPtr("SMBIOSAssetTag"), "an empty string is a value, not NULL")
}

func TestRowInt64(t *testing.T) {
	for _, v := range []any{int8(7), int16(7), int32(7), int64(7), int(7), uint8(7), uint16(7), uint32(7), uint64(7), uint(7), "7"} {
		n, ok := Row{"v": v}.Int64("v")
		assert.True(t, ok, "%T", v)
		assert.Equal(t, int64(7), n, "%T", v)
	}

	// WMI sends 64-bit integers, e.g. TotalVisibleMemorySize, as strings
	n, ok := Row{"v": "17179869184"}.Int64("v")
	require.True(t, ok)
	assert.Equal(t, int64(17179869184), n)

	for _, v := range []any{nil, "abc", true, 1.5, []any{int32(1)}, uint64(math.MaxUint64)} {
		_, ok := Row{"v": v}.Int64("v")
		assert.False(t, ok, "%T %v", v, v)
	}
	_, ok = Row{}.Int64("missing")
	assert.False(t, ok)
}

// ChassisTypes is documented as uint16[], but WMI sends VT_I4 elements: the
// mismatch that panicked the struct-based WMI library.
func TestRowInt64s(t *testing.T) {
	types, ok := Row{"ChassisTypes": []any{int32(3), int32(17)}}.Int64s("ChassisTypes")
	require.True(t, ok)
	assert.Equal(t, []int64{3, 17}, types)

	types, ok = Row{"ChassisTypes": []any{uint16(1)}}.Int64s("ChassisTypes")
	require.True(t, ok)
	assert.Equal(t, []int64{1}, types)

	types, ok = Row{"ChassisTypes": []any{}}.Int64s("ChassisTypes")
	require.True(t, ok)
	assert.Empty(t, types)

	for _, v := range []any{nil, int32(3), []any{int32(3), "x"}} {
		_, ok := Row{"ChassisTypes": v}.Int64s("ChassisTypes")
		assert.False(t, ok, "%v", v)
	}
}

// The CIM_DATETIME offset is in minutes; it is parsed the way the previous WMI
// library did, so ReleaseDate keeps its value.
func TestRowTime(t *testing.T) {
	cases := map[string]time.Time{
		"20240115000000.000000+000": time.Date(2024, 1, 15, 0, 0, 0, 0, time.UTC),
		"20240115123000.500000+060": time.Date(2024, 1, 15, 12, 30, 0, 500000000, time.FixedZone("", 60*60)),
		"20240115000000.000000-300": time.Date(2024, 1, 15, 0, 0, 0, 0, time.FixedZone("", -5*60*60)),
	}
	for in, want := range cases {
		got, ok := Row{"ReleaseDate": in}.Time("ReleaseDate")
		require.True(t, ok, in)
		assert.True(t, want.Equal(got), "%s: %v != %v", in, got, want)
	}

	for _, v := range []any{nil, "", "2024******.******+***", "not a date", int32(2024)} {
		_, ok := Row{"ReleaseDate": v}.Time("ReleaseDate")
		assert.False(t, ok, "%v", v)
	}
}
