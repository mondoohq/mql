// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package llx

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

// A null array receiver (e.g. a missing map key resolving to a typed null
// array, like secpol.privilegerights["SeMissing"]) must not error when the
// all/any/none/one assertion builtins are called on it. It propagates as a
// null bool so the check fails cleanly instead of crashing the scan.
func TestArrayAssertions_NullReceiver(t *testing.T) {
	cases := []struct {
		name string
		fn   func(*blockExecutor, *RawData, *Chunk, uint64) (*RawData, uint64, error)
	}{
		{"all", arrayAllV2},
		{"any", arrayAnyV2},
		{"none", arrayNoneV2},
		{"one", arrayOneV2},
	}
	for _, c := range cases {
		t.Run(c.name+" on typed null array returns null bool, no error", func(t *testing.T) {
			res, ref, err := c.fn(nil, &RawData{Type: types.Array(types.String), Value: nil}, nil, 0)
			require.NoError(t, err)
			require.Equal(t, uint64(0), ref)
			require.NotNil(t, res)
			require.Equal(t, types.Bool, res.Type)
			require.Nil(t, res.Value)
			require.NoError(t, res.Error)
		})

		t.Run(c.name+" preserves a genuine upstream error", func(t *testing.T) {
			boom := errors.New("upstream boom")
			res, _, err := c.fn(nil, &RawData{Type: types.Array(types.String), Value: nil, Error: boom}, nil, 0)
			require.NoError(t, err)
			require.NotNil(t, res)
			require.Equal(t, boom, res.Error)
		})
	}
}

func TestArrayFlat(t *testing.T) {
	t.Run("empty array with missing type info", func(t *testing.T) {
		res, ref, err := arrayFlat(nil, &RawData{
			Type:  types.ArrayLike,
			Value: []any{},
		}, nil, 0)
		require.NoError(t, err)
		require.Equal(t, uint64(0), ref)
		require.Equal(t, ArrayData([]any{}, types.Any), res)
	})
}

// Ensure internal array helpers return empty slices (not nil) so that downstream
// operations like array concatenation do not hit "cannot add arrays to null".
func TestArrayHelpers_EmptyNotNil(t *testing.T) {
	t.Run("flatten of empty array returns empty slice", func(t *testing.T) {
		res := flatten([]any{})
		require.NotNil(t, res)
		require.Equal(t, []any{}, res)
	})

	t.Run("_arraySample with zero count returns empty slice", func(t *testing.T) {
		res := _arraySample([]any{1, 2, 3}, 0)
		require.NotNil(t, res)
		require.Equal(t, []any{}, res)
	})

	t.Run("_arraySample with empty array returns empty slice", func(t *testing.T) {
		res := _arraySample([]any{}, 5)
		require.NotNil(t, res)
		require.Equal(t, []any{}, res)
	})
}

func TestRawValuesEqual(t *testing.T) {
	v4 := ParseIP("192.0.2.1")
	// The same address held in its 16-byte form, as net.ParseIP returns it.
	v4in16 := v4
	v4in16.IP = v4.IP.To16()
	require.Len(t, v4in16.IP, 16)

	withPrefix := ParseIP("192.0.2.1/25")
	shared := map[string]any{"a": int64(1)}

	cases := []struct {
		name string
		a, b any
		want bool
	}{
		{"same ip", v4, ParseIP("192.0.2.1"), true},
		{"ip in 4 and 16 byte form", v4, v4in16, true},
		{"different ip", v4, ParseIP("192.0.2.2"), false},
		{"same ip, different prefix length", v4, withPrefix, false},
		{"ip and string", v4, "192.0.2.1", false},
		{"ip and nil", v4, nil, false},
		{"nil and ip", nil, v4, false},
		{"nil and nil", nil, nil, true},
		{"equal dicts", map[string]any{"a": int64(1)}, map[string]any{"a": int64(1)}, true},
		{"same dict", shared, shared, true},
		{"different dicts", map[string]any{"a": int64(1)}, map[string]any{"a": int64(2)}, false},
		{"equal nested arrays", []any{int64(1), "x"}, []any{int64(1), "x"}, true},
		{"different nested arrays", []any{int64(1)}, []any{int64(2)}, false},
		{"equal strings", "x", "x", true},
		{"int and float", int64(1), float64(1), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.NotPanics(t, func() {
				require.Equal(t, c.want, rawValuesEqual(c.a, c.b))
			})
		})
	}
}

func TestTarrayCmpTarray_IP(t *testing.T) {
	ips := func(s ...string) *RawData {
		arr := make([]any, len(s))
		for i := range s {
			arr[i] = ParseIP(s[i])
		}
		return ArrayData(arr, types.IP)
	}
	left := ips("192.0.2.1", "2001:db8::1")
	require.True(t, cmpArrays(left, ips("192.0.2.1", "2001:db8::1"), tArrayCmp(left, left)))
	require.False(t, cmpArrays(left, ips("2001:db8::1", "192.0.2.1"), tArrayCmp(left, left)))
	require.False(t, cmpArrays(left, ips("192.0.2.1"), tArrayCmp(left, left)))
}
