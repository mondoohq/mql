// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResolvePluginPortRangeFrom(t *testing.T) {
	t.Run("unset means an OS-assigned port on every platform", func(t *testing.T) {
		for _, tcp := range []bool{true, false} {
			r, err := resolvePluginPortRangeFrom("", tcp)
			require.NoError(t, err)
			// Min 0 is what makes go-plugin bind 127.0.0.1:0. Max must stay
			// non-zero: with both at zero go-plugin silently swaps in its own
			// 10000-25000 default, the range this whole file exists to leave.
			assert.Equal(t, uint(0), r.Min)
			assert.NotEqual(t, uint(0), r.Max)
		}
	})

	t.Run("configured range is used where the transport is TCP", func(t *testing.T) {
		r, err := resolvePluginPortRangeFrom("50000-50100", true)
		require.NoError(t, err)
		assert.Equal(t, pluginPortRange{Min: 50000, Max: 50100}, r)
	})

	t.Run("configured range tolerates whitespace", func(t *testing.T) {
		r, err := resolvePluginPortRangeFrom(" 50000 - 50100 ", true)
		require.NoError(t, err)
		assert.Equal(t, pluginPortRange{Min: 50000, Max: 50100}, r)
	})

	t.Run("single port range is allowed", func(t *testing.T) {
		r, err := resolvePluginPortRangeFrom("50000-50000", true)
		require.NoError(t, err)
		assert.Equal(t, pluginPortRange{Min: 50000, Max: 50000}, r)
	})

	t.Run("malformed value is an error where the transport is TCP", func(t *testing.T) {
		_, err := resolvePluginPortRangeFrom("fifty-thousand", true)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "provider_port_range")
	})

	t.Run("malformed value is ignored where the transport is not TCP", func(t *testing.T) {
		// A typo in a fleet-wide mondoo.yml must not fail Linux scans over a
		// Windows-only setting; the resolver logs and uses the default instead.
		r, err := resolvePluginPortRangeFrom("fifty-thousand", false)
		require.NoError(t, err)
		assert.Equal(t, ephemeralPluginPortRange, r)
	})
}

func TestParsePluginPortRange(t *testing.T) {
	bad := map[string]string{
		"no dash":         "50000",
		"empty min":       "-50000",
		"empty max":       "50000-",
		"min above max":   "50100-50000",
		"port zero min":   "0-100",
		"port zero max":   "0-0",
		"above 65535":     "50000-70000",
		"negative":        "-1-50000",
		"not a number":    "abc-def",
		"float":           "50000.5-50100",
		"extra separator": "50000-50100-50200",
	}
	for name, in := range bad {
		t.Run(name, func(t *testing.T) {
			_, err := parsePluginPortRange(in)
			assert.Error(t, err, in)
		})
	}

	good := map[string]pluginPortRange{
		"1-65535":     {Min: 1, Max: 65535},
		"50000-50100": {Min: 50000, Max: 50100},
		"8080-8080":   {Min: 8080, Max: 8080},
	}
	for in, want := range good {
		t.Run(in, func(t *testing.T) {
			r, err := parsePluginPortRange(in)
			require.NoError(t, err)
			assert.Equal(t, want, r)
		})
	}
}
