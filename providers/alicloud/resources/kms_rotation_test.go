// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseRotationIntervalSeconds(t *testing.T) {
	tests := []struct {
		name     string
		value    string
		expected int64
		ok       bool
	}{
		{"one year, as KMS reports a key interval", "31536000s", 31536000, true},
		{"one week, as KMS reports a secret interval", "604800s", 604800, true},
		{"bare digits with no suffix", "86400", 86400, true},
		{"surrounding whitespace", "  3600s  ", 3600, true},
		{"explicit zero is a reading, not an absence", "0s", 0, true},
		// An absent interval must not read as an interval of zero seconds: zero
		// would claim the key rotates continuously.
		{"empty", "", 0, false},
		{"suffix only", "s", 0, false},
		{"negative", "-604800s", 0, false},
		{"hours are not a unit KMS reports", "24h", 0, false},
		{"fractional", "1.5s", 0, false},
		{"letters", "garbage", 0, false},
		{"digits with trailing junk", "604800sx", 0, false},
		{"digits with embedded junk", "60x4800s", 0, false},
		{"wider than int64", "99999999999999999999s", 0, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			seconds, ok := parseRotationIntervalSeconds(test.value)
			require.Equal(t, test.ok, ok)
			assert.Equal(t, test.expected, seconds)
		})
	}
}

func TestKmsRotationIntervalSeconds(t *testing.T) {
	t.Run("a readable interval becomes a value the field can carry", func(t *testing.T) {
		got := kmsRotationIntervalSeconds("31536000s")
		require.NotNil(t, got)
		assert.Equal(t, int64(31536000), *got)
	})

	t.Run("an explicit zero is carried, not dropped", func(t *testing.T) {
		got := kmsRotationIntervalSeconds("0s")
		require.NotNil(t, got)
		assert.Equal(t, int64(0), *got)
	})

	// Nil is what keeps the MQL field null through llx.IntDataPtr. Returning a
	// pointer to zero here would report a rotation interval of zero seconds on
	// every key that has automatic rotation disabled.
	t.Run("no interval reported stays nil", func(t *testing.T) {
		assert.Nil(t, kmsRotationIntervalSeconds(""))
	})

	t.Run("an unparseable interval stays nil", func(t *testing.T) {
		assert.Nil(t, kmsRotationIntervalSeconds("24h"))
	})
}
