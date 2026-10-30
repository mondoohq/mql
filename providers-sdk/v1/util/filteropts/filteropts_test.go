// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package filteropts

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParseCsvSliceOpt(t *testing.T) {
	t.Run("parses comma-separated values correctly", func(t *testing.T) {
		opts := map[string]string{
			"key": "value1,value2,value3",
		}
		result := ParseCsvSliceOpt(opts, "key")
		expected := []string{"value1", "value2", "value3"}
		require.Equal(t, expected, result)
	})

	t.Run("returns empty slice for missing key", func(t *testing.T) {
		opts := map[string]string{}
		result := ParseCsvSliceOpt(opts, "key")
		expected := []string{}
		require.Equal(t, expected, result)
	})

	t.Run("returns empty slice for empty value", func(t *testing.T) {
		opts := map[string]string{
			"key": "",
		}
		result := ParseCsvSliceOpt(opts, "key")
		expected := []string{}
		require.Equal(t, expected, result)
	})
}

func TestParseBoolOpt(t *testing.T) {
	t.Run("parses true values correctly", func(t *testing.T) {
		trueValues := []string{"true", "TRUE", "t", "T", "1"}
		for _, val := range trueValues {
			result := ParseBoolOpt(map[string]string{"key": val}, "key", false)
			require.True(t, result)
		}
	})

	t.Run("parses false values correctly", func(t *testing.T) {
		falseValues := []string{"false", "FALSE", "f", "F", "0"}
		for _, val := range falseValues {
			result := ParseBoolOpt(map[string]string{"key": val}, "key", true)
			require.False(t, result)
		}
	})

	t.Run("returns default for missing key", func(t *testing.T) {
		require.True(t, ParseBoolOpt(map[string]string{}, "key", true))
		require.False(t, ParseBoolOpt(map[string]string{}, "key", false))
	})

	t.Run("returns default for unparseable value", func(t *testing.T) {
		require.True(t, ParseBoolOpt(map[string]string{"key": "notabool"}, "key", true))
		require.False(t, ParseBoolOpt(map[string]string{"key": "notabool"}, "key", false))
	})
}
