// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSasParseTime(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("parses the space-separated form the APIs return", func(t *testing.T) {
		got := sasParseTime(strPtr("2026-03-14 09:26:53"))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC), got.UTC())
	})

	t.Run("parses a date-only value", func(t *testing.T) {
		got := sasParseTime(strPtr("2026-03-14"))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC), got.UTC())
	})

	t.Run("parses RFC3339", func(t *testing.T) {
		got := sasParseTime(strPtr("2026-03-14T09:26:53Z"))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC), got.UTC())
	})

	// An unparseable value must stay null rather than becoming the zero time,
	// which would render as the year 1 and read as a real timestamp.
	t.Run("nil and unparseable values stay null", func(t *testing.T) {
		assert.Nil(t, sasParseTime(nil))
		assert.Nil(t, sasParseTime(strPtr("")))
		assert.Nil(t, sasParseTime(strPtr("14/03/2026")))
		assert.Nil(t, sasParseTime(strPtr("never")))
	})
}
