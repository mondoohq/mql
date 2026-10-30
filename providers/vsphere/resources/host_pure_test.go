// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseVibDate(t *testing.T) {
	t.Run("valid date parses", func(t *testing.T) {
		got := parseVibDate("2020-07-16")
		require.NotNil(t, got)
		assert.Equal(t, 2020, got.Year())
		assert.Equal(t, 7, int(got.Month()))
		assert.Equal(t, 16, got.Day())
	})

	// A VIB with a missing/blank date must degrade that one field to null and
	// must NOT sink the whole host's package list (the pre-fix behavior).
	t.Run("empty string yields nil, not an error", func(t *testing.T) {
		assert.Nil(t, parseVibDate(""))
	})

	t.Run("unparseable value yields nil", func(t *testing.T) {
		assert.Nil(t, parseVibDate("not-a-date"))
		assert.Nil(t, parseVibDate("2020/07/16"))     // wrong separators
		assert.Nil(t, parseVibDate("2020-07-16 UTC")) // trailing junk
	})
}
