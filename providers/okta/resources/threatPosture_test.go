// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseOktaTimestamp(t *testing.T) {
	// The legacy /api/v1/behaviors form that breaks the SDK's RFC3339 parsing.
	got := parseOktaTimestamp("2026-07-20 17:34:59.0")
	if assert.NotNil(t, got) {
		assert.Equal(t, 2026, got.Year())
		assert.Equal(t, 34, got.Minute())
	}

	// RFC3339 (used by most other endpoints).
	got = parseOktaTimestamp("2024-03-01T12:34:56Z")
	if assert.NotNil(t, got) {
		assert.Equal(t, 56, got.Second())
	}

	// Space form without fractional seconds.
	assert.NotNil(t, parseOktaTimestamp("2026-07-20 17:34:59"))

	// Empty and unparseable render as null.
	assert.Nil(t, parseOktaTimestamp(""))
	assert.Nil(t, parseOktaTimestamp("garbage"))
}

func TestOktaMapStr(t *testing.T) {
	m := map[string]any{"id": "bhv1", "count": 5, "nilval": nil}
	assert.Equal(t, "bhv1", oktaMapStr(m, "id"))
	assert.Equal(t, "", oktaMapStr(m, "count"))  // non-string
	assert.Equal(t, "", oktaMapStr(m, "nilval")) // nil
	assert.Equal(t, "", oktaMapStr(m, "absent")) // missing
	require.Equal(t, "", oktaMapStr(map[string]any{}, "id"))
}
