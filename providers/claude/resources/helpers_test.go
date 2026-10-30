// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseFamily(t *testing.T) {
	tests := []struct {
		id   string
		want string
	}{
		{"claude-opus-4-6", "opus"},
		{"claude-sonnet-5", "sonnet"},
		{"claude-haiku-4-5-20251001", "haiku"},
		{"claude-3-5-sonnet-20241022", "sonnet"},
		{"some-unknown-model", ""},
		{"", ""},
		// A family the provider has no prior knowledge of still resolves, so a
		// newly released one is never reported as an empty family.
		{"claude-fable-5", "fable"},
		{"claude-3-5-newfamily-20260101", "newfamily"},
		// An id carrying only a version has no family to report.
		{"claude-2.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			assert.Equal(t, tt.want, parseFamily(tt.id))
		})
	}
}

func TestParseTime(t *testing.T) {
	// An empty string is a valid "not set" value and must yield the zero time
	// with no error, so a missing timestamp never fails the whole list call.
	zero, err := parseTime("")
	require.NoError(t, err)
	assert.True(t, zero.IsZero())

	got, err := parseTime("2026-01-02T15:04:05Z")
	require.NoError(t, err)
	assert.Equal(t, time.Date(2026, 1, 2, 15, 4, 5, 0, time.UTC), got.UTC())

	_, err = parseTime("not-a-timestamp")
	assert.Error(t, err)
}

func TestToInterfaceMap(t *testing.T) {
	assert.Equal(t, map[string]any{}, toInterfaceMap(nil))
	assert.Equal(t,
		map[string]any{"team": "platform", "env": "prod"},
		toInterfaceMap(map[string]string{"team": "platform", "env": "prod"}),
	)
}

func TestToInterfaceSlice(t *testing.T) {
	// A nil slice must convert to an empty slice, not nil, so an absent list
	// renders as [] rather than null.
	assert.Equal(t, []any{}, toInterfaceSlice(nil))
	assert.Equal(t, []any{"a", "b"}, toInterfaceSlice([]string{"a", "b"}))
}

func TestRawJSONToDict(t *testing.T) {
	// An absent schema decodes to nil so the dict field renders as null
	// instead of an empty object that implies the tool takes no input.
	got, err := rawJSONToDict("")
	require.NoError(t, err)
	assert.Nil(t, got)

	got, err = rawJSONToDict("null")
	require.NoError(t, err)
	assert.Nil(t, got)

	// Numbers must decode to float64 and nested values to plain maps and
	// slices, since dict fields only accept JSON-native types.
	got, err = rawJSONToDict(`{"type":"object","properties":{"path":{"type":"string"}},"required":["path"],"max":3}`)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"type": "object",
		"properties": map[string]any{
			"path": map[string]any{"type": "string"},
		},
		"required": []any{"path"},
		"max":      float64(3),
	}, got)

	_, err = rawJSONToDict("{not json")
	assert.Error(t, err)
}
