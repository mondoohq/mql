// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

func TestIsAccessDenied(t *testing.T) {
	tests := []struct {
		name string
		resp *http.Response
		want bool
	}{
		{"nil response", nil, false},
		{"200 OK", &http.Response{StatusCode: http.StatusOK}, false},
		{"401 Unauthorized", &http.Response{StatusCode: http.StatusUnauthorized}, true},
		{"403 Forbidden", &http.Response{StatusCode: http.StatusForbidden}, true},
		// NOTE: 404 is not treated as access-denied; only 401/403 degrade to null.
		{"404 Not Found", &http.Response{StatusCode: http.StatusNotFound}, false},
		{"500 Internal Server Error", &http.Response{StatusCode: http.StatusInternalServerError}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isAccessDenied(tt.resp))
		})
	}
}

func TestStrSlice(t *testing.T) {
	assert.Equal(t, []any{}, strSlice(nil))
	assert.Equal(t, []any{}, strSlice([]string{}))
	assert.Equal(t, []any{"a", "b"}, strSlice([]string{"a", "b"}))
}

func TestTimePtr(t *testing.T) {
	assert.Nil(t, timePtr(time.Time{}), "zero time maps to nil")

	now := time.Date(2026, 7, 19, 10, 0, 0, 0, time.UTC)
	got := timePtr(now)
	require.NotNil(t, got)
	assert.Equal(t, now, *got)
}

func TestDictTime(t *testing.T) {
	assert.Nil(t, dictTime(time.Time{}), "zero time maps to nil so the dict value round-trips")

	ts := time.Date(2026, 7, 19, 10, 30, 0, 0, time.UTC)
	assert.Equal(t, "2026-07-19T10:30:00Z", dictTime(ts))
}

func TestTagMap(t *testing.T) {
	assert.Equal(t, map[string]any{}, tagMap(nil))
	assert.Equal(t, map[string]any{}, tagMap([]admin.ResourceTag{}))

	assert.Equal(t, map[string]any{"env": "prod", "owner": "platform"}, tagMap([]admin.ResourceTag{
		{Key: "env", Value: "prod"},
		{Key: "owner", Value: "platform"},
	}))

	assert.Equal(t, map[string]any{"env": "staging"}, tagMap([]admin.ResourceTag{
		{Key: "env", Value: "prod"},
		{Key: "env", Value: "staging"},
	}), "a later tag wins on a duplicate key")

	assert.Equal(t, map[string]any{"": ""}, tagMap([]admin.ResourceTag{{}}),
		"an empty tag still occupies a key rather than being dropped")
}
