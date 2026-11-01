// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package llx_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

func TestResourceMapV2(t *testing.T) {
	t.Run("ArrayLike not empty", func(t *testing.T) {
		result, err := exec.Exec(`users.where(group != empty).map(name).all(_ != empty)`, testutils.LinuxMock(), testutils.Features, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, true, result.Value)
	})
	t.Run("ArrayLike empty", func(t *testing.T) {
		result, err := exec.Exec(`users.where(group == empty).map(name).all(_ != empty)`, testutils.LinuxMock(), testutils.Features, nil)
		require.NoError(t, err)
		require.NotNil(t, result)
		require.Equal(t, true, result.Value)
	})
}

// A where inside a block runs once per element of the outer list, and each run
// keeps different items. Every run must see its own filter result, not the
// first run's (a regression in v14.9.1, when field answers began to be cached
// across the runtime while every run stored its result under the same id).
func TestResourceWhereV2_InsideBlock(t *testing.T) {
	blockValues := func(t *testing.T, query string) []any {
		t.Helper()
		result, err := exec.Exec(query, testutils.LinuxMock(), testutils.Features, nil)
		require.NoError(t, err)
		require.NoError(t, result.Error)
		rows, ok := result.Value.([]any)
		require.True(t, ok, "expected a list of block results, got %T", result.Value)
		values := make([]any, len(rows))
		for i, row := range rows {
			fields, ok := row.(map[string]any)
			require.True(t, ok, "expected a block result, got %T", row)
			require.Len(t, fields, 1)
			for _, v := range fields {
				values[i] = v
			}
		}
		return values
	}

	t.Run("list of the filter result", func(t *testing.T) {
		got := blockValues(t, `["root", "chris", "nobody"] { x = _; users.where(name == x).list.map(name) }`)
		assert.Equal(t, []any{[]any{"root"}, []any{"chris"}, []any{}}, got)
	})
	t.Run("length of the filter result", func(t *testing.T) {
		got := blockValues(t, `[1, 1000] { x = _; users.where(uid >= x).length }`)
		assert.Equal(t, []any{int64(3), int64(2)}, got)
	})
}

func TestPermissionsAtMost(t *testing.T) {
	tests := []struct {
		mode, mask int64
		want       bool
	}{
		{0, 0, true},
		{0o640, 0, false},
		{0o640, 0o640, true},
		{0o600, 0o640, true},
		{0o604, 0o640, false}, // below 0640 numerically, but other-readable
		{0o4755, 0o755, false},
		{0o4755, 0o4755, true},
		{0o1777, 0o7777, true},
		{0o100644, 0o644, true}, // file type bits are not permission bits
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, llx.PermissionsAtMost(tc.mode, tc.mask), "mode %o mask %o", tc.mode, tc.mask)
	}
}

func TestPermissionsAtLeast(t *testing.T) {
	tests := []struct {
		mode, mask int64
		want       bool
	}{
		{0, 0, true},
		{0o640, 0, true},
		{0, 0o600, false},
		{0o640, 0o600, true},
		{0o640, 0o660, false},
		{0o1777, 0o1000, true},
		{0o777, 0o1000, false},
		{0o1777, 0o7777, false},
		{0o7777, 0o7777, true},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, llx.PermissionsAtLeast(tc.mode, tc.mask), "mode %o mask %o", tc.mode, tc.mask)
	}
}
