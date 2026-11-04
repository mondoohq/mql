// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package llx_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/exec"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
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
	// blockValues returns the value of one field from each block result: the
	// only field when key is empty, otherwise the field named key.
	blockValues := func(t *testing.T, query string, key string) []any {
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
			if key != "" {
				v, ok := fields[key]
				require.True(t, ok, "expected field %q in the block result, got %v", key, fields)
				values[i] = v
				continue
			}
			require.Len(t, fields, 1)
			for _, v := range fields {
				values[i] = v
			}
		}
		return values
	}

	t.Run("list of the filter result", func(t *testing.T) {
		got := blockValues(t, `["root", "chris", "nobody"] { x = _; users.where(name == x).list.map(name) }`, "")
		assert.Equal(t, []any{[]any{"root"}, []any{"chris"}, []any{}}, got)
	})
	t.Run("length of the filter result", func(t *testing.T) {
		got := blockValues(t, `[1, 1000] { x = _; users.where(uid >= x).length }`, "")
		assert.Equal(t, []any{int64(3), int64(2)}, got)
	})
	// all() keeps the items that fail its condition with whereNot, which stores
	// its result the same way as where.
	t.Run("all, filtered with whereNot", func(t *testing.T) {
		got := blockValues(t, `[0, 1000] { x = _; users.all(uid >= x) }`, "users.all()")
		assert.Equal(t, []any{true, false}, got)
	})
}

// cloneRecorder is a runtime that only records the ids that filter results
// are stored under.
type cloneRecorder struct {
	llx.Runtime
	ids []string
}

func (r *cloneRecorder) CloneResource(src llx.Resource, id string, fields []string, args map[string]*llx.Primitive) (llx.Resource, error) {
	r.ids = append(r.ids, id)
	return &llx.MockResource{Name: src.MqlName(), ID: id}, nil
}

// Synthetic: the id a filter result is stored under names the filter block,
// the filtered resource and the items kept. The runtime also drops cached
// fields when an id is stored again, so the block tests above pass without
// this; the id is what keeps a recording, which that drop doesn't reach, from
// answering one result for another.
func TestFilterResultResource(t *testing.T) {
	userList := func(ids ...string) *llx.Primitive {
		items := make([]*llx.Primitive, len(ids))
		for i, id := range ids {
			items[i] = &llx.Primitive{Type: string(types.Resource("user")), Value: []byte(id)}
		}
		return llx.ArrayPrimitive(items, types.Resource("user"))
	}
	cloneID := func(t *testing.T, srcID string, filtered *llx.Primitive) string {
		t.Helper()
		r := &cloneRecorder{}
		src := &llx.MockResource{Name: "users", ID: srcID}
		_, err := llx.FilterResultResource(r, src, "block", nil, map[string]*llx.Primitive{"list": filtered}, filtered)
		require.NoError(t, err)
		require.Len(t, r.ids, 1)
		return r.ids[0]
	}

	t.Run("the same items of the same resource share an id", func(t *testing.T) {
		a := cloneID(t, "users", userList("root", "chris"))
		b := cloneID(t, "users", userList("root", "chris"))
		assert.Equal(t, a, b)
		assert.True(t, strings.HasPrefix(a, "block/"), "the id starts with the filter block: %s", a)
	})
	t.Run("different items get different ids", func(t *testing.T) {
		assert.NotEqual(t, cloneID(t, "users", userList("root")), cloneID(t, "users", userList("chris")))
		assert.NotEqual(t, cloneID(t, "users", userList()), cloneID(t, "users", userList("root")))
	})
	t.Run("the same items of different resources get different ids", func(t *testing.T) {
		assert.NotEqual(t, cloneID(t, "files/root", userList()), cloneID(t, "files/home", userList()))
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
