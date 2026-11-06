// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"go.mondoo.com/mql/llx"
)

func TestModelStudioTokenList(t *testing.T) {
	str := func(s string) *string { return &s }

	t.Run("follows tokens until an empty one", func(t *testing.T) {
		// Synthetic: no target showed this.
		pages := map[string]struct {
			items []int
			next  *string
		}{
			"":  {[]int{1, 2}, str("a")},
			"a": {[]int{3}, str("b")},
			"b": {[]int{4}, str("")},
		}
		calls := 0
		got, err := modelStudioTokenList(func(token *string) ([]int, *string, error) {
			calls++
			key := ""
			if token != nil {
				key = *token
			}
			p := pages[key]
			return p.items, p.next, nil
		})
		require.NoError(t, err)
		assert.Equal(t, []int{1, 2, 3, 4}, got)
		assert.Equal(t, 3, calls)
	})

	t.Run("a repeated token stops the walk", func(t *testing.T) {
		// Synthetic: no target showed this.
		calls := 0
		got, err := modelStudioTokenList(func(token *string) ([]int, *string, error) {
			calls++
			if calls > 5 {
				t.Fatal("stuck cursor was followed")
			}
			return []int{calls}, str("same"), nil
		})
		require.NoError(t, err)
		assert.Equal(t, []int{1, 2}, got)
	})

	t.Run("an error fails the walk", func(t *testing.T) {
		boom := errors.New("boom")
		_, err := modelStudioTokenList(func(token *string) ([]int, *string, error) { return nil, nil, boom })
		assert.ErrorIs(t, err, boom)
	})
}

func TestModelStudioBodyError(t *testing.T) {
	// Synthetic: no target showed this.
	f, tr := false, true
	code, msg := "Forbidden.NoPermission", "no permission"
	assert.NoError(t, modelStudioBodyError("ListApiKeys", nil, nil, nil))
	assert.NoError(t, modelStudioBodyError("ListApiKeys", &tr, nil, nil))
	err := modelStudioBodyError("ListApiKeys", &f, &code, &msg)
	require.Error(t, err)
	assert.Contains(t, err.Error(), code)
}

func TestModelStudioKeyEnabled(t *testing.T) {
	// Synthetic: the disabled flag values from the ListApiKeys model; no target showed these.
	zero, one := int32(0), int32(1)
	assert.Equal(t, true, modelStudioKeyEnabled(&zero).Value)
	assert.Equal(t, false, modelStudioKeyEnabled(&one).Value)
	assert.Equal(t, llx.NilData, modelStudioKeyEnabled(nil))
}
