// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/types"
)

func TestStrArray(t *testing.T) {
	t.Run("nil slice", func(t *testing.T) {
		res := strArray(nil)
		require.NotNil(t, res)
		assert.Equal(t, types.Array(types.String), res.Type)
		assert.Equal(t, []any{}, res.Value)
	})

	t.Run("values are preserved in order", func(t *testing.T) {
		res := strArray([]string{"a", "b", "c"})
		assert.Equal(t, types.Array(types.String), res.Type)
		assert.Equal(t, []any{"a", "b", "c"}, res.Value)
	})
}

func TestIdItemsToStrings(t *testing.T) {
	t.Run("nil slice yields empty (non-nil) slice", func(t *testing.T) {
		assert.Equal(t, []string{}, idItemsToStrings(nil))
	})

	t.Run("extracts ids in order", func(t *testing.T) {
		items := []idItem{{ID: "ru"}, {ID: "xyz"}, {ID: "pw"}}
		assert.Equal(t, []string{"ru", "xyz", "pw"}, idItemsToStrings(items))
	})
}

func TestTimeOrNil(t *testing.T) {
	t.Run("nil returns MQL null", func(t *testing.T) {
		res := timeOrNil(nil)
		require.NotNil(t, res)
		assert.Equal(t, types.Nil, res.Type)
	})

	t.Run("non-nil returns the time value", func(t *testing.T) {
		ts := time.Date(2026, 7, 22, 12, 0, 0, 0, time.UTC)
		res := timeOrNil(&ts)
		require.NotNil(t, res)
		assert.Equal(t, types.Time, res.Type)
		require.IsType(t, &time.Time{}, res.Value)
		assert.Equal(t, ts, *res.Value.(*time.Time))
	})
}
