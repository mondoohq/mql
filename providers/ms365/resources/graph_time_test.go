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

func TestGraphTimeData(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		assert.Nil(t, graphTimeData(nil).Value)
	})

	t.Run("never-set sentinel", func(t *testing.T) {
		sentinel := time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC)
		assert.Nil(t, graphTimeData(&sentinel).Value)
	})

	t.Run("zero value", func(t *testing.T) {
		var zero time.Time
		assert.Nil(t, graphTimeData(&zero).Value)
	})

	t.Run("year 1 with a time of day", func(t *testing.T) {
		offset := time.Date(1, 1, 1, 8, 0, 0, 0, time.UTC)
		assert.Nil(t, graphTimeData(&offset).Value)
	})

	t.Run("real timestamp", func(t *testing.T) {
		ts := time.Date(2026, 3, 2, 10, 0, 0, 0, time.UTC)
		res := graphTimeData(&ts)
		assert.Equal(t, types.Time, res.Type)
		got, ok := res.Value.(*time.Time)
		require.True(t, ok)
		assert.Equal(t, ts, *got)
	})

	t.Run("early but real timestamp", func(t *testing.T) {
		ts := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
		assert.NotNil(t, graphTimeData(&ts).Value)
	})
}
