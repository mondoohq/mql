// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestTime_Conversions(t *testing.T) {
	mtime := mqlTime{}
	t.Run("back and forth duration (1 hour)", func(t *testing.T) {
		hour, err := mtime.hour()
		require.NoError(t, err)
		assert.Equal(t, llx.DurationToTime(60*60), *hour, "time.hour returns an hour in time")

		rd := llx.TimeData(*hour)
		res := rd.Result()
		require.Empty(t, res.Error, "no error converting raw data to a primitive")
		back := res.Data.RawData()
		assert.Equal(t, hour, back.Value, "time.hour converts values to primitive and back and remains the same")
		assert.Equal(t, llx.DurationToTime(60*60), *(back.Value.(*time.Time)), "time.hour after conversion to primitive and back is still an hour")
	})

	t.Run("back and forth duration (1sec)", func(t *testing.T) {
		second, err := mtime.second()
		require.NoError(t, err)
		assert.Equal(t, llx.DurationToTime(1), *second, "time.second returns a second in time")

		rd := llx.TimeData(*second)
		res := rd.Result()
		require.Empty(t, res.Error, "no error converting raw data to a primitive")
		back := res.Data.RawData()
		assert.Equal(t, second, back.Value, "time.second converts values to primitive and back and remains the same")
		assert.Equal(t, llx.DurationToTime(1), *(back.Value.(*time.Time)), "time.second after conversion to primitive and back is still a second")
	})
}
