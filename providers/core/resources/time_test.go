// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"math"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

func duration(i int64) *time.Time {
	res := llx.DurationToTime(i)
	return &res
}

func TestFuzzyTime(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	code := "time.now.unix"
	t.Run(code, func(t *testing.T) {
		res := x.TestQuery(t, code)
		now := time.Now().Unix()
		assert.NotEmpty(t, res)

		assert.NotNil(t, res[0].Result().Error)
		val := res[0].Data.Value
		valInt, ok := val.(int64)
		assert.Equal(t, true, ok)
		min := now - 1
		max := now + 1
		between := min <= valInt && valInt <= max
		assert.Equal(t, true, between)
	})
}

func TestTimeParsing(t *testing.T) {
	parserTimestamp := int64(1136214245)

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.date('0000-01-01T02:03:04Z').seconds",
			Expectation: int64(4 + 3*60 + 2*60*60),
		},
		{
			Code:        "parse.date('0000-01-01T02:03:04Z').minutes",
			Expectation: int64(3 + 2*60),
		},
		{
			Code:        "parse.date('0000-01-01T02:03:04Z').hours",
			Expectation: int64(2),
		},
		{
			Code:        "parse.date('0000-01-11T02:03:04Z').days",
			Expectation: int64(10),
		},
		{
			Code:        "parse.date('1970-01-01T01:02:03Z').unix",
			Expectation: int64(1*60*60 + 0o2*60 + 0o3),
		},
		{
			Code:        "parse.date('1970-01-01T01:02:04Z') - parse.date('1970-01-01T01:02:03Z')",
			Expectation: duration(1),
		},
		{
			Code:        "parse.date('0000-01-01T00:00:03Z') * 3",
			Expectation: duration(9),
		},
		// Testing all the default parsers
		{
			Code:        "parse.date('2006-01-02T15:04:05Z').unix",
			Expectation: parserTimestamp,
		},
		{
			Code:        "parse.date('2006-01-02 15:04:05').unix",
			Expectation: parserTimestamp,
		},
		{
			Code:        "parse.date('2006-01-02').unix",
			Expectation: parserTimestamp - (15*60*60 + 4*60 + 5),
		},
		{
			Code:        "parse.date('15:04:05').unix",
			Expectation: duration(15*60*60 + 4*60 + 5).Unix(),
		},
		{
			Code:        "parse.date('Mon, 02 Jan 2006 15:04:05 MST').unix",
			Expectation: parserTimestamp,
		},
		{
			Code:        "parse.date('Mon Jan 2 15:04:05 2006').unix",
			Expectation: parserTimestamp,
		},
		{
			Code:        "parse.date('02 Jan 06 15:04 MST').unix",
			Expectation: parserTimestamp - 5, // since it doesn't have seconds
		},
		{
			Code:        "parse.date('Monday, 02-Jan-06 15:04:05 MST').unix",
			Expectation: parserTimestamp,
		},
		{
			Code:        "parse.date('3:04PM').unix",
			Expectation: duration(15*60*60 + 4*60).Unix(),
		},
		{
			Code:        "parse.date('Jan 2 15:04:05').unix",
			Expectation: duration(1*24*60*60 + 15*60*60 + 4*60 + 5).Unix(),
		},
	})

	parserTimestampTZ := int64(1136239445)
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.date('Mon, 02 Jan 2006 15:04:05 -0700').unix",
			Expectation: parserTimestampTZ,
		},
		{
			Code:        "parse.date('02 Jan 06 15:04 -0700').unix",
			Expectation: parserTimestampTZ - 5, // since it doesn't have seconds
		},
	})
}

func TestTime_Methods(t *testing.T) {
	now := time.Now()
	today, _ := time.ParseInLocation("2006-01-02", now.Format("2006-01-02"), now.Location())
	tomorrow := today.Add(24 * time.Hour)

	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "time.now > time.today",
			ResultIndex: 2,
			Expectation: true,
		},
		{
			Code:        "time.today",
			Expectation: &today,
		},
		{
			Code:        "time.tomorrow",
			Expectation: &tomorrow,
		},
		{
			Code:        "time.hour",
			Expectation: duration(60 * 60),
		},
		{
			Code:        "2*time.hour + 1*time.hour",
			Expectation: duration(3 * 60 * 60),
		},
		{
			Code:        "time.today + 1*time.day",
			Expectation: &tomorrow,
		},
		{
			Code:        "2*time.hour - 1*time.hour",
			Expectation: duration(60 * 60),
		},
		{
			Code:        "3 * time.second",
			Expectation: duration(3),
		},
		{
			Code:        "3 * time.minute",
			Expectation: duration(3 * 60),
		},
		{
			Code:        "3 * time.hour",
			Expectation: duration(3 * 60 * 60),
		},
		{
			Code:        "3 * time.day",
			Expectation: duration(3 * 60 * 60 * 24),
		},
		{
			Code:        "1 * time.day > 3 * time.hour",
			ResultIndex: 2, Expectation: true,
		},
		{
			Code:        "time.now != Never",
			ResultIndex: 2, Expectation: true,
		},
		{
			Code:        "time.now - Never",
			Expectation: &llx.NeverPastTime,
		},
		{
			Code:        "Never - time.now",
			Expectation: &llx.NeverFutureTime,
		},
		{
			Code:        "Never - Never",
			Expectation: &llx.NeverPastTime,
		},
		{
			Code:        "Never * 3",
			Expectation: &llx.NeverFutureTime,
		},
		{
			Code:        "a = Never - time.now; a.days",
			Expectation: int64(math.MaxInt64),
		},
	})
}
