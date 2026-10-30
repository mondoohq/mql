// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

func TestParse_Date(t *testing.T) {
	simpleDate, err := time.Parse("2006-01-02", "2023-12-23")
	if err != nil {
		panic("cannot parse time needed for testing")
	}

	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.date('2023-12-23T00:00:00Z')",
			ResultIndex: 0,
			Expectation: &simpleDate,
		},
		{
			Code:        "parse.date('2023/12/23', '2006/01/02')",
			ResultIndex: 0,
			Expectation: &simpleDate,
		},
		{
			Code:        "parse.date('Mon Dec 23 00:00:00 2023', 'ansic')",
			ResultIndex: 0,
			Expectation: &simpleDate,
		},
		{
			Code:        "parse.date('2023-12-23T00:00:00Z', 'rfc3339')",
			ResultIndex: 0,
			Expectation: &simpleDate,
		},
		{
			Code:        "parse.date('2023-12-23T00:00:00Z', 'RFC3339')", // ensure the format finding is case-insensitive
			ResultIndex: 0,
			Expectation: &simpleDate,
		},
	})
}

func TestParse_DateError(t *testing.T) {
	tests := []testutils.SimpleTest{
		{
			Code:        "parse.date('2023-12-23T00:00:00Z', 1234)", // handle invalid format
			ResultIndex: 0,
			Expectation: "failed to compile code: Incorrect type on argument 1 in parse.date: expected string, got: int",
		},
		{
			Code:        "parse.date(123456)", // handle invalid timestamp format
			ResultIndex: 0,
			Expectation: "failed to compile code: Incorrect type on argument 0 in parse.date: expected string, got: int",
		},
		{
			Code:        "dict = { 'x': 'y'}; parse.date(dict)", // handle invalid input that is a dict
			ResultIndex: 0,
			Expectation: "failed to compile code: Incorrect type on argument 0 in parse.date: expected string, got: map[string]string",
		},
		{
			Code:        "parse.date(mondoo.jobEnvironment)", // handle invalid input that is a dict and cannot be handled during compile time
			ResultIndex: 0,
			Expectation: "failed to parse time, timestamp needs to be a string",
		},
	}
	for i := range tests {
		cur := tests[i]
		t.Run(cur.Code, func(t *testing.T) {
			res, err := x.TestQueryPWithError(t, cur.Code, mqlc.EmptyPropsHandler)
			var errMsg string
			if err != nil {
				errMsg = err.Error()
			}
			if res != nil && res[0].Data.Error != nil {
				errMsg = res[0].Data.Error.Error()
			}
			assert.Equal(t, cur.Expectation, errMsg)
		})
	}
}

func TestParse_Duration(t *testing.T) {
	twoSecs := llx.DurationToTime(2)
	tenMin := llx.DurationToTime(10 * 60)
	threeHours := llx.DurationToTime(3 * 60 * 60)
	thirtyDays := llx.DurationToTime(30 * 60 * 60 * 24)
	sevenYears := llx.DurationToTime(7 * 60 * 60 * 24 * 365)
	x.TestSimple(t, []testutils.SimpleTest{
		{
			Code:        "parse.duration('2')",
			ResultIndex: 0,
			Expectation: &twoSecs,
		},
		{
			Code:        "parse.duration('2seconds')",
			ResultIndex: 0,
			Expectation: &twoSecs,
		},
		{
			Code:        "parse.duration('10min')",
			ResultIndex: 0,
			Expectation: &tenMin,
		},
		{
			Code:        "parse.duration('3h')",
			ResultIndex: 0,
			Expectation: &threeHours,
		},
		{
			Code:        "parse.duration('30day')",
			ResultIndex: 0,
			Expectation: &thirtyDays,
		},
		{
			Code:        "parse.duration('7y')",
			ResultIndex: 0,
			Expectation: &sevenYears,
		},
	})
}
