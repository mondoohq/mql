// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalizeTriggerType(t *testing.T) {
	cases := map[string]string{
		"MSFT_TaskDailyTrigger":              "daily",
		"MSFT_TaskWeeklyTrigger":             "weekly",
		"MSFT_TaskMonthlyTrigger":            "monthly",
		"MSFT_TaskMonthlyDOWTrigger":         "monthlyDOW",
		"MSFT_TaskBootTrigger":               "boot",
		"MSFT_TaskLogonTrigger":              "logon",
		"MSFT_TaskRegistrationTrigger":       "registration",
		"MSFT_TaskTimeTrigger":               "time",
		"MSFT_TaskEventTrigger":              "event",
		"MSFT_TaskIdleTrigger":               "idle",
		"MSFT_TaskSessionStateChangeTrigger": "sessionStateChange",
		"":                                   "",
	}
	for in, want := range cases {
		assert.Equal(t, want, normalizeTriggerType(in), in)
	}
}

func TestParseWindowsTaskTime(t *testing.T) {
	// empty and never-ran sentinel both yield nil
	assert.Nil(t, parseWindowsTaskTime(""))
	assert.Nil(t, parseWindowsTaskTime("   "))
	assert.Nil(t, parseWindowsTaskTime("1899-11-30T00:00:00"))

	// CIM datetime string without timezone
	tm := parseWindowsTaskTime("2024-01-01T03:00:00")
	require.NotNil(t, tm)
	assert.Equal(t, 2024, tm.Year())
	assert.Equal(t, 3, tm.Hour())

	// round-trip ("o") formatted DateTime with offset
	tm = parseWindowsTaskTime("2024-03-10T07:00:00.0000000-07:00")
	require.NotNil(t, tm)
	assert.Equal(t, 2024, tm.Year())

	// legacy /Date(ms)/ form
	tm = parseWindowsTaskTime("/Date(1709044800000)/")
	require.NotNil(t, tm)
	assert.Equal(t, 2024, tm.Year())

	// unparseable input yields nil
	assert.Nil(t, parseWindowsTaskTime("not-a-date"))
}

func TestParseWindowsTaskTimeNeverRanSentinels(t *testing.T) {
	tests := []struct {
		name  string
		value string
	}{
		// The value the Task Scheduler 2.0 API reports for a task that has
		// never run. It is recent enough to clear a pre-1980 cutoff, so it
		// used to be returned as a real timestamp.
		{name: "modern API sentinel", value: "1999-11-30T00:00:00"},
		{name: "modern API sentinel, round-trip form", value: "1999-11-30T00:00:00.0000000"},
		{name: "modern API sentinel, RFC3339 UTC", value: "1999-11-30T00:00:00Z"},
		{name: "modern API sentinel, /Date(ms)/ form", value: "/Date(943920000000)/"},
		// The legacy API's sentinel, which the pre-1980 cutoff already caught.
		{name: "legacy API sentinel", value: "1899-12-30T00:00:00"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Nil(t, parseWindowsTaskTime(tt.value),
				"a task that has never run must report null, not a date an audit can compare against")
		})
	}
}

func TestParseWindowsTaskTimeKeepsRealRuns(t *testing.T) {
	// A real run on the day after the sentinel must survive: the guard is an
	// exact match on the sentinel instant, not a cutoff that swallows 1999.
	got := parseWindowsTaskTime("1999-12-01T00:00:00Z")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(1999, 12, 1, 0, 0, 0, 0, time.UTC), got.UTC())

	// The same date as the sentinel but a different time of day is a real run.
	got = parseWindowsTaskTime("1999-11-30T09:30:00Z")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(1999, 11, 30, 9, 30, 0, 0, time.UTC), got.UTC())

	got = parseWindowsTaskTime("2026-08-12T21:57:57Z")
	require.NotNil(t, got)
	assert.Equal(t, time.Date(2026, 8, 12, 21, 57, 57, 0, time.UTC), got.UTC())
}
