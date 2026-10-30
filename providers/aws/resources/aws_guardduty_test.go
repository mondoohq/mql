// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseAwsTimestamp(t *testing.T) {
	t.Run("RFC3339 with Z suffix", func(t *testing.T) {
		ts := parseAwsTimestamp("2026-04-09T05:40:04Z")
		require.NotNil(t, ts)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, time.April, ts.Month())
		assert.Equal(t, 9, ts.Day())
		assert.Equal(t, 5, ts.Hour())
		assert.Equal(t, 40, ts.Minute())
		assert.Equal(t, 4, ts.Second())
		assert.Equal(t, time.UTC, ts.Location())
	})

	t.Run("RFC3339 with timezone offset", func(t *testing.T) {
		ts := parseAwsTimestamp("2026-04-09T05:40:04+00:00")
		require.NotNil(t, ts)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, 5, ts.Hour())
	})

	t.Run("timestamp without timezone (e.g. EC2 Verified Access)", func(t *testing.T) {
		ts := parseAwsTimestamp("2026-04-09T05:40:04")
		require.NotNil(t, ts)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, time.April, ts.Month())
		assert.Equal(t, 9, ts.Day())
		assert.Equal(t, 5, ts.Hour())
		assert.Equal(t, 40, ts.Minute())
		assert.Equal(t, 4, ts.Second())
		assert.Equal(t, time.UTC, ts.Location())
	})

	t.Run("empty string returns nil", func(t *testing.T) {
		ts := parseAwsTimestamp("")
		assert.Nil(t, ts)
	})

	t.Run("garbage string returns nil", func(t *testing.T) {
		ts := parseAwsTimestamp("not-a-timestamp")
		assert.Nil(t, ts)
	})

	t.Run("timestamp with non-RFC3339 timezone offset +0000 (e.g. Lambda layers)", func(t *testing.T) {
		ts := parseAwsTimestamp("2026-04-12T18:11:01.019+0000")
		require.NotNil(t, ts)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, time.April, ts.Month())
		assert.Equal(t, 12, ts.Day())
		assert.Equal(t, 18, ts.Hour())
		assert.Equal(t, 11, ts.Minute())
		assert.Equal(t, 1, ts.Second())
	})

	t.Run("timestamp with non-RFC3339 negative timezone offset", func(t *testing.T) {
		ts := parseAwsTimestamp("2026-04-12T11:11:01.019-0700")
		require.NotNil(t, ts)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, 11, ts.Hour())
	})

	t.Run("timestamp with milliseconds and Z suffix", func(t *testing.T) {
		ts := parseAwsTimestamp("2026-04-12T18:11:01.019Z")
		require.NotNil(t, ts)
		assert.Equal(t, 18, ts.Hour())
		assert.Equal(t, 11, ts.Minute())
	})
}

func TestParseAwsTimestampPtr(t *testing.T) {
	t.Run("nil input returns nil", func(t *testing.T) {
		ts := parseAwsTimestampPtr(nil)
		assert.Nil(t, ts)
	})

	t.Run("valid RFC3339 string pointer", func(t *testing.T) {
		s := "2026-04-09T12:00:00Z"
		ts := parseAwsTimestampPtr(&s)
		require.NotNil(t, ts)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, 12, ts.Hour())
	})

	t.Run("timestamp without timezone via pointer", func(t *testing.T) {
		s := "2026-04-10T05:51:33"
		ts := parseAwsTimestampPtr(&s)
		require.NotNil(t, ts)
		assert.Equal(t, 2026, ts.Year())
		assert.Equal(t, time.April, ts.Month())
		assert.Equal(t, 10, ts.Day())
		assert.Equal(t, 5, ts.Hour())
		assert.Equal(t, 51, ts.Minute())
		assert.Equal(t, 33, ts.Second())
		assert.Equal(t, time.UTC, ts.Location())
	})
}

// TestParseGuardDutyTimestamp pins the regression that made every GuardDuty
// member report 1970-01-01: fmt.Sscanf(s, "%f", ...) does not have to consume
// its whole input, so an ISO-8601 string parsed as the bare year 2023 and was
// then read as an epoch second.
func TestParseGuardDutyTimestamp(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("ISO-8601 is parsed as a real date, not epoch seconds", func(t *testing.T) {
		got := parseGuardDutyTimestamp(strPtr("2023-01-19T20:31:32.152Z"))
		require.NotNil(t, got)
		assert.Equal(t, 2023, got.UTC().Year())
		assert.Equal(t, time.January, got.UTC().Month())
		assert.Equal(t, 19, got.UTC().Day())
	})

	t.Run("epoch seconds are still accepted", func(t *testing.T) {
		got := parseGuardDutyTimestamp(strPtr("1674160292"))
		require.NotNil(t, got)
		assert.Equal(t, 2023, got.UTC().Year())
	})

	t.Run("nil and empty yield nil", func(t *testing.T) {
		assert.Nil(t, parseGuardDutyTimestamp(nil))
		assert.Nil(t, parseGuardDutyTimestamp(strPtr("")))
	})

	t.Run("unparseable input yields nil rather than a bogus date", func(t *testing.T) {
		assert.Nil(t, parseGuardDutyTimestamp(strPtr("not-a-timestamp")))
	})
}

// TestParseAwsTimestampLayouts walks every layout the helper accepts, one case
// per entry in awsTimestampLayouts. The "+0000" form without fractional
// seconds is the one Lambda provisioned concurrency returns; before it was
// added, the layout ahead of it demanded a fractional part, every other layout
// rejected the offset, and lastModified read null on every provisioned
// concurrency config in every account.
func TestParseAwsTimestampLayouts(t *testing.T) {
	for _, tc := range []struct {
		name   string
		input  string
		hour   int
		minute int
		second int
		// offsetSeconds is the zone offset the parsed value must carry.
		offsetSeconds int
	}{
		{
			name:   "RFC3339",
			input:  "2026-08-31T20:11:24Z",
			hour:   20,
			minute: 11,
			second: 24,
		},
		{
			name:   "numeric offset with fractional seconds",
			input:  "2026-08-31T20:11:24.019+0000",
			hour:   20,
			minute: 11,
			second: 24,
		},
		{
			name:   "numeric offset without fractional seconds",
			input:  "2026-08-31T20:11:24+0000",
			hour:   20,
			minute: 11,
			second: 24,
		},
		{
			name:          "negative numeric offset without fractional seconds",
			input:         "2026-08-31T13:11:24-0700",
			hour:          13,
			minute:        11,
			second:        24,
			offsetSeconds: -7 * 60 * 60,
		},
		{
			name:   "no timezone",
			input:  "2026-08-31T20:11:24",
			hour:   20,
			minute: 11,
			second: 24,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ts := parseAwsTimestamp(tc.input)
			require.NotNil(t, ts, "layout for %q must parse", tc.input)
			assert.Equal(t, 2026, ts.Year())
			assert.Equal(t, time.August, ts.Month())
			assert.Equal(t, 31, ts.Day())
			assert.Equal(t, tc.hour, ts.Hour())
			assert.Equal(t, tc.minute, ts.Minute())
			assert.Equal(t, tc.second, ts.Second())

			_, offset := ts.Zone()
			assert.Equal(t, tc.offsetSeconds, offset)

			// Every case above names the same instant, so they must all
			// normalize to the same UTC time.
			assert.Equal(t, "2026-08-31T20:11:24Z", ts.UTC().Format(time.RFC3339))
		})
	}
}

// TestParseAwsTimestampRejectsGarbage pins that widening the layout list did
// not turn the helper into something that accepts anything.
func TestParseAwsTimestampRejectsGarbage(t *testing.T) {
	for _, input := range []string{
		"",
		"not-a-timestamp",
		"2026-08-31",
		"2026-08-31 20:11:24",
		"2026-08-31T20:11:24+00",
	} {
		assert.Nil(t, parseAwsTimestamp(input), "must not parse %q", input)
	}
}
