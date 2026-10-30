// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"
)

func TestParseSnowflakeShowTimestamp(t *testing.T) {
	// nil cases: empty and unparseable input must return nil, never panic.
	for _, in := range []string{"", "   ", "not-a-timestamp", "2023-01-02"} {
		if got := parseSnowflakeShowTimestamp(in); got != nil {
			t.Errorf("parseSnowflakeShowTimestamp(%q) = %v, want nil", in, got)
		}
	}

	want := time.Date(2023, 1, 2, 15, 4, 5, 0, time.FixedZone("", -7*3600))
	valid := []string{
		"2023-01-02 15:04:05.000000000 -0700",
		"2023-01-02T15:04:05-07:00",
	}
	for _, in := range valid {
		got := parseSnowflakeShowTimestamp(in)
		if got == nil {
			t.Fatalf("parseSnowflakeShowTimestamp(%q) = nil, want a time", in)
		}
		if !got.Equal(want) {
			t.Errorf("parseSnowflakeShowTimestamp(%q) = %v, want %v", in, got, want)
		}
	}
}
