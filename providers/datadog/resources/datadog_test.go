// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"testing"
	"time"
)

func TestEpochMillisToTimePtr(t *testing.T) {
	// 1_700_000_000_000 ms == 2023-11-14T22:13:20Z. Parsing this value as
	// seconds (the bug this helper fixes) would land in the year ~55871.
	ms := int64(1_700_000_000_000)
	got := epochMillisToTimePtr(ms)
	if got == nil {
		t.Fatal("expected non-nil time for a non-zero millisecond timestamp")
	}
	if y := got.UTC().Year(); y != 2023 {
		t.Fatalf("expected year 2023, got %d (millisecond value likely parsed as seconds)", y)
	}
	if !got.Equal(time.UnixMilli(ms)) {
		t.Fatalf("expected %v, got %v", time.UnixMilli(ms), *got)
	}
}

func TestEpochMillisToTimePtr_Zero(t *testing.T) {
	if got := epochMillisToTimePtr(0); got != nil {
		t.Fatalf("expected nil for a zero (unset) timestamp, got %v", *got)
	}
}

func TestEpochSecondsToTimePtr(t *testing.T) {
	// 1_700_000_000 s == 2023-11-14T22:13:20Z.
	sec := int64(1_700_000_000)
	got := epochSecondsToTimePtr(sec)
	if got == nil {
		t.Fatal("expected non-nil time for a non-zero seconds timestamp")
	}
	if y := got.UTC().Year(); y != 2023 {
		t.Fatalf("expected year 2023, got %d", y)
	}
	if !got.Equal(time.Unix(sec, 0)) {
		t.Fatalf("expected %v, got %v", time.Unix(sec, 0), *got)
	}
}

func TestEpochSecondsToTimePtr_Zero(t *testing.T) {
	if got := epochSecondsToTimePtr(0); got != nil {
		t.Fatalf("expected nil for a zero (unset) timestamp, got %v", *got)
	}
}

// TestEpochUnitsDiverge documents why the seconds vs milliseconds distinction
// matters: the same numeric value interpreted as seconds vs milliseconds yields
// timestamps thousands of years apart.
func TestEpochUnitsDiverge(t *testing.T) {
	v := int64(1_700_000_000_000)
	asMillis := epochMillisToTimePtr(v)
	asSeconds := epochSecondsToTimePtr(v)
	if asMillis.UTC().Year() == asSeconds.UTC().Year() {
		t.Fatal("expected millisecond and second interpretations to differ")
	}
	if asSeconds.UTC().Year() < 50000 {
		t.Fatalf("expected the seconds interpretation of a millisecond value to be far in the future, got year %d", asSeconds.UTC().Year())
	}
}

func TestTimePtr(t *testing.T) {
	if got := timePtr(time.Time{}); got != nil {
		t.Fatalf("expected nil for the zero time, got %v", *got)
	}
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	got := timePtr(now)
	if got == nil || !got.Equal(now) {
		t.Fatalf("expected %v, got %v", now, got)
	}
}

func TestParseTime(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
	}{
		{"empty", "", true},
		{"invalid", "not-a-timestamp", true},
		{"valid RFC3339", "2024-01-02T03:04:05Z", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := parseTime(tc.input)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", *got)
				}
				return
			}
			if got == nil {
				t.Fatal("expected non-nil time")
			}
			want, _ := time.Parse(time.RFC3339, tc.input)
			if !got.Equal(want) {
				t.Fatalf("expected %v, got %v", want, *got)
			}
		})
	}
}

func TestToAnyStrings(t *testing.T) {
	got := toAnyStrings([]string{"a", "b", "c"})
	if len(got) != 3 {
		t.Fatalf("expected len 3, got %d", len(got))
	}
	for i, want := range []string{"a", "b", "c"} {
		if got[i].(string) != want {
			t.Fatalf("index %d: expected %q, got %v", i, want, got[i])
		}
	}

	// A nil slice must produce a non-nil, empty result so it serializes as an
	// empty array rather than null.
	empty := toAnyStrings(nil)
	if empty == nil {
		t.Fatal("expected non-nil slice for nil input")
	}
	if len(empty) != 0 {
		t.Fatalf("expected empty slice, got len %d", len(empty))
	}
}

func TestIsForbidden(t *testing.T) {
	if isForbidden(nil) {
		t.Fatal("expected false for a nil response")
	}
	if isForbidden(&http.Response{StatusCode: http.StatusOK}) {
		t.Fatal("expected false for a 200 response")
	}
	if !isForbidden(&http.Response{StatusCode: http.StatusForbidden}) {
		t.Fatal("expected true for a 403 response")
	}
}
