// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"
)

// TestFlexTimeUnmarshalEdgeCases documents the corner behaviors of
// flexTime.UnmarshalJSON that the happy-path cases in TestFlexTimeUnmarshal do
// not exercise: the silent drop of unparseable strings, the fact that every
// numeric value is read as milliseconds (never seconds), and which malformed
// inputs propagate an error versus which are swallowed.
func TestFlexTimeUnmarshalEdgeCases(t *testing.T) {
	t.Run("unparseable string is silently dropped", func(t *testing.T) {
		var ft flexTime
		// NOTE: a non-RFC3339 string does NOT surface an error. time.Parse
		// fails, the error is discarded, and f.t is left nil -> Time()==nil.
		// The value is silently lost with no signal to the caller. This test
		// is the record of that behavior; it is a known wart, not a spec we
		// endorse.
		if err := json.Unmarshal([]byte(`"not-a-timestamp"`), &ft); err != nil {
			t.Fatalf("expected nil error on unparseable string (silent drop), got %v", err)
		}
		if got := ft.Time(); got != nil {
			t.Fatalf("expected nil time for unparseable string, got %v", got)
		}
	})

	t.Run("date-only string is dropped (not RFC3339)", func(t *testing.T) {
		var ft flexTime
		// "2021-01-01" lacks the time+offset RFC3339 requires, so it parses to
		// nothing and is silently dropped, same as any other unparseable string.
		if err := json.Unmarshal([]byte(`"2021-01-01"`), &ft); err != nil {
			t.Fatalf("expected nil error, got %v", err)
		}
		if got := ft.Time(); got != nil {
			t.Fatalf("expected nil time for date-only string, got %v", got)
		}
	})

	t.Run("numeric is always milliseconds, never seconds", func(t *testing.T) {
		var ft flexTime
		if err := json.Unmarshal([]byte(`1600000000`), &ft); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got := ft.Time()
		if got == nil {
			t.Fatalf("expected a time, got nil")
		}
		// NOTE: the code calls time.UnixMilli unconditionally. A 10-digit unix
		// *seconds* epoch (1600000000 == 2020-09-13) is therefore misread by a
		// factor of 1000, landing in Jan 1970 instead. flexTime has no way to
		// distinguish a seconds epoch from a millis epoch and always assumes
		// millis.
		want := time.UnixMilli(1600000000)
		if !got.Equal(want) {
			t.Fatalf("expected %v (millis interpretation), got %v", want, got)
		}
		if got.UTC().Year() != 1970 {
			t.Fatalf("expected a seconds epoch to be misread as 1970, got year %d", got.UTC().Year())
		}
	})

	t.Run("zero epoch decodes to the unix epoch", func(t *testing.T) {
		var ft flexTime
		if err := json.Unmarshal([]byte(`0`), &ft); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		got := ft.Time()
		if got == nil {
			t.Fatalf("expected a time, got nil")
		}
		// A literal 0 is a present value (0 ms since epoch), not absence, so it
		// is decoded rather than dropped.
		if !got.Equal(time.UnixMilli(0)) {
			t.Fatalf("expected unix epoch, got %v", got)
		}
	})

	t.Run("fractional number returns an error", func(t *testing.T) {
		var ft flexTime
		// Unlike the string path, a value that reaches the numeric branch and
		// fails to decode into int64 DOES propagate its error. So the swallowing
		// is specific to string parsing, not a blanket behavior.
		if err := json.Unmarshal([]byte(`1.5`), &ft); err == nil {
			t.Fatalf("expected an error for a fractional number, got nil (time=%v)", ft.Time())
		}
	})

	t.Run("array literal reaches the numeric branch and errors", func(t *testing.T) {
		var ft flexTime
		// The branch is chosen on the first byte being '"'. A '[' is not, so an
		// array is fed to the int64 decode and errors rather than being handled
		// as a list.
		if err := json.Unmarshal([]byte(`[1,2]`), &ft); err == nil {
			t.Fatalf("expected an error for an array literal, got nil (time=%v)", ft.Time())
		}
	})
}

// TestParseTargetsMalformed covers the inputs parseTargets cannot normalize.
// Every malformed shape collapses to nil rather than erroring, since the
// function has no error return.
func TestParseTargetsMalformed(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{name: "array of numbers", input: `[1,2,3]`},
		{name: "array of objects", input: `[{"a":1}]`},
		{name: "json object", input: `{"target":"production"}`},
		{name: "bare number", input: `42`},
		{name: "boolean", input: `true`},
		{name: "garbage", input: `not json`},
		{name: "whitespace only", input: `   `},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// NOTE: parseTargets silently returns nil for anything it can't
			// coerce to a string or []string; there is no error channel, so a
			// malformed target is indistinguishable from an absent one.
			if got := parseTargets(json.RawMessage(tt.input)); got != nil {
				t.Fatalf("expected nil for malformed input %q, got %#v", tt.input, got)
			}
		})
	}
}

// TestStoreConnectedToProject verifies the predicate that decides whether a
// store belongs to a given project id.
func TestStoreConnectedToProject(t *testing.T) {
	connected := &storeRecord{
		ProjectsMetadata: []storeProjectMetadata{
			{ProjectID: "prj_a"},
			{ProjectID: "prj_b"},
		},
	}

	tests := []struct {
		name      string
		rec       *storeRecord
		projectID string
		want      bool
	}{
		{name: "connected to first", rec: connected, projectID: "prj_a", want: true},
		{name: "connected to last", rec: connected, projectID: "prj_b", want: true},
		{name: "not connected", rec: connected, projectID: "prj_x", want: false},
		{name: "empty connections slice", rec: &storeRecord{ProjectsMetadata: []storeProjectMetadata{}}, projectID: "prj_a", want: false},
		{name: "nil connections slice", rec: &storeRecord{ProjectsMetadata: nil}, projectID: "prj_a", want: false},
		{name: "empty query does not match populated store", rec: connected, projectID: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := storeConnectedToProject(tt.rec, tt.projectID); got != tt.want {
				t.Fatalf("storeConnectedToProject(%q) = %v, want %v", tt.projectID, got, tt.want)
			}
		})
	}

	t.Run("empty query matches an entry with an empty project id", func(t *testing.T) {
		// NOTE: the predicate is a plain string equality with no special-casing
		// of the empty string, so an empty query id matches a metadata entry
		// whose ProjectID is also empty. Callers pass a real project id, so this
		// does not bite in practice, but it is the literal behavior.
		rec := &storeRecord{ProjectsMetadata: []storeProjectMetadata{{ProjectID: ""}}}
		if !storeConnectedToProject(rec, "") {
			t.Fatalf("expected empty-id entry to match empty query")
		}
	})
}
