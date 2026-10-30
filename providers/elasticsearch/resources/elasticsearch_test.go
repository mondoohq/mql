// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"
)

func TestJSONHasContent(t *testing.T) {
	// No restriction: absent, null, and the empty forms Elasticsearch returns
	// for field_security ({}) and query ("").
	noRestriction := []struct {
		raw   string
		empty []string
	}{
		{"", []string{"{}"}},
		{"null", []string{"{}"}},
		{"{}", []string{"{}"}},
		{"  {}  ", []string{"{}"}},
		{`""`, []string{`""`}},
		{"null", []string{`""`}},
	}
	for _, c := range noRestriction {
		if jsonHasContent(json.RawMessage(c.raw), c.empty...) {
			t.Errorf("jsonHasContent(%q) = true, want false (no restriction)", c.raw)
		}
	}

	// Real restrictions must read as present.
	restriction := []struct {
		raw   string
		empty []string
	}{
		{`{"grant":["message"]}`, []string{"{}"}},
		{`{"term":{"dept":"eng"}}`, []string{`""`}},
	}
	for _, c := range restriction {
		if !jsonHasContent(json.RawMessage(c.raw), c.empty...) {
			t.Errorf("jsonHasContent(%q) = false, want true (has restriction)", c.raw)
		}
	}
}

func TestEpochMillisToTime(t *testing.T) {
	// A known epoch-ms value round-trips to the expected UTC time.
	got := epochMillisToTime(1786127942579)
	want := time.UnixMilli(1786127942579).UTC()
	if !got.Equal(want) {
		t.Errorf("epochMillisToTime = %v, want %v", got, want)
	}
	// Zero and negative values yield the zero time (never-expires / unset).
	if !epochMillisToTime(0).IsZero() {
		t.Error("epochMillisToTime(0) should be the zero time")
	}
	if !epochMillisToTime(-1).IsZero() {
		t.Error("epochMillisToTime(-1) should be the zero time")
	}
}

func TestIsReserved(t *testing.T) {
	if !isReserved(map[string]any{"_reserved": true}) {
		t.Error("_reserved:true should be reserved")
	}
	if isReserved(map[string]any{"_reserved": false}) {
		t.Error("_reserved:false should not be reserved")
	}
	if isReserved(map[string]any{}) {
		t.Error("absent _reserved should not be reserved")
	}
	if isReserved(nil) {
		t.Error("nil metadata should not be reserved")
	}
	// A non-bool _reserved must not panic and must be treated as not reserved.
	if isReserved(map[string]any{"_reserved": "yes"}) {
		t.Error("non-bool _reserved should not be reserved")
	}
}

func TestToStringSlice(t *testing.T) {
	got := toStringSlice([]string{"a", "b"})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("toStringSlice = %v", got)
	}
	// Never nil, so llx.ArrayData receives a real slice.
	if got := toStringSlice(nil); got == nil || len(got) != 0 {
		t.Errorf("toStringSlice(nil) = %v, want empty non-nil", got)
	}
}
