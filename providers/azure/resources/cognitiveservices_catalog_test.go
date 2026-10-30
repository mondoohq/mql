// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"
)

func TestParseModelDate(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	tests := []struct {
		name  string
		value *string
		want  string // RFC3339, or "" when the result must be nil
	}{
		{"date only", strPtr("2025-06-30"), "2025-06-30T00:00:00Z"},
		{"rfc3339", strPtr("2025-06-30T12:30:00Z"), "2025-06-30T12:30:00Z"},
		{"nil", nil, ""},
		{"empty", strPtr(""), ""},
		// An unparseable value must yield nil rather than a zero time: a zero time
		// would read as a retirement date in 1970 and make every deployment look
		// long expired.
		{"unparseable", strPtr("not-a-date"), ""},
		{"partial", strPtr("2025-06"), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseModelDate(tt.value)
			if tt.want == "" {
				if got != nil {
					t.Errorf("parseModelDate(%v) = %v, want nil", tt.value, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("parseModelDate(%v) = nil, want %s", *tt.value, tt.want)
			}
			if formatted := got.UTC().Format(time.RFC3339); formatted != tt.want {
				t.Errorf("parseModelDate(%v) = %s, want %s", *tt.value, formatted, tt.want)
			}
		})
	}
}
