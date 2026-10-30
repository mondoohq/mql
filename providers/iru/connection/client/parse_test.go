// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package client

import "testing"

func TestParseTime(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		wantNil bool
		wantY   int
	}{
		{"empty", "", true, 0},
		{"whitespace", "   ", true, 0},
		{"garbage", "not a time", true, 0},
		{"rfc3339nano Z", "2026-07-22T18:07:24.422285Z", false, 2026},
		{"rfc3339", "2026-07-22T18:07:24Z", false, 2026},
		{"space + colon offset (device detail)", "2026-02-18 14:42:04.395339+00:00", false, 2026},
		{"space + colon offset no micros", "2026-02-18 14:42:04+00:00", false, 2026},
		{"space + spaced offset (profiles)", "2026-02-18 14:42:41 +0000", false, 2026},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ParseTime(tt.in)
			if tt.wantNil {
				if got != nil {
					t.Fatalf("ParseTime(%q) = %v, want nil", tt.in, got)
				}
				return
			}
			if got == nil {
				t.Fatalf("ParseTime(%q) = nil, want a time", tt.in)
			}
			if got.Year() != tt.wantY {
				t.Errorf("ParseTime(%q).Year() = %d, want %d", tt.in, got.Year(), tt.wantY)
			}
		})
	}
}

func TestParseBool(t *testing.T) {
	truthy := []string{"True", "true", "TRUE", "Yes", "yes", "enabled", "on", "1", "  True  "}
	falsy := []string{"False", "false", "No", "no", "disabled", "", "0", "maybe"}
	for _, s := range truthy {
		if !ParseBool(s) {
			t.Errorf("ParseBool(%q) = false, want true", s)
		}
	}
	for _, s := range falsy {
		if ParseBool(s) {
			t.Errorf("ParseBool(%q) = true, want false", s)
		}
	}
}

func TestParseInt(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"10", 10},
		{" 1 ", 1},
		{"0", 0},
		{"", 0},
		{"32 GB", 0}, // non-numeric memory string does not partially parse
		{"-5", -5},
	}
	for _, tt := range tests {
		if got := ParseInt(tt.in); got != tt.want {
			t.Errorf("ParseInt(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}

func TestParseIntOK(t *testing.T) {
	tests := []struct {
		in     string
		want   int64
		wantOK bool
	}{
		{"10", 10, true},
		{"", 0, true},          // absent value, not a failure
		{"  ", 0, true},        // whitespace-only, treated as absent
		{"32 GB", 0, false},    // genuinely non-numeric
		{"No value", 0, false}, // Kandji sometimes emits this literal
	}
	for _, tt := range tests {
		got, ok := ParseIntOK(tt.in)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("ParseIntOK(%q) = (%d, %v), want (%d, %v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestParseMemoryBytes(t *testing.T) {
	tests := []struct {
		in   string
		want int64
	}{
		{"32 GB LPDDR5", 32 << 30},
		{"16 GB", 16 << 30},
		{"512 MB", 512 << 20},
		{"1 TB", 1 << 40},
		{"", 0},
		{"32GB", 0},  // no separating space, no recognizable unit token
		{"lots", 0},  // non-numeric
		{"8 GiB", 0}, // unrecognized unit spelling
	}
	for _, tt := range tests {
		if got := ParseMemoryBytes(tt.in); got != tt.want {
			t.Errorf("ParseMemoryBytes(%q) = %d, want %d", tt.in, got, tt.want)
		}
	}
}
