// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// The workspace-conf endpoint returns every setting as a string and omits any
// key that was never explicitly set. The distinction between "absent" and
// "present but false" is what separates a null field from a hardening control
// that is genuinely off, so these parsers decide whether an audit reads a
// workspace as unconfigured or as insecure.

func TestConfBoolFrom(t *testing.T) {
	tests := []struct {
		name    string
		conf    map[string]string
		key     string
		wantNil bool
		want    bool
	}{
		{
			// Absent must stay null. Reporting false would claim the setting is
			// off when the workspace simply never set it.
			name:    "absent key is null",
			conf:    map[string]string{},
			key:     "enableTokensConfig",
			wantNil: true,
		},
		{name: "true", conf: map[string]string{"k": "true"}, key: "k", want: true},
		{name: "one is true", conf: map[string]string{"k": "1"}, key: "k", want: true},
		{name: "false", conf: map[string]string{"k": "false"}, key: "k", want: false},
		{name: "zero is false", conf: map[string]string{"k": "0"}, key: "k", want: false},
		{
			// Anything the endpoint returns that is not an accepted truthy form
			// reads as false rather than null, because the key was present.
			name: "unrecognized value is false, not null",
			conf: map[string]string{"k": "TRUE"},
			key:  "k",
			want: false,
		},
		{
			name: "empty value is false, not null",
			conf: map[string]string{"k": ""},
			key:  "k",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := confBoolFrom(tc.conf, tc.key)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("confBoolFrom() = %v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("confBoolFrom() = nil, want %v", tc.want)
			}
			if *got != tc.want {
				t.Fatalf("confBoolFrom() = %v, want %v", *got, tc.want)
			}
		})
	}
}

func TestConfIntFrom(t *testing.T) {
	tests := []struct {
		name    string
		conf    map[string]string
		key     string
		wantNil bool
		want    int64
	}{
		{
			name:    "absent key is null",
			conf:    map[string]string{},
			key:     "maxTokenLifetimeDays",
			wantNil: true,
		},
		{name: "positive", conf: map[string]string{"k": "90"}, key: "k", want: 90},
		{name: "zero", conf: map[string]string{"k": "0"}, key: "k", want: 0},
		{name: "negative", conf: map[string]string{"k": "-1"}, key: "k", want: -1},
		{
			// An unparseable value is null rather than zero. Zero would read as
			// a real limit of zero days, which is a materially different claim.
			name:    "unparseable value is null, not zero",
			conf:    map[string]string{"k": "unlimited"},
			key:     "k",
			wantNil: true,
		},
		{
			name:    "empty value is null",
			conf:    map[string]string{"k": ""},
			key:     "k",
			wantNil: true,
		},
		{
			name:    "overflow is null",
			conf:    map[string]string{"k": "99999999999999999999"},
			key:     "k",
			wantNil: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := confIntFrom(tc.conf, tc.key)
			if tc.wantNil {
				if got != nil {
					t.Fatalf("confIntFrom() = %v, want nil", *got)
				}
				return
			}
			if got == nil {
				t.Fatalf("confIntFrom() = nil, want %v", tc.want)
			}
			if *got != tc.want {
				t.Fatalf("confIntFrom() = %v, want %v", *got, tc.want)
			}
		})
	}
}
