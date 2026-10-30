// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"
	"time"
)

func TestFlexTimeUnmarshal(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantNil bool
		wantMs  int64
	}{
		{name: "epoch millis", input: `1600000000000`, wantMs: 1600000000000},
		{name: "rfc3339 string", input: `"2021-01-01T00:00:00Z"`, wantMs: time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()},
		{name: "json null", input: `null`, wantNil: true},
		{name: "empty string", input: `""`, wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ft flexTime
			if err := json.Unmarshal([]byte(tt.input), &ft); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			got := ft.Time()
			if tt.wantNil {
				if got != nil {
					t.Fatalf("expected nil, got %v", got)
				}
				return
			}
			if got == nil {
				t.Fatalf("expected time, got nil")
			}
			if got.UnixMilli() != tt.wantMs {
				t.Fatalf("expected %d ms, got %d ms", tt.wantMs, got.UnixMilli())
			}
		})
	}
}

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "array", input: `["production","preview"]`, want: []string{"production", "preview"}},
		{name: "single string", input: `"production"`, want: []string{"production"}},
		{name: "null", input: `null`, want: nil},
		{name: "empty string", input: `""`, want: nil},
		{name: "empty array", input: `[]`, want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseTargets(json.RawMessage(tt.input))
			if len(got) != len(tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, got)
			}
			for i := range tt.want {
				if got[i] != tt.want[i] {
					t.Fatalf("index %d: expected %q, got %q", i, tt.want[i], got[i])
				}
			}
		})
	}
}

func TestLogHeadersUnmarshal(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "list of headers", input: `["x-api-key","user-agent"]`, want: []string{"x-api-key", "user-agent"}},
		{name: "wildcard records every header", input: `"*"`, want: []string{"*"}},
		{name: "null", input: `null`, want: nil},
		{name: "empty array", input: `[]`, want: []string{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var lh logHeaders
			if err := json.Unmarshal([]byte(tt.input), &lh); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if len(lh.values) != len(tt.want) {
				t.Fatalf("expected %v, got %v", tt.want, lh.values)
			}
			for i := range tt.want {
				if lh.values[i] != tt.want[i] {
					t.Fatalf("index %d: expected %q, got %q", i, tt.want[i], lh.values[i])
				}
			}
		})
	}
}

func TestExpirationRecordDecodesRetentionPolicy(t *testing.T) {
	// The same shape is returned as a team default and as a project policy, so
	// one decoder serves both; absent fields must stay zero rather than error.
	var exp expirationRecord
	if err := json.Unmarshal([]byte(`{"expirationDays":30,"deploymentsToKeep":3}`), &exp); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if intPtrOrZero(exp.ExpirationDays) != 30 {
		t.Errorf("expirationDays: expected 30, got %d", intPtrOrZero(exp.ExpirationDays))
	}
	if intPtrOrZero(exp.DeploymentsToKeep) != 3 {
		t.Errorf("deploymentsToKeep: expected 3, got %d", intPtrOrZero(exp.DeploymentsToKeep))
	}
	if intPtrOrZero(exp.ExpirationDaysProduction) != 0 {
		t.Errorf("absent expirationDaysProduction should be 0, got %d", intPtrOrZero(exp.ExpirationDaysProduction))
	}
}

func TestDictOrNilPreservesAbsence(t *testing.T) {
	// An absent object must stay null so a policy can tell "not configured"
	// apart from "configured empty".
	if got := dictOrNil(nil); got != nil {
		t.Errorf("expected nil for an absent object, got %v", got)
	}
	if got := dictOrNil(map[string]any{}); got == nil {
		t.Error("expected an empty object to survive as non-nil")
	}
}

func TestFirewallRuleAction(t *testing.T) {
	tests := []struct {
		name  string
		input any
		want  string
	}{
		{name: "plain string", input: "deny", want: "deny"},
		{name: "nested mitigate", input: map[string]any{"mitigate": map[string]any{"action": "deny"}}, want: "deny"},
		{name: "flat action", input: map[string]any{"action": "log"}, want: "log"},
		{name: "unknown shape", input: map[string]any{"foo": "bar"}, want: ""},
		{name: "nil", input: nil, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := firewallRuleAction(tt.input); got != tt.want {
				t.Fatalf("expected %q, got %q", tt.want, got)
			}
		})
	}
}
