// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"testing"
)

func TestNormalizeSubdomain(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"bare subdomain", "mondoo", "mondoo"},
		{"uppercased", "MonDoo", "mondoo"},
		{"surrounding whitespace", "  mondoo  ", "mondoo"},
		{"full host", "mondoo.api.kandji.io", "mondoo"},
		{"full https url", "https://mondoo.api.kandji.io", "mondoo"},
		{"full url with trailing slash", "https://mondoo.api.kandji.io/", "mondoo"},
		{"url with path and query", "https://mondoo.api.kandji.io/api/v1?x=1", "mondoo"},
		{"http scheme", "http://mondoo.api.kandji.io", "mondoo"},
		{"empty", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeSubdomain(tt.in); got != tt.want {
				t.Errorf("normalizeSubdomain(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestKeyedMemo(t *testing.T) {
	var m keyedMemo[int]
	calls := 0

	// A failed fetch must not be cached.
	if _, err := m.get("k", func() (int, error) {
		calls++
		return 0, errors.New("boom")
	}); err == nil {
		t.Fatal("expected error from first fetch")
	}

	// Retry runs the fetch again (the error was not cached) and succeeds.
	if v, err := m.get("k", func() (int, error) {
		calls++
		return 42, nil
	}); err != nil || v != 42 {
		t.Fatalf("retry after error = (%d, %v), want (42, nil)", v, err)
	}

	// A subsequent hit is served from cache; the fetch does not run.
	if v, err := m.get("k", func() (int, error) {
		calls++
		return -1, nil
	}); err != nil || v != 42 {
		t.Fatalf("cached get = (%d, %v), want (42, nil)", v, err)
	}

	if calls != 2 {
		t.Errorf("fetch ran %d times, want 2 (fail + success; the cached hit must not refetch)", calls)
	}

	// A different key is independent and fetches on its own.
	if v, err := m.get("other", func() (int, error) {
		calls++
		return 7, nil
	}); err != nil || v != 7 {
		t.Fatalf("independent key = (%d, %v), want (7, nil)", v, err)
	}
}

func TestAPIURLFromSubdomain(t *testing.T) {
	if got, want := apiURLFromSubdomain("mondoo"), "https://mondoo.api.kandji.io"; got != want {
		t.Errorf("apiURLFromSubdomain(mondoo) = %q, want %q", got, want)
	}
}
