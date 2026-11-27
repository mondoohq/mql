// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/fastly/go-fastly/v10/fastly"
)

// TestTLSDomainNames extracts hostnames from TLS domain relations. Synthetic:
// no target showed this; the nil-element case guards convert-style panics on a
// relation the API left sparse.
func TestTLSDomainNames(t *testing.T) {
	tests := []struct {
		name    string
		domains []*fastly.TLSDomain
		want    []string
	}{
		{
			name:    "nil list",
			domains: nil,
			want:    []string{},
		},
		{
			name:    "names, with a nil element skipped",
			domains: []*fastly.TLSDomain{{ID: "www.example.com"}, nil, {ID: "api.example.com"}},
			want:    []string{"www.example.com", "api.example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tlsDomainNames(tc.domains)
			if len(got) != len(tc.want) {
				t.Fatalf("len = %d (%v), want %d (%v)", len(got), got, len(tc.want), tc.want)
			}
			for i := range tc.want {
				if got[i] != tc.want[i] {
					t.Errorf("[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}
