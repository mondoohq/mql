// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "testing"

// TestPaginateAll walks the page-numbered TLS endpoints. Synthetic: no target
// showed this; the cases cover the accumulation and the short-page stop that a
// truncation bug would get wrong.
func TestPaginateAll(t *testing.T) {
	// page returns a slice of n empty-string pointers, matching what paginateAll
	// counts (len), without needing real records.
	page := func(n int) []*string {
		out := make([]*string, n)
		for i := range out {
			s := ""
			out[i] = &s
		}
		return out
	}

	tests := []struct {
		name     string
		pages    []int // records returned for page 1, 2, 3, ...
		wantLen  int
		wantCall int
	}{
		{
			// Synthetic: three pages, the last short, so the walk stops after it.
			name:     "multiple pages, short last page",
			pages:    []int{tlsPageSize, tlsPageSize, 37},
			wantLen:  tlsPageSize*2 + 37,
			wantCall: 3,
		},
		{
			// Synthetic: a single short page needs only one request.
			name:     "single short page",
			pages:    []int{5},
			wantLen:  5,
			wantCall: 1,
		},
		{
			// Synthetic: an empty account returns nothing in one request.
			name:     "empty",
			pages:    []int{0},
			wantLen:  0,
			wantCall: 1,
		},
		{
			// Synthetic: a full final page must trigger one more fetch, which
			// comes back empty. A naive "stop when the page is full" would miss
			// records; a naive "stop only when empty" is exactly this.
			name:     "exactly full then empty",
			pages:    []int{tlsPageSize, 0},
			wantLen:  tlsPageSize,
			wantCall: 2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			got, err := paginateAll(func(p int) ([]*string, error) {
				calls++
				if p < 1 {
					t.Fatalf("page number must start at 1, got %d", p)
				}
				if p <= len(tc.pages) {
					return page(tc.pages[p-1]), nil
				}
				return nil, nil
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(got) != tc.wantLen {
				t.Errorf("len = %d, want %d", len(got), tc.wantLen)
			}
			if calls != tc.wantCall {
				t.Errorf("fetch called %d times, want %d", calls, tc.wantCall)
			}
		})
	}
}

// TestPaginateAllPropagatesError checks that a mid-walk error aborts the walk.
// Synthetic: covers the API-failure path.
func TestPaginateAllPropagatesError(t *testing.T) {
	wantErr := errTest
	_, err := paginateAll(func(p int) ([]*string, error) {
		return nil, wantErr
	})
	if err != wantErr {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

var errTest = &stringError{"boom"}

type stringError struct{ s string }

func (e *stringError) Error() string { return e.s }
