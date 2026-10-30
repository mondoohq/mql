// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

var errPageFailed = errors.New("page request failed")

// token is a helper for the *string page tokens OCI uses.
//
//go:fix inline
func token(s string) *string { return new(s) }

// TestOciPaginateWalksEveryPage covers the shape all 143 converted call sites
// share: pages are concatenated in order, and the walk stops when the response
// reports no next page.
func TestOciPaginateWalksEveryPage(t *testing.T) {
	pages := [][]int{{1, 2}, {3, 4}, {5}}
	nextTokens := []*string{new("p2"), new("p3"), nil}

	var sawTokens []*string
	call := 0
	items, err := ociPaginate(context.Background(), func(_ context.Context, page *string) ([]int, *string, error) {
		sawTokens = append(sawTokens, page)
		batch, next := pages[call], nextTokens[call]
		call++
		return batch, next, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []int{1, 2, 3, 4, 5}
	if len(items) != len(want) {
		t.Fatalf("got %d items, want %d: %v", len(items), len(want), items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Errorf("item %d = %d, want %d (pages concatenated out of order)", i, items[i], want[i])
		}
	}

	// The first request must carry no token, and each later one must carry the
	// token the previous response returned. Getting this wrong re-requests page
	// one forever.
	if len(sawTokens) != 3 {
		t.Fatalf("made %d requests, want 3", len(sawTokens))
	}
	if sawTokens[0] != nil {
		t.Errorf("first request carried token %q, want nil", *sawTokens[0])
	}
	if sawTokens[1] == nil || *sawTokens[1] != "p2" {
		t.Errorf("second request did not carry the first response's token")
	}
	if sawTokens[2] == nil || *sawTokens[2] != "p3" {
		t.Errorf("third request did not carry the second response's token")
	}
}

// TestOciPaginateSinglePage is the common case: one request, no next token.
func TestOciPaginateSinglePage(t *testing.T) {
	calls := 0
	items, err := ociPaginate(context.Background(), func(_ context.Context, _ *string) ([]string, *string, error) {
		calls++
		return []string{"only"}, nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d requests for a single page, want 1", calls)
	}
	if len(items) != 1 || items[0] != "only" {
		t.Errorf("got %v, want [only]", items)
	}
}

// TestOciPaginateEmptyCollection pins that an empty collection is not an error
// and does not loop. Listers hand the result straight to a range loop, so nil
// and empty behave alike downstream.
func TestOciPaginateEmptyCollection(t *testing.T) {
	calls := 0
	items, err := ociPaginate(context.Background(), func(_ context.Context, _ *string) ([]int, *string, error) {
		calls++
		return nil, nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d requests, want 1", calls)
	}
	if len(items) != 0 {
		t.Errorf("got %v, want no items", items)
	}
}

// TestOciPaginateDiscardsPartialResultOnError is the property the callers'
// error handling depends on. A half-collected list returned alongside an error
// invites a caller to use it, and a confident subset is the failure mode the
// pool wrappers exist to prevent.
func TestOciPaginateDiscardsPartialResultOnError(t *testing.T) {
	call := 0
	items, err := ociPaginate(context.Background(), func(_ context.Context, _ *string) ([]int, *string, error) {
		call++
		if call < 3 {
			// Distinct per page: an unchanged token is itself an error now,
			// and a fixture repeating one would fail here for that reason
			// rather than for the one this test is about.
			return []int{call}, new(fmt.Sprintf("page-%d", call+1)), nil
		}
		return nil, nil, errPageFailed
	})
	if !errors.Is(err, errPageFailed) {
		t.Fatalf("got error %v, want errPageFailed", err)
	}
	if items != nil {
		t.Errorf("got %v alongside the error, want nil", items)
	}
}

// TestOciPaginateSurfacesAFirstPageError makes sure a failure before anything
// was collected is reported rather than read as an empty collection.
func TestOciPaginateSurfacesAFirstPageError(t *testing.T) {
	_, err := ociPaginate(context.Background(), func(_ context.Context, _ *string) ([]int, *string, error) {
		return nil, nil, errPageFailed
	})
	if !errors.Is(err, errPageFailed) {
		t.Fatalf("got error %v, want errPageFailed", err)
	}
}

// TestOciPaginatePassesTheContextThrough keeps the context reaching the request
// rather than being swallowed by the helper, so a cancelled scan stops paging.
func TestOciPaginatePassesTheContextThrough(t *testing.T) {
	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "carried")

	_, err := ociPaginate(ctx, func(inner context.Context, _ *string) ([]int, *string, error) {
		if inner.Value(ctxKey{}) != "carried" {
			t.Error("the callback received a different context than the caller passed")
		}
		return nil, nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- SCIM ------------------------------------------------------------------

// TestOciScimPaginateWalksByStartIndex covers the identity-domains scheme:
// 1-based startIndex advanced by the number of resources returned, terminating
// once the reported total is passed.
func TestOciScimPaginateWalksByStartIndex(t *testing.T) {
	total := ociScimPageSize + 3

	var sawIndexes []int
	items, err := ociScimPaginate(context.Background(), func(_ context.Context, startIndex int) ([]int, *int, error) {
		sawIndexes = append(sawIndexes, startIndex)
		if startIndex == 1 {
			return make([]int, ociScimPageSize), &total, nil
		}
		return make([]int, 3), &total, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != total {
		t.Errorf("collected %d resources, want %d", len(items), total)
	}

	// SCIM is 1-based, and the second page starts one past the first page's
	// last resource. An off-by-one here silently skips or repeats a user.
	want := []int{1, 1 + ociScimPageSize}
	if len(sawIndexes) != len(want) {
		t.Fatalf("made %d requests at %v, want %d", len(sawIndexes), sawIndexes, len(want))
	}
	for i := range want {
		if sawIndexes[i] != want[i] {
			t.Errorf("request %d used startIndex %d, want %d", i, sawIndexes[i], want[i])
		}
	}
}

// TestOciScimPaginateStopsOnAShortPageWithoutATotal covers a domain that omits
// totalResults, where a page shorter than the requested count is the only
// signal that the collection is exhausted.
func TestOciScimPaginateStopsOnAShortPageWithoutATotal(t *testing.T) {
	calls := 0
	items, err := ociScimPaginate(context.Background(), func(_ context.Context, _ int) ([]int, *int, error) {
		calls++
		if calls == 1 {
			return make([]int, ociScimPageSize), nil, nil
		}
		return make([]int, 5), nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 2 {
		t.Errorf("made %d requests, want 2 (a short page ends the walk)", calls)
	}
	if want := ociScimPageSize + 5; len(items) != want {
		t.Errorf("collected %d resources, want %d", len(items), want)
	}
}

// TestOciScimPaginateStopsOnAnEmptyPage guards the termination case that would
// otherwise loop forever: a page with no resources cannot advance startIndex.
func TestOciScimPaginateStopsOnAnEmptyPage(t *testing.T) {
	calls := 0
	items, err := ociScimPaginate(context.Background(), func(_ context.Context, _ int) ([]int, *int, error) {
		calls++
		return nil, nil, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d requests for an empty collection, want 1", calls)
	}
	if len(items) != 0 {
		t.Errorf("got %v, want no resources", items)
	}
}

// TestOciScimPaginateDiscardsPartialResultOnError mirrors the token-based
// helper: the caller must not receive a partial page set with an error.
func TestOciScimPaginateDiscardsPartialResultOnError(t *testing.T) {
	total := ociScimPageSize * 3
	calls := 0
	items, err := ociScimPaginate(context.Background(), func(_ context.Context, _ int) ([]int, *int, error) {
		calls++
		if calls == 1 {
			return make([]int, ociScimPageSize), &total, nil
		}
		return nil, nil, errPageFailed
	})
	if !errors.Is(err, errPageFailed) {
		t.Fatalf("got error %v, want errPageFailed", err)
	}
	if items != nil {
		t.Errorf("got %d resources alongside the error, want nil", len(items))
	}
}

// TestOciPaginateStopsOnAStuckCursor covers the one shape the walk cannot
// survive on its own. An endpoint that echoes the page token it was handed
// would be asked for the same page forever: the collection grows without
// bound, the scan hangs, and nothing names the region or service responsible.
//
// Reported rather than truncated. Returning what was collected would hand back
// the same page N times as though it were a complete listing, which is the
// confident-subset failure the rest of this helper's error handling exists to
// avoid.
func TestOciPaginateStopsOnAStuckCursor(t *testing.T) {
	calls := 0
	items, err := ociPaginate(context.Background(), func(_ context.Context, _ *string) ([]int, *string, error) {
		calls++
		if calls > 100 {
			t.Fatal("pagination did not terminate on a repeated page token")
		}
		return []int{calls}, new("stuck"), nil
	})
	if err == nil {
		t.Fatal("got no error for a page token that never advanced")
	}
	if !strings.Contains(err.Error(), "did not advance") {
		t.Errorf("error %q does not say the cursor was stuck", err)
	}
	if items != nil {
		t.Errorf("got %v alongside the error, want nil", items)
	}
	// Two requests: the first has no token to compare against, the second
	// returns the same one it was given.
	if calls != 2 {
		t.Errorf("made %d requests before stopping, want 2", calls)
	}
}

// TestOciPaginateAllowsARepeatedTokenAfterAnAdvance keeps the guard from
// firing on a cursor that legitimately revisits a value. Only an immediate
// repeat is stuck; a walk that moves p1 -> p2 -> p1 -> nil is odd but is
// making progress, and rejecting it would truncate a real listing.
func TestOciPaginateAllowsARepeatedTokenAfterAnAdvance(t *testing.T) {
	nextTokens := []*string{new("p1"), new("p2"), new("p1"), nil}

	call := 0
	items, err := ociPaginate(context.Background(), func(_ context.Context, _ *string) ([]int, *string, error) {
		next := nextTokens[call]
		call++
		return []int{call}, next, nil
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 4 {
		t.Errorf("got %d items, want 4: %v", len(items), items)
	}
}
