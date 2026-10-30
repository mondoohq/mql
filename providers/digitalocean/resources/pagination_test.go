// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pageOf builds the response godo returns for a page that has a successor.
// godo derives the current page from the prev link, so a page after the first
// has to carry one or the walk cannot advance.
func pageOf(prev, next string) *godo.Response {
	pages := &godo.Pages{
		Next: "https://api.digitalocean.com/v2/things?page=" + next,
		Last: "https://api.digitalocean.com/v2/things?page=" + next,
	}
	if prev != "" {
		pages.Prev = "https://api.digitalocean.com/v2/things?page=" + prev
	}
	return &godo.Response{Links: &godo.Links{Pages: pages}}
}

// lastPage builds the response godo returns for the final page: an envelope
// with no next link.
func lastPage(prev string) *godo.Response {
	if prev == "" {
		return &godo.Response{Links: &godo.Links{Pages: &godo.Pages{}}}
	}
	return &godo.Response{Links: &godo.Links{Pages: &godo.Pages{
		Prev: "https://api.digitalocean.com/v2/things?page=" + prev,
	}}}
}

func TestPaginate_SinglePage(t *testing.T) {
	calls := 0
	got, err := paginate(context.Background(), func(_ context.Context, opt *godo.ListOptions) ([]string, *godo.Response, error) {
		calls++
		assert.Equal(t, listPerPage, opt.PerPage, "first call must ask for a full page")
		return []string{"a", "b"}, lastPage(""), nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, got)
	assert.Equal(t, 1, calls)
}

func TestPaginate_FollowsEveryPage(t *testing.T) {
	// The bug this guards against is breaking after page one, which truncates
	// a list silently rather than failing.
	var pages [][]string
	seen := []int{}
	pages = [][]string{{"a"}, {"b"}, {"c"}}
	got, err := paginate(context.Background(), func(_ context.Context, opt *godo.ListOptions) ([]string, *godo.Response, error) {
		seen = append(seen, opt.Page)
		switch len(seen) {
		case 1:
			return pages[0], pageOf("", "2"), nil
		case 2:
			return pages[1], pageOf("1", "3"), nil
		default:
			return pages[2], lastPage("2"), nil
		}
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, got, "every page must be collected")
	assert.Equal(t, []int{0, 2, 3}, seen, "each request must advance the page")
}

func TestPaginate_NilResponseDoesNotPanic(t *testing.T) {
	// godo returns (result, nil, nil) on endpoints with no pagination
	// envelope. Dereferencing that response panics the provider, which takes
	// down the entire scan rather than one field.
	got, err := paginate(context.Background(), func(_ context.Context, _ *godo.ListOptions) ([]string, *godo.Response, error) {
		return []string{"only"}, nil, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"only"}, got)
}

func TestPaginate_NilLinksDoesNotPanic(t *testing.T) {
	got, err := paginate(context.Background(), func(_ context.Context, _ *godo.ListOptions) ([]string, *godo.Response, error) {
		return []string{"only"}, &godo.Response{}, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"only"}, got)
}

func TestPaginate_PropagatesError(t *testing.T) {
	want := errors.New("boom")
	got, err := paginate(context.Background(), func(_ context.Context, _ *godo.ListOptions) ([]string, *godo.Response, error) {
		return nil, nil, want
	})
	assert.ErrorIs(t, err, want)
	assert.Nil(t, got, "a failed list must not report a partial set as complete")
}

func TestPaginate_ErrorOnLaterPageIsNotPartialSuccess(t *testing.T) {
	// A list that fails halfway must not look like a short list.
	want := errors.New("page 2 failed")
	n := 0
	got, err := paginate(context.Background(), func(_ context.Context, _ *godo.ListOptions) ([]string, *godo.Response, error) {
		n++
		if n == 1 {
			return []string{"a"}, pageOf("", "2"), nil
		}
		return nil, nil, want
	})
	assert.ErrorIs(t, err, want)
	assert.Nil(t, got)
}

func TestPaginate_EmptyResult(t *testing.T) {
	got, err := paginate(context.Background(), func(_ context.Context, _ *godo.ListOptions) ([]string, *godo.Response, error) {
		return nil, lastPage(""), nil
	})
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestPaginate_MalformedNextLink(t *testing.T) {
	// A next link godo cannot parse is an error, not a silent stop.
	got, err := paginate(context.Background(), func(_ context.Context, _ *godo.ListOptions) ([]string, *godo.Response, error) {
		return []string{"a"}, &godo.Response{Links: &godo.Links{Pages: &godo.Pages{
			Next: "://not a url",
			Prev: "://not a url",
		}}}, nil
	})
	assert.Error(t, err)
	assert.Nil(t, got)
}

// TestPaginate_StuckCursorIsReported guards against an endpoint that
// ignores the page parameter and answers the same page forever while
// still advertising a next link. Without the guard the loop never
// terminates: the scan hangs and the accumulated slice grows until the
// process runs out of memory. Reporting it beats returning the pages
// collected so far, which would be a truncated list presented as a
// complete one.
func TestPaginate_StuckCursorIsReported(t *testing.T) {
	calls := 0
	_, err := paginate(context.Background(), func(ctx context.Context, opt *godo.ListOptions) ([]int, *godo.Response, error) {
		calls++
		if calls > 50 {
			t.Fatal("paginate did not terminate on a repeating page")
		}
		// Always reports itself as page 1 with more to come.
		return []int{calls}, &godo.Response{Links: &godo.Links{
			Pages: &godo.Pages{Next: "https://api.example/v2/things?page=2", Last: "https://api.example/v2/things?page=9"},
		}}, nil
	})

	require.Error(t, err, "a repeating page must be reported, not looped on")
	assert.Contains(t, err.Error(), "repeating a page")
	assert.Less(t, calls, 50)
}
