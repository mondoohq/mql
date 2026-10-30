// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// --- fixtures ---------------------------------------------------------------

// fakeItem stands in for an ARM row.
type fakeItem struct{ name string }

// fakePage stands in for an ARM list response.
type fakePage struct{ values []*fakeItem }

// fakePager replays a fixed script of pages and errors. Each entry is either a
// page or an error; the pager reports More until the script is exhausted.
type fakePager struct {
	pages []fakePage
	errs  []error // errs[i], when non-nil, is returned instead of pages[i]
	at    int
	// deadlines records whether each NextPage call arrived with a deadline set,
	// so a test can assert the timeout is actually applied.
	deadlines []bool
}

func (p *fakePager) More() bool { return p.at < len(p.pages) }

func (p *fakePager) NextPage(ctx context.Context) (fakePage, error) {
	_, ok := ctx.Deadline()
	p.deadlines = append(p.deadlines, ok)

	i := p.at
	p.at++
	if i < len(p.errs) && p.errs[i] != nil {
		return fakePage{}, p.errs[i]
	}
	return p.pages[i], nil
}

func fakePageItems(p fakePage) []*fakeItem { return p.values }

// stubResource is the minimum that satisfies plugin.Resource, so listPaged can
// be exercised without a runtime or a schema.
type stubResource struct{ id string }

func (r *stubResource) MqlID() string   { return r.id }
func (r *stubResource) MqlName() string { return "stub" }

func stubCreate(_ *plugin.Runtime, item *fakeItem) (plugin.Resource, error) {
	return &stubResource{id: item.name}, nil
}

func items(names ...string) []*fakeItem {
	res := make([]*fakeItem, 0, len(names))
	for _, n := range names {
		res = append(res, &fakeItem{name: n})
	}
	return res
}

func ids(t *testing.T, res []any) []string {
	t.Helper()
	out := make([]string, 0, len(res))
	for _, r := range res {
		s, ok := r.(*stubResource)
		require.True(t, ok, "unexpected element type %T", r)
		out = append(out, s.id)
	}
	return out
}

// --- azureFault -------------------------------------------------------------

func TestAzureFault(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want azureFaultKind
	}{
		{"403 is denied", armError(http.StatusForbidden, ""), faultDenied},
		{"404 is absent", armError(http.StatusNotFound, ""), faultAbsent},
		// A throttle or a server error proves nothing about the collection.
		// Degrading either one would report an authoritative answer derived
		// from a call that never returned data.
		{"429 is fatal", armError(http.StatusTooManyRequests, ""), faultFatal},
		{"500 is fatal", armError(http.StatusInternalServerError, ""), faultFatal},
		{"401 is fatal", armError(http.StatusUnauthorized, ""), faultFatal},
		{"a plain error is fatal", errors.New("dial tcp: i/o timeout"), faultFatal},
		{"nil is fatal", nil, faultFatal},
		{
			"a wrapped response error is still classified",
			fmt.Errorf("listing namespaces: %w", armError(http.StatusForbidden, "")),
			faultDenied,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, azureFault(tt.err))
		})
	}
}

// --- listPaged --------------------------------------------------------------

func TestListPagedWalksEveryPage(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{pages: []fakePage{
		{values: items("a", "b")},
		{values: items("c")},
	}}

	res, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b", "c"}, ids(t, res))
	assert.False(t, field.IsSet(), "a successful walk must leave the field to GetOrCompute")
}

func TestListPagedSkipsNilItems(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{pages: []fakePage{
		{values: []*fakeItem{{name: "a"}, nil, {name: "b"}}},
	}}

	res, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

	require.NoError(t, err)
	assert.Equal(t, []string{"a", "b"}, ids(t, res))
}

func TestListPagedEmptyCollection(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{pages: []fakePage{{values: nil}}}

	res, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

	require.NoError(t, err)
	assert.Empty(t, res)
	assert.False(t, field.IsSet())
}

// A denied read must report null, not an empty list. An empty list is a claim
// that there is nothing there, and `things.none(insecure)` passes on it -- so
// reporting one for a read that was refused is a silent pass on a collection
// nobody was able to look at.
func TestListPagedDeniedReportsNullNotEmpty(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{
		pages: []fakePage{{}},
		errs:  []error{armError(http.StatusForbidden, "")},
	}

	res, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

	require.NoError(t, err)
	assert.Nil(t, res)
	require.True(t, field.IsSet(), "the field must be set proactively, or GetOrCompute renders nil as []")
	assert.True(t, field.IsNull())
}

// A 404 means the resource provider is not registered here, which is an answer:
// there are genuinely zero resources. An empty list is correct and a null would
// understate what the call established.
func TestListPagedAbsentReportsEmptyList(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{
		pages: []fakePage{{}},
		errs:  []error{armError(http.StatusNotFound, "")},
	}

	res, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

	require.NoError(t, err)
	assert.NotNil(t, res)
	assert.Empty(t, res)
	assert.False(t, field.IsSet(), "an absent collection is a normal empty result")
}

func TestListPagedFatalErrorSurfaces(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{
		pages: []fakePage{{}},
		errs:  []error{armError(http.StatusTooManyRequests, "")},
	}

	res, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

	require.Error(t, err)
	assert.Nil(t, res)
	assert.False(t, field.IsSet())
}

// Once any row has been read, a later fault must not degrade: returning the rows
// collected so far would present a truncated collection as a complete one, and
// no policy can tell the difference. This is the case the per-call-site loops
// got wrong in both directions -- some returned partial results, some returned
// the error.
func TestListPagedDoesNotDegradeAfterPartialRead(t *testing.T) {
	for _, status := range []int{http.StatusForbidden, http.StatusNotFound} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var field plugin.TValue[[]any]
			pager := &fakePager{
				pages: []fakePage{{values: items("a")}, {}},
				errs:  []error{nil, armError(status, "")},
			}

			res, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

			require.Error(t, err)
			assert.Contains(t, err.Error(), "could not read all things")
			assert.Nil(t, res, "a truncated collection must not be returned as complete")
			assert.False(t, field.IsSet())
		})
	}
}

func TestListPagedPropagatesCreateErrors(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{pages: []fakePage{{values: items("a", "b")}}}
	boom := errors.New("schema mismatch")

	res, err := listPaged(nil, &field, "things", pager, fakePageItems,
		func(_ *plugin.Runtime, item *fakeItem) (plugin.Resource, error) {
			if item.name == "b" {
				return nil, boom
			}
			return &stubResource{id: item.name}, nil
		})

	require.ErrorIs(t, err, boom)
	assert.Nil(t, res)
}

// The plugin API hands an accessor no context to inherit, so listPaged builds
// one. If it ever stops doing so, a hung ARM call stalls the field forever with
// nothing to time it out.
func TestListPagedBoundsEachPage(t *testing.T) {
	var field plugin.TValue[[]any]
	pager := &fakePager{pages: []fakePage{
		{values: items("a")},
		{values: items("b")},
	}}

	_, err := listPaged(nil, &field, "things", pager, fakePageItems, stubCreate)

	require.NoError(t, err)
	require.Len(t, pager.deadlines, 2)
	for i, hasDeadline := range pager.deadlines {
		assert.True(t, hasDeadline, "page %d was fetched with no deadline", i)
	}
}
