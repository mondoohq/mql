// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pagedRoundTripper serves two pages for any Okta collection GET: the first
// request (no `after` cursor) returns page one plus a `Link: rel="next"`
// header pointing at the same path with `after=p2`; the follow-up request
// returns page two with no next link. It records how many requests it saw so a
// test can prove the client actually followed the next link rather than
// stopping after page one.
type pagedRoundTripper struct {
	page1     string
	page2     string
	nextQuery string // e.g. "after=p2"
	calls     int
}

func (rt *pagedRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls++
	body := rt.page1
	header := http.Header{}
	if strings.Contains(req.URL.RawQuery, rt.nextQuery) {
		body = rt.page2
	} else {
		next := "https://" + req.URL.Host + req.URL.Path + "?" + rt.nextQuery
		header.Set("Link", "<"+next+`>; rel="next"`)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(bytes.NewBufferString(body)),
		Request:    req,
	}, nil
}

// fakeClient returns an ApiExtension whose transport is the given round-tripper,
// so pagination is exercised without touching any global http.Client.
func fakeClient(rt http.RoundTripper) *ApiExtension {
	return &ApiExtension{
		Host:       "x.okta.com",
		Authorize:  func(req *http.Request) error { req.Header.Set("Authorization", "SSWS t"); return nil },
		HTTPClient: &http.Client{Transport: rt},
	}
}

// TestListPolicyRulesFollowsPagination guards the ACCESS_POLICY rule fetch
// against the single-page truncation regression: it must follow the
// `Link: rel="next"` header and return rules from every page.
func TestListPolicyRulesFollowsPagination(t *testing.T) {
	t.Parallel()
	rt := &pagedRoundTripper{
		page1:     `[{"id":"rule1"},{"id":"rule2"}]`,
		page2:     `[{"id":"rule3"}]`,
		nextQuery: "after=p2",
	}

	m := fakeClient(rt)
	rules, err := m.ListPolicyRules(context.Background(), "pol1", 200)
	require.NoError(t, err)
	require.Len(t, rules, 3, "expected rules from both pages, not just the first")
	assert.Equal(t, 2, rt.calls, "expected the client to follow the next-page link once")
}

// TestListPoliciesFollowsPagination guards the same behavior for the policy
// listing itself across all policy types.
func TestListPoliciesFollowsPagination(t *testing.T) {
	t.Parallel()
	rt := &pagedRoundTripper{
		page1:     `[{"id":"p1"},{"id":"p2"}]`,
		page2:     `[{"id":"p3"}]`,
		nextQuery: "after=p2",
	}

	m := fakeClient(rt)
	policies, _, err := m.ListPolicies(context.Background(), "ACCESS_POLICY", 200)
	require.NoError(t, err)
	require.Len(t, policies, 3, "expected policies from both pages, not just the first")
	assert.Equal(t, 2, rt.calls)
}

// cyclingRoundTripper always returns a `next` link pointing back at the same
// path, simulating a malformed Okta response that would otherwise loop forever.
type cyclingRoundTripper struct{ calls int }

func (rt *cyclingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls++
	header := http.Header{}
	header.Set("Link", "<https://"+req.URL.Host+req.URL.Path+`?after=loop>; rel="next"`)
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(bytes.NewBufferString(`[{"id":"x"}]`)),
		Request:    req,
	}, nil
}

// TestPaginationStopsOnCyclingLink proves a self-referential `Link: rel="next"`
// ends the walk at the repeat rather than being followed to the page cap.
// Following it to the cap would report the cycling page's records a thousand
// times over, which reads as a real collection rather than as a failure.
func TestPaginationStopsOnCyclingLink(t *testing.T) {
	t.Parallel()
	rt := &cyclingRoundTripper{}
	m := fakeClient(rt)

	rules, err := m.ListPolicyRules(context.Background(), "pol1", 200)
	require.NoError(t, err)
	assert.Equal(t, 2, rt.calls, "the repeated cursor should end the walk")
	assert.Len(t, rules, 2, "no record should be collected more than the pages that carried it")
}

// advancingRoundTripper hands back a fresh `next` cursor on every call, so the
// walk never repeats a URL and only the page cap can stop it.
type advancingRoundTripper struct{ calls int }

func (rt *advancingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls++
	header := http.Header{}
	header.Set("Link", fmt.Sprintf("<https://%s%s?after=%d>; rel=\"next\"", req.URL.Host, req.URL.Path, rt.calls))
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(bytes.NewBufferString(`[{"id":"x"}]`)),
		Request:    req,
	}, nil
}

// TestPaginationStopsAtPageCap proves the maxPages bound still terminates an
// endpoint that keeps offering a new cursor forever, which the repeated-URL
// guard cannot see.
func TestPaginationStopsAtPageCap(t *testing.T) {
	t.Parallel()
	rt := &advancingRoundTripper{}
	m := fakeClient(rt)

	_, err := m.ListPolicyRules(context.Background(), "pol1", 200)
	require.NoError(t, err)
	assert.Equal(t, maxPages, rt.calls, "loop should stop at the maxPages bound")
}

// TestNextPageURL covers the cursor guard on its own, including the shape that
// ends a normal walk.
func TestNextPageURL(t *testing.T) {
	t.Parallel()

	const current = "https://test.okta.com/api/v1/policies?after=1"

	t.Run("advances to a different cursor", func(t *testing.T) {
		next := nextPageURL(current, []string{`<https://test.okta.com/api/v1/policies?after=2>; rel="next"`})
		assert.Equal(t, "https://test.okta.com/api/v1/policies?after=2", next)
	})

	t.Run("stops on a cursor that repeats the current page", func(t *testing.T) {
		assert.Equal(t, "", nextPageURL(current, []string{`<` + current + `>; rel="next"`}))
	})

	t.Run("stops when no next link is offered", func(t *testing.T) {
		assert.Equal(t, "", nextPageURL(current, []string{`<https://test.okta.com/api/v1/policies>; rel="self"`}))
	})

	t.Run("stops when there is no Link header at all", func(t *testing.T) {
		assert.Equal(t, "", nextPageURL(current, nil))
	})
}
