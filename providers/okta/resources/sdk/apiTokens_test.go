// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListApiTokensFollowsPagination covers the API token listing now that it
// runs through ApiExtension: the transport is injectable, so the previously
// untestable `Link: rel="next"` loop is exercised here.
func TestListApiTokensFollowsPagination(t *testing.T) {
	t.Parallel()
	rt := &pagedRoundTripper{
		page1:     `[{"id":"t1","name":"one"},{"id":"t2","name":"two"}]`,
		page2:     `[{"id":"t3","name":"three"}]`,
		nextQuery: "after=p2",
	}

	m := fakeClient(rt)
	tokens, err := m.ListApiTokens(context.Background(), 200)
	require.NoError(t, err)
	require.Len(t, tokens, 3, "expected tokens from both pages, not just the first")
	assert.Equal(t, 2, rt.calls, "expected the client to follow the next-page link once")
	assert.Equal(t, "t3", tokens[2].Id)
}

// singlePageRoundTripper serves one page with no `Link` header at all.
type singlePageRoundTripper struct {
	body  string
	calls int
}

func (rt *singlePageRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.calls++
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(rt.body)),
		Request:    req,
	}, nil
}

// TestListUserFactorsDecodesProfile proves the factors fetch keeps the
// per-factorType `profile` object, which is the whole reason we bypass the
// generated SDK's UserFactor union.
func TestListUserFactorsDecodesProfile(t *testing.T) {
	t.Parallel()
	rt := &singlePageRoundTripper{
		body: `[{"id":"f1","factorType":"sms","profile":{"phoneNumber":"+15551234567"}}]`,
	}

	m := fakeClient(rt)
	factors, err := m.ListUserFactors(context.Background(), "user1")
	require.NoError(t, err)
	require.Len(t, factors, 1)
	assert.Equal(t, 1, rt.calls, "the factors endpoint is not paginated")
	assert.Contains(t, string(factors[0]), `"phoneNumber":"+15551234567"`)
}

// TestListUserFactorsEscapesUserId guards against a user id with URL-unsafe
// characters breaking out of the path segment.
func TestListUserFactorsEscapesUserId(t *testing.T) {
	t.Parallel()
	rt := &pathCapturingRoundTripper{body: `[]`}

	m := fakeClient(rt)
	_, err := m.ListUserFactors(context.Background(), "a/b c")
	require.NoError(t, err)
	assert.Equal(t, "/api/v1/users/a%2Fb%20c/factors", rt.path)
}

// pathCapturingRoundTripper records the escaped request path.
type pathCapturingRoundTripper struct {
	body string
	path string
}

func (rt *pathCapturingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	rt.path = req.URL.EscapedPath()
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(rt.body)),
		Request:    req,
	}, nil
}
