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

// statusRoundTripper serves a single response with a caller-chosen status, so
// the error paths that branch on the status code can be exercised.
type statusRoundTripper struct {
	status int
	body   string
}

func (rt *statusRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: rt.status,
		Header:     http.Header{},
		Body:       io.NopCloser(bytes.NewBufferString(rt.body)),
		Request:    req,
	}, nil
}

// TestListClientRoleGroupTargetsFollowsPagination guards the client-scoped
// group targets against single-page truncation. Truncating here understates
// privilege in a way that reads as correct: a scoped admin would appear to
// administer fewer groups than it does.
func TestListClientRoleGroupTargetsFollowsPagination(t *testing.T) {
	t.Parallel()
	rt := &pagedRoundTripper{
		page1:     `[{"id":"g1","profile":{"name":"one"}},{"id":"g2","profile":{"name":"two"}}]`,
		page2:     `[{"id":"g3","profile":{"name":"three"}}]`,
		nextQuery: "after=p2",
	}

	groups, _, err := fakeClient(rt).ListClientRoleGroupTargets(context.Background(), "client1", "role1")
	require.NoError(t, err)
	require.Len(t, groups, 3, "expected targets from both pages, not just the first")
	assert.Equal(t, 2, rt.calls, "expected the client to follow the next-page link once")
	assert.Equal(t, "g3", groups[2].GetId())
}

// TestListClientRoleAppTargetsDecodesBothTargetShapes pins the distinction the
// resource layer depends on: Okta returns app-instance targets carrying an
// `id` and catalog app-type targets carrying only a `name`, from the same
// collection. Losing the empty-id case would silently turn the broader
// app-type grant into a specific instance.
func TestListClientRoleAppTargetsDecodesBothTargetShapes(t *testing.T) {
	t.Parallel()
	rt := &singlePageRoundTripper{
		body: `[
			{"id":"0oa1","name":"salesforce","displayName":"Salesforce EMEA"},
			{"name":"office365","displayName":"Microsoft Office 365"}
		]`,
	}

	apps, _, err := fakeClient(rt).ListClientRoleAppTargets(context.Background(), "client1", "role1")
	require.NoError(t, err)
	require.Len(t, apps, 2)

	assert.Equal(t, "0oa1", apps[0].GetId(), "instance target keeps its app instance id")
	assert.Equal(t, "salesforce", apps[0].GetName())

	assert.Empty(t, apps[1].GetId(), "catalog app-type target carries no instance id")
	assert.Equal(t, "office365", apps[1].GetName())
}

// TestListClientRoleTargetsReturnsResponseOn404 proves the caller can tell an
// unscoped assignment (no targets resource) apart from a real failure, since
// it branches on the returned status code to degrade to an empty list.
func TestListClientRoleTargetsReturnsResponseOn404(t *testing.T) {
	t.Parallel()
	rt := &statusRoundTripper{status: http.StatusNotFound, body: `{"errorCode":"E0000007"}`}

	_, resp, err := fakeClient(rt).ListClientRoleGroupTargets(context.Background(), "client1", "role1")
	require.Error(t, err)
	require.NotNil(t, resp, "the response must survive the error so callers can inspect the status")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}
