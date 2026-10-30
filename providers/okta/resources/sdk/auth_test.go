// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetAppliesAuthorize proves the raw path stamps whatever credential the
// connection supplies, rather than assuming the SSWS scheme. A service app
// authenticates with a bearer token, so hardcoding the scheme here would 401
// every hand-rolled endpoint while the SDK-served ones kept working.
func TestGetAppliesAuthorize(t *testing.T) {
	t.Parallel()
	rt := &singlePageRoundTripper{body: `[]`}
	m := &ApiExtension{
		Host:       "x.okta.com",
		HTTPClient: &http.Client{Transport: rt},
		Authorize: func(req *http.Request) error {
			req.Header.Set("Authorization", "Bearer minted-access-token")
			return nil
		},
	}

	var out []map[string]any
	resp, err := m.get(context.Background(), m.url("/api/v1/zones"), &out)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "Bearer minted-access-token", resp.Request.Header.Get("Authorization"))
}

// TestGetFailsWhenAuthorizeFails covers a token exchange that could not be
// completed. The request must not be sent unauthenticated, which Okta would
// answer with a 401 that reads as a permissions problem rather than a
// credential one.
func TestGetFailsWhenAuthorizeFails(t *testing.T) {
	t.Parallel()
	rt := &singlePageRoundTripper{body: `[]`}
	m := &ApiExtension{
		Host:       "x.okta.com",
		HTTPClient: &http.Client{Transport: rt},
		Authorize: func(req *http.Request) error {
			return errors.New("private key jwt exchange failed")
		},
	}

	_, err := m.get(context.Background(), m.url("/api/v1/zones"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private key jwt exchange failed")
	assert.Zero(t, rt.calls, "the request must not be sent without a credential")
}
