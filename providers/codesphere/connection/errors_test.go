// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func resp(code int, header ...string) *http.Response {
	h := http.Header{}
	for i := 0; i+1 < len(header); i += 2 {
		h.Set(header[i], header[i+1])
	}
	return &http.Response{StatusCode: code, Header: h}
}

// Synthetic: status codes the API can answer with; no live Codesphere account
// was available.
func TestClassify(t *testing.T) {
	base := errors.New("boom")

	assert.NoError(t, Classify(resp(500), nil))

	// A transport failure has no response and is not a refusal.
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNSPECIFIED, llx.KindOf(Classify(nil, base)))

	cases := map[int]llx.ErrorKind{
		http.StatusUnauthorized:    llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED,
		http.StatusForbidden:       llx.ErrorKind_ERROR_KIND_FORBIDDEN,
		http.StatusNotFound:        llx.ErrorKind_ERROR_KIND_NOT_FOUND,
		http.StatusTooManyRequests: llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS,
		http.StatusBadGateway:      llx.ErrorKind_ERROR_KIND_UNAVAILABLE,
		http.StatusBadRequest:      llx.ErrorKind_ERROR_KIND_UNSPECIFIED,
	}
	for code, want := range cases {
		assert.Equal(t, want, llx.KindOf(Classify(resp(code), base)), code)
	}

	// A rejected token fails every call, so it ends the asset.
	var e *llx.Error
	require.ErrorAs(t, Classify(resp(http.StatusUnauthorized), base), &e)
	assert.Equal(t, llx.ErrorScope_ERROR_SCOPE_ASSET, e.Scope)

	// A refusal is scoped to the call only.
	require.ErrorAs(t, Classify(resp(http.StatusForbidden), base), &e)
	assert.Equal(t, llx.ErrorScope_ERROR_SCOPE_UNSPECIFIED, e.Scope)

	require.ErrorAs(t, Classify(resp(http.StatusTooManyRequests, "Retry-After", "30"), base), &e)
	assert.Equal(t, 30*time.Second, e.RetryAfter)

	require.ErrorAs(t, Classify(resp(http.StatusTooManyRequests, "Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT"), base), &e)
	assert.Zero(t, e.RetryAfter, "HTTP-date form is not parsed")
}

// Measured: the Codesphere cloud API (cloud.codesphere.com, 2026-11-18)
// answered GET /teams with an invalid token with 401, title "Authentication
// failed" and detail "Authentication token does not exist or is not valid
// anymore.", which the vendor client renders with the detail as a pointer
// address. The other body fields are not reproduced.
func TestClassifyDescribesAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":401,"title":"Authentication failed","detail":"Authentication token does not exist or is not valid anymore."}`))
	}))
	defer srv.Close()

	conn := testConnection(t, srv.URL)
	_, r, err := conn.API().TeamsAPI.TeamsListTeams(conn.Context()).Execute()
	require.Error(t, err)

	got := Classify(r, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED, llx.KindOf(got))
	assert.Contains(t, got.Error(), "codesphere API GET /teams: 401 Unauthorized: Authentication failed (Authentication token does not exist or is not valid anymore.)")
	assert.NotContains(t, got.Error(), "%!s")
}

// Synthetic: a problem body without title or detail still yields the status.
func TestClassifyDescribesBareError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	conn := testConnection(t, srv.URL)
	_, r, err := conn.API().TeamsAPI.TeamsListTeams(conn.Context()).Execute()
	require.Error(t, err)

	got := Classify(r, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_FORBIDDEN, llx.KindOf(got))
	assert.Equal(t, "codesphere API GET /teams: 403 Forbidden", got.Error())
}
