// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tsclient "tailscale.com/client/tailscale/v2"
)

// apiErrorWithStatus produces a genuine tsclient.APIError by driving the real
// client against a stub server. The status could be set on a hand-rolled
// APIError, but only the SDK's own request path proves it populates the field
// these helpers read, which is what would break if the SDK changed how it
// reports failures.
func apiErrorWithStatus(t *testing.T, status int) error {
	t.Helper()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"message":"stub failure"}`))
	}))
	t.Cleanup(server.Close)

	baseURL, err := url.Parse(server.URL)
	require.NoError(t, err)

	client := &tsclient.Client{BaseURL: baseURL, Tailnet: "example.com", APIKey: "stub"}
	_, err = client.Devices().Get(context.Background(), "stub-device")
	require.Error(t, err, "the stub server must produce an API error")
	return err
}

func TestAPIStatusCode(t *testing.T) {
	for _, status := range []int{400, 401, 403, 404, 429, 500} {
		err := apiErrorWithStatus(t, status)
		assert.Equal(t, status, APIStatusCode(err), "status %d", status)
	}
}

func TestAPIStatusCode_NonAPIErrors(t *testing.T) {
	assert.Equal(t, 0, APIStatusCode(nil))
	assert.Equal(t, 0, APIStatusCode(errors.New("dial tcp: connection refused")))
	// A plain error that merely mentions a status must not be mistaken for one.
	assert.Equal(t, 0, APIStatusCode(errors.New("request to /v2/thing (403) failed")))
}

func TestAPIStatusCode_WrappedError(t *testing.T) {
	err := apiErrorWithStatus(t, 403)
	assert.Equal(t, 403, APIStatusCode(errors.Join(errors.New("context"), err)))
}

func TestIsAccessDenied(t *testing.T) {
	assert.True(t, IsAccessDenied(apiErrorWithStatus(t, 401)))
	assert.True(t, IsAccessDenied(apiErrorWithStatus(t, 403)))
	assert.False(t, IsAccessDenied(apiErrorWithStatus(t, 404)))
	assert.False(t, IsAccessDenied(apiErrorWithStatus(t, 500)))
	assert.False(t, IsAccessDenied(nil))
	assert.False(t, IsAccessDenied(errors.New("boom")))
}

func TestIsUnavailable(t *testing.T) {
	// Nothing configured for this log type.
	assert.True(t, IsUnavailable(apiErrorWithStatus(t, 404)))
	// Feature not included in the tailnet's plan, or scope not granted.
	assert.True(t, IsUnavailable(apiErrorWithStatus(t, 403)))
	// A real failure must still surface.
	assert.False(t, IsUnavailable(apiErrorWithStatus(t, 500)))
	assert.False(t, IsUnavailable(apiErrorWithStatus(t, 401)))
	assert.False(t, IsUnavailable(nil))
}

// TestIsNotFoundStillWorks guards the assumption IsUnavailable is built on:
// that the SDK's own 404 helper agrees with our status parsing.
func TestIsNotFoundStillWorks(t *testing.T) {
	err := apiErrorWithStatus(t, 404)
	assert.True(t, tsclient.IsNotFound(err))
	assert.Equal(t, 404, APIStatusCode(err))
}
