// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The Okta error code is the only thing separating a feature the org is not
// licensed for (401 E0000015) from a dead credential (401 E0000011), so it has
// to survive onto the error the raw endpoints return.
func TestNewAPIError(t *testing.T) {
	t.Parallel()

	resp := &http.Response{StatusCode: http.StatusUnauthorized, Status: "401 Unauthorized"}

	t.Run("reads the code out of an Okta error body", func(t *testing.T) {
		body := []byte(`{"errorCode":"E0000015","errorSummary":"You do not have permission to access the feature you are requesting"}`)
		err := newAPIError("https://test.okta.com/api/v1/policies", resp, body)

		assert.Equal(t, "E0000015", err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
		assert.Equal(t, "401 Unauthorized", err.Status)
	})

	t.Run("a body that is not an Okta error leaves the code empty", func(t *testing.T) {
		err := newAPIError("https://test.okta.com/api/v1/policies", resp, []byte(`<html>gateway</html>`))
		assert.Equal(t, "", err.Code)
		assert.Equal(t, http.StatusUnauthorized, err.StatusCode)
	})

	t.Run("no response leaves the status unset rather than guessed", func(t *testing.T) {
		err := newAPIError("https://test.okta.com/api/v1/policies", nil, []byte(`{}`))
		assert.Equal(t, 0, err.StatusCode)
		assert.Equal(t, "", err.Status)
	})

	// Callers already branch on the body carried in the message, so the
	// message has to keep carrying it.
	t.Run("the message still carries the URL, status and body", func(t *testing.T) {
		body := []byte(`{"errorCode":"E0000003","errorSummary":"Invalid policy type"}`)
		bad := &http.Response{StatusCode: http.StatusBadRequest, Status: "400 Bad Request"}
		err := newAPIError("https://test.okta.com/api/v1/policies?type=ENTITY_RISK", bad, body)

		message := err.Error()
		assert.Contains(t, message, "https://test.okta.com/api/v1/policies?type=ENTITY_RISK")
		assert.Contains(t, message, "400 Bad Request")
		assert.Contains(t, message, "Invalid policy type")
	})
}

// A failed raw request must hand back the typed error, not a formatted string,
// or nothing downstream can read the code off it.
func TestGetReturnsAPIError(t *testing.T) {
	t.Parallel()

	m := fakeClient(&statusRoundTripper{
		status: http.StatusUnauthorized,
		body:   `{"errorCode":"E0000015","errorSummary":"feature not enabled"}`,
	})

	_, _, err := m.ListPolicies(context.Background(), "ENTITY_RISK", 200)
	require.Error(t, err)

	apiErr := &APIError{}
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, "E0000015", apiErr.Code)
	assert.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}
