// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
)

func doErr(status int) error {
	return &godo.ErrorResponse{
		Response: &http.Response{StatusCode: status},
		Message:  http.StatusText(status),
	}
}

// The teams endpoint must be called in an organization context. A token
// without that context cannot read the teams, which the accessor reports as
// null rather than as an empty list - an empty list is an answer, and
// `.none()` over it passes vacuously. A rejected token (401) is a plain
// failure and stays an error.
func TestNoOrganizationContext(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"forbidden means the teams are unreadable", doErr(http.StatusForbidden), true},
		{"not found means the teams are unreadable", doErr(http.StatusNotFound), true},
		{"precondition failed means the teams are unreadable", doErr(http.StatusPreconditionFailed), true},

		{"an unauthorized token is a real problem", doErr(http.StatusUnauthorized), false},
		{"a rate limit is transient", doErr(http.StatusTooManyRequests), false},
		{"a service fault is a real failure", doErr(http.StatusInternalServerError), false},
		{"a transport error carries no status", errors.New("dial tcp: no such host"), false},
		{"nil is not a match", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, noOrganizationContext(tc.err))
		})
	}
}

// The error travels back up through the client, so the classifier has to see
// through wrapping.
func TestNoOrganizationContextThroughWrapping(t *testing.T) {
	assert.True(t, noOrganizationContext(
		fmt.Errorf("listing teams: %w", doErr(http.StatusForbidden))))
	assert.False(t, noOrganizationContext(
		fmt.Errorf("listing teams: %w", doErr(http.StatusUnauthorized))))
}

// A godo ErrorResponse with no underlying HTTP response must not be treated as
// an absent organization, since nothing established that.
func TestNoOrganizationContextWithoutResponse(t *testing.T) {
	assert.False(t, noOrganizationContext(&godo.ErrorResponse{Message: "boom"}))
}
