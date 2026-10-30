// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// GitHub answers the private-vulnerability-reporting endpoint with 422 for any
// repository that is private or archived, which is a normal state rather than a
// failure. Letting that error escape fails the whole repository listing the
// field was read from, so a single archived repository takes out every other
// repository in the query.
func TestPrivateVulnerabilityReportingEnabledRaw(t *testing.T) {
	for _, tc := range []struct {
		name      string
		status    int
		body      string
		want      bool
		wantError bool
	}{
		{name: "enabled", status: http.StatusOK, body: `{"enabled": true}`, want: true},
		{name: "disabled", status: http.StatusOK, body: `{"enabled": false}`, want: false},
		{
			name:   "private or archived repository",
			status: http.StatusUnprocessableEntity,
			body:   `{"message": "Repository must be public and not archived"}`,
			want:   false,
		},
		{
			name:   "not found",
			status: http.StatusNotFound,
			body:   `{"message": "Not Found"}`,
			want:   false,
		},
		{
			name:   "permission denied",
			status: http.StatusForbidden,
			body:   `{"message": "Resource not accessible by personal access token"}`,
			want:   false,
		},
		{
			name:      "server error propagates",
			status:    http.StatusInternalServerError,
			body:      `{"message": "boom"}`,
			want:      false,
			wantError: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/api/v3/repos/o/r/private-vulnerability-reporting", r.URL.Path)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer server.Close()

			got, err := privateVulnerabilityReportingEnabledRaw(
				context.Background(), newTestGithubClient(t, server), "o", "r")
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}
