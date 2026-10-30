// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestClassifyError(t *testing.T) {
	// Synthetic: the error codes come from the Slack API reference pages of
	// admin.apps.approved.list, admin.apps.requests.list and
	// admin.slackbot.skills.list; no target returned them.
	apiErr := func(code string) error {
		return slack.SlackErrorResponse{Err: code}
	}

	cases := []struct {
		name string
		err  error
		want llx.ErrorKind
	}{
		{"missing scope", apiErr("missing_scope"), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"workspace token instead of org user token", apiErr("not_allowed_token_type"), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"caller is no org admin", apiErr("not_an_admin"), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"workspace access not granted", apiErr("team_access_not_granted"), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
		{"not on Enterprise Grid", apiErr("not_an_enterprise"), llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{"admin APIs not enabled", apiErr("feature_not_enabled"), llx.ErrorKind_ERROR_KIND_NOT_APPLICABLE},
		{"revoked token", apiErr("token_revoked"), llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"invalid auth", apiErr("invalid_auth"), llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"deprecated method", apiErr("method_deprecated"), llx.ErrorKind_ERROR_KIND_GONE},
		{"server failure", apiErr("internal_error"), llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"workspace migrating", apiErr("team_added_to_org"), llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"rate limited code", apiErr("ratelimited"), llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"rate limited response", &slack.RateLimitedError{RetryAfter: 30 * time.Second}, llx.ErrorKind_ERROR_KIND_TOO_MANY_REQUESTS},
		{"HTTP 503", slack.StatusCodeError{Code: 503, Status: "503 Service Unavailable"}, llx.ErrorKind_ERROR_KIND_UNAVAILABLE},
		{"HTTP 401", slack.StatusCodeError{Code: 401, Status: "401 Unauthorized"}, llx.ErrorKind_ERROR_KIND_UNAUTHENTICATED},
		{"wrapped API error", fmt.Errorf("listing apps: %w", apiErr("missing_scope")), llx.ErrorKind_ERROR_KIND_FORBIDDEN},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyError(tc.err, adminAppsReadScope)
			assert.Equal(t, tc.want, llx.KindOf(got))
			// SlackErrorResponse holds slices, so errors.Is cannot compare it;
			// the Slack message must survive classification.
			assert.Contains(t, got.Error(), tc.err.Error())
		})
	}
}

func TestClassifyErrorLeavesOthersUnclassified(t *testing.T) {
	// Synthetic: inputs that are not a refusal Slack documents.
	cases := []struct {
		name string
		err  error
	}{
		{"bad cursor", slack.SlackErrorResponse{Err: "invalid_cursor"}},
		{"unknown code", slack.SlackErrorResponse{Err: "something_new"}},
		{"transport failure", &url.Error{Op: "Post", URL: "https://slack.com/api/admin.apps.approved.list", Err: errors.New("connection refused")}},
		{"HTTP 400", slack.StatusCodeError{Code: 400, Status: "400 Bad Request"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyError(tc.err, adminAppsReadScope)
			var lerr *llx.Error
			assert.False(t, errors.As(got, &lerr), "expected no llx error kind, got %v", llx.KindOf(got))
			assert.Equal(t, tc.err, got)
		})
	}
}

func TestClassifyErrorRecordsScopeAndRetryAfter(t *testing.T) {
	// Synthetic: the scope a refusal names and Slack's Retry-After hint.
	var lerr *llx.Error
	require.True(t, errors.As(classifyError(slack.SlackErrorResponse{Err: "missing_scope"}, adminAppsReadScope), &lerr))
	assert.Equal(t, []string{"admin.apps:read"}, lerr.Permissions)

	lerr = nil
	require.True(t, errors.As(classifyError(&slack.RateLimitedError{RetryAfter: 30 * time.Second}, ""), &lerr))
	assert.Equal(t, 30*time.Second, lerr.RetryAfter)

	assert.NoError(t, classifyError(nil, adminAppsReadScope))
}
