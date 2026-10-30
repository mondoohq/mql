// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"net/http"

	"github.com/slack-go/slack"
	"go.mondoo.com/mql/llx"
)

// classifyError turns a Slack Web API failure into an llx error kind (ADR
// 046). scope is the OAuth scope the call needs, for example admin.apps:read,
// recorded on a refusal. Error codes Slack does not document as a refusal, an
// unavailable feature or a server-side failure, and anything that is not an
// API answer (a transport failure, a timeout), are returned unclassified.
func classifyError(err error, scope string) error {
	if err == nil {
		return nil
	}

	var rateLimited *slack.RateLimitedError
	if errors.As(err, &rateLimited) {
		return llx.TooManyRequests(err, llx.WithRetryAfter(rateLimited.RetryAfter))
	}

	var statusErr slack.StatusCodeError
	if errors.As(err, &statusErr) {
		switch {
		case statusErr.Code == http.StatusUnauthorized:
			return llx.Unauthenticated(err)
		case statusErr.Code == http.StatusForbidden:
			return llx.Forbidden(err, permissionOpts(scope)...)
		case statusErr.Code == http.StatusTooManyRequests:
			return llx.TooManyRequests(err)
		case statusErr.Code >= 500:
			return llx.Unavailable(err)
		}
		return err
	}

	var apiErr slack.SlackErrorResponse
	if !errors.As(err, &apiErr) {
		return err
	}

	switch apiErr.Err {
	case "invalid_auth", "not_authed", "token_expired", "token_revoked", "account_inactive":
		return llx.Unauthenticated(err)
	case "missing_scope", "not_allowed_token_type", "not_an_admin", "not_allowed",
		"no_permission", "access_denied", "restricted_action", "user_is_restricted",
		"team_access_not_granted", "two_factor_setup_required", "accesslimited":
		return llx.Forbidden(err, permissionOpts(scope)...)
	case "not_an_enterprise", "feature_not_enabled", "enterprise_is_restricted":
		return llx.NotApplicable(err)
	case "method_deprecated", "deprecated_endpoint":
		return llx.Gone(err)
	case "ratelimited":
		return llx.TooManyRequests(err)
	case "fatal_error", "internal_error", "service_unavailable", "org_login_required", "team_added_to_org":
		return llx.Unavailable(err)
	}
	return err
}

func permissionOpts(scope string) []llx.ErrorOption {
	if scope == "" {
		return nil
	}
	return []llx.ErrorOption{llx.WithPermissions(scope)}
}
