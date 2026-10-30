// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"errors"

	tsclient "tailscale.com/client/tailscale/v2"
)

// APIStatusCode returns the HTTP status code of a Tailscale API error, or 0
// when err is not a Tailscale API error (a transport failure, a context
// cancellation, a JSON decode error).
func APIStatusCode(err error) int {
	if err == nil {
		return 0
	}

	var apiErr tsclient.APIError
	if !errors.As(err, &apiErr) {
		return 0
	}
	return apiErr.Status
}

// IsAccessDenied reports whether err is a Tailscale API authorization failure:
// either the credential is invalid (401) or it lacks the scope required for the
// endpoint (403). OAuth clients are scoped per resource, so a tailnet the
// caller can otherwise read may still refuse individual endpoints.
func IsAccessDenied(err error) bool {
	switch APIStatusCode(err) {
	case 401, 403:
		return true
	default:
		return false
	}
}

// IsUnavailable reports whether err indicates the endpoint carries no data for
// this tailnet, either because nothing is configured (404) or because the
// tailnet's plan does not include the feature (403). Callers use it to degrade
// an optional collection to empty rather than failing the whole query.
func IsUnavailable(err error) bool {
	return tsclient.IsNotFound(err) || APIStatusCode(err) == 403
}
