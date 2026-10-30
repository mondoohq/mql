// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/databricks/databricks-sdk-go/apierr"
)

// databricksStatusCode reports the HTTP status a Databricks API error carries,
// and whether the error was an API error at all. A transport failure (DNS, TLS,
// a dropped connection, a cancelled context) never produces an
// apierr.APIError, so it reports false and can never be mistaken for an answer
// the server gave.
func databricksStatusCode(err error) (int, bool) {
	if err == nil {
		return 0, false
	}
	var apiErr *apierr.APIError
	if !errors.As(err, &apiErr) || apiErr == nil {
		return 0, false
	}
	if apiErr.StatusCode == 0 {
		return 0, false
	}
	return apiErr.StatusCode, true
}

// isDatabricksUnreadable reports whether a call failed because the caller is
// not allowed to read the object, rather than because the object holds
// nothing. A field that hits this reports null: "not allowed to look" and
// "there is nothing there" are different answers, and a security check must not
// pass on the first while believing the second.
func isDatabricksUnreadable(err error) bool {
	code, ok := databricksStatusCode(err)
	if !ok {
		return false
	}
	return code == 401 || code == 403
}

// isDatabricksFeatureUnavailable reports whether a call failed because the
// feature it addresses is not present on this account or workspace, which
// Databricks answers with 400 (the securable or setting is not enabled), 404
// (the endpoint is not served on this tier), or 501. This is a genuine
// absence, so a collection gated on it is empty rather than null. It
// deliberately does not cover 403, which is a permission failure.
func isDatabricksFeatureUnavailable(err error) bool {
	code, ok := databricksStatusCode(err)
	if !ok {
		return false
	}
	return code == 400 || code == 404 || code == 501
}
