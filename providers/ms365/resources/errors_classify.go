// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"strings"

	"github.com/cockroachdb/errors"
	betaodataerrors "github.com/microsoftgraph/msgraph-beta-sdk-go/models/odataerrors"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"go.mondoo.com/mql/llx"
)

// graphStatusCode returns the HTTP status Microsoft Graph answered a failed
// request with, or 0 when the error carries no Graph response (a transport
// failure, a context cancellation). Both SDKs' ODataError embed the Kiota
// ApiError, which reports the status through GetStatusCode.
func graphStatusCode(err error) int {
	var statusErr interface{ GetStatusCode() int }
	if errors.As(err, &statusErr) && statusErr != nil {
		return statusErr.GetStatusCode()
	}
	return 0
}

// graphErrorMessage returns the message Microsoft Graph attached to a failed
// request, or "" when there is none.
func graphErrorMessage(err error) string {
	var betaOdataErr *betaodataerrors.ODataError
	if errors.As(err, &betaOdataErr) && betaOdataErr != nil {
		if payload := betaOdataErr.GetErrorEscaped(); payload != nil && payload.GetMessage() != nil {
			return *payload.GetMessage()
		}
	}
	var oDataErr *odataerrors.ODataError
	if errors.As(err, &oDataErr) && oDataErr != nil {
		if payload := oDataErr.GetErrorEscaped(); payload != nil && payload.GetMessage() != nil {
			return *payload.GetMessage()
		}
	}
	return ""
}

// isGraphLicenseRequired reports whether Graph refused a request because the
// tenant lacks the license the feature needs, rather than because the caller
// lacks a permission. Graph answers both with 403, so the message decides.
func isGraphLicenseRequired(message string) bool {
	m := strings.ToLower(message)
	return strings.Contains(m, "license") || strings.Contains(m, "licence")
}

// classifyGraphError gives a refused Graph read its ADR 046 kind: a 401 is
// Unauthenticated, a 403 for a missing license is NotApplicable, any other 403
// is Forbidden naming the Graph permission the call needs. Anything else is
// returned unchanged, since a wrong kind is worse than none.
func classifyGraphError(err error, permissions ...string) error {
	if err == nil {
		return nil
	}
	switch graphStatusCode(err) {
	case http.StatusUnauthorized:
		return llx.Unauthenticated(err)
	case http.StatusForbidden:
		if isGraphLicenseRequired(graphErrorMessage(err)) {
			return llx.NotApplicable(err)
		}
		return llx.Forbidden(err, llx.WithPermissions(permissions...))
	}
	return err
}
