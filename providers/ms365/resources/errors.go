// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cockroachdb/errors"
	abstractions "github.com/microsoft/kiota-abstractions-go"
	betaodataerrors "github.com/microsoftgraph/msgraph-beta-sdk-go/models/odataerrors"
	"github.com/microsoftgraph/msgraph-sdk-go/models/odataerrors"
	"go.mondoo.com/mql/llx"
)

// graphErrorCode returns the Microsoft Graph error code carried by an
// ODataError -- "Request_ResourceNotFound", "Authorization_RequestDenied" and
// so on -- or "" when the error is not an ODataError or carries no code.
// Both the v1 and the beta SDK model the payload separately, so both are
// checked.
func graphErrorCode(err error) string {
	if err == nil {
		return ""
	}

	var betaOdataErr *betaodataerrors.ODataError
	if errors.As(err, &betaOdataErr) && betaOdataErr != nil {
		if payload := betaOdataErr.GetErrorEscaped(); payload != nil {
			if code := payload.GetCode(); code != nil {
				return *code
			}
		}
	}

	var oDataErr *odataerrors.ODataError
	if errors.As(err, &oDataErr) && oDataErr != nil {
		if payload := oDataErr.GetErrorEscaped(); payload != nil {
			if code := payload.GetCode(); code != nil {
				return *code
			}
		}
	}

	return ""
}

// isResourceNotFound reports whether Graph rejected the request because a
// referenced directory object no longer exists. Graph raises this for the whole
// request when an $expand cannot resolve one of its targets, so callers that
// expand a reference need it to tell a dangling reference apart from a real
// failure.
func isResourceNotFound(err error) bool {
	return graphErrorCode(err) == "Request_ResourceNotFound"
}

// graphRequestError is the readable message transformError builds for a Graph
// failure. It keeps the ODataError as its cause so graphErrorCode, and with it
// isResourceNotFound, still answers for an error that went through
// transformError, as every resource init does.
type graphRequestError struct {
	msg   string
	cause error
}

func (e *graphRequestError) Error() string { return e.msg }
func (e *graphRequestError) Unwrap() error { return e.cause }

func transformError(err error) error {
	var betaOdataErr *betaodataerrors.ODataError
	if errors.As(err, &betaOdataErr) {
		statusCode := betaOdataErr.ResponseStatusCode

		errorPayload := betaOdataErr.GetErrorEscaped()
		if errorPayload != nil && errorPayload.GetMessage() != nil {
			return &graphRequestError{
				msg:   fmt.Sprintf("an API error while performing request Code: %d, Message: %s", statusCode, *errorPayload.GetMessage()),
				cause: err,
			}
		}

		return &graphRequestError{msg: fmt.Sprintf("an API error occurred with HTTP status code %d", statusCode), cause: err}
	}

	oDataErr, ok := err.(*odataerrors.ODataError)
	if ok && oDataErr != nil {
		if err := oDataErr.GetErrorEscaped(); err != nil {
			code, msg := "", ""
			if c := err.GetCode(); c != nil {
				code = *c
			}
			if m := err.GetMessage(); m != nil {
				msg = *m
			}
			return &graphRequestError{
				msg:   fmt.Sprintf("error while performing request. Code: %s, Message: %s", code, msg),
				cause: oDataErr,
			}
		}
	}
	return err
}

// graphStatusCode returns the HTTP status of a Graph ODataError, from either
// the v1 or the beta SDK, or 0 when err is not one.
func graphStatusCode(err error) int {
	var betaOdataErr *betaodataerrors.ODataError
	if errors.As(err, &betaOdataErr) && betaOdataErr != nil {
		return betaOdataErr.ResponseStatusCode
	}
	var oDataErr *odataerrors.ODataError
	if errors.As(err, &oDataErr) && oDataErr != nil {
		return oDataErr.ResponseStatusCode
	}
	return 0
}

// graphErrorMessage returns the message Microsoft Graph attached to a failed
// request, from either the v1 or the beta SDK, or "" when there is none.
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

// classifyGraphError turns a Graph failure into the error a field returns,
// classified by the status Graph answered with:
//
//   - 401 is unauthenticated (the token was rejected),
//   - 403 is a refusal, naming the permissions the call needs, unless Graph
//     says the tenant lacks the license the feature needs, which is not
//     applicable,
//   - 429 is throttling, carrying Graph's Retry-After hint when it sent one,
//   - 5xx is the service being unavailable.
//
// Anything else, including a transport failure with no status at all, keeps
// the readable message transformError builds and stays unclassified.
func classifyGraphError(err error, permissions ...string) error {
	if err == nil {
		return nil
	}
	status := graphStatusCode(err)
	switch {
	case status == http.StatusUnauthorized:
		return llx.Unauthenticated(transformError(err))
	case status == http.StatusForbidden:
		if isPremiumLicenseRequired(err) {
			return llx.NotApplicable(transformError(err))
		}
		return llx.Forbidden(transformError(err), llx.WithPermissions(permissions...))
	case status == http.StatusTooManyRequests:
		if d, ok := graphRetryAfter(err, time.Now()); ok {
			return llx.TooManyRequests(transformError(err), llx.WithRetryAfter(d))
		}
		return llx.TooManyRequests(transformError(err))
	case status >= 500 && status <= 599:
		return llx.Unavailable(transformError(err))
	}
	return transformError(err)
}

// graphRetryAfter reads the Retry-After header of a Graph error, in either of
// its two forms (delay seconds or an HTTP date relative to now). It reports
// false when the header is absent, unparsable, or not in the future.
func graphRetryAfter(err error, now time.Time) (time.Duration, bool) {
	// Both the v1 and the beta ODataError embed the Kiota ApiError, which
	// carries the response headers, so this one structural match covers both.
	var withHeaders interface {
		GetResponseHeaders() *abstractions.ResponseHeaders
	}
	if !errors.As(err, &withHeaders) || withHeaders == nil {
		return 0, false
	}
	headers := withHeaders.GetResponseHeaders()
	if headers == nil {
		return 0, false
	}
	values := headers.Get("Retry-After")
	if len(values) == 0 {
		return 0, false
	}
	value := strings.TrimSpace(values[0])
	if secs, perr := strconv.Atoi(value); perr == nil {
		if secs <= 0 {
			return 0, false
		}
		return time.Duration(secs) * time.Second, true
	}
	if at, perr := http.ParseTime(value); perr == nil {
		if d := at.Sub(now); d > 0 {
			return d, true
		}
	}
	return 0, false
}
