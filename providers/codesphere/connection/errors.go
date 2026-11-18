// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	cs "github.com/codesphere-cloud/cs-go/api/openapi_client"
	"go.mondoo.com/mql/llx"
)

// Classify turns a failed API call into an error kind (ADR 046) from the HTTP
// status the API answered with. A call that never got a response (DNS,
// connection refused, timeout) has no status and stays unclassified, since a
// transport failure is not a refusal.
func Classify(resp *http.Response, err error) error {
	if err == nil {
		return nil
	}
	if resp == nil {
		return err
	}
	err = describe(resp, err)
	switch code := resp.StatusCode; {
	case code == http.StatusUnauthorized:
		// The token is rejected, so every other call on this asset fails the
		// same way.
		return llx.Unauthenticated(err, llx.WithScope(llx.ErrorScope_ERROR_SCOPE_ASSET, ""))
	case code == http.StatusForbidden:
		return llx.Forbidden(err)
	case code == http.StatusNotFound:
		return llx.NotFound(err)
	case code == http.StatusTooManyRequests:
		var opts []llx.ErrorOption
		if d, ok := retryAfter(resp.Header.Get("Retry-After")); ok {
			opts = append(opts, llx.WithRetryAfter(d))
		}
		return llx.TooManyRequests(err, opts...)
	case code >= 500:
		return llx.Unavailable(err)
	default:
		return err
	}
}

// describe replaces the API client's error text, which prints the problem's
// optional detail as a pointer address, with the request, the HTTP status,
// and the problem's title and detail.
func describe(resp *http.Response, err error) error {
	var body []byte
	var apiErr *cs.GenericOpenAPIError
	var apiErrVal cs.GenericOpenAPIError
	switch {
	case errors.As(err, &apiErr):
		body = apiErr.Body()
	case errors.As(err, &apiErrVal):
		body = apiErrVal.Body()
	default:
		return err
	}

	msg := resp.Status
	var problem struct {
		Title  *string `json:"title"`
		Detail *string `json:"detail"`
	}
	if json.Unmarshal(body, &problem) == nil {
		if problem.Title != nil && *problem.Title != "" {
			msg += ": " + *problem.Title
		}
		if problem.Detail != nil && *problem.Detail != "" {
			msg += " (" + *problem.Detail + ")"
		}
	}
	if req := resp.Request; req != nil && req.URL != nil {
		msg = "codesphere API " + req.Method + " " + req.URL.Path + ": " + msg
	}
	return errors.New(msg)
}

// retryAfter parses the delay-seconds form of a Retry-After header.
func retryAfter(v string) (time.Duration, bool) {
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0, false
	}
	return time.Duration(secs) * time.Second, true
}
