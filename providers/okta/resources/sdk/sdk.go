// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// APIError is what a raw Okta endpoint answers a >= 400 status with. It keeps
// the status code and the Okta error code from the response body so callers can
// tell a feature the org does not have from a request that genuinely failed,
// without matching on message text. The message is the full body, which is what
// callers that already branch on its content read.
type APIError struct {
	// URL is the absolute URL the request was issued against.
	URL string
	// Status is the HTTP status line, e.g. "404 Not Found".
	Status string
	// StatusCode is the HTTP status code.
	StatusCode int
	// Code is the Okta error code carried in the body (for example
	// "E0000015"), or "" when the body carries none.
	Code string
	// Body is the raw response body.
	Body []byte
}

func (e *APIError) Error() string {
	return fmt.Sprintf("okta API request to %s failed: %s: %s", e.URL, e.Status, string(e.Body))
}

// newAPIError builds the error for a failed raw request, reading the Okta error
// code out of the body. A body that is not an Okta error object leaves Code
// empty rather than failing the request for a second reason.
func newAPIError(url string, resp *http.Response, body []byte) *APIError {
	err := &APIError{URL: url, Body: body}
	if resp != nil {
		err.Status = resp.Status
		err.StatusCode = resp.StatusCode
	}
	var decoded struct {
		ErrorCode string `json:"errorCode"`
	}
	if json.Unmarshal(body, &decoded) == nil {
		err.Code = decoded.ErrorCode
	}
	return err
}

// ApiExtension handles cases where Okta's SDK doesn't expose a particular API.
// The SDK no longer ships a public RequestExecutor, so we issue the raw
// authenticated requests ourselves against the org host carried by the
// connection.
type ApiExtension struct {
	// Host is the org host (e.g. "dev-12345.okta.com"), without scheme.
	Host string
	// Authorize stamps the Authorization header onto each outgoing request.
	// The connection supplies it so this path authenticates the same way the
	// generated SDK does, whether that is an SSWS API token or a service app's
	// private key JWT. A nil Authorize sends the request unauthenticated,
	// which Okta answers with a 401.
	Authorize func(req *http.Request) error
	// HTTPClient issues the requests. When nil, http.DefaultClient is used.
	// Tests inject a client with a custom transport so pagination can be
	// exercised without mutating any global state.
	HTTPClient *http.Client
}

// httpClient returns the configured client, falling back to the shared default.
func (m *ApiExtension) httpClient() *http.Client {
	if m.HTTPClient != nil {
		return m.HTTPClient
	}
	return http.DefaultClient
}

// get issues an authenticated GET against an absolute Okta URL and decodes the
// JSON body into out (when non-nil). It returns the raw http.Response so callers
// can inspect the status code and Link headers for pagination. On a >= 400
// status it returns the response together with an error so callers can still
// branch on resp.StatusCode (e.g. to treat 404 as an empty result).
func (m *ApiExtension) get(ctx context.Context, url string, out any) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	if m.Authorize != nil {
		if err := m.Authorize(req); err != nil {
			return nil, err
		}
	}

	resp, err := m.httpClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, err
	}
	if resp.StatusCode >= http.StatusBadRequest {
		return resp, newAPIError(url, resp, raw)
	}
	if out != nil && len(raw) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp, err
		}
	}
	return resp, nil
}

// getPaged walks every page of a collection endpoint, following the `Link:
// rel="next"` header until Okta stops offering one, and returns the
// concatenated items. The returned http.Response is the first page's, so
// callers can branch on its status code to treat a 404 as an empty result.
//
// It is a free function rather than a method because Go does not allow type
// parameters on methods.
func getPaged[T any](ctx context.Context, m *ApiExtension, path string) ([]T, *http.Response, error) {
	items := []T{}
	nextURL := m.url(path)
	var firstResp *http.Response

	for i := 0; i < maxPages && nextURL != ""; i++ {
		var page []T
		resp, err := m.get(ctx, nextURL, &page)
		if firstResp == nil {
			firstResp = resp
		}
		if err != nil {
			return nil, resp, err
		}
		items = append(items, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return items, firstResp, nil
}

// url builds an absolute org URL for the given API path (e.g. "/api/v1/zones").
func (m *ApiExtension) url(path string) string {
	return fmt.Sprintf("https://%s%s", m.Host, path)
}

// urlWithParams builds an absolute org URL with a query string, omitting the
// "?" entirely when there are no parameters so the URL does not end in a bare
// separator.
func (m *ApiExtension) urlWithParams(path string, params url.Values) string {
	u := m.url(path)
	if len(params) == 0 {
		return u
	}
	return u + "?" + params.Encode()
}
