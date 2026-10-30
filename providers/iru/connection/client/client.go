// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package client is a hand-rolled REST client for the Iru (formerly Kandji)
// API. Iru does not publish a Go SDK; the surface we need is small enough
// (devices, blueprints, library items, users, tenant) that a typed client
// is less code than wrapping a community SDK and lets us own pagination
// and rate-limit semantics.
package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	defaultPageLimit = 300
	defaultTimeout   = 60 * time.Second

	// maxErrorBodyBytes caps how much of a non-2xx response body we read into
	// an APIError, so a misbehaving server can't return a huge payload and
	// exhaust memory.
	maxErrorBodyBytes = 64 * 1024
)

// Client talks to a single Iru tenant.
type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
}

// New builds a client for the given base URL (e.g. https://<sub>.api.kandji.io)
// and bearer token. The base URL may omit a trailing slash and may include or
// omit a scheme; missing schemes default to https.
func New(baseURL, token string) (*Client, error) {
	if token == "" {
		return nil, errors.New("iru: missing API token")
	}
	if baseURL == "" {
		return nil, errors.New("iru: missing API URL")
	}
	if !strings.Contains(baseURL, "://") {
		baseURL = "https://" + baseURL
	}
	u, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil {
		return nil, fmt.Errorf("iru: invalid API URL: %w", err)
	}
	return &Client{
		baseURL:    u,
		token:      token,
		httpClient: &http.Client{Timeout: defaultTimeout},
	}, nil
}

// BaseURL returns the tenant base URL the client was configured with.
func (c *Client) BaseURL() string { return c.baseURL.String() }

// APIError represents a non-2xx response from the Iru API.
type APIError struct {
	StatusCode int
	Path       string
	Body       string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("iru: %s returned %d: %s", e.Path, e.StatusCode, e.Body)
}

// IsAccessDenied returns true for 401/403 responses, the analog of
// AWS's Is400AccessDeniedError. Callers can use this to log-and-skip
// rather than failing the whole query when a token lacks a permission
// flag for a specific endpoint.
func IsAccessDenied(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

// do issues a GET against the given path with optional query params and
// decodes the JSON response into out. 429 responses honor Retry-After.
func (c *Client) do(path string, query url.Values, out any) error {
	u := *c.baseURL
	u.Path = strings.TrimRight(u.Path, "/") + "/" + strings.TrimLeft(path, "/")
	if query != nil {
		u.RawQuery = query.Encode()
	}

	for range 4 {
		req, err := http.NewRequest(http.MethodGet, u.String(), nil)
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("Accept", "application/json")

		resp, err := c.httpClient.Do(req)
		if err != nil {
			return err
		}

		if resp.StatusCode == http.StatusTooManyRequests {
			retryAfter := parseRetryAfter(resp.Header.Get("Retry-After"))
			resp.Body.Close()
			time.Sleep(retryAfter)
			continue
		}

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			// Cap the error body so a malformed or adversarial server can't
			// exhaust memory with a multi-GB 4xx/5xx payload.
			body, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodyBytes))
			resp.Body.Close()
			return &APIError{StatusCode: resp.StatusCode, Path: path, Body: strings.TrimSpace(string(body))}
		}

		if out == nil {
			resp.Body.Close()
			return nil
		}
		err = json.NewDecoder(resp.Body).Decode(out)
		resp.Body.Close()
		return err
	}
	return fmt.Errorf("iru: %s exceeded retry budget", path)
}

// maxRetryAfter caps the wait Retry-After can induce so a misbehaving or
// adversarial server can't park a goroutine indefinitely.
const maxRetryAfter = 30 * time.Second

func parseRetryAfter(h string) time.Duration {
	if h == "" {
		return 2 * time.Second
	}
	if n, err := strconv.Atoi(h); err == nil && n > 0 {
		d := time.Duration(n) * time.Second
		if d > maxRetryAfter {
			return maxRetryAfter
		}
		return d
	}
	return 2 * time.Second
}

// paginateArray fetches every page of a listing endpoint that returns a
// bare JSON array and pages with limit/offset (the /devices endpoint). It
// stops once a page returns fewer than a full page of rows.
func (c *Client) paginateArray(path string, decode func(raw json.RawMessage) (int, error)) error {
	offset := 0
	for {
		q := url.Values{}
		q.Set("limit", strconv.Itoa(defaultPageLimit))
		q.Set("offset", strconv.Itoa(offset))

		var raw json.RawMessage
		if err := c.do(path, q, &raw); err != nil {
			return err
		}
		n, err := decode(raw)
		if err != nil {
			return err
		}
		if n < defaultPageLimit {
			return nil
		}
		offset += n
	}
}

// paginateEnvelope walks a listing endpoint that returns a DRF-style
// envelope, {"results": [...], "next": "<url>"}, and follows the `next`
// link until it is null. This handles both the offset-paged endpoints
// (blueprints, library items) and the cursor-paged ones (users), because
// both hand back the next page as a fully-formed URL. decode receives the
// raw `results` array for each page.
func (c *Client) paginateEnvelope(path string, decode func(results json.RawMessage) error) error {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(defaultPageLimit))
	for {
		var env struct {
			Next    string          `json:"next"`
			Results json.RawMessage `json:"results"`
		}
		if err := c.do(path, q, &env); err != nil {
			return err
		}
		if len(env.Results) > 0 {
			if err := decode(env.Results); err != nil {
				return err
			}
		}
		if env.Next == "" {
			return nil
		}
		// `next` is an absolute URL on the tenant host; reuse its path and
		// query (offset or cursor) verbatim for the following request.
		u, err := url.Parse(env.Next)
		if err != nil {
			return err
		}
		path = u.Path
		q = u.Query()
	}
}
