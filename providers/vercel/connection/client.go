// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// APIError captures a non-2xx response from the Vercel API.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Path       string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("vercel API %s: %d %s (%s)", e.Path, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("vercel API %s: %d %s", e.Path, e.StatusCode, e.Code)
}

// IsForbidden reports whether err is a 401/403 access-denied response. Callers
// degrade to null rather than failing the whole scan, since enterprise-gated
// endpoints return 403 on Hobby and Pro plans.
func IsForbidden(err error) bool {
	var apiErr *APIError
	if ok := asAPIError(err, &apiErr); ok {
		return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

// IsNotFound reports whether err is a 404 response.
func IsNotFound(err error) bool {
	var apiErr *APIError
	if ok := asAPIError(err, &apiErr); ok {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// asAPIError unwraps err to an *APIError. It uses errors.As so a wrapped
// APIError still degrades correctly rather than propagating as a hard error.
func asAPIError(err error, target **APIError) bool {
	return errors.As(err, target)
}

// Get performs a GET against the Vercel API and decodes the JSON body into out.
func (c *VercelConnection) Get(ctx context.Context, path string, query url.Values, out any) error {
	body, err := c.do(ctx, path, query)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("vercel API %s: decode response: %w", path, err)
	}
	return nil
}

func (c *VercelConnection) do(ctx context.Context, path string, query url.Values) ([]byte, error) {
	u := c.baseURL + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("vercel API %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("vercel API %s: read response: %w", path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Path: path}
		var envelope struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(body, &envelope) == nil {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		}
		return nil, apiErr
	}

	return body, nil
}

// pagination mirrors the cursor envelope Vercel returns on paginated list
// endpoints. next is a millisecond timestamp used as the until parameter for the
// following page, or null on the last page.
type pagination struct {
	Next *int64 `json:"next"`
}

// GetPaged follows Vercel's cursor pagination for a list endpoint, collecting
// every element under the given JSON key. Endpoints that do not paginate (no
// pagination envelope) return a single page. teamId, when non-empty, scopes the
// request to a team.
func GetPaged[T any](ctx context.Context, c *VercelConnection, path string, query url.Values, key string) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}

	var results []T
	for {
		sent := query.Get("until")

		body, err := c.do(ctx, path, query)
		if err != nil {
			return nil, err
		}

		var pg struct {
			Pagination *pagination `json:"pagination"`
		}
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, fmt.Errorf("vercel API %s: decode pagination: %w", path, err)
		}

		next := ""
		if pg.Pagination != nil && pg.Pagination.Next != nil {
			next = strconv.FormatInt(*pg.Pagination.Next, 10)
		}

		// An endpoint that reports a next cursor but ignores the until
		// parameter answers every request with the first page. Detect that by
		// the cursor we sent coming straight back, and drop the response
		// instead of appending the same records a second time.
		if sent != "" && next == sent {
			break
		}

		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("vercel API %s: decode response: %w", path, err)
		}

		if raw, ok := envelope[key]; ok && len(raw) > 0 && !isJSONNull(raw) {
			var page []T
			if err := json.Unmarshal(raw, &page); err != nil {
				return nil, fmt.Errorf("vercel API %s: decode %q: %w", path, key, err)
			}
			results = append(results, page...)
		}

		if next == "" {
			break
		}
		query.Set("until", next)
	}

	return results, nil
}

// GetPagedFrom follows the continuation-token pagination used by the newer list
// endpoints, where the next cursor is passed back as the from parameter and may
// arrive as either an opaque string token or a numeric timestamp.
func GetPagedFrom[T any](ctx context.Context, c *VercelConnection, path string, query url.Values, key string) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}

	var results []T
	for {
		sent := query.Get("from")

		body, err := c.do(ctx, path, query)
		if err != nil {
			return nil, err
		}

		var pg struct {
			Pagination *struct {
				Next json.RawMessage `json:"next"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, fmt.Errorf("vercel API %s: decode pagination: %w", path, err)
		}

		next := ""
		if pg.Pagination != nil && len(pg.Pagination.Next) > 0 && !isJSONNull(pg.Pagination.Next) {
			next = cursorValue(pg.Pagination.Next)
		}

		// As in GetPaged, a cursor echoed straight back means the endpoint
		// ignored it and replayed the first page, so the records are already
		// held and must not be appended twice.
		if sent != "" && next == sent {
			break
		}

		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("vercel API %s: decode response: %w", path, err)
		}

		if raw, ok := envelope[key]; ok && len(raw) > 0 && !isJSONNull(raw) {
			var page []T
			if err := json.Unmarshal(raw, &page); err != nil {
				return nil, fmt.Errorf("vercel API %s: decode %q: %w", path, key, err)
			}
			results = append(results, page...)
		}

		if next == "" {
			break
		}
		query.Set("from", next)
	}

	return results, nil
}

// cursorValue renders a continuation cursor as the string form the from
// parameter expects, accepting either a quoted token or a bare number.
func cursorValue(raw json.RawMessage) string {
	var token string
	if err := json.Unmarshal(raw, &token); err == nil {
		return token
	}
	var num int64
	if err := json.Unmarshal(raw, &num); err == nil {
		return strconv.FormatInt(num, 10)
	}
	return ""
}

func isJSONNull(raw json.RawMessage) bool {
	return strings.TrimSpace(string(raw)) == "null"
}

// cursorPagination mirrors the string-cursor envelope used by a few endpoints
// (for example access-group members and projects), where next is an opaque
// continuation token passed back as the next parameter.
type cursorPagination struct {
	Next *string `json:"next"`
}

// GetPagedCursor follows string-cursor pagination for a list endpoint,
// collecting every element under the given JSON key. It is the counterpart to
// GetPaged for endpoints that page with an opaque next token rather than an
// until timestamp.
func GetPagedCursor[T any](ctx context.Context, c *VercelConnection, path string, query url.Values, key string) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}

	var results []T
	for {
		sent := query.Get("next")

		body, err := c.do(ctx, path, query)
		if err != nil {
			return nil, err
		}

		var pg struct {
			Pagination *cursorPagination `json:"pagination"`
		}
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, fmt.Errorf("vercel API %s: decode pagination: %w", path, err)
		}

		next := ""
		if pg.Pagination != nil && pg.Pagination.Next != nil {
			next = *pg.Pagination.Next
		}

		// As in GetPaged, an endpoint that reports a cursor but ignores the
		// next parameter replays the first page forever. The records are
		// already held, so the response is dropped rather than appended twice.
		if sent != "" && next == sent {
			break
		}

		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("vercel API %s: decode response: %w", path, err)
		}

		if raw, ok := envelope[key]; ok && len(raw) > 0 && !isJSONNull(raw) {
			var page []T
			if err := json.Unmarshal(raw, &page); err != nil {
				return nil, fmt.Errorf("vercel API %s: decode %q: %w", path, key, err)
			}
			results = append(results, page...)
		}

		if next == "" {
			break
		}
		query.Set("next", next)
	}

	return results, nil
}

// TeamQuery returns a url.Values pre-populated with the given team id, or empty
// values when teamID is blank.
func TeamQuery(teamID string) url.Values {
	q := url.Values{}
	if teamID != "" {
		q.Set("teamId", teamID)
	}
	return q
}
