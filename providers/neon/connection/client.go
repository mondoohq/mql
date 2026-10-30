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
)

// APIError captures a non-2xx response from the Neon API.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Path       string
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("neon API %s: %d %s (%s)", e.Path, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("neon API %s: %d %s", e.Path, e.StatusCode, e.Code)
}

// IsForbidden reports whether err is a 401/403 access-denied response. Callers
// degrade to null rather than failing the whole scan, since a personal API key
// cannot read organization-scoped endpoints and plan-gated features answer 403.
func IsForbidden(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode == http.StatusForbidden
	}
	return false
}

// IsNotFound reports whether err is a 404 response.
func IsNotFound(err error) bool {
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == http.StatusNotFound
	}
	return false
}

// Get performs a GET against the Neon API and decodes the JSON body into out.
func (c *NeonConnection) Get(ctx context.Context, path string, query url.Values, out any) error {
	body, err := c.do(ctx, path, query)
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("neon API %s: decode response: %w", path, err)
	}
	return nil
}

func (c *NeonConnection) do(ctx context.Context, path string, query url.Values) ([]byte, error) {
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
		return nil, fmt.Errorf("neon API %s: %w", path, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("neon API %s: read response: %w", path, err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: resp.StatusCode, Path: path}
		var envelope struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(body, &envelope) == nil {
			apiErr.Code = envelope.Code
			apiErr.Message = envelope.Message
		}
		return nil, apiErr
	}

	return body, nil
}

// pageSize is the number of records requested per page on the cursor-paginated
// endpoints.
const pageSize = 100

// maxPages bounds a paginated walk so an endpoint that answers with a
// stationary cursor cannot loop forever.
const maxPages = 200

// GetPagedCursor walks Neon's cursor pagination for a list endpoint,
// collecting every element under the given JSON key. The cursor of the last
// page is passed back as the cursor parameter of the next request; a page
// shorter than the requested limit ends the walk.
//
// Neon serves two pagination shapes under the same `pagination` object. Older
// endpoints, such as the project list, carry the next cursor as `cursor`;
// newer ones, such as a project's branches and an organization's members,
// carry it as `next`. Both are read here, because an endpoint whose shape goes
// unread looks exactly like a single short page and would silently truncate
// the list at the first page.
func GetPagedCursor[T any](ctx context.Context, c *NeonConnection, path string, query url.Values, key string) ([]T, error) {
	if query == nil {
		query = url.Values{}
	}
	query.Set("limit", strconv.Itoa(pageSize))

	var results []T
	for range maxPages {
		sent := query.Get("cursor")

		body, err := c.do(ctx, path, query)
		if err != nil {
			return nil, err
		}

		var envelope map[string]json.RawMessage
		if err := json.Unmarshal(body, &envelope); err != nil {
			return nil, fmt.Errorf("neon API %s: decode response: %w", path, err)
		}

		var batch []T
		if raw, ok := envelope[key]; ok && len(raw) > 0 && string(raw) != "null" {
			if err := json.Unmarshal(raw, &batch); err != nil {
				return nil, fmt.Errorf("neon API %s: decode %q: %w", path, key, err)
			}
		}
		results = append(results, batch...)

		// A short page is the last page.
		if len(batch) < pageSize {
			break
		}

		var pg struct {
			Pagination *struct {
				Cursor string `json:"cursor"`
				Next   string `json:"next"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(body, &pg); err != nil {
			return nil, fmt.Errorf("neon API %s: decode pagination: %w", path, err)
		}
		if pg.Pagination == nil {
			break
		}

		next := pg.Pagination.Next
		if next == "" {
			next = pg.Pagination.Cursor
		}
		if next == "" {
			break
		}

		// A cursor that comes straight back means the endpoint ignored it and
		// would replay the same page for every further request.
		if next == sent {
			break
		}
		query.Set("cursor", next)
	}

	return results, nil
}

// GetList fetches a list endpoint that does not paginate, returning the
// elements held under the given JSON key.
func GetList[T any](ctx context.Context, c *NeonConnection, path string, query url.Values, key string) ([]T, error) {
	body, err := c.do(ctx, path, query)
	if err != nil {
		return nil, err
	}

	// A few endpoints answer with a bare array rather than an envelope.
	if key == "" {
		var out []T
		if err := json.Unmarshal(body, &out); err != nil {
			return nil, fmt.Errorf("neon API %s: decode response: %w", path, err)
		}
		return out, nil
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, fmt.Errorf("neon API %s: decode response: %w", path, err)
	}

	raw, ok := envelope[key]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}

	var out []T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("neon API %s: decode %q: %w", path, key, err)
	}
	return out, nil
}
