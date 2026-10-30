// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mistralai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const (
	DefaultBaseURL   = "https://api.mistral.ai"
	maxErrorBodySize = 64 << 10
	defaultPageSize  = 100
)

type Client struct {
	baseURL    string
	token      string
	httpClient *http.Client
}

type ClientOption func(*Client)

func WithBaseURL(url string) ClientOption {
	return func(c *Client) {
		c.baseURL = url
	}
}

func NewClient(token string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: DefaultBaseURL,
		token:   token,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *Client) request(ctx context.Context, method, endpoint string, result any) error {
	u, err := url.Parse(c.baseURL + endpoint)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBodySize))
		var apiErr APIError
		if err := json.Unmarshal(bodyBytes, &apiErr); err != nil {
			return &APIError{
				Message:    fmt.Sprintf("request failed (status: %d): %s", resp.StatusCode, string(bodyBytes)),
				StatusCode: resp.StatusCode,
			}
		}
		apiErr.StatusCode = resp.StatusCode
		return &apiErr
	}

	if result != nil {
		if err := json.NewDecoder(resp.Body).Decode(result); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}

	return nil
}

func (c *Client) ListModels(ctx context.Context) (*ModelList, error) {
	var models ModelList
	if err := c.request(ctx, http.MethodGet, "/v1/models", &models); err != nil {
		return nil, err
	}
	return &models, nil
}

func (c *Client) GetModel(ctx context.Context, modelID string) (*Model, error) {
	var model Model
	if err := c.request(ctx, http.MethodGet, "/v1/models/"+url.PathEscape(modelID), &model); err != nil {
		return nil, err
	}
	return &model, nil
}

// pagedList is the envelope every offset-paginated Mistral list endpoint
// returns. Total and HasMore are pointers so a missing field ("null" or
// absent) is distinguishable from a real zero/false.
type pagedList[T any] struct {
	Data    []T    `json:"data"`
	Object  string `json:"object"`
	Total   *int   `json:"total"`
	HasMore *bool  `json:"has_more"`
}

// listPaged walks every page of an offset-paginated endpoint and returns the
// concatenated results. Termination prefers the strongest signal the API
// actually provides, so it stays correct whether or not a given endpoint
// returns has_more/total, and even if the server caps page_size below what we
// request:
//  1. an empty page means there is nothing left;
//  2. an explicit has_more:false means the server says it is done;
//  3. otherwise, if a total is reported, stop once we have collected it;
//  4. with no pagination metadata at all, a short page is the last page.
func listPaged[T any](ctx context.Context, c *Client, path string) ([]T, error) {
	var all []T
	for page := 0; ; page++ {
		var resp pagedList[T]
		endpoint := fmt.Sprintf("%s?page=%d&page_size=%d", path, page, defaultPageSize)
		if err := c.request(ctx, http.MethodGet, endpoint, &resp); err != nil {
			return nil, err
		}
		all = append(all, resp.Data...)

		switch {
		case len(resp.Data) == 0:
			return all, nil
		case resp.HasMore != nil:
			if !*resp.HasMore {
				return all, nil
			}
		case resp.Total != nil:
			if len(all) >= *resp.Total {
				return all, nil
			}
		case len(resp.Data) < defaultPageSize:
			return all, nil
		}
	}
}

func (c *Client) ListFineTuningJobs(ctx context.Context) ([]FineTuningJob, error) {
	return listPaged[FineTuningJob](ctx, c, "/v1/fine_tuning/jobs")
}

func (c *Client) ListFiles(ctx context.Context) ([]File, error) {
	return listPaged[File](ctx, c, "/v1/files")
}

func (c *Client) ListBatchJobs(ctx context.Context) ([]BatchJob, error) {
	return listPaged[BatchJob](ctx, c, "/v1/batch/jobs")
}

// ListConnectors walks every page of GET /v1/connectors. That endpoint uses
// keyset pagination rather than the offset envelope the older list endpoints
// return: it reports the next cursor under pagination.next_cursor and a null
// or empty cursor means the walk is finished. A server that keeps handing back
// the cursor it was given would otherwise loop forever, so a repeated cursor
// also ends the walk.
func (c *Client) ListConnectors(ctx context.Context) ([]Connector, error) {
	var all []Connector
	cursor := ""
	seen := map[string]bool{}
	for {
		q := url.Values{}
		q.Set("page_size", strconv.Itoa(defaultPageSize))
		if cursor != "" {
			q.Set("cursor", cursor)
		}

		var page connectorPage
		if err := c.request(ctx, http.MethodGet, "/v1/connectors?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		all = append(all, page.Items...)

		if page.Pagination.NextCursor == nil || *page.Pagination.NextCursor == "" {
			return all, nil
		}
		next := *page.Pagination.NextCursor
		if seen[next] {
			return all, nil
		}
		seen[next] = true
		cursor = next
	}
}

// ListLibraries walks every page of GET /v1/libraries. The endpoint offers both
// a deprecated offset "page" parameter and an opaque continuation token; the
// token is the supported form, so the walk follows next_page_token and stops
// when it comes back null, empty, or unchanged.
func (c *Client) ListLibraries(ctx context.Context) ([]Library, error) {
	var all []Library
	token := ""
	seen := map[string]bool{}
	for {
		q := url.Values{}
		q.Set("page_size", strconv.Itoa(defaultPageSize))
		if token != "" {
			q.Set("page_token", token)
		}

		var page libraryPage
		if err := c.request(ctx, http.MethodGet, "/v1/libraries?"+q.Encode(), &page); err != nil {
			return nil, err
		}
		all = append(all, page.Data...)

		if page.NextPageToken == nil || *page.NextPageToken == "" {
			return all, nil
		}
		next := *page.NextPageToken
		if seen[next] {
			return all, nil
		}
		seen[next] = true
		token = next
	}
}

// ListLibraryAccesses returns every entity a library is shared with. The
// endpoint is not paginated.
func (c *Client) ListLibraryAccesses(ctx context.Context, libraryID string) ([]LibraryAccess, error) {
	var resp libraryAccessList
	endpoint := "/v1/libraries/" + url.PathEscape(libraryID) + "/share"
	if err := c.request(ctx, http.MethodGet, endpoint, &resp); err != nil {
		return nil, err
	}
	return resp.Data, nil
}

func IsAccessDenied(err error) bool {
	if err == nil {
		return false
	}
	if apiErr, ok := errors.AsType[*APIError](err); ok {
		return apiErr.StatusCode == 401 || apiErr.StatusCode == 403
	}
	return false
}
