// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ApiToken represents an Okta API token. Okta's golang SDK does not (yet) expose
// the /api/v1/api-tokens endpoint, so we model the response shape ourselves.
//
// Reference: https://developer.okta.com/docs/api/openapi/okta-management/management/tags/apitoken
type ApiToken struct {
	Id          string     `json:"id,omitempty"`
	Name        string     `json:"name,omitempty"`
	UserId      string     `json:"userId,omitempty"`
	ClientName  string     `json:"clientName,omitempty"`
	Created     *time.Time `json:"created,omitempty"`
	ExpiresAt   *time.Time `json:"expiresAt,omitempty"`
	LastUpdated *time.Time `json:"lastUpdated,omitempty"`
	TokenWindow string     `json:"tokenWindow,omitempty"`
}

// ListApiTokens fetches all API tokens for the org. The endpoint requires Super
// Admin privileges. We issue it ourselves because the Okta golang SDK does not
// include this resource.
//
// Pagination follows Okta's `Link: <url>; rel="next"` response header convention
// until no `next` link is returned.
func (m *ApiExtension) ListApiTokens(ctx context.Context, limit int) ([]*ApiToken, error) {
	params := url.Values{}
	if limit > 0 {
		params.Set("limit", strconv.Itoa(limit))
	}
	nextURL := m.urlWithParams("/api/v1/api-tokens", params)

	result := []*ApiToken{}
	for i := 0; i < maxPages && nextURL != ""; i++ {
		page := []*ApiToken{}
		resp, err := m.get(ctx, nextURL, &page)
		if err != nil {
			return nil, err
		}
		result = append(result, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return result, nil
}

// nextPageURL returns the URL of the page after the one just fetched, or an
// empty string when the walk is over. A `next` link pointing back at the URL
// that produced it is treated as the end: following it would re-fetch the same
// page until the page cap and report every record it holds that many times
// over, which reads as a real collection rather than as a failure.
func nextPageURL(current string, headers []string) string {
	next := nextLinkURL(headers)
	if next == current {
		return ""
	}
	return next
}

// nextLinkURL parses RFC 5988 `Link` headers and returns the URL whose rel is `next`,
// or an empty string when no such link is present. Okta returns one Link entry per
// header value (e.g., `<https://...>; rel="next"`).
func nextLinkURL(headers []string) string {
	for _, h := range headers {
		parts := strings.Split(h, ";")
		if len(parts) < 2 {
			continue
		}
		rel := ""
		for _, p := range parts[1:] {
			if strings.Contains(p, `rel="next"`) {
				rel = "next"
				break
			}
		}
		if rel != "next" {
			continue
		}
		raw := strings.TrimSpace(parts[0])
		raw = strings.TrimPrefix(raw, "<")
		raw = strings.TrimSuffix(raw, ">")
		return raw
	}
	return ""
}
