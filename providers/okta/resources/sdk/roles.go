// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/http"
)

type ListCustomRolesResponse struct {
	Roles []*CustomRole `json:"roles,omitempty"`
}

type CustomRole struct {
	Id          string   `json:"id,omitempty"`
	Label       string   `json:"label,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
	Links       any      `json:"_links,omitempty"`
}

// ListCustomRoles fetches all custom IAM roles, following Okta's
// `Link: <url>; rel="next"` pagination. The returned http.Response is the first
// page's response, so callers can branch on its status code (e.g. treat 404 as
// an empty result).
func (m *ApiExtension) ListCustomRoles(ctx context.Context) ([]*CustomRole, *http.Response, error) {
	roles := []*CustomRole{}
	nextURL := m.url("/api/v1/iam/roles")
	var firstResp *http.Response

	for nextURL != "" {
		var page ListCustomRolesResponse
		resp, err := m.get(ctx, nextURL, &page)
		if firstResp == nil {
			firstResp = resp
		}
		if err != nil {
			return nil, resp, err
		}
		roles = append(roles, page.Roles...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return roles, firstResp, nil
}
