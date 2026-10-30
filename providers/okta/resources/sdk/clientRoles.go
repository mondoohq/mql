// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/http"

	"github.com/okta/okta-sdk-golang/v6/okta"
)

// ListClientRoles fetches the administrator roles assigned to an OAuth 2.0
// service client, hitting `/oauth2/v1/clients/{clientId}/roles`. The SDK's
// generated RoleAssignmentAPI.ListRolesForClient types this endpoint's
// response as a single Client object, which does not carry the returned roles
// array, so we issue the request ourselves and decode it into the role type
// the resource mapper already understands.
//
// The returned http.Response is the first page's response so callers can treat
// a 404 (client has no role assignments, or is not a service client) as an
// empty result.
func (m *ApiExtension) ListClientRoles(ctx context.Context, clientID string) ([]*okta.Role, *http.Response, error) {
	roles := []*okta.Role{}
	nextURL := m.url("/oauth2/v1/clients/" + clientID + "/roles")
	var firstResp *http.Response

	for nextURL != "" {
		var page []*okta.Role
		resp, err := m.get(ctx, nextURL, &page)
		if firstResp == nil {
			firstResp = resp
		}
		if err != nil {
			return nil, resp, err
		}
		roles = append(roles, page...)
		if resp == nil {
			break
		}
		nextURL = nextPageURL(nextURL, resp.Header.Values("Link"))
	}

	return roles, firstResp, nil
}
