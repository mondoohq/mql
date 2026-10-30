// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package sdk

import (
	"context"
	"net/http"

	"github.com/okta/okta-sdk-golang/v6/okta"
)

// ListClientRoleGroupTargets fetches the groups an OAuth 2.0 service client's
// administrator role assignment is narrowed to, hitting
// `/oauth2/v1/clients/{clientId}/roles/{roleId}/targets/groups`.
//
// The SDK's RoleTargetAPI.ListGroupTargetRoleForClient types this endpoint's
// response as a single Client object, which carries no targets, so the request
// is issued here instead. This is the same generated-type mismatch that made
// ListClientRoles necessary.
func (m *ApiExtension) ListClientRoleGroupTargets(ctx context.Context, clientID, roleID string) ([]okta.Group, *http.Response, error) {
	return getPaged[okta.Group](ctx, m, "/oauth2/v1/clients/"+clientID+"/roles/"+roleID+"/targets/groups")
}

// ListClientRoleAppTargets fetches the applications an OAuth 2.0 service
// client's administrator role assignment is narrowed to, hitting
// `/oauth2/v1/clients/{clientId}/roles/{roleId}/targets/catalog/apps`.
//
// As with the group targets above, the SDK types
// RoleTargetAPI.ListAppTargetRoleToClient's response as a single Client, so the
// request is issued here.
func (m *ApiExtension) ListClientRoleAppTargets(ctx context.Context, clientID, roleID string) ([]okta.CatalogApplication, *http.Response, error) {
	return getPaged[okta.CatalogApplication](ctx, m, "/oauth2/v1/clients/"+clientID+"/roles/"+roleID+"/targets/catalog/apps")
}
