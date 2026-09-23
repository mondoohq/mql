// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
	"go.mongodb.org/atlas-sdk/v20250312025/admin"
)

// mqlMongodbatlasConnectedOrgConfigInternal carries the federation the
// connection belongs to, the identity providers it names, and the role mappings
// that arrived with the listing.
type mqlMongodbatlasConnectedOrgConfigInternal struct {
	cacheFederationID   string
	cacheIdpID          string
	cacheDataAccessIdps []string
	cacheRoleMappings   *[]admin.AuthFederationRoleMapping
}

// connectedOrgConfigs lists the organizations connected to the federation.
// hasRoleMappings on the federation only reports that some mapping exists;
// these carry the mappings themselves, and postAuthRoleGrants, which grants
// roles to every federated user regardless of any mapping.
func (r *mqlMongodbatlasFederationConfig) connectedOrgConfigs() ([]any, error) {
	client := atlasClient(r.MqlRuntime)
	ctx := context.Background()
	fedID := r.Id.Data

	out := []any{}
	err := forEachPage(func(page int) (int, error) {
		resp, httpResp, err := client.FederatedAuthenticationAPI.
			ListConnectedOrgConfigs(ctx, fedID).
			ItemsPerPage(pageSize).PageNum(page).Execute()
		if err != nil {
			if isAccessDenied(httpResp) {
				r.ConnectedOrgConfigs.State = plugin.StateIsSet | plugin.StateIsNull
				out = nil
				return 0, nil
			}
			return 0, err
		}
		results := resp.GetResults()
		for i := range results {
			res, err := newMqlMongodbatlasConnectedOrgConfig(r.MqlRuntime, fedID, results[i])
			if err != nil {
				return 0, err
			}
			out = append(out, res)
		}
		return len(results), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func newMqlMongodbatlasConnectedOrgConfig(runtime *plugin.Runtime, fedID string, c admin.ConnectedOrgConfig) (*mqlMongodbatlasConnectedOrgConfig, error) {
	conflicts := []string{}
	for _, u := range c.GetUserConflicts() {
		conflicts = append(conflicts, u.GetEmailAddress())
	}

	res, err := CreateResource(runtime, "mongodbatlas.connectedOrgConfig", map[string]*llx.RawData{
		// One organization can be connected to more than one federation, so
		// the federation is a dimension of the key alongside the organization.
		"__id":                            llx.StringData("mongodbatlas.connectedOrgConfig/" + fedID + "/" + c.GetOrgId()),
		"orgId":                           llx.StringData(c.GetOrgId()),
		"domainRestrictionEnabled":        llx.BoolData(c.GetDomainRestrictionEnabled()),
		"domainAllowList":                 llx.ArrayData(strSlice(c.GetDomainAllowList()), types.String),
		"postAuthRoleGrants":              llx.ArrayData(strSlice(c.GetPostAuthRoleGrants()), types.String),
		"instantUserProvisioningDisabled": llx.BoolDataPtr(c.InstantUserProvisioningDisabled),
		"conflictingUsernames":            llx.ArrayData(strSlice(conflicts), types.String),
	})
	if err != nil {
		return nil, err
	}
	cfg := res.(*mqlMongodbatlasConnectedOrgConfig)
	cfg.cacheFederationID = fedID
	cfg.cacheIdpID = c.GetIdentityProviderId()
	cfg.cacheDataAccessIdps = c.GetDataAccessIdentityProviderIds()
	cfg.cacheRoleMappings = c.RoleMappings
	return cfg, nil
}

// resolveIdentityProvider fetches one identity provider within a federation.
func resolveIdentityProvider(runtime *plugin.Runtime, fedID, idpID string) (*mqlMongodbatlasIdentityProvider, error) {
	idp, httpResp, err := atlasClient(runtime).FederatedAuthenticationAPI.
		GetIdentityProvider(context.Background(), fedID, idpID).Execute()
	if err != nil {
		if isAccessDenied(httpResp) || (httpResp != nil && httpResp.StatusCode == http.StatusNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return newMqlMongodbatlasIdentityProvider(runtime, fedID, *idp)
}

// identityProvider resolves the provider that authenticates sign-in for the
// connected organization. Null when the connection names none.
func (r *mqlMongodbatlasConnectedOrgConfig) identityProvider() (*mqlMongodbatlasIdentityProvider, error) {
	if r.cacheIdpID == "" {
		r.IdentityProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	idp, err := resolveIdentityProvider(r.MqlRuntime, r.cacheFederationID, r.cacheIdpID)
	if err != nil {
		return nil, err
	}
	if idp == nil {
		r.IdentityProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return idp, nil
}

// dataAccessIdentityProviders resolves the providers authorized to grant
// database access, which is a separate authorization from workforce sign-in.
func (r *mqlMongodbatlasConnectedOrgConfig) dataAccessIdentityProviders() ([]any, error) {
	out := []any{}
	for _, id := range r.cacheDataAccessIdps {
		if id == "" {
			continue
		}
		idp, err := resolveIdentityProvider(r.MqlRuntime, r.cacheFederationID, id)
		if err != nil {
			return nil, err
		}
		// Dropping a provider that could not be read would under-report which
		// providers grant database access, so the failure is reported.
		if idp == nil {
			r.DataAccessIdentityProviders.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		out = append(out, idp)
	}
	return out, nil
}

// roleMappings expands the mappings from identity provider group to Atlas role.
// The connected organization listing usually carries them inline; when it does
// not, they are read from the mapping endpoint.
func (r *mqlMongodbatlasConnectedOrgConfig) roleMappings() ([]any, error) {
	fedID := r.cacheFederationID
	orgID := r.OrgId.Data

	mappings := []admin.AuthFederationRoleMapping{}
	if r.cacheRoleMappings != nil {
		mappings = *r.cacheRoleMappings
	} else {
		// The role mapping endpoint answers with every mapping for the
		// connected organization and takes no page parameters.
		resp, httpResp, err := atlasClient(r.MqlRuntime).FederatedAuthenticationAPI.
			ListRoleMappings(context.Background(), fedID, orgID).Execute()
		if err != nil {
			// An unread mapping set is not an absent one, and "no mapping
			// grants ORG_OWNER" is precisely the assertion this feeds.
			if isAccessDenied(httpResp) {
				r.RoleMappings.State = plugin.StateIsSet | plugin.StateIsNull
				return nil, nil
			}
			return nil, err
		}
		mappings = resp.GetResults()
	}

	out := []any{}
	for i := range mappings {
		res, err := newMqlMongodbatlasRoleMapping(r.MqlRuntime, fedID, orgID, mappings[i])
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// mqlMongodbatlasRoleMappingInternal carries the project-scoped grants of the
// mapping, which are expanded on demand.
type mqlMongodbatlasRoleMappingInternal struct {
	cacheKey            string
	cacheProjectGrants  map[string][]string
	cacheProjectOrdered []string
}

// splitRoleAssignments separates a role mapping's assignments into the
// organization roles it grants and the per-project roles, keyed by project.
// An assignment naming a project is a project grant even when it also carries
// the organization it belongs to, so the project id is what decides.
func splitRoleAssignments(assignments []admin.ConnectedOrgConfigRoleAssignment) (orgRoles []string, projectRoles map[string][]string, projectOrder []string) {
	orgRoles = []string{}
	projectRoles = map[string][]string{}
	projectOrder = []string{}
	for _, a := range assignments {
		role := a.GetRole()
		if role == "" {
			continue
		}
		groupID := a.GetGroupId()
		if groupID == "" {
			orgRoles = append(orgRoles, role)
			continue
		}
		if _, seen := projectRoles[groupID]; !seen {
			projectOrder = append(projectOrder, groupID)
		}
		projectRoles[groupID] = append(projectRoles[groupID], role)
	}
	return orgRoles, projectRoles, projectOrder
}

func newMqlMongodbatlasRoleMapping(runtime *plugin.Runtime, fedID, orgID string, m admin.AuthFederationRoleMapping) (*mqlMongodbatlasRoleMapping, error) {
	orgRoles, projectRoles, projectOrder := splitRoleAssignments(m.GetRoleAssignments())

	// A mapping id is assigned per connected organization, so the federation
	// and the organization are both dimensions of the key. A mapping that
	// carries no id is keyed by the external group it matches, which is unique
	// within one connected organization.
	key := m.GetId()
	if key == "" {
		key = m.GetExternalGroupName()
	}

	res, err := CreateResource(runtime, "mongodbatlas.roleMapping", map[string]*llx.RawData{
		"__id":              llx.StringData("mongodbatlas.roleMapping/" + fedID + "/" + orgID + "/" + key),
		"id":                llx.StringDataPtr(m.Id),
		"externalGroupName": llx.StringData(m.GetExternalGroupName()),
		"orgRoles":          llx.ArrayData(strSlice(orgRoles), types.String),
	})
	if err != nil {
		return nil, err
	}
	mapping := res.(*mqlMongodbatlasRoleMapping)
	mapping.cacheKey = fedID + "/" + orgID + "/" + key
	mapping.cacheProjectGrants = projectRoles
	mapping.cacheProjectOrdered = projectOrder
	return mapping, nil
}

// mqlMongodbatlasRoleMappingProjectRoleInternal carries the project the grant
// applies to, resolved through the organization's project listing.
type mqlMongodbatlasRoleMappingProjectRoleInternal struct {
	cacheGroupID string
}

// projectRoles expands the mapping's project-scoped grants, one entry per
// project it grants any role on.
func (r *mqlMongodbatlasRoleMapping) projectRoles() ([]any, error) {
	out := []any{}
	for _, groupID := range r.cacheProjectOrdered {
		res, err := CreateResource(r.MqlRuntime, "mongodbatlas.roleMapping.projectRole", map[string]*llx.RawData{
			"__id":  llx.StringData("mongodbatlas.roleMapping.projectRole/" + r.cacheKey + "/" + groupID),
			"roles": llx.ArrayData(strSlice(r.cacheProjectGrants[groupID]), types.String),
		})
		if err != nil {
			return nil, err
		}
		grant := res.(*mqlMongodbatlasRoleMappingProjectRole)
		grant.cacheGroupID = groupID
		out = append(out, grant)
	}
	return out, nil
}

// project resolves the project the mapped roles apply to.
func (r *mqlMongodbatlasRoleMappingProjectRole) project() (*mqlMongodbatlasProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheGroupID)
}
