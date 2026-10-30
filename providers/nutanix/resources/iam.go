// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	authn "github.com/nutanix/ntnx-api-golang-clients/iam-go-client/v4/models/iam/v4/authn"
	authz "github.com/nutanix/ntnx-api-golang-clients/iam-go-client/v4/models/iam/v4/authz"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/nutanix/connection"
	"go.mondoo.com/mql/types"
)

// ---------------------------------------------------------------------------
// users
// ---------------------------------------------------------------------------

func newMqlUser(runtime *plugin.Runtime, u *authn.User) (*mqlNutanixIamUser, error) {
	if u.ExtId == nil {
		return nil, nil
	}
	userType := ""
	if u.UserType != nil {
		userType = u.UserType.GetName()
	}
	status := ""
	if u.Status != nil {
		status = u.Status.GetName()
	}
	creationType := ""
	if u.CreationType != nil {
		creationType = u.CreationType.GetName()
	}
	res, err := CreateResource(runtime, "nutanix.iam.user", map[string]*llx.RawData{
		"__id":                        llx.StringDataPtr(u.ExtId),
		"id":                          llx.StringDataPtr(u.ExtId),
		"tenantId":                    llx.StringDataPtr(u.TenantId),
		"username":                    llx.StringDataPtr(u.Username),
		"userType":                    llx.StringData(userType),
		"status":                      llx.StringData(status),
		"creationType":                llx.StringData(creationType),
		"displayName":                 llx.StringDataPtr(u.DisplayName),
		"firstName":                   llx.StringDataPtr(u.FirstName),
		"lastName":                    llx.StringDataPtr(u.LastName),
		"emailId":                     llx.StringDataPtr(u.EmailId),
		"description":                 llx.StringDataPtr(u.Description),
		"idpId":                       llx.StringDataPtr(u.IdpId),
		"locale":                      llx.StringDataPtr(u.Locale),
		"region":                      llx.StringDataPtr(u.Region),
		"isForceResetPasswordEnabled": llx.BoolData(derefBool(u.IsForceResetPasswordEnabled)),
		"createdBy":                   llx.StringDataPtr(u.CreatedBy),
		"createdTime":                 llx.TimeDataPtr(u.CreatedTime),
		"lastLoginTime":               llx.TimeDataPtr(u.LastLoginTime),
		"lastUpdatedTime":             llx.TimeDataPtr(u.LastUpdatedTime),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanixIamUser), nil
}

func (a *mqlNutanix) users() ([]any, error) {
	conn := a.conn()
	api := conn.UsersApi()
	limit := pageSize
	res := []any{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.IamMu(), func() (*authn.ListUsersApiResponse, error) {
			return api.ListUsers(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]authn.User)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListUsers", data)
		}
		for i := range items {
			mqlUser, err := newMqlUser(a.MqlRuntime, &items[i])
			if err != nil {
				return nil, err
			}
			if mqlUser == nil {
				continue
			}
			res = append(res, mqlUser)
		}
		if len(items) < limit {
			break
		}
	}
	return res, nil
}

// userByID resolves a Nutanix IAM user by its external UUID, returning the
// cached resource when it was already created during this scan and otherwise
// fetching it on demand. A nil result means the user could not be found.
func userByID(runtime *plugin.Runtime, userID string) (*mqlNutanixIamUser, error) {
	if u, ok := cachedResource[*mqlNutanixIamUser](runtime, "nutanix.iam.user", userID); ok {
		return u, nil
	}
	conn := runtime.Connection.(*connection.NutanixConnection)
	id := userID
	resp, err := guard(conn.IamMu(), func() (*authn.GetUserApiResponse, error) {
		return conn.UsersApi().GetUserById(&id)
	})
	if err != nil {
		return nil, err
	}
	data := resp.GetData()
	if data == nil {
		return nil, nil
	}
	user, ok := data.(authn.User)
	if !ok {
		return nil, nil
	}
	return newMqlUser(runtime, &user)
}

// ---------------------------------------------------------------------------
// user groups
// ---------------------------------------------------------------------------

func (a *mqlNutanix) userGroups() ([]any, error) {
	conn := a.conn()
	api := conn.UserGroupsApi()
	limit := pageSize
	res := []any{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.IamMu(), func() (*authn.ListUserGroupsApiResponse, error) {
			return api.ListUserGroups(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]authn.UserGroup)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListUserGroups", data)
		}
		for i := range items {
			g := items[i]
			if g.ExtId == nil {
				continue
			}
			groupType := ""
			if g.GroupType != nil {
				groupType = g.GroupType.GetName()
			}
			mqlGroup, err := CreateResource(a.MqlRuntime, "nutanix.iam.group", map[string]*llx.RawData{
				"__id":              llx.StringDataPtr(g.ExtId),
				"id":                llx.StringDataPtr(g.ExtId),
				"name":              llx.StringDataPtr(g.Name),
				"groupType":         llx.StringData(groupType),
				"distinguishedName": llx.StringDataPtr(g.DistinguishedName),
				"idpId":             llx.StringDataPtr(g.IdpId),
				"createdBy":         llx.StringDataPtr(g.CreatedBy),
				"createdTime":       llx.TimeDataPtr(g.CreatedTime),
				"lastUpdatedTime":   llx.TimeDataPtr(g.LastUpdatedTime),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
		if len(items) < limit {
			break
		}
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// roles
// ---------------------------------------------------------------------------

func newMqlRole(runtime *plugin.Runtime, r *authz.Role) (*mqlNutanixIamRole, error) {
	if r.ExtId == nil {
		return nil, nil
	}
	operations := []any{}
	for _, op := range r.Operations {
		operations = append(operations, op)
	}
	entityTypes := []any{}
	for _, et := range r.AccessibleEntityTypes {
		entityTypes = append(entityTypes, et)
	}
	res, err := CreateResource(runtime, "nutanix.iam.role", map[string]*llx.RawData{
		"__id":                    llx.StringDataPtr(r.ExtId),
		"id":                      llx.StringDataPtr(r.ExtId),
		"tenantId":                llx.StringDataPtr(r.TenantId),
		"displayName":             llx.StringDataPtr(r.DisplayName),
		"description":             llx.StringDataPtr(r.Description),
		"isSystemDefined":         llx.BoolData(derefBool(r.IsSystemDefined)),
		"operations":              llx.ArrayData(operations, types.String),
		"accessibleEntityTypes":   llx.ArrayData(entityTypes, types.String),
		"assignedUsersCount":      llx.IntData(derefInt64(r.AssignedUsersCount)),
		"assignedUserGroupsCount": llx.IntData(derefInt64(r.AssignedUserGroupsCount)),
		"createdBy":               llx.StringDataPtr(r.CreatedBy),
		"createdTime":             llx.TimeDataPtr(r.CreatedTime),
		"lastUpdatedTime":         llx.TimeDataPtr(r.LastUpdatedTime),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlNutanixIamRole), nil
}

func (a *mqlNutanix) roles() ([]any, error) {
	conn := a.conn()
	api := conn.RolesApi()
	limit := pageSize
	res := []any{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.IamMu(), func() (*authz.ListRolesApiResponse, error) {
			return api.ListRoles(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]authz.Role)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListRoles", data)
		}
		for i := range items {
			mqlRole, err := newMqlRole(a.MqlRuntime, &items[i])
			if err != nil {
				return nil, err
			}
			if mqlRole == nil {
				continue
			}
			res = append(res, mqlRole)
		}
		if len(items) < limit {
			break
		}
	}
	return res, nil
}

// ---------------------------------------------------------------------------
// authorization policies
// ---------------------------------------------------------------------------

func (a *mqlNutanix) authorizationPolicies() ([]any, error) {
	conn := a.conn()
	api := conn.AuthorizationPoliciesApi()
	limit := pageSize
	res := []any{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.IamMu(), func() (*authz.ListAuthorizationPoliciesApiResponse, error) {
			return api.ListAuthorizationPolicies(&p, &limit, nil, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]authz.AuthorizationPolicy)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListAuthorizationPolicies", data)
		}
		for i := range items {
			ap := items[i]
			if ap.ExtId == nil {
				continue
			}
			policyType := ""
			if ap.AuthorizationPolicyType != nil {
				policyType = ap.AuthorizationPolicyType.GetName()
			}
			entities, err := convert.JsonToDictSlice(ap.Entities)
			if err != nil {
				return nil, err
			}
			identities, err := convert.JsonToDictSlice(ap.Identities)
			if err != nil {
				return nil, err
			}
			mqlPolicy, err := CreateResource(a.MqlRuntime, "nutanix.iam.authorizationPolicy", map[string]*llx.RawData{
				"__id":                    llx.StringDataPtr(ap.ExtId),
				"id":                      llx.StringDataPtr(ap.ExtId),
				"tenantId":                llx.StringDataPtr(ap.TenantId),
				"displayName":             llx.StringDataPtr(ap.DisplayName),
				"description":             llx.StringDataPtr(ap.Description),
				"authorizationPolicyType": llx.StringData(policyType),
				"isSystemDefined":         llx.BoolData(derefBool(ap.IsSystemDefined)),
				"assignedUsersCount":      llx.IntData(derefInt(ap.AssignedUsersCount)),
				"assignedUserGroupsCount": llx.IntData(derefInt(ap.AssignedUserGroupsCount)),
				"entities":                llx.ArrayData(entities, types.Dict),
				"identities":              llx.ArrayData(identities, types.Dict),
				"createdBy":               llx.StringDataPtr(ap.CreatedBy),
				"createdTime":             llx.TimeDataPtr(ap.CreatedTime),
				"lastUpdatedTime":         llx.TimeDataPtr(ap.LastUpdatedTime),
			})
			if err != nil {
				return nil, err
			}
			mp := mqlPolicy.(*mqlNutanixIamAuthorizationPolicy)
			if ap.Role != nil {
				mp.cacheRoleId = *ap.Role
			}
			res = append(res, mp)
		}
		if len(items) < limit {
			break
		}
	}
	return res, nil
}

type mqlNutanixIamAuthorizationPolicyInternal struct {
	cacheRoleId string
}

func (a *mqlNutanixIamAuthorizationPolicy) role() (*mqlNutanixIamRole, error) {
	if a.cacheRoleId == "" {
		a.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if r, ok := cachedResource[*mqlNutanixIamRole](a.MqlRuntime, "nutanix.iam.role", a.cacheRoleId); ok {
		return r, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.NutanixConnection)
	roleId := a.cacheRoleId
	resp, err := guard(conn.IamMu(), func() (*authz.GetRoleApiResponse, error) {
		return conn.RolesApi().GetRoleById(&roleId)
	})
	if err != nil {
		return nil, err
	}
	data := resp.GetData()
	if data == nil {
		a.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	role, ok := data.(authz.Role)
	if !ok {
		a.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newMqlRole(a.MqlRuntime, &role)
}

// ---------------------------------------------------------------------------
// directory services
// ---------------------------------------------------------------------------

func (a *mqlNutanix) directoryServices() ([]any, error) {
	conn := a.conn()
	api := conn.DirectoryServicesApi()
	limit := pageSize
	res := []any{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.IamMu(), func() (*authn.ListDirectoryServicesApiResponse, error) {
			return api.ListDirectoryServices(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]authn.DirectoryService)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListDirectoryServices", data)
		}
		for i := range items {
			ds := items[i]
			if ds.ExtId == nil {
				continue
			}
			directoryType := ""
			if ds.DirectoryType != nil {
				directoryType = ds.DirectoryType.GetName()
			}
			groupSearchType := ""
			if ds.GroupSearchType != nil {
				groupSearchType = ds.GroupSearchType.GetName()
			}
			secondaryUrls := []any{}
			for _, u := range ds.SecondaryUrls {
				secondaryUrls = append(secondaryUrls, u)
			}
			whitelisted := []any{}
			for _, g := range ds.WhiteListedGroups {
				whitelisted = append(whitelisted, g)
			}
			serviceAccountUsername := ""
			if ds.ServiceAccount != nil && ds.ServiceAccount.Username != nil {
				serviceAccountUsername = *ds.ServiceAccount.Username
			}
			mqlDs, err := CreateResource(a.MqlRuntime, "nutanix.iam.directoryService", map[string]*llx.RawData{
				"__id":                   llx.StringDataPtr(ds.ExtId),
				"id":                     llx.StringDataPtr(ds.ExtId),
				"name":                   llx.StringDataPtr(ds.Name),
				"directoryType":          llx.StringData(directoryType),
				"domainName":             llx.StringDataPtr(ds.DomainName),
				"url":                    llx.StringDataPtr(ds.Url),
				"secondaryUrls":          llx.ArrayData(secondaryUrls, types.String),
				"groupSearchType":        llx.StringData(groupSearchType),
				"whiteListedGroups":      llx.ArrayData(whitelisted, types.String),
				"serviceAccountUsername": llx.StringData(serviceAccountUsername),
				"createdBy":              llx.StringDataPtr(ds.CreatedBy),
				"createdTime":            llx.TimeDataPtr(ds.CreatedTime),
				"lastUpdatedTime":        llx.TimeDataPtr(ds.LastUpdatedTime),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlDs)
		}
		if len(items) < limit {
			break
		}
	}
	return res, nil
}

// urlUsesLdaps reports whether the given URL uses the secure LDAPS scheme,
// matching the "ldaps://" prefix case-insensitively.
func urlUsesLdaps(url string) bool {
	return strings.HasPrefix(strings.ToLower(url), "ldaps://")
}

func (d *mqlNutanixIamDirectoryService) usesLdaps() (bool, error) {
	url := d.GetUrl()
	if url.Error != nil {
		return false, url.Error
	}
	return urlUsesLdaps(url.Data), nil
}

// ---------------------------------------------------------------------------
// SAML identity providers
// ---------------------------------------------------------------------------

func (a *mqlNutanix) samlIdentityProviders() ([]any, error) {
	conn := a.conn()
	api := conn.SamlIdentityProvidersApi()
	limit := pageSize
	res := []any{}
	for page := 0; ; page++ {
		p := page
		resp, err := guard(conn.IamMu(), func() (*authn.ListSamlIdentityProvidersApiResponse, error) {
			return api.ListSamlIdentityProviders(&p, &limit, nil, nil, nil)
		})
		if err != nil {
			return nil, err
		}
		data := resp.GetData()
		if data == nil {
			break
		}
		items, ok := data.([]authn.SamlIdentityProvider)
		if !ok {
			return nil, fmt.Errorf("nutanix: unexpected response type %T from ListSamlIdentityProviders", data)
		}
		for i := range items {
			idp := items[i]
			if idp.ExtId == nil {
				continue
			}
			mqlIdp, err := CreateResource(a.MqlRuntime, "nutanix.iam.samlIdentityProvider", map[string]*llx.RawData{
				"__id":                    llx.StringDataPtr(idp.ExtId),
				"id":                      llx.StringDataPtr(idp.ExtId),
				"name":                    llx.StringDataPtr(idp.Name),
				"entityIssuer":            llx.StringDataPtr(idp.EntityIssuer),
				"usernameAttribute":       llx.StringDataPtr(idp.UsernameAttribute),
				"emailAttribute":          llx.StringDataPtr(idp.EmailAttribute),
				"groupsAttribute":         llx.StringDataPtr(idp.GroupsAttribute),
				"idpMetadataUrl":          llx.StringDataPtr(idp.IdpMetadataUrl),
				"isSignedAuthnReqEnabled": llx.BoolData(derefBool(idp.IsSignedAuthnReqEnabled)),
				"createdTime":             llx.TimeDataPtr(idp.CreatedTime),
				"lastUpdatedTime":         llx.TimeDataPtr(idp.LastUpdatedTime),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlIdp)
		}
		if len(items) < limit {
			break
		}
	}
	return res, nil
}
