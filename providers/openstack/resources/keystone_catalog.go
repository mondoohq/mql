// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/credentials"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/ec2credentials"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/endpoints"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/regions"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/services"
	"github.com/gophercloud/gophercloud/v2/openstack/identity/v3/trusts"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// resolveUser resolves a Keystone user by ID into a typed reference, marking
// the field null when the ID is empty. Mirrors resolveProject.
func resolveUser(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOpenstackUser]) (*mqlOpenstackUser, error) {
	if id == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "openstack.user", map[string]*llx.RawData{"id": llx.StringData(id)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackUser), nil
}

// ---- openstack.credential ----

func (r *mqlOpenstackCredential) id() (string, error) {
	return "openstack.credential/" + r.Id.Data, nil
}

func initOpenstackCredential(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetCredentials()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		c := raw.(*mqlOpenstackCredential)
		if c.Id.Data == id {
			return args, c, nil
		}
	}
	initSyntheticID("openstack.credential", "id", args)
	return args, nil, nil
}

type mqlOpenstackCredentialInternal struct {
	cacheUserID    string
	cacheProjectID string
}

func (o *mqlOpenstack) credentials() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}
	pages, err := credentials.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := credentials.ExtractCredentials(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, cred := range items {
		// The credential blob holds secret material (e.g. the ec2 secret key)
		// and is deliberately not exposed.
		res, err := CreateResource(o.MqlRuntime, "openstack.credential", map[string]*llx.RawData{
			"__id": llx.StringData("openstack.credential/" + cred.ID),
			"id":   llx.StringData(cred.ID),
			"type": llx.StringData(cred.Type),
		})
		if err != nil {
			return nil, err
		}
		mqlCred := res.(*mqlOpenstackCredential)
		mqlCred.cacheUserID = cred.UserID
		mqlCred.cacheProjectID = cred.ProjectID
		out = append(out, mqlCred)
	}
	return out, nil
}

func (r *mqlOpenstackCredential) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

func (r *mqlOpenstackCredential) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

// ---- openstack.ec2Credential ----

func (r *mqlOpenstackEc2Credential) id() (string, error) {
	return "openstack.ec2Credential/" + r.Access.Data, nil
}

func initOpenstackEc2Credential(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	access, ok := stringArg(args, "access")
	if !ok || access == "" {
		return args, nil, nil
	}
	// EC2 credentials are listed per user (no global list endpoint), so a
	// by-access lookup can't resolve against a root list. Synthesize an __id
	// so a direct openstack.ec2Credential("access") reference stays addressable.
	initSyntheticID("openstack.ec2Credential", "access", args)
	return args, nil, nil
}

type mqlOpenstackEc2CredentialInternal struct {
	cacheUserID    string
	cacheProjectID string
	cacheTrustID   string
}

func (r *mqlOpenstackUser) ec2Credentials() ([]any, error) {
	c := conn(r.MqlRuntime)
	client, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}
	pages, err := ec2credentials.List(client, r.Id.Data).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := ec2credentials.ExtractCredentials(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, cred := range items {
		// The secret key (cred.Secret) is deliberately not exposed.
		res, err := CreateResource(r.MqlRuntime, "openstack.ec2Credential", map[string]*llx.RawData{
			"__id":   llx.StringData("openstack.ec2Credential/" + cred.Access),
			"access": llx.StringData(cred.Access),
		})
		if err != nil {
			return nil, err
		}
		mqlCred := res.(*mqlOpenstackEc2Credential)
		mqlCred.cacheUserID = cred.UserID
		mqlCred.cacheProjectID = cred.TenantID
		mqlCred.cacheTrustID = cred.TrustID
		out = append(out, mqlCred)
	}
	return out, nil
}

func (r *mqlOpenstackEc2Credential) user() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheUserID, &r.User)
}

func (r *mqlOpenstackEc2Credential) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackEc2Credential) trust() (*mqlOpenstackTrust, error) {
	if r.cacheTrustID == "" {
		r.Trust.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.trust", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheTrustID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackTrust), nil
}

// ---- openstack.trust ----

func (r *mqlOpenstackTrust) id() (string, error) {
	return "openstack.trust/" + r.Id.Data, nil
}

func initOpenstackTrust(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetTrusts()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		t := raw.(*mqlOpenstackTrust)
		if t.Id.Data == id {
			return args, t, nil
		}
	}
	initSyntheticID("openstack.trust", "id", args)
	return args, nil, nil
}

type mqlOpenstackTrustInternal struct {
	cacheTrusteeUserID      string
	cacheTrustorUserID      string
	cacheProjectID          string
	cacheRedelegatedTrustID string
	cacheRoleIDs            []string
}

func (r *mqlOpenstackTrust) roles() ([]any, error) {
	return rolesByID(r.MqlRuntime, r.cacheRoleIDs)
}

func (o *mqlOpenstack) trusts() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}
	pages, err := trusts.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := trusts.ExtractTrusts(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, t := range items {
		roleNames := make([]string, 0, len(t.Roles))
		roleIDs := make([]string, 0, len(t.Roles))
		for _, role := range t.Roles {
			roleNames = append(roleNames, role.Name)
			if role.ID != "" {
				roleIDs = append(roleIDs, role.ID)
			}
		}
		res, err := CreateResource(o.MqlRuntime, "openstack.trust", map[string]*llx.RawData{
			"__id":              llx.StringData("openstack.trust/" + t.ID),
			"id":                llx.StringData(t.ID),
			"impersonation":     llx.BoolData(t.Impersonation),
			"roleNames":         stringSliceData(roleNames),
			"allowRedelegation": llx.BoolData(t.AllowRedelegation),
			"remainingUses":     llx.IntData(int64(t.RemainingUses)),
			"redelegationCount": llx.IntData(int64(t.RedelegationCount)),
			"expiresAt":         llx.TimeDataPtr(timePtr(t.ExpiresAt)),
		})
		if err != nil {
			return nil, err
		}
		mqlTrust := res.(*mqlOpenstackTrust)
		mqlTrust.cacheTrusteeUserID = t.TrusteeUserID
		mqlTrust.cacheTrustorUserID = t.TrustorUserID
		mqlTrust.cacheProjectID = t.ProjectID
		mqlTrust.cacheRedelegatedTrustID = t.RedelegatedTrustID
		mqlTrust.cacheRoleIDs = roleIDs
		out = append(out, mqlTrust)
	}
	return out, nil
}

func (r *mqlOpenstackTrust) trustee() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheTrusteeUserID, &r.Trustee)
}

func (r *mqlOpenstackTrust) trustor() (*mqlOpenstackUser, error) {
	return resolveUser(r.MqlRuntime, r.cacheTrustorUserID, &r.Trustor)
}

func (r *mqlOpenstackTrust) project() (*mqlOpenstackProject, error) {
	return resolveProject(r.MqlRuntime, r.cacheProjectID, &r.Project)
}

func (r *mqlOpenstackTrust) redelegated() (*mqlOpenstackTrust, error) {
	if r.cacheRedelegatedTrustID == "" {
		r.Redelegated.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.trust", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheRedelegatedTrustID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackTrust), nil
}

// ---- openstack.identity.service ----

func (r *mqlOpenstackIdentityService) id() (string, error) {
	return "openstack.identity.service/" + r.Id.Data, nil
}

func initOpenstackIdentityService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetIdentityServices()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		s := raw.(*mqlOpenstackIdentityService)
		if s.Id.Data == id {
			return args, s, nil
		}
	}
	initSyntheticID("openstack.identity.service", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) identityServices() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}
	pages, err := services.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := services.ExtractServices(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, s := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.identity.service", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.identity.service/" + s.ID),
			"id":          llx.StringData(s.ID),
			"name":        llx.StringData(s.Name),
			"type":        llx.StringData(s.Type),
			"description": llx.StringData(s.Description),
			"enabled":     llx.BoolData(s.Enabled),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- openstack.identity.endpoint ----

type mqlOpenstackIdentityEndpointInternal struct {
	cacheRegion    string
	cacheServiceID string
}

func (r *mqlOpenstackIdentityEndpoint) id() (string, error) {
	return "openstack.identity.endpoint/" + r.Id.Data, nil
}

func initOpenstackIdentityEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetIdentityEndpoints()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		e := raw.(*mqlOpenstackIdentityEndpoint)
		if e.Id.Data == id {
			return args, e, nil
		}
	}
	initSyntheticID("openstack.identity.endpoint", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) identityEndpoints() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}
	pages, err := endpoints.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := endpoints.ExtractEndpoints(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, e := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.identity.endpoint", map[string]*llx.RawData{
			"__id":        llx.StringData("openstack.identity.endpoint/" + e.ID),
			"id":          llx.StringData(e.ID),
			"interface":   llx.StringData(string(e.Availability)),
			"name":        llx.StringData(e.Name),
			"url":         llx.StringData(e.URL),
			"enabled":     llx.BoolData(e.Enabled),
			"description": llx.StringData(e.Description),
		})
		if err != nil {
			return nil, err
		}
		mqlEndpoint := res.(*mqlOpenstackIdentityEndpoint)
		mqlEndpoint.cacheRegion = e.Region
		mqlEndpoint.cacheServiceID = e.ServiceID
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackIdentityEndpoint) region() (*mqlOpenstackIdentityRegion, error) {
	if r.cacheRegion == "" {
		r.Region.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.identity.region", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheRegion),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackIdentityRegion), nil
}

func (r *mqlOpenstackIdentityEndpoint) service() (*mqlOpenstackIdentityService, error) {
	if r.cacheServiceID == "" {
		r.Service.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.identity.service", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheServiceID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackIdentityService), nil
}

// ---- openstack.identity.region ----

func (r *mqlOpenstackIdentityRegion) id() (string, error) {
	return "openstack.identity.region/" + r.Id.Data, nil
}

func initOpenstackIdentityRegion(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	id, ok := stringArg(args, "id")
	if !ok || id == "" {
		return args, nil, nil
	}
	root, err := CreateResource(runtime, "openstack", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	list := root.(*mqlOpenstack).GetRegions()
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for _, raw := range list.Data {
		reg := raw.(*mqlOpenstackIdentityRegion)
		if reg.Id.Data == id {
			return args, reg, nil
		}
	}
	initSyntheticID("openstack.identity.region", "id", args)
	return args, nil, nil
}

func (o *mqlOpenstack) regions() ([]any, error) {
	c := conn(o.MqlRuntime)
	client, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}
	pages, err := regions.List(client, nil).AllPages(ctx())
	if err != nil {
		if translateOpenstackError(err) == nil {
			return []any{}, nil
		}
		return nil, err
	}
	items, err := regions.ExtractRegions(pages)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(items))
	for _, reg := range items {
		res, err := CreateResource(o.MqlRuntime, "openstack.identity.region", map[string]*llx.RawData{
			"__id":           llx.StringData("openstack.identity.region/" + reg.ID),
			"id":             llx.StringData(reg.ID),
			"description":    llx.StringData(reg.Description),
			"parentRegionId": llx.StringData(reg.ParentRegionID),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (r *mqlOpenstackIdentityRegion) parentRegion() (*mqlOpenstackIdentityRegion, error) {
	if r.ParentRegionId.Data == "" {
		r.ParentRegion.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "openstack.identity.region", map[string]*llx.RawData{
		"id": llx.StringData(r.ParentRegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOpenstackIdentityRegion), nil
}
