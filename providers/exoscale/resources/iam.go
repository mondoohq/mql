// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"
	"strconv"

	v3 "github.com/exoscale/egoscale/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// ---- roles ----

type mqlExoscaleIamRoleInternal struct {
	cachePolicy *v3.IAMPolicy
}

func (r *mqlExoscale) iamRoles() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListIAMRoles(ctx())
	if err != nil {
		return nil, classifyError(err, "list-iam-roles")
	}
	out := make([]any, 0, len(res.IAMRoles))
	for _, role := range res.IAMRoles {
		m, err := CreateResource(r.MqlRuntime, "exoscale.iam.role", map[string]*llx.RawData{
			"__id":          llx.StringData("exoscale.iam.role/" + string(role.ID)),
			"id":            llx.StringData(string(role.ID)),
			"name":          llx.StringData(role.Name),
			"description":   llx.StringData(role.Description),
			"editable":      boolData(role.Editable),
			"labels":        labelData(role.Labels),
			"permissions":   stringArrayData(role.Permissions),
			"maxSessionTtl": llx.IntData(role.MaxSessionTtl),
		})
		if err != nil {
			return nil, err
		}
		m.(*mqlExoscaleIamRole).cachePolicy = role.Policy
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleIamRole) policy() (*mqlExoscaleIamPolicy, error) {
	if r.cachePolicy == nil {
		nullResource(&r.Policy)
		return nil, nil
	}
	return newMqlExoscaleIamPolicy(r.MqlRuntime, "role/"+r.Id.Data, r.cachePolicy)
}

func roleByID(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlExoscaleIamRole]) (*mqlExoscaleIamRole, error) {
	if id == "" {
		nullResource(field)
		return nil, nil
	}
	ns, err := root(runtime)
	if err != nil {
		return nil, err
	}
	list := ns.GetIamRoles()
	if list.Error != nil {
		return nil, list.Error
	}
	if role, ok := pickOneByID(list.Data, id, func(r *mqlExoscaleIamRole) string { return r.Id.Data }); ok {
		return role, nil
	}
	nullResource(field)
	return nil, nil
}

// ---- policies ----

type mqlExoscaleIamPolicyInternal struct {
	owner string
	cache *v3.IAMPolicy
}

func (r *mqlExoscale) iamOrganizationPolicy() (*mqlExoscaleIamPolicy, error) {
	p, err := conn(r.MqlRuntime).Client().GetIAMOrganizationPolicy(ctx())
	if err != nil {
		return nil, classifyError(err, "get-iam-organization-policy")
	}
	if p == nil {
		nullResource(&r.IamOrganizationPolicy)
		return nil, nil
	}
	return newMqlExoscaleIamPolicy(r.MqlRuntime, "organization", p)
}

// newMqlExoscaleIamPolicy builds a policy owned by a role ("role/<id>") or by
// the organization ("organization"). The owner keys the cache entry.
func newMqlExoscaleIamPolicy(runtime *plugin.Runtime, owner string, p *v3.IAMPolicy) (*mqlExoscaleIamPolicy, error) {
	res, err := CreateResource(runtime, "exoscale.iam.policy", map[string]*llx.RawData{
		"__id":                   llx.StringData("exoscale.iam.policy/" + owner),
		"defaultServiceStrategy": llx.StringData(string(p.DefaultServiceStrategy)),
	})
	if err != nil {
		return nil, err
	}
	m := res.(*mqlExoscaleIamPolicy)
	m.owner = owner
	m.cache = p
	return m, nil
}

type mqlExoscaleIamPolicyServiceInternal struct {
	cacheRules []v3.IAMServicePolicyRule
	key        string
}

// services lists the per-service policies sorted by service name, so the
// order is stable across scans.
func (r *mqlExoscaleIamPolicy) services() ([]any, error) {
	if r.cache == nil {
		return []any{}, nil
	}
	names := make([]string, 0, len(r.cache.Services))
	for name := range r.cache.Services {
		names = append(names, name)
	}
	slices.Sort(names)
	out := make([]any, 0, len(names))
	for _, name := range names {
		svc := r.cache.Services[name]
		key := r.owner + "/" + name
		res, err := CreateResource(r.MqlRuntime, "exoscale.iam.policy.service", map[string]*llx.RawData{
			"__id": llx.StringData("exoscale.iam.policy.service/" + key),
			"name": llx.StringData(name),
			"type": llx.StringData(string(svc.Type)),
		})
		if err != nil {
			return nil, err
		}
		m := res.(*mqlExoscaleIamPolicyService)
		m.cacheRules = svc.Rules
		m.key = key
		out = append(out, m)
	}
	return out, nil
}

// rules keeps the API order: rules are evaluated top to bottom.
func (r *mqlExoscaleIamPolicyService) rules() ([]any, error) {
	out := make([]any, 0, len(r.cacheRules))
	for i, rule := range r.cacheRules {
		res, err := CreateResource(r.MqlRuntime, "exoscale.iam.policy.rule", map[string]*llx.RawData{
			"__id":       llx.StringData("exoscale.iam.policy.rule/" + r.key + "/" + strconv.Itoa(i)),
			"action":     llx.StringData(string(rule.Action)),
			"expression": llx.StringData(rule.Expression),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// ---- API keys ----

type mqlExoscaleIamApiKeyInternal struct {
	cacheRoleID string
}

func (r *mqlExoscale) iamApiKeys() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListAPIKeys(ctx())
	if err != nil {
		return nil, classifyError(err, "list-api-keys")
	}
	out := make([]any, 0, len(res.APIKeys))
	for _, k := range res.APIKeys {
		m, err := CreateResource(r.MqlRuntime, "exoscale.iam.apiKey", map[string]*llx.RawData{
			"__id":    llx.StringData("exoscale.iam.apiKey/" + k.Key),
			"key":     llx.StringData(k.Key),
			"name":    llx.StringData(k.Name),
			"created": timeData(k.CreatedAT),
		})
		if err != nil {
			return nil, err
		}
		m.(*mqlExoscaleIamApiKey).cacheRoleID = string(k.RoleID)
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleIamApiKey) role() (*mqlExoscaleIamRole, error) {
	return roleByID(r.MqlRuntime, r.cacheRoleID, &r.Role)
}

// ---- users ----

type mqlExoscaleIamUserInternal struct {
	cacheRoleID string
}

func (r *mqlExoscale) iamUsers() ([]any, error) {
	res, err := conn(r.MqlRuntime).Client().ListUsers(ctx())
	if err != nil {
		return nil, classifyError(err, "list-users")
	}
	out := make([]any, 0, len(res.Users))
	for _, u := range res.Users {
		m, err := CreateResource(r.MqlRuntime, "exoscale.iam.user", map[string]*llx.RawData{
			"__id":                    llx.StringData("exoscale.iam.user/" + string(u.ID)),
			"id":                      llx.StringData(string(u.ID)),
			"email":                   llx.StringData(u.Email),
			"pending":                 boolData(u.Pending),
			"sso":                     boolData(u.Sso),
			"twoFactorAuthentication": boolData(u.TwoFactorAuthentication),
		})
		if err != nil {
			return nil, err
		}
		if u.Role != nil {
			m.(*mqlExoscaleIamUser).cacheRoleID = string(u.Role.ID)
		}
		out = append(out, m)
	}
	return out, nil
}

func (r *mqlExoscaleIamUser) role() (*mqlExoscaleIamRole, error) {
	return roleByID(r.MqlRuntime, r.cacheRoleID, &r.Role)
}
