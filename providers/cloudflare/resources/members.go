// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
	"encoding/json"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/cloudflare/connection"
	"go.mondoo.com/mql/types"
)

// accountMember mirrors an account membership record, decoded via the client's
// generic Get.
type accountMember struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	User   struct {
		ID                             string `json:"id"`
		Email                          string `json:"email"`
		FirstName                      string `json:"first_name"`
		LastName                       string `json:"last_name"`
		TwoFactorAuthenticationEnabled bool   `json:"two_factor_authentication_enabled"`
	} `json:"user"`
	Roles []struct {
		ID          string          `json:"id"`
		Name        string          `json:"name"`
		Description string          `json:"description"`
		Permissions json.RawMessage `json:"permissions"`
	} `json:"roles"`
	Policies []accountMemberPolicy `json:"policies"`
}

// accountMemberPolicy is a domain-scoped grant assigned to a member.
type accountMemberPolicy struct {
	ID               string `json:"id"`
	Access           string `json:"access"`
	PermissionGroups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"permission_groups"`
	ResourceGroups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		// Scope is kept in its raw decoded form: `{key, objects: [{key}]}`.
		Scope any `json:"scope"`
	} `json:"resource_groups"`
}

// memberPolicyDicts converts a member's domain-scoped grants into dicts. Each
// entry carries the policy id, whether it allows or denies, the permission
// groups it grants and the resource groups it applies to.
func memberPolicyDicts(policies []accountMemberPolicy) []any {
	out := make([]any, 0, len(policies))
	for i := range policies {
		p := policies[i]
		pgs := make([]any, 0, len(p.PermissionGroups))
		for j := range p.PermissionGroups {
			pgs = append(pgs, map[string]any{
				"id":   p.PermissionGroups[j].ID,
				"name": p.PermissionGroups[j].Name,
			})
		}
		rgs := make([]any, 0, len(p.ResourceGroups))
		for j := range p.ResourceGroups {
			rgs = append(rgs, map[string]any{
				"id":    p.ResourceGroups[j].ID,
				"name":  p.ResourceGroups[j].Name,
				"scope": p.ResourceGroups[j].Scope,
			})
		}
		out = append(out, map[string]any{
			"id":               p.ID,
			"access":           p.Access,
			"permissionGroups": pgs,
			"resourceGroups":   rgs,
		})
	}
	return out
}

func (c *mqlCloudflareAccountMember) id() (string, error) {
	if c.Id.Error != nil {
		return "", c.Id.Error
	}
	return "cloudflare/account/member/" + c.Id.Data, nil
}

func (c *mqlCloudflareAccount) members() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.CloudflareConnection)

	members, err := cfGetPaged[accountMember](conn, fmt.Sprintf("accounts/%s/members", c.Id.Data))
	if err != nil {
		return degradedList(err)
	}

	results := []any{}
	for i := range members {
		m := members[i]

		roles := make([]any, 0, len(m.Roles))
		for j := range m.Roles {
			r := m.Roles[j]
			role, err := NewResource(c.MqlRuntime, "cloudflare.account.role", map[string]*llx.RawData{
				"id":          llx.StringData(r.ID),
				"name":        llx.StringData(r.Name),
				"description": llx.StringData(r.Description),
				"permissions": rawJSONDict(string(r.Permissions)),
			})
			if err != nil {
				return nil, err
			}
			roles = append(roles, role)
		}

		res, err := NewResource(c.MqlRuntime, "cloudflare.account.member", map[string]*llx.RawData{
			"id":                             llx.StringData(m.ID),
			"status":                         llx.StringData(m.Status),
			"userId":                         llx.StringData(m.User.ID),
			"email":                          llx.StringData(m.User.Email),
			"firstName":                      llx.StringData(m.User.FirstName),
			"lastName":                       llx.StringData(m.User.LastName),
			"twoFactorAuthenticationEnabled": llx.BoolData(m.User.TwoFactorAuthenticationEnabled),
			"roles":                          llx.ArrayData(roles, types.Resource("cloudflare.account.role")),
			"policies":                       llx.ArrayData(memberPolicyDicts(m.Policies), types.Dict),
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
