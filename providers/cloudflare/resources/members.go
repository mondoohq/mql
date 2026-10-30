// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1
package resources

import (
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
		ID          string `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
	} `json:"roles"`
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
		})
		if err != nil {
			return nil, err
		}
		results = append(results, res)
	}
	return results, nil
}
