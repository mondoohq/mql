// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/fastly/go-fastly/v10/fastly"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func newUser(runtime *plugin.Runtime, u *fastly.User) (*mqlFastlyUser, error) {
	res, err := CreateResource(runtime, ResourceFastlyUser, map[string]*llx.RawData{
		"__id":                   llx.StringData(ptrStr(u.UserID)),
		"id":                     llx.StringDataPtr(u.UserID),
		"login":                  llx.StringDataPtr(u.Login),
		"name":                   llx.StringDataPtr(u.Name),
		"role":                   llx.StringDataPtr(u.Role),
		"locked":                 llx.BoolDataPtr(u.Locked),
		"twoFactorAuthEnabled":   llx.BoolDataPtr(u.TwoFactorAuthEnabled),
		"twoFactorSetupRequired": llx.BoolDataPtr(u.TwoFactorSetupRequired),
		"requireNewPassword":     llx.BoolDataPtr(u.RequireNewPassword),
		"createdAt":              llx.TimeDataPtr(u.CreatedAt),
		"updatedAt":              llx.TimeDataPtr(u.UpdatedAt),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlFastlyUser), nil
}

func (r *mqlFastlyUser) id() (string, error) {
	return r.Id.Data, nil
}
