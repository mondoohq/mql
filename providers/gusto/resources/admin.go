// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/gusto/connection"
)

func (a *mqlGustoAdmin) id() (string, error) {
	return "gusto.admin/" + a.Uuid.Data, a.Uuid.Error
}

func initGustoAdmin(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	uuidArg, ok := args["uuid"]
	if !ok || uuidArg == nil || uuidArg.Value == nil {
		return args, nil, nil
	}
	uuid, ok := uuidArg.Value.(string)
	if !ok || uuid == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GustoConnection)
	companies, err := conn.ListCompanies(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for _, company := range companies {
		admins, err := conn.ListAdmins(context.Background(), company.UUID)
		if err != nil {
			return nil, nil, err
		}
		for i := range admins {
			if admins[i].UUID != uuid {
				continue
			}
			a, err := newMqlGustoAdmin(runtime, &admins[i])
			if err != nil {
				return nil, nil, err
			}
			return args, a, nil
		}
	}
	return nil, nil, errors.New("gusto.admin with uuid " + uuid + " not accessible with the configured token")
}

func newMqlGustoAdmin(runtime *plugin.Runtime, a *connection.Admin) (*mqlGustoAdmin, error) {
	r, err := CreateResource(runtime, "gusto.admin", map[string]*llx.RawData{
		"uuid":        llx.StringData(a.UUID),
		"companyUuid": llx.StringData(a.CompanyUUID),
		"firstName":   llx.StringData(a.FirstName),
		"lastName":    llx.StringData(a.LastName),
		"email":       llx.StringData(a.Email),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoAdmin), nil
}
