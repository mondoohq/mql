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

func (c *mqlGustoCompany) id() (string, error) {
	return "gusto.company/" + c.Uuid.Data, c.Uuid.Error
}

func initGustoCompany(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	for i := range companies {
		if companies[i].UUID != uuid {
			continue
		}
		c := &companies[i]
		args["uuid"] = llx.StringData(c.UUID)
		args["name"] = llx.StringData(c.Name)
		args["tradeName"] = llx.StringData(c.TradeName)
		args["entityType"] = llx.StringData(c.EntityType)
		args["tier"] = llx.StringData(c.Tier)
		args["isSuspended"] = llx.BoolData(c.IsSuspended)
		args["companyStatus"] = llx.StringData(c.CompanyStatus)
		args["slug"] = llx.StringData(c.Slug)
		args["joinDate"] = llx.TimeData(c.JoinDate.Time)
		return args, nil, nil
	}
	return nil, nil, errors.New("gusto.company with uuid " + uuid + " not accessible with the configured token")
}

func (c *mqlGustoCompany) employees() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.GustoConnection)
	employees, err := conn.ListEmployees(context.Background(), c.Uuid.Data)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(employees))
	for i := range employees {
		r, err := newMqlGustoEmployee(c.MqlRuntime, &employees[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (c *mqlGustoCompany) contractors() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.GustoConnection)
	contractors, err := conn.ListContractors(context.Background(), c.Uuid.Data)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(contractors))
	for i := range contractors {
		r, err := newMqlGustoContractor(c.MqlRuntime, &contractors[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (c *mqlGustoCompany) departments() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.GustoConnection)
	departments, err := conn.ListDepartments(context.Background(), c.Uuid.Data)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(departments))
	for i := range departments {
		r, err := newMqlGustoDepartment(c.MqlRuntime, &departments[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (c *mqlGustoCompany) locations() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.GustoConnection)
	locations, err := conn.ListLocations(context.Background(), c.Uuid.Data)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(locations))
	for i := range locations {
		r, err := newMqlGustoLocation(c.MqlRuntime, &locations[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (c *mqlGustoCompany) admins() ([]any, error) {
	conn := c.MqlRuntime.Connection.(*connection.GustoConnection)
	admins, err := conn.ListAdmins(context.Background(), c.Uuid.Data)
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(admins))
	for i := range admins {
		r, err := newMqlGustoAdmin(c.MqlRuntime, &admins[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
