// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/gusto/connection"
)

func (g *mqlGusto) id() (string, error) {
	return "gusto", nil
}

func (g *mqlGusto) companies() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GustoConnection)
	companies, err := conn.ListCompanies(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(companies))
	for i := range companies {
		r, err := newMqlGustoCompany(g.MqlRuntime, &companies[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// getCompanies returns the companies list from the field cache, so all
// aggregation methods share a single list fetch rather than re-listing.
func (g *mqlGusto) getCompanies() ([]*mqlGustoCompany, error) {
	tv := g.GetCompanies()
	if tv.Error != nil {
		return nil, tv.Error
	}
	out := make([]*mqlGustoCompany, 0, len(tv.Data))
	for _, c := range tv.Data {
		out = append(out, c.(*mqlGustoCompany))
	}
	return out, nil
}

func (g *mqlGusto) employees() ([]any, error) {
	companies, err := g.getCompanies()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, company := range companies {
		employees := company.GetEmployees()
		if employees.Error != nil {
			return nil, employees.Error
		}
		out = append(out, employees.Data...)
	}
	return out, nil
}

func (g *mqlGusto) contractors() ([]any, error) {
	companies, err := g.getCompanies()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, company := range companies {
		contractors := company.GetContractors()
		if contractors.Error != nil {
			return nil, contractors.Error
		}
		out = append(out, contractors.Data...)
	}
	return out, nil
}

func (g *mqlGusto) departments() ([]any, error) {
	companies, err := g.getCompanies()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, company := range companies {
		departments := company.GetDepartments()
		if departments.Error != nil {
			return nil, departments.Error
		}
		out = append(out, departments.Data...)
	}
	return out, nil
}

func (g *mqlGusto) locations() ([]any, error) {
	companies, err := g.getCompanies()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, company := range companies {
		locations := company.GetLocations()
		if locations.Error != nil {
			return nil, locations.Error
		}
		out = append(out, locations.Data...)
	}
	return out, nil
}

func (g *mqlGusto) admins() ([]any, error) {
	companies, err := g.getCompanies()
	if err != nil {
		return nil, err
	}
	out := []any{}
	for _, company := range companies {
		admins := company.GetAdmins()
		if admins.Error != nil {
			return nil, admins.Error
		}
		out = append(out, admins.Data...)
	}
	return out, nil
}

func newMqlGustoCompany(runtime *plugin.Runtime, c *connection.Company) (*mqlGustoCompany, error) {
	r, err := CreateResource(runtime, "gusto.company", map[string]*llx.RawData{
		"uuid":          llx.StringData(c.UUID),
		"name":          llx.StringData(c.Name),
		"tradeName":     llx.StringData(c.TradeName),
		"entityType":    llx.StringData(c.EntityType),
		"tier":          llx.StringData(c.Tier),
		"isSuspended":   llx.BoolData(c.IsSuspended),
		"companyStatus": llx.StringData(c.CompanyStatus),
		"slug":          llx.StringData(c.Slug),
		"joinDate":      llx.TimeData(c.JoinDate.Time),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoCompany), nil
}
