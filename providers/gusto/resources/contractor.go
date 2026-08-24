// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gusto/connection"
)

type mqlGustoContractorInternal struct {
	cacheCompanyUUID string
}

func (c *mqlGustoContractor) id() (string, error) {
	return "gusto.contractor/" + c.Uuid.Data, c.Uuid.Error
}

func initGustoContractor(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	uuid, err := uuidArg(args, "gusto.contractor")
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.GustoConnection)
	companies, err := conn.ListCompanies(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for _, company := range companies {
		contractors, err := conn.ListContractors(context.Background(), company.UUID)
		if err != nil {
			return nil, nil, err
		}
		for i := range contractors {
			if contractors[i].UUID != uuid {
				continue
			}
			c, err := newMqlGustoContractor(runtime, &contractors[i])
			if err != nil {
				return nil, nil, err
			}
			return args, c, nil
		}
	}
	return nil, nil, errors.New("gusto.contractor with uuid " + uuid + " not accessible with the configured token")
}

func newMqlGustoContractor(runtime *plugin.Runtime, c *connection.Contractor) (*mqlGustoContractor, error) {
	r, err := CreateResource(runtime, "gusto.contractor", map[string]*llx.RawData{
		"uuid":             llx.StringData(c.UUID),
		"type":             llx.StringData(c.Type),
		"isActive":         llx.BoolData(c.IsActive),
		"firstName":        llx.StringData(c.FirstName),
		"middleInitial":    llx.StringData(c.MiddleInitial),
		"lastName":         llx.StringData(c.LastName),
		"businessName":     llx.StringData(c.BusinessName),
		"email":            llx.StringData(c.Email),
		"startDate":        llx.TimeDataPtr(c.StartDate.Ptr()),
		"onboarded":        llx.BoolData(c.Onboarded),
		"onboardingStatus": llx.StringData(c.OnboardingStatus),
	})
	if err != nil {
		return nil, err
	}
	contractor := r.(*mqlGustoContractor)
	contractor.cacheCompanyUUID = c.CompanyUUID
	return contractor, nil
}

func (c *mqlGustoContractor) company() (*mqlGustoCompany, error) {
	return resolveCompany(c.MqlRuntime, c.cacheCompanyUUID, &c.Company)
}
