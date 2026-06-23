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

func (c *mqlGustoContractor) id() (string, error) {
	return "gusto.contractor/" + c.Uuid.Data, c.Uuid.Error
}

func initGustoContractor(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
		"companyUuid":      llx.StringData(c.CompanyUUID),
		"type":             llx.StringData(c.Type),
		"isActive":         llx.BoolData(c.IsActive),
		"firstName":        llx.StringData(c.FirstName),
		"middleInitial":    llx.StringData(c.MiddleInitial),
		"lastName":         llx.StringData(c.LastName),
		"businessName":     llx.StringData(c.BusinessName),
		"email":            llx.StringData(c.Email),
		"startDate":        llx.TimeData(c.StartDate.Time),
		"selfOnboarding":   llx.BoolData(c.SelfOnboarding),
		"onboardingStatus": llx.StringData(c.OnboardingStatus),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoContractor), nil
}
