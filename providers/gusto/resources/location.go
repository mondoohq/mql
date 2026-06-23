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

func (l *mqlGustoLocation) id() (string, error) {
	return "gusto.location/" + l.Uuid.Data, l.Uuid.Error
}

func initGustoLocation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
		locations, err := conn.ListLocations(context.Background(), company.UUID)
		if err != nil {
			return nil, nil, err
		}
		for i := range locations {
			if locations[i].UUID != uuid {
				continue
			}
			populateLocationArgs(args, &locations[i])
			return args, nil, nil
		}
	}
	return nil, nil, errors.New("gusto.location with uuid " + uuid + " not accessible with the configured token")
}

func populateLocationArgs(args map[string]*llx.RawData, l *connection.Location) {
	args["uuid"] = llx.StringData(l.UUID)
	args["companyUuid"] = llx.StringData(l.CompanyUUID)
	args["street1"] = llx.StringData(l.Street1)
	args["street2"] = llx.StringData(l.Street2)
	args["city"] = llx.StringData(l.City)
	args["state"] = llx.StringData(l.State)
	args["zip"] = llx.StringData(l.Zip)
	args["country"] = llx.StringData(l.Country)
	args["filingAddress"] = llx.BoolData(l.FilingAddress)
	args["mailingAddress"] = llx.BoolData(l.MailingAddress)
	args["active"] = llx.BoolData(l.Active)
}

func newMqlGustoLocation(runtime *plugin.Runtime, l *connection.Location) (*mqlGustoLocation, error) {
	args := map[string]*llx.RawData{}
	populateLocationArgs(args, l)
	r, err := CreateResource(runtime, "gusto.location", args)
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoLocation), nil
}
