// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlExoscale) id() (string, error) {
	return "exoscale", nil
}

func (r *mqlExoscale) zones() ([]any, error) {
	zones, err := conn(r.MqlRuntime).Zones()
	if err != nil {
		return nil, classifyError(err, "list-zones")
	}
	out := make([]any, 0, len(zones))
	for _, z := range zones {
		res, err := CreateResource(r.MqlRuntime, "exoscale.zone", map[string]*llx.RawData{
			"__id":        llx.StringData("exoscale.zone/" + string(z.Name)),
			"name":        llx.StringData(string(z.Name)),
			"apiEndpoint": llx.StringData(string(z.APIEndpoint)),
			"sosEndpoint": llx.StringData(string(z.SOSEndpoint)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// initExoscaleOrganization reads the organization the connection's API key
// belongs to. The connection already fetched it to verify the credentials.
func initExoscaleOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	org := conn(runtime).Org()
	if org == nil {
		var err error
		org, err = conn(runtime).Client().GetOrganization(ctx())
		if err != nil {
			return nil, nil, classifyError(err, "get-organization")
		}
	}
	if org == nil {
		return nil, nil, errors.New("exoscale.organization: the API returned no organization")
	}
	args["__id"] = llx.StringData("exoscale.organization/" + string(org.ID))
	args["id"] = llx.StringData(string(org.ID))
	args["name"] = llx.StringData(org.Name)
	args["country"] = llx.StringData(org.Country)
	args["currency"] = llx.StringData(org.Currency)
	return args, nil, nil
}

func (r *mqlExoscaleOrganization) id() (string, error) {
	return "exoscale.organization/" + r.Id.Data, nil
}
