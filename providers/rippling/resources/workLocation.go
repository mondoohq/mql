// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/rippling/connection"
)

func (l *mqlRipplingWorkLocation) id() (string, error) {
	return "rippling.workLocation/" + l.Id.Data, l.Id.Error
}

func initRipplingWorkLocation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.RipplingConnection)
	locations, err := conn.ListWorkLocations(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for i := range locations {
		if locations[i].ID != id {
			continue
		}
		populateWorkLocationArgs(args, &locations[i])
		return args, nil, nil
	}
	return nil, nil, errors.New("rippling.workLocation with id " + id + " not accessible with the configured token")
}

func populateWorkLocationArgs(args map[string]*llx.RawData, l *connection.WorkLocation) {
	addr := l.Address
	if addr == nil {
		addr = &connection.NestedAddress{}
	}
	args["id"] = llx.StringData(l.ID)
	args["nickname"] = llx.StringData(l.Nickname)
	args["phone"] = llx.StringData(l.Phone)
	args["streetLine1"] = llx.StringData(addr.StreetLine1)
	args["streetLine2"] = llx.StringData(addr.StreetLine2)
	args["city"] = llx.StringData(addr.City)
	args["state"] = llx.StringData(addr.State)
	args["zip"] = llx.StringData(addr.Zip)
	args["country"] = llx.StringData(addr.Country)
}

func newMqlRipplingWorkLocation(runtime *plugin.Runtime, l *connection.WorkLocation) (*mqlRipplingWorkLocation, error) {
	args := map[string]*llx.RawData{}
	populateWorkLocationArgs(args, l)
	r, err := CreateResource(runtime, "rippling.workLocation", args)
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingWorkLocation), nil
}

func (l *mqlRipplingWorkLocation) employees() ([]any, error) {
	conn := l.MqlRuntime.Connection.(*connection.RipplingConnection)
	employees, err := conn.ListEmployees(context.Background())
	if err != nil {
		return nil, err
	}
	out := []any{}
	for i := range employees {
		if employees[i].WorkLocation != l.Id.Data {
			continue
		}
		emp, err := newMqlRipplingEmployee(l.MqlRuntime, &employees[i])
		if err != nil {
			return nil, err
		}
		out = append(out, emp)
	}
	return out, nil
}
