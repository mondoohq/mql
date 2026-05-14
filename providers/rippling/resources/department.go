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

type mqlRipplingDepartmentInternal struct {
	parentID string
}

func (d *mqlRipplingDepartment) id() (string, error) {
	return "rippling.department/" + d.Id.Data, d.Id.Error
}

func initRipplingDepartment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	departments, err := conn.ListDepartments(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for i := range departments {
		if departments[i].ID != id {
			continue
		}
		// Build the resource directly so the Internal struct's parentID is
		// populated — otherwise parent() would resolve to null.
		dept, err := newMqlRipplingDepartment(runtime, &departments[i])
		if err != nil {
			return nil, nil, err
		}
		return args, dept, nil
	}
	return nil, nil, errors.New("rippling.department with id " + id + " not accessible with the configured token")
}

func newMqlRipplingDepartment(runtime *plugin.Runtime, d *connection.Department) (*mqlRipplingDepartment, error) {
	r, err := CreateResource(runtime, "rippling.department", map[string]*llx.RawData{
		"id":   llx.StringData(d.ID),
		"name": llx.StringData(d.Name),
	})
	if err != nil {
		return nil, err
	}
	dept := r.(*mqlRipplingDepartment)
	dept.parentID = d.Parent
	return dept, nil
}

func (d *mqlRipplingDepartment) parent() (*mqlRipplingDepartment, error) {
	if d.parentID == "" {
		d.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(d.MqlRuntime, "rippling.department", map[string]*llx.RawData{
		"id": llx.StringData(d.parentID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingDepartment), nil
}

func (d *mqlRipplingDepartment) employees() ([]any, error) {
	conn := d.MqlRuntime.Connection.(*connection.RipplingConnection)
	employees, err := conn.ListEmployees(context.Background())
	if err != nil {
		return nil, err
	}
	out := []any{}
	for i := range employees {
		if employees[i].Department != d.Id.Data {
			continue
		}
		emp, err := newMqlRipplingEmployee(d.MqlRuntime, &employees[i])
		if err != nil {
			return nil, err
		}
		out = append(out, emp)
	}
	return out, nil
}
