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

type mqlGustoDepartmentInternal struct {
	employeeUUIDs   []string
	contractorUUIDs []string
}

func (d *mqlGustoDepartment) id() (string, error) {
	return "gusto.department/" + d.Uuid.Data, d.Uuid.Error
}

func initGustoDepartment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
		departments, err := conn.ListDepartments(context.Background(), company.UUID)
		if err != nil {
			return nil, nil, err
		}
		for i := range departments {
			if departments[i].UUID != uuid {
				continue
			}
			// Build the resource directly so the Internal struct's
			// employeeUUIDs are populated — otherwise employees() would
			// fall back to re-listing the company's employees.
			dept, err := newMqlGustoDepartment(runtime, &departments[i])
			if err != nil {
				return nil, nil, err
			}
			return args, dept, nil
		}
	}
	return nil, nil, errors.New("gusto.department with uuid " + uuid + " not accessible with the configured token")
}

func newMqlGustoDepartment(runtime *plugin.Runtime, d *connection.Department) (*mqlGustoDepartment, error) {
	r, err := CreateResource(runtime, "gusto.department", map[string]*llx.RawData{
		"uuid":        llx.StringData(d.UUID),
		"companyUuid": llx.StringData(d.CompanyUUID),
		"name":        llx.StringData(d.Title),
	})
	if err != nil {
		return nil, err
	}
	dept := r.(*mqlGustoDepartment)
	dept.employeeUUIDs = make([]string, 0, len(d.EmployeeRefs))
	for _, ref := range d.EmployeeRefs {
		dept.employeeUUIDs = append(dept.employeeUUIDs, ref.UUID)
	}
	dept.contractorUUIDs = make([]string, 0, len(d.ContractorRef))
	for _, ref := range d.ContractorRef {
		dept.contractorUUIDs = append(dept.contractorUUIDs, ref.UUID)
	}
	return dept, nil
}

func (d *mqlGustoDepartment) employees() ([]any, error) {
	// List the company's employees once (cached on the connection) and build
	// each resource directly. Resolving employee UUIDs via NewResource would
	// trigger gusto.employee's init, which walks every accessible company per
	// employee — an O(companies) cost we avoid here.
	conn := d.MqlRuntime.Connection.(*connection.GustoConnection)
	employees, err := conn.ListEmployees(context.Background(), d.CompanyUuid.Data)
	if err != nil {
		return nil, err
	}

	// If the parent department list populated employee UUIDs, resolve exactly
	// that set. Otherwise fall back to filtering by department_uuid — needed
	// when the department is selected directly via `gusto.department(uuid: ...)`.
	if len(d.employeeUUIDs) > 0 {
		byUUID := make(map[string]*connection.Employee, len(employees))
		for i := range employees {
			byUUID[employees[i].UUID] = &employees[i]
		}
		out := make([]any, 0, len(d.employeeUUIDs))
		for _, uuid := range d.employeeUUIDs {
			e, ok := byUUID[uuid]
			if !ok {
				continue
			}
			r, err := newMqlGustoEmployee(d.MqlRuntime, e)
			if err != nil {
				return nil, err
			}
			out = append(out, r)
		}
		return out, nil
	}

	out := []any{}
	for i := range employees {
		if employees[i].DepartmentUUID != d.Uuid.Data {
			continue
		}
		r, err := newMqlGustoEmployee(d.MqlRuntime, &employees[i])
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func (d *mqlGustoDepartment) contractors() ([]any, error) {
	uuids := d.contractorUUIDs

	// If the Internal struct has no contractor UUIDs yet (e.g. the resource
	// was created by a path other than newMqlGustoDepartment), re-fetch the
	// department from the API to obtain the contractor refs. The list is
	// cached on the connection, so this is at most one HTTP request.
	if len(uuids) == 0 && d.CompanyUuid.Data != "" && d.Uuid.Data != "" {
		conn := d.MqlRuntime.Connection.(*connection.GustoConnection)
		departments, err := conn.ListDepartments(context.Background(), d.CompanyUuid.Data)
		if err != nil {
			return nil, err
		}
		for i := range departments {
			if departments[i].UUID != d.Uuid.Data {
				continue
			}
			uuids = make([]string, 0, len(departments[i].ContractorRef))
			for _, ref := range departments[i].ContractorRef {
				uuids = append(uuids, ref.UUID)
			}
			break
		}
	}

	out := make([]any, 0, len(uuids))
	for _, uuid := range uuids {
		r, err := NewResource(d.MqlRuntime, "gusto.contractor", map[string]*llx.RawData{
			"uuid": llx.StringData(uuid),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
