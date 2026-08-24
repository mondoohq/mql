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
	cacheCompanyUUID string
	employeeUUIDs    []string
	contractorUUIDs  []string
}

func (d *mqlGustoDepartment) id() (string, error) {
	return "gusto.department/" + d.Uuid.Data, d.Uuid.Error
}

func initGustoDepartment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	uuid, err := uuidArg(args, "gusto.department")
	if err != nil {
		return nil, nil, err
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
		"uuid": llx.StringData(d.UUID),
		"name": llx.StringData(d.Title),
	})
	if err != nil {
		return nil, err
	}
	dept := r.(*mqlGustoDepartment)
	dept.cacheCompanyUUID = d.CompanyUUID
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

func (d *mqlGustoDepartment) company() (*mqlGustoCompany, error) {
	return resolveCompany(d.MqlRuntime, d.cacheCompanyUUID, &d.Company)
}

func (d *mqlGustoDepartment) employees() ([]any, error) {
	employees, err := d.companyEmployees()
	if err != nil {
		return nil, err
	}

	// The department payload lists the uuids assigned to it. Resolve exactly
	// that set from the company roster, which is memoized on the connection.
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

	// No uuid list to work from, so fall back to the department_uuid carried
	// by each employee record.
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
	uuids, err := d.contractorRefs()
	if err != nil {
		return nil, err
	}
	if len(uuids) == 0 {
		return []any{}, nil
	}

	// Resolve against the company's contractor list rather than one
	// NewResource per uuid: gusto.contractor's init walks every accessible
	// company, so a per-uuid lookup would cost O(contractors x companies).
	contractors, err := d.companyContractors()
	if err != nil {
		return nil, err
	}
	byUUID := make(map[string]*connection.Contractor, len(contractors))
	for i := range contractors {
		byUUID[contractors[i].UUID] = &contractors[i]
	}

	out := make([]any, 0, len(uuids))
	for _, uuid := range uuids {
		c, ok := byUUID[uuid]
		if !ok {
			continue
		}
		r, err := newMqlGustoContractor(d.MqlRuntime, c)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// contractorRefs returns the contractor uuids assigned to the department,
// re-reading the department list when the resource was built by a path that
// did not populate them. The list is memoized on the connection.
func (d *mqlGustoDepartment) contractorRefs() ([]string, error) {
	if len(d.contractorUUIDs) > 0 || d.cacheCompanyUUID == "" || d.Uuid.Data == "" {
		return d.contractorUUIDs, nil
	}
	conn := d.MqlRuntime.Connection.(*connection.GustoConnection)
	departments, err := conn.ListDepartments(context.Background(), d.cacheCompanyUUID)
	if err != nil {
		return nil, err
	}
	for i := range departments {
		if departments[i].UUID != d.Uuid.Data {
			continue
		}
		uuids := make([]string, 0, len(departments[i].ContractorRef))
		for _, ref := range departments[i].ContractorRef {
			uuids = append(uuids, ref.UUID)
		}
		return uuids, nil
	}
	return nil, nil
}

func (d *mqlGustoDepartment) companyEmployees() ([]connection.Employee, error) {
	conn := d.MqlRuntime.Connection.(*connection.GustoConnection)
	return conn.ListEmployees(context.Background(), d.cacheCompanyUUID)
}

func (d *mqlGustoDepartment) companyContractors() ([]connection.Contractor, error) {
	conn := d.MqlRuntime.Connection.(*connection.GustoConnection)
	return conn.ListContractors(context.Background(), d.cacheCompanyUUID)
}
