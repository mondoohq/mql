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

type mqlGustoEmployeeInternal struct {
	cacheCompanyUUID    string
	cacheManagerUUID    string
	cacheDepartmentUUID string
}

func (e *mqlGustoEmployee) id() (string, error) {
	return "gusto.employee/" + e.Uuid.Data, e.Uuid.Error
}

func initGustoEmployee(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	// Without a company scope the only way to resolve an employee by uuid is
	// to walk every accessible company. The lists are memoized on the
	// connection, so repeated lookups cost one fetch per company.
	uuid, err := uuidArg(args, "gusto.employee")
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.GustoConnection)
	companies, err := conn.ListCompanies(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for _, company := range companies {
		employees, err := conn.ListEmployees(context.Background(), company.UUID)
		if err != nil {
			return nil, nil, err
		}
		for i := range employees {
			if employees[i].UUID != uuid {
				continue
			}
			// Build the resource directly so the Internal struct's cached
			// company, manager, and department UUIDs are populated. Otherwise
			// those references would resolve to null.
			emp, err := newMqlGustoEmployee(runtime, &employees[i])
			if err != nil {
				return nil, nil, err
			}
			return args, emp, nil
		}
	}
	return nil, nil, errors.New("gusto.employee with uuid " + uuid + " not accessible with the configured token")
}

func newMqlGustoEmployee(runtime *plugin.Runtime, e *connection.Employee) (*mqlGustoEmployee, error) {
	personalEmail := e.Email
	if e.WorkEmail != "" && personalEmail == e.WorkEmail {
		personalEmail = ""
	}

	r, err := CreateResource(runtime, "gusto.employee", map[string]*llx.RawData{
		"uuid":                    llx.StringData(e.UUID),
		"firstName":               llx.StringData(e.FirstName),
		"middleInitial":           llx.StringData(e.MiddleInitial),
		"lastName":                llx.StringData(e.LastName),
		"preferredFirstName":      llx.StringData(e.PreferredFirstName),
		"workEmail":               llx.StringData(e.WorkEmail),
		"personalEmail":           llx.StringData(personalEmail),
		"phone":                   llx.StringData(e.Phone),
		"currentEmploymentStatus": llx.StringData(e.CurrentEmploymentStatus),
		"onboarded":               llx.BoolData(e.Onboarded),
		"onboardingStatus":        llx.StringData(e.OnboardingStatus),
		"terminated":              llx.BoolData(e.Terminated),
		"hiredAt":                 llx.TimeDataPtr(e.HiredAt.Ptr()),
	})
	if err != nil {
		return nil, err
	}
	emp := r.(*mqlGustoEmployee)
	emp.cacheCompanyUUID = e.CompanyUUID
	emp.cacheManagerUUID = e.ManagerUUID
	emp.cacheDepartmentUUID = e.DepartmentUUID
	return emp, nil
}

func (e *mqlGustoEmployee) company() (*mqlGustoCompany, error) {
	return resolveCompany(e.MqlRuntime, e.cacheCompanyUUID, &e.Company)
}

func (e *mqlGustoEmployee) manager() (*mqlGustoEmployee, error) {
	if e.cacheManagerUUID == "" {
		e.Manager.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "gusto.employee", map[string]*llx.RawData{
		"uuid": llx.StringData(e.cacheManagerUUID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoEmployee), nil
}

func (e *mqlGustoEmployee) department() (*mqlGustoDepartment, error) {
	if e.cacheDepartmentUUID == "" {
		e.Department.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "gusto.department", map[string]*llx.RawData{
		"uuid": llx.StringData(e.cacheDepartmentUUID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoDepartment), nil
}
