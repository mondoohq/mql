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

type mqlGustoEmployeeInternal struct {
	managerUUID      string
	departmentUUID   string
	workLocationUUID string
}

func (e *mqlGustoEmployee) id() (string, error) {
	return "gusto.employee/" + e.Uuid.Data, e.Uuid.Error
}

func initGustoEmployee(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	// Without a company scope the only way to resolve an employee by uuid is
	// to walk every accessible company. We do that lazily here.
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
		employees, err := conn.ListEmployees(context.Background(), company.UUID)
		if err != nil {
			return nil, nil, err
		}
		for i := range employees {
			if employees[i].UUID != uuid {
				continue
			}
			// Build the resource directly so the Internal struct's
			// manager/department/work-location UUIDs are populated —
			// otherwise those typed references would resolve to null.
			emp, err := newMqlGustoEmployee(runtime, &employees[i])
			if err != nil {
				return nil, nil, err
			}
			return args, emp, nil
		}
	}
	return nil, nil, errors.New("gusto.employee with uuid " + uuid + " not accessible with the configured token")
}

func populateEmployeeArgs(args map[string]*llx.RawData, e *connection.Employee) {
	args["uuid"] = llx.StringData(e.UUID)
	args["companyUuid"] = llx.StringData(e.CompanyUUID)
	args["firstName"] = llx.StringData(e.FirstName)
	args["middleInitial"] = llx.StringData(e.MiddleInitial)
	args["lastName"] = llx.StringData(e.LastName)
	args["preferredFirstName"] = llx.StringData(e.PreferredFirstName)
	args["workEmail"] = llx.StringData(e.WorkEmail)
	personalEmail := e.Email
	if e.WorkEmail != "" && personalEmail == e.WorkEmail {
		personalEmail = ""
	}
	args["personalEmail"] = llx.StringData(personalEmail)
	args["phone"] = llx.StringData(e.Phone)
	args["currentEmployment"] = llx.BoolData(e.CurrentEmployment)
	args["onboarded"] = llx.BoolData(e.Onboarded)
	args["onboardingStatus"] = llx.StringData(e.OnboardingStatus)
	args["terminated"] = llx.BoolData(e.Terminated)
	args["twoFactorAuthenticationEnabled"] = llx.BoolData(e.TwoFactorAuthenticationEnabled)
	args["createdAt"] = llx.TimeData(e.CreatedAt)
}

func newMqlGustoEmployee(runtime *plugin.Runtime, e *connection.Employee) (*mqlGustoEmployee, error) {
	args := map[string]*llx.RawData{}
	populateEmployeeArgs(args, e)
	r, err := CreateResource(runtime, "gusto.employee", args)
	if err != nil {
		return nil, err
	}
	emp := r.(*mqlGustoEmployee)
	emp.managerUUID = e.ManagerUUID
	emp.departmentUUID = e.DepartmentUUID
	emp.workLocationUUID = e.WorkLocationUUID
	return emp, nil
}

func (e *mqlGustoEmployee) manager() (*mqlGustoEmployee, error) {
	if e.managerUUID == "" {
		e.Manager.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "gusto.employee", map[string]*llx.RawData{
		"uuid": llx.StringData(e.managerUUID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoEmployee), nil
}

func (e *mqlGustoEmployee) department() (*mqlGustoDepartment, error) {
	if e.departmentUUID == "" {
		e.Department.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "gusto.department", map[string]*llx.RawData{
		"uuid": llx.StringData(e.departmentUUID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoDepartment), nil
}

func (e *mqlGustoEmployee) workLocation() (*mqlGustoLocation, error) {
	if e.workLocationUUID == "" {
		e.WorkLocation.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "gusto.location", map[string]*llx.RawData{
		"uuid": llx.StringData(e.workLocationUUID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlGustoLocation), nil
}
