// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/rippling/connection"
)

type mqlRipplingEmployeeInternal struct {
	managerID      string
	departmentID   string
	teamID         string
	workLocationID string
}

func (e *mqlRipplingEmployee) id() (string, error) {
	return "rippling.employee/" + e.Id.Data, e.Id.Error
}

func initRipplingEmployee(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	employees, err := conn.ListEmployees(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for i := range employees {
		if employees[i].ID != id {
			continue
		}
		// Build the resource directly so the Internal struct's manager /
		// department / team / work-location IDs are populated — otherwise
		// those cross-references would resolve to null.
		emp, err := newMqlRipplingEmployee(runtime, &employees[i])
		if err != nil {
			return nil, nil, err
		}
		return args, emp, nil
	}
	return nil, nil, errors.New("rippling.employee with id " + id + " not accessible with the configured token")
}

func populateEmployeeArgs(args map[string]*llx.RawData, e *connection.Employee) {
	args["id"] = llx.StringData(e.ID)
	args["employeeNumber"] = llx.IntData(int64(e.EmployeeNumber))
	args["firstName"] = llx.StringData(e.FirstName)
	args["middleName"] = llx.StringData(e.MiddleName)
	args["lastName"] = llx.StringData(e.LastName)
	args["preferredFirstName"] = llx.StringData(e.PreferredFirstName)
	args["workEmail"] = llx.StringData(e.WorkEmail)
	args["personalEmail"] = llx.StringData(e.PersonalEmail)
	args["phoneNumber"] = llx.StringData(e.PhoneNumber)
	args["title"] = llx.StringData(e.Title)
	args["employmentType"] = llx.StringData(e.EmploymentType)
	args["roleStatus"] = llx.StringData(e.RoleStatus)
	args["terminated"] = llx.BoolData(isTerminated(e))
	args["startDate"] = llx.TimeData(e.StartDate.Time)
	args["endDate"] = llx.TimeData(e.EndDate.Time)
	args["terminationDate"] = llx.TimeData(e.TerminationDate.Time)
	args["terminationType"] = llx.StringData(e.TerminationType)
	args["terminationReason"] = llx.StringData(e.TerminationReason)
	args["createdAt"] = llx.TimeData(e.CreatedAt.Time)
	args["updatedAt"] = llx.TimeData(e.UpdatedAt.Time)
}

// isTerminated derives the terminated bool from the explicit termination
// signals Rippling exposes. We treat any TERMINATED roleStatus as
// terminated, and otherwise fall back to a non-empty terminationDate.
// Both signals can be set on the same record; either is sufficient.
func isTerminated(e *connection.Employee) bool {
	if strings.EqualFold(e.RoleStatus, "TERMINATED") {
		return true
	}
	return !e.TerminationDate.Time.IsZero()
}

func newMqlRipplingEmployee(runtime *plugin.Runtime, e *connection.Employee) (*mqlRipplingEmployee, error) {
	args := map[string]*llx.RawData{}
	populateEmployeeArgs(args, e)
	r, err := CreateResource(runtime, "rippling.employee", args)
	if err != nil {
		return nil, err
	}
	emp := r.(*mqlRipplingEmployee)
	emp.managerID = e.Manager
	emp.departmentID = e.Department
	emp.teamID = e.Team
	emp.workLocationID = e.WorkLocation
	return emp, nil
}

func (e *mqlRipplingEmployee) manager() (*mqlRipplingEmployee, error) {
	if e.managerID == "" {
		e.Manager.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveEmployee(e.MqlRuntime, e.managerID)
}

func (e *mqlRipplingEmployee) department() (*mqlRipplingDepartment, error) {
	if e.departmentID == "" {
		e.Department.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "rippling.department", map[string]*llx.RawData{
		"id": llx.StringData(e.departmentID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingDepartment), nil
}

func (e *mqlRipplingEmployee) team() (*mqlRipplingTeam, error) {
	if e.teamID == "" {
		e.Team.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "rippling.team", map[string]*llx.RawData{
		"id": llx.StringData(e.teamID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingTeam), nil
}

func (e *mqlRipplingEmployee) workLocation() (*mqlRipplingWorkLocation, error) {
	if e.workLocationID == "" {
		e.WorkLocation.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(e.MqlRuntime, "rippling.workLocation", map[string]*llx.RawData{
		"id": llx.StringData(e.workLocationID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingWorkLocation), nil
}
