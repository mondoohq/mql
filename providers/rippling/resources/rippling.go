// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers/rippling/connection"
)

func (r *mqlRippling) id() (string, error) {
	return "rippling", nil
}

func (r *mqlRippling) companies() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.RipplingConnection)
	company, err := conn.GetCompany(context.Background())
	if err != nil {
		return nil, err
	}
	c, err := newMqlRipplingCompany(r.MqlRuntime, company)
	if err != nil {
		return nil, err
	}
	return []any{c}, nil
}

func (r *mqlRippling) employees() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.RipplingConnection)
	employees, err := conn.ListEmployees(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(employees))
	for i := range employees {
		emp, err := newMqlRipplingEmployee(r.MqlRuntime, &employees[i])
		if err != nil {
			return nil, err
		}
		out = append(out, emp)
	}
	return out, nil
}

func (r *mqlRippling) departments() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.RipplingConnection)
	departments, err := conn.ListDepartments(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(departments))
	for i := range departments {
		d, err := newMqlRipplingDepartment(r.MqlRuntime, &departments[i])
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

func (r *mqlRippling) teams() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.RipplingConnection)
	teams, err := conn.ListTeams(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(teams))
	for i := range teams {
		t, err := newMqlRipplingTeam(r.MqlRuntime, &teams[i])
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func (r *mqlRippling) workLocations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.RipplingConnection)
	locations, err := conn.ListWorkLocations(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(locations))
	for i := range locations {
		l, err := newMqlRipplingWorkLocation(r.MqlRuntime, &locations[i])
		if err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, nil
}

func (r *mqlRippling) groups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.RipplingConnection)
	groups, err := conn.ListGroups(context.Background())
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(groups))
	for i := range groups {
		g, err := newMqlRipplingGroup(r.MqlRuntime, &groups[i])
		if err != nil {
			return nil, err
		}
		out = append(out, g)
	}
	return out, nil
}

// resolveEmployee returns the cached MQL employee resource for the given
// id, fetching the full list once and reusing it for subsequent lookups
// during a single connection. Used by every typed cross-ref into
// rippling.employee.
func resolveEmployee(runtime *plugin.Runtime, id string) (*mqlRipplingEmployee, error) {
	r, err := NewResource(runtime, "rippling.employee", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingEmployee), nil
}
