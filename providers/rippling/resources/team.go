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

type mqlRipplingTeamInternal struct {
	parentTeamID string
}

func (t *mqlRipplingTeam) id() (string, error) {
	return "rippling.team/" + t.Id.Data, t.Id.Error
}

func initRipplingTeam(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	teams, err := conn.ListTeams(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for i := range teams {
		if teams[i].ID != id {
			continue
		}
		// Build the resource directly so the Internal struct's parentTeamID
		// is populated — otherwise parentTeam() would resolve to null.
		t, err := newMqlRipplingTeam(runtime, &teams[i])
		if err != nil {
			return nil, nil, err
		}
		return args, t, nil
	}
	return nil, nil, errors.New("rippling.team with id " + id + " not accessible with the configured token")
}

func newMqlRipplingTeam(runtime *plugin.Runtime, t *connection.Team) (*mqlRipplingTeam, error) {
	r, err := CreateResource(runtime, "rippling.team", map[string]*llx.RawData{
		"id":   llx.StringData(t.ID),
		"name": llx.StringData(t.Name),
	})
	if err != nil {
		return nil, err
	}
	team := r.(*mqlRipplingTeam)
	team.parentTeamID = t.ParentTeam
	return team, nil
}

func (t *mqlRipplingTeam) parentTeam() (*mqlRipplingTeam, error) {
	if t.parentTeamID == "" {
		t.ParentTeam.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(t.MqlRuntime, "rippling.team", map[string]*llx.RawData{
		"id": llx.StringData(t.parentTeamID),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlRipplingTeam), nil
}

func (t *mqlRipplingTeam) employees() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.RipplingConnection)
	employees, err := conn.ListEmployees(context.Background())
	if err != nil {
		return nil, err
	}
	out := []any{}
	for i := range employees {
		if employees[i].Team != t.Id.Data {
			continue
		}
		emp, err := newMqlRipplingEmployee(t.MqlRuntime, &employees[i])
		if err != nil {
			return nil, err
		}
		out = append(out, emp)
	}
	return out, nil
}
