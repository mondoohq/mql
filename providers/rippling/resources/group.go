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

type mqlRipplingGroupInternal struct {
	memberIDs []string
}

func (g *mqlRipplingGroup) id() (string, error) {
	return "rippling.group/" + g.Id.Data, g.Id.Error
}

func initRipplingGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
	groups, err := conn.ListGroups(context.Background())
	if err != nil {
		return nil, nil, err
	}
	for i := range groups {
		if groups[i].ID != id {
			continue
		}
		// Build the resource directly so the Internal struct's memberIDs are
		// populated — otherwise members() would resolve to an empty list.
		g, err := newMqlRipplingGroup(runtime, &groups[i])
		if err != nil {
			return nil, nil, err
		}
		return args, g, nil
	}
	return nil, nil, errors.New("rippling.group with id " + id + " not accessible with the configured token")
}

func newMqlRipplingGroup(runtime *plugin.Runtime, g *connection.Group) (*mqlRipplingGroup, error) {
	r, err := CreateResource(runtime, "rippling.group", map[string]*llx.RawData{
		"id":      llx.StringData(g.ID),
		"name":    llx.StringData(g.Name),
		"version": llx.StringData(g.Version),
	})
	if err != nil {
		return nil, err
	}
	group := r.(*mqlRipplingGroup)
	group.memberIDs = append(group.memberIDs, g.Users...)
	return group, nil
}

func (g *mqlRipplingGroup) members() ([]any, error) {
	out := make([]any, 0, len(g.memberIDs))
	for _, id := range g.memberIDs {
		emp, err := resolveEmployee(g.MqlRuntime, id)
		if err != nil {
			return nil, err
		}
		out = append(out, emp)
	}
	return out, nil
}
