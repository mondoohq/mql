// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/jumpcloud/connection"
)

func newMqlJumpcloudUserGroup(runtime *plugin.Runtime, g *connection.Group) (*mqlJumpcloudUserGroup, error) {
	res, err := CreateResource(runtime, "jumpcloud.userGroup", map[string]*llx.RawData{
		"id":          llx.StringData(g.ID),
		"name":        llx.StringData(g.Name),
		"description": llx.StringData(g.Description),
		"email":       llx.StringData(g.Email),
		"type":        llx.StringData(g.Type),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJumpcloudUserGroup), nil
}

func (g *mqlJumpcloudUserGroup) id() (string, error) {
	return "jumpcloud.userGroup/" + g.Id.Data, nil
}

// members resolves the user accounts that belong to the group via the v2
// membership graph.
func (g *mqlJumpcloudUserGroup) members() ([]any, error) {
	conn := resolveConn(g.MqlRuntime)
	ctx := context.Background()

	conns, err := conn.Client().GraphConnections(ctx, connection.GraphPath("/v2/usergroups", g.Id.Data, "members"))
	if err != nil {
		return nil, err
	}
	ids := connection.GraphTargetIDs(conns, "")

	_, idx, err := conn.Users(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		user, ok := idx[id]
		if !ok {
			user, err = conn.Client().GetSystemUser(ctx, id)
			if err != nil {
				log.Warn().Str("user", id).Err(err).Msg("jumpcloud: failed to resolve group member")
				continue
			}
		}
		res, err := newMqlJumpcloudUser(g.MqlRuntime, user)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func newMqlJumpcloudSystemGroup(runtime *plugin.Runtime, g *connection.Group) (*mqlJumpcloudSystemGroup, error) {
	res, err := CreateResource(runtime, "jumpcloud.systemGroup", map[string]*llx.RawData{
		"id":          llx.StringData(g.ID),
		"name":        llx.StringData(g.Name),
		"description": llx.StringData(g.Description),
		"type":        llx.StringData(g.Type),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJumpcloudSystemGroup), nil
}

func (g *mqlJumpcloudSystemGroup) id() (string, error) {
	return "jumpcloud.systemGroup/" + g.Id.Data, nil
}

// members resolves the systems that belong to the group via the v2 membership
// graph.
func (g *mqlJumpcloudSystemGroup) members() ([]any, error) {
	conn := resolveConn(g.MqlRuntime)
	ctx := context.Background()

	conns, err := conn.Client().GraphConnections(ctx, connection.GraphPath("/v2/systemgroups", g.Id.Data, "members"))
	if err != nil {
		return nil, err
	}
	ids := connection.GraphTargetIDs(conns, "")

	_, idx, err := conn.Systems(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		s, ok := idx[id]
		if !ok {
			s, err = conn.Client().GetSystem(ctx, id)
			if err != nil {
				log.Warn().Str("system", id).Err(err).Msg("jumpcloud: failed to resolve group member")
				continue
			}
		}
		res, err := newMqlJumpcloudSystem(g.MqlRuntime, s)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
