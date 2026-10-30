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

func newMqlJumpcloudSystem(runtime *plugin.Runtime, s *connection.System) (*mqlJumpcloudSystem, error) {
	res, err := CreateResource(runtime, "jumpcloud.system", map[string]*llx.RawData{
		"id":                             llx.StringData(s.EffectiveID()),
		"hostname":                       llx.StringData(s.Hostname),
		"displayName":                    llx.StringData(s.DisplayName),
		"os":                             llx.StringData(s.OS),
		"version":                        llx.StringData(s.Version),
		"agentVersion":                   llx.StringData(s.AgentVersion),
		"arch":                           llx.StringData(s.Arch),
		"active":                         llx.BoolData(s.Active),
		"allowSshRootLogin":              llx.BoolData(s.AllowSshRootLogin),
		"allowSshPasswordAuthentication": llx.BoolData(s.AllowSshPasswordAuthentication),
		"allowMultiFactorAuthentication": llx.BoolData(s.AllowMultiFactorAuthentication),
		"allowPublicKeyAuthentication":   llx.BoolData(s.AllowPublicKeyAuthentication),
		"fdeActive":                      llx.BoolData(s.FdeActive()),
		"systemInsightsEnabled":          llx.BoolData(s.InsightsEnabled()),
		"hasServiceAccount":              llx.BoolData(s.HasServiceAccount),
		"remoteIP":                       llx.StringData(s.RemoteIP),
		"lastContact":                    llx.TimeDataPtr(connection.ParseTime(s.LastContact)),
		"created":                        llx.TimeDataPtr(connection.ParseTime(s.Created)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJumpcloudSystem), nil
}

func (s *mqlJumpcloudSystem) id() (string, error) {
	return "jumpcloud.system/" + s.Id.Data, nil
}

// users resolves the accounts associated with the system via the v2
// association graph.
func (s *mqlJumpcloudSystem) users() ([]any, error) {
	conn := resolveConn(s.MqlRuntime)
	ctx := context.Background()

	conns, err := conn.Client().GraphConnections(ctx, connection.GraphPath("/v2/systems", s.Id.Data, "users"))
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
				log.Warn().Str("user", id).Err(err).Msg("jumpcloud: failed to resolve associated user")
				continue
			}
		}
		res, err := newMqlJumpcloudUser(s.MqlRuntime, user)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

// systemGroups resolves the system groups the system belongs to via the v2
// membership graph.
func (s *mqlJumpcloudSystem) systemGroups() ([]any, error) {
	conn := resolveConn(s.MqlRuntime)
	ctx := context.Background()

	conns, err := conn.Client().GraphConnections(ctx, connection.GraphPath("/v2/systems", s.Id.Data, "memberof"))
	if err != nil {
		return nil, err
	}
	ids := connection.GraphTargetIDs(conns, "")

	_, idx, err := conn.SystemGroups(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		g, ok := idx[id]
		if !ok {
			g, err = conn.Client().GetSystemGroup(ctx, id)
			if err != nil {
				log.Warn().Str("systemGroup", id).Err(err).Msg("jumpcloud: failed to resolve associated system group")
				continue
			}
		}
		res, err := newMqlJumpcloudSystemGroup(s.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
