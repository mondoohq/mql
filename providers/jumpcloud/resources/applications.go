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

func newMqlJumpcloudApplication(runtime *plugin.Runtime, a *connection.Application) (*mqlJumpcloudApplication, error) {
	res, err := CreateResource(runtime, "jumpcloud.application", map[string]*llx.RawData{
		"id":          llx.StringData(a.ID),
		"name":        llx.StringData(a.Name),
		"displayName": llx.StringData(a.DisplayName),
		"ssoUrl":      llx.StringData(a.SsoURL),
		"active":      llx.BoolData(a.Active),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlJumpcloudApplication), nil
}

func (a *mqlJumpcloudApplication) id() (string, error) {
	return "jumpcloud.application/" + a.Id.Data, nil
}

// userGroups resolves the user groups that grant access to the application via
// the v2 association graph.
func (a *mqlJumpcloudApplication) userGroups() ([]any, error) {
	conn := resolveConn(a.MqlRuntime)
	ctx := context.Background()

	conns, err := conn.Client().GraphConnections(ctx, connection.GraphPath("/v2/applications", a.Id.Data, "usergroups"))
	if err != nil {
		return nil, err
	}
	ids := connection.GraphTargetIDs(conns, "")

	_, idx, err := conn.UserGroups(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]any, 0, len(ids))
	for _, id := range ids {
		g, ok := idx[id]
		if !ok {
			g, err = conn.Client().GetUserGroup(ctx, id)
			if err != nil {
				log.Warn().Str("userGroup", id).Err(err).Msg("jumpcloud: failed to resolve application user group")
				continue
			}
		}
		res, err := newMqlJumpcloudUserGroup(a.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
