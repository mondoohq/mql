// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
)

type mqlPortainerEnvironmentGroupInternal struct {
	cacheTagIds []int64
}

func newMqlPortainerEnvironmentGroup(runtime *plugin.Runtime, g *models.PortainerEndpointGroup) (*mqlPortainerEnvironmentGroup, error) {
	res, err := CreateResource(runtime, "portainer.environmentGroup", map[string]*llx.RawData{
		"__id":               llx.StringData("portainer.environmentGroup/" + strconv.FormatInt(g.ID, 10)),
		"id":                 llx.IntData(g.ID),
		"name":               llx.StringData(g.Name),
		"description":        llx.StringData(g.Description),
		"teamAccessPolicies": llx.DictData(accessPoliciesToDict(g.TeamAccessPolicies)),
		"userAccessPolicies": llx.DictData(accessPoliciesToDict(g.UserAccessPolicies)),
		"teamAccessRoles":    llx.DictData(accessRolesToDict(g.TeamAccessPolicies)),
		"userAccessRoles":    llx.DictData(accessRolesToDict(g.UserAccessPolicies)),
	})
	if err != nil {
		return nil, err
	}
	mqlGroup := res.(*mqlPortainerEnvironmentGroup)
	mqlGroup.cacheTagIds = g.TagIds
	return mqlGroup, nil
}

// tags resolves the cached tag ids to the tags assigned to the group.
func (r *mqlPortainerEnvironmentGroup) tags() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	return resolvePortainerTags(r.MqlRuntime, conn, r.cacheTagIds)
}

func (r *mqlPortainer) environmentGroups() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	groups, err := conn.EndpointGroups()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(groups))
	for _, g := range groups {
		mqlGroup, err := newMqlPortainerEnvironmentGroup(r.MqlRuntime, g)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}
