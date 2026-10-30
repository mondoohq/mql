// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/portainer/connection"
	"go.mondoo.com/mql/types"
)

// errNoRoleID reports a role the API returned without an identifier. Its cache
// key would collide with every other such role, so it is skipped.
var errNoRoleID = errors.New("Portainer role has no identifier")

func newMqlPortainerRole(runtime *plugin.Runtime, r *models.PortainereeRole) (*mqlPortainerRole, error) {
	// Every scalar on a role is a required field the API returns as a pointer,
	// so a nil one is a role the server did not fully describe rather than a
	// role named "" with priority 0. The identifier is the cache key, so a role
	// without one cannot be created at all; the caller skips it.
	if r.ID == nil {
		return nil, errNoRoleID
	}
	args := map[string]*llx.RawData{
		"__id":        llx.StringData("portainer.role/" + strconv.FormatInt(*r.ID, 10)),
		"id":          llx.IntDataPtr(r.ID),
		"name":        llx.StringDataPtr(r.Name),
		"description": llx.StringDataPtr(r.Description),
		"priority":    llx.IntDataPtr(r.Priority),
	}
	if names, ok := grantedAuthorizations(r.Authorizations); ok {
		args["authorizations"] = llx.ArrayData(names, types.String)
	} else {
		args["authorizations"] = llx.NilData
	}

	res, err := CreateResource(runtime, "portainer.role", args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlPortainerRole), nil
}

func (r *mqlPortainer) roles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	roles, err := conn.Roles()
	if connection.IsForbidden(err) {
		// Listing role definitions is administrator-only; a refusal is not
		// evidence that the instance defines none.
		log.Debug().Msg("not permitted to list Portainer role definitions")
		r.Roles.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(roles))
	for _, role := range roles {
		mqlRole, err := newMqlPortainerRole(r.MqlRuntime, role)
		if errors.Is(err, errNoRoleID) {
			log.Warn().Msg("skipping Portainer role without an identifier")
			continue
		}
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	return res, nil
}
