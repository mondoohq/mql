// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"slices"
	"strconv"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/portainer/connection"
	"go.mondoo.com/mql/types"
)

type mqlPortainerRegistryInternal struct {
	cacheAccesses models.PortainerRegistryAccesses
}

type mqlPortainerRegistryAccessInternal struct {
	cacheEndpointId int64
}

func newMqlPortainerRegistry(runtime *plugin.Runtime, r *models.PortainereeRegistry) (*mqlPortainerRegistry, error) {
	res, err := CreateResource(runtime, "portainer.registry", map[string]*llx.RawData{
		"__id":                  llx.StringData("portainer.registry/" + strconv.FormatInt(r.ID, 10)),
		"id":                    llx.IntData(r.ID),
		"name":                  llx.StringData(r.Name),
		"type":                  llx.StringData(connection.RegistryType(r.Type)),
		"url":                   llx.StringData(r.URL),
		"baseUrl":               llx.StringData(r.BaseURL),
		"authenticationEnabled": llx.BoolData(r.Authentication),
		"username":              llx.StringData(r.Username),
	})
	if err != nil {
		return nil, err
	}
	mqlRegistry := res.(*mqlPortainerRegistry)
	mqlRegistry.cacheAccesses = r.RegistryAccesses
	return mqlRegistry, nil
}

func (r *mqlPortainer) registries() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	registries, err := conn.Registries()
	if connection.IsForbidden(err) {
		// Listing registries is administrator-only. A refusal is not evidence
		// that the instance has none, so the field is null rather than an empty
		// list an audit would read as a pass.
		log.Debug().Msg("not permitted to list Portainer registries")
		r.Registries.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(registries))
	for _, reg := range registries {
		mqlRegistry, err := newMqlPortainerRegistry(r.MqlRuntime, reg)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRegistry)
	}
	return res, nil
}

// registryAccessEndpointIDs returns the environment ids a registry is granted
// on, in ascending order. The API keys the grants by environment id rendered as
// a string; an entry whose key is not a number cannot be attributed to an
// environment and is skipped rather than reported against a wrong one.
func registryAccessEndpointIDs(accesses models.PortainerRegistryAccesses) []int64 {
	ids := make([]int64, 0, len(accesses))
	for key := range accesses {
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			log.Warn().Str("key", key).Msg("skipping Portainer registry access with a non-numeric environment key")
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// accesses reports which teams and users may use the registry on each
// environment.
func (r *mqlPortainerRegistry) accesses() ([]any, error) {
	res := []any{}
	for _, endpointID := range registryAccessEndpointIDs(r.cacheAccesses) {
		policies := r.cacheAccesses[strconv.FormatInt(endpointID, 10)]

		// A registry grant repeats per environment, so the cache key has to
		// carry both the registry and the environment it applies to.
		mqlAccess, err := CreateResource(r.MqlRuntime, "portainer.registry.access", map[string]*llx.RawData{
			"__id": llx.StringData("portainer.registry.access/" +
				strconv.FormatInt(r.Id.Data, 10) + "/" + strconv.FormatInt(endpointID, 10)),
			"namespaces":         llx.ArrayData(convert.SliceAnyToInterface(policies.Namespaces), types.String),
			"teamAccessPolicies": llx.DictData(accessPoliciesToDict(policies.TeamAccessPolicies)),
			"userAccessPolicies": llx.DictData(accessPoliciesToDict(policies.UserAccessPolicies)),
			"teamAccessRoles":    llx.DictData(accessRolesToDict(policies.TeamAccessPolicies)),
			"userAccessRoles":    llx.DictData(accessRolesToDict(policies.UserAccessPolicies)),
		})
		if err != nil {
			return nil, err
		}
		mqlAccess.(*mqlPortainerRegistryAccess).cacheEndpointId = endpointID
		res = append(res, mqlAccess)
	}
	return res, nil
}

// environment resolves the environment the grant applies to.
func (r *mqlPortainerRegistryAccess) environment() (*mqlPortainerEnvironment, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	return resolvePortainerEnvironment(r.MqlRuntime, conn, r.cacheEndpointId, &r.Environment)
}
