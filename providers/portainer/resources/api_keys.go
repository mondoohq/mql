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
	"go.mondoo.com/mql/providers/portainer/connection"
	"go.mondoo.com/mql/types"
)

type mqlPortainerApiKeyInternal struct {
	cacheUserId int64
}

type mqlPortainerUserEnvironmentAuthorizationInternal struct {
	cacheEndpointId int64
}

func newMqlPortainerApiKey(runtime *plugin.Runtime, k *models.PortainerAPIKey) (*mqlPortainerApiKey, error) {
	// Neither the key material nor its stored digest is mapped: the key is a
	// bearer credential and the digest is derived from it.
	//
	// API key ids are small integers, so the cache key carries the account the
	// key belongs to as well as the key's own id.
	res, err := CreateResource(runtime, "portainer.apiKey", map[string]*llx.RawData{
		"__id": llx.StringData("portainer.apiKey/" +
			strconv.FormatInt(k.UserID, 10) + "/" + strconv.FormatInt(k.ID, 10)),
		"id":          llx.IntData(k.ID),
		"description": llx.StringData(k.Description),
		"prefix":      llx.StringData(k.Prefix),
		"dateCreated": llx.TimeDataPtr(unixTimePtr(k.DateCreated)),
		"lastUsed":    llx.TimeDataPtr(unixTimePtr(k.LastUsed)),
	})
	if err != nil {
		return nil, err
	}
	mqlKey := res.(*mqlPortainerApiKey)
	mqlKey.cacheUserId = k.UserID
	return mqlKey, nil
}

// apiKeys returns the API keys issued for the account.
func (r *mqlPortainerUser) apiKeys() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)

	keys, err := conn.APIKeys(r.Id.Data)
	if connection.IsForbidden(err) {
		// Only an administrator, or the owner of the account, may list its
		// keys. A refusal is not evidence that the account holds none, so the
		// field is reported as null rather than as an empty list.
		log.Debug().Int64("user", r.Id.Data).Msg("not permitted to list Portainer API keys for this account")
		r.ApiKeys.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(keys))
	for _, k := range keys {
		mqlKey, err := newMqlPortainerApiKey(r.MqlRuntime, k)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

// user resolves the account the key was issued for.
func (r *mqlPortainerApiKey) user() (*mqlPortainerUser, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	users, err := conn.Users()
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u.ID == r.cacheUserId {
			return newMqlPortainerUser(r.MqlRuntime, u)
		}
	}
	r.User.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// userEnvironmentAuthorizationIDs returns the environment ids an account holds
// computed authorizations on, in ascending order. The API keys them by
// environment id rendered as a string; an entry whose key is not a number
// cannot be attributed to an environment and is skipped rather than reported
// against a wrong one.
func userEnvironmentAuthorizationIDs(auths models.PortainerEndpointAuthorizations) []int64 {
	ids := make([]int64, 0, len(auths))
	for key := range auths {
		id, err := strconv.ParseInt(key, 10, 64)
		if err != nil {
			log.Warn().Str("key", key).Msg("skipping Portainer user authorizations with a non-numeric environment key")
			continue
		}
		ids = append(ids, id)
	}
	slices.Sort(ids)
	return ids
}

// environmentAuthorizations reports the authorization set the server itself
// computed for the account on each environment.
func (r *mqlPortainerUser) environmentAuthorizations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	users, err := conn.Users()
	if err != nil {
		return nil, err
	}
	var auths models.PortainerEndpointAuthorizations
	found := false
	for _, u := range users {
		if u.ID == r.Id.Data {
			auths = u.EndpointAuthorizations
			found = true
			break
		}
	}
	if !found || auths == nil {
		// The instance computes no per-environment authorizations, or the
		// account is not visible to this token. Either way nothing was read, so
		// the field is null rather than an empty list.
		r.EnvironmentAuthorizations.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	res := []any{}
	for _, endpointID := range userEnvironmentAuthorizationIDs(auths) {
		names, ok := grantedAuthorizations(auths[strconv.FormatInt(endpointID, 10)])
		if !ok {
			names = []any{}
		}
		// The authorization set repeats per environment, so the cache key has
		// to carry both the account and the environment it applies to.
		mqlAuth, err := CreateResource(r.MqlRuntime, "portainer.user.environmentAuthorization", map[string]*llx.RawData{
			"__id": llx.StringData("portainer.user.environmentAuthorization/" +
				strconv.FormatInt(r.Id.Data, 10) + "/" + strconv.FormatInt(endpointID, 10)),
			"authorizations": llx.ArrayData(names, types.String),
		})
		if err != nil {
			return nil, err
		}
		mqlAuth.(*mqlPortainerUserEnvironmentAuthorization).cacheEndpointId = endpointID
		res = append(res, mqlAuth)
	}
	return res, nil
}

// environment resolves the environment the authorizations apply to.
func (r *mqlPortainerUserEnvironmentAuthorization) environment() (*mqlPortainerEnvironment, error) {
	conn := r.MqlRuntime.Connection.(*connection.PortainerConnection)
	return resolvePortainerEnvironment(r.MqlRuntime, conn, r.cacheEndpointId, &r.Environment)
}
