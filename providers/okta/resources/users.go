// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

// mqlOktaUserInternal caches the ids behind the realm and manager references.
// Neither is exposed as a raw field: realmId names a realm, and managerId names
// another user, so both are reachable only through the reference that resolves
// them.
type mqlOktaUserInternal struct {
	cacheRealmId   string
	cacheManagerId string
	// cacheUserTypeId holds the user type the account is assigned, which
	// userType resolves to the full type.
	cacheUserTypeId string
}

// initOktaUser allows callers to construct an okta.user via NewResource by id.
// When only an id is provided, this fetches the user lazily (cached by the
// runtime) so referencing the same user across resources does not N+1 the API.
func initOktaUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// If we already have the full set of fields, no fetch needed.
	if len(args) > 1 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Value == nil {
		// Bare resource construction (no id) is a valid empty state.
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	ctx := context.Background()
	user, resp, err := client.UserAPI.GetUser(ctx, id).Execute()
	if err != nil {
		if isOktaNotFound(resp) {
			return nil, nil, fmt.Errorf("%w: okta.user %q", errOktaResourceNotFound, id)
		}
		return nil, nil, err
	}

	// Returning the built resource is the only way to populate the Internal
	// struct the realm and manager references read from. Merging args instead
	// would leave both empty on every user reached by reference rather than
	// through the collection.
	res, err := newMqlOktaUser(runtime, user)
	if err != nil {
		return nil, nil, err
	}
	return nil, res, nil
}

func (o *mqlOkta) users() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	userSetSlice, resp, err := client.UserAPI.ListUsers(ctx).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	if len(userSetSlice) == 0 {
		return nil, nil
	}

	list := []any{}
	appendEntry := func(datalist []okta.User) error {
		for i := range datalist {
			r, err := newMqlOktaUser(o.MqlRuntime, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	err = appendEntry(userSetSlice)
	if err != nil {
		return nil, err
	}

	for resp != nil && resp.HasNextPage() {
		var userSetSlice []okta.User
		resp, err = resp.Next(&userSetSlice)
		if err != nil {
			return nil, err
		}
		err = appendEntry(userSetSlice)
		if err != nil {
			return nil, err
		}
	}
	return list, nil
}

// oktaUserFromAny normalizes any of the SDK's user-shaped types (User,
// UserGetSingleton, GroupMember) into an okta.User. They share the same JSON
// shape, so routing everything through one normalized type keeps a single code
// path for every place a user is materialized.
func oktaUserFromAny(src any) (*okta.User, error) {
	if v, ok := src.(*okta.User); ok {
		return v, nil
	}
	raw, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	user := &okta.User{}
	if err := json.Unmarshal(raw, user); err != nil {
		return nil, err
	}
	return user, nil
}

// oktaUserManagerId reads the manager id out of a user's profile. Okta models
// the reporting line as a profile attribute rather than a first-class field,
// and leaves it unset on orgs that do not import one.
func oktaUserManagerId(user *okta.User) string {
	if user.Profile == nil {
		return ""
	}
	return oktaStr(user.Profile.ManagerId.Get())
}

// oktaUserArgs builds the okta.user resource fields.
func oktaUserArgs(user *okta.User) (map[string]*llx.RawData, error) {
	credentials, err := convert.JsonToDict(user.Credentials)
	if err != nil {
		return nil, err
	}
	profileDict, err := convert.JsonToDict(user.Profile)
	if err != nil {
		return nil, err
	}

	return map[string]*llx.RawData{
		"id":                    llx.StringData(oktaStr(user.Id)),
		"credentials":           llx.DictData(credentials),
		"activated":             llx.TimeDataPtr(user.Activated.Get()),
		"created":               llx.TimeDataPtr(user.Created),
		"lastLogin":             llx.TimeDataPtr(user.LastLogin.Get()),
		"lastUpdated":           llx.TimeDataPtr(user.LastUpdated),
		"passwordChanged":       llx.TimeDataPtr(user.PasswordChanged.Get()),
		"profile":               llx.DictData(profileDict),
		"status":                llx.StringData(oktaStr(user.Status)),
		"statusChanged":         llx.TimeDataPtr(user.StatusChanged.Get()),
		"transitioningToStatus": llx.StringData(oktaStr(user.TransitioningToStatus.Get())),
	}, nil
}

func newMqlOktaUser(runtime *plugin.Runtime, src any) (*mqlOktaUser, error) {
	user, err := oktaUserFromAny(src)
	if err != nil {
		return nil, err
	}
	args, err := oktaUserArgs(user)
	if err != nil {
		return nil, err
	}
	r, err := CreateResource(runtime, "okta.user", args)
	if err != nil {
		return nil, err
	}
	mqlUser := r.(*mqlOktaUser)
	mqlUser.cacheRealmId = oktaStr(user.RealmId)
	mqlUser.cacheManagerId = oktaUserManagerId(user)
	if user.Type != nil {
		mqlUser.cacheUserTypeId = oktaStr(user.Type.Id)
	}
	return mqlUser, nil
}

func (o *mqlOktaUser) id() (string, error) {
	return "okta.user/" + o.Id.Data, o.Id.Error
}

func (o *mqlOktaUser) roles() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	roles, resp, err := client.RoleAssignmentAUserAPI.ListAssignedRolesForUser(ctx, o.Id.Data).Execute()
	if err != nil {
		return nil, err
	}
	res := []any{}

	appendEntry := func(datalist []okta.ListGroupAssignedRoles200ResponseInner) error {
		for i := range datalist {
			mqlOktaRole, err := newMqlOktaAssignedRole(o.MqlRuntime, &datalist[i], "user", o.Id.Data)
			if err != nil {
				return err
			}
			if mqlOktaRole == nil {
				log.Warn().Str("user", o.Id.Data).
					Msg("skipping a role assignment of an unrecognized kind")
				continue
			}
			res = append(res, mqlOktaRole)
		}
		return nil
	}
	err = appendEntry(roles)
	if err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var userRoles []okta.ListGroupAssignedRoles200ResponseInner
		resp, err = resp.Next(&userRoles)
		if err != nil {
			return nil, err
		}
		err = appendEntry(userRoles)
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (o *mqlOktaUser) userType() (*mqlOktaUserType, error) {
	return resolveOktaUserTypeRef(o.MqlRuntime, o.cacheUserTypeId, &o.UserType)
}

func (o *mqlOktaUser) realm() (*mqlOktaRealm, error) {
	return resolveOktaRealmRef(o.MqlRuntime, o.cacheRealmId, &o.Realm)
}

func (o *mqlOktaUser) manager() (*mqlOktaUser, error) {
	return resolveOktaUserRef(o.MqlRuntime, o.cacheManagerId, &o.Manager)
}

func (o *mqlOktaUser) groups() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}

	ctx := context.Background()
	slice, resp, err := client.UserResourcesAPI.ListUserGroups(ctx, o.Id.Data).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.Groups)
		}
		return nil, err
	}

	all, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(all))
	for i := range all {
		r, err := newMqlOktaGroup(o.MqlRuntime, &all[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (o *mqlOktaUser) identityProviders() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}

	ctx := context.Background()
	// No .Limit here: the SDK request type for this endpoint offers only
	// Execute, so the API sets the page size.
	slice, resp, err := client.IdentityProviderUsersAPI.ListUserIdentityProviders(ctx, o.Id.Data).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.IdentityProviders)
		}
		return nil, err
	}

	all, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(all))
	for i := range all {
		r, err := newMqlOktaIdentityProvider(o.MqlRuntime, &all[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func (o *mqlOktaUser) blocks() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}

	ctx := context.Background()
	// No .Limit here, for the same reason as identityProviders above.
	slice, resp, err := client.UserAPI.ListUserBlocks(ctx, o.Id.Data).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.Blocks)
		}
		return nil, err
	}

	all, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(all))
	for i := range all {
		block, err := convert.JsonToDict(&all[i])
		if err != nil {
			return nil, err
		}
		list = append(list, block)
	}
	return list, nil
}
