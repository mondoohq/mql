// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"slices"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/zoom/connection"
	"go.mondoo.com/mql/types"
)

// mqlZoomUserInternal caches the raw role and group IDs from list/init time
// so the role and groups accessors can resolve them into typed references
// without re-parsing the source payload.
type mqlZoomUserInternal struct {
	cacheRoleId   string
	cacheGroupIds []string
}

const usersPageSize = 300

// zoomSsoLoginType is the login type Zoom reports for users who authenticate
// through the account's SSO configuration. Note that the neighbouring value
// 100 is Zoom Work email, which is not SSO.
const zoomSsoLoginType = 101

// userVerified reports whether the user's email address is verified. Zoom
// encodes this as 0 (unverified) or 1 (verified).
func userVerified(u *connection.User) bool {
	return u.Verified != 0
}

// userSsoLinked reports whether the user signs in through the account's SSO
// configuration. Zoom returns a user's sign-in methods as a list, and a user
// who has ever signed in another way keeps that method alongside SSO, so this
// asks whether SSO is among them rather than whether it is the only one.
func userSsoLinked(u *connection.User) bool {
	return slices.Contains(u.LoginTypes, zoomSsoLoginType)
}

// resolveZoomUsers turns a list of user IDs into typed zoom.user resources.
// Each ID is resolved from the account roster, which is read at most once per
// connection, so a role or group with N members costs one roster walk rather
// than N per-member GetUser calls. An identifier the roster does not carry,
// such as the email address Zoom reports in place of the ID of a user who has
// not completed onboarding, falls back to a direct lookup, and an identifier
// that resolves to nothing is skipped rather than failing the whole list.
func resolveZoomUsers(runtime *plugin.Runtime, conn *connection.ZoomConnection, memberIds []string) ([]any, error) {
	if len(memberIds) == 0 {
		return []any{}, nil
	}

	index, err := conn.UserIndex(context.Background())
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(memberIds))
	for _, id := range memberIds {
		if u, ok := index[id]; ok {
			res, err := newMqlZoomUser(runtime, u)
			if err != nil {
				return nil, err
			}
			all = append(all, res)
			continue
		}

		res, err := NewResource(runtime, "zoom.user", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			log.Debug().Err(err).Str("user", id).Msg("zoom> unable to resolve member")
			continue
		}
		all = append(all, res)
	}
	return all, nil
}

// users lists every user provisioned on the account, in every provisioning
// status. Zoom's List Users endpoint answers for one status per call and
// defaults to active, so asking only for that one would leave a deactivated
// user, which still holds its group memberships, and a pending user, which
// still holds a claim on an account email address, structurally invisible.
func (r *mqlZoom) users() ([]any, error) {
	conn := r.conn()

	users, err := conn.Client().ListAllUsers(context.Background(), usersPageSize)
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(users))
	for i := range users {
		res, err := newMqlZoomUser(r.MqlRuntime, &users[i])
		if err != nil {
			// Zoom returns neither an ID nor an email for a user it cannot
			// identify; there is nothing to key such a record on, so it is
			// skipped rather than failing the roster.
			log.Debug().Err(err).Msg("zoom> skipping unidentifiable user")
			continue
		}
		all = append(all, res)
	}
	return all, nil
}

// userCacheKey returns the value a user is cached under. Zoom does not return
// an ID for a user in the pending status, so a roster that includes pending
// users cannot key every entry on the ID alone; the email address is the only
// other handle Zoom gives, and it is unique across an account. The prefix
// keeps a user keyed by email from colliding with a user whose ID happens to
// be that same string.
func userCacheKey(u *connection.User) string {
	if u.ID != "" {
		return u.ID
	}
	if u.Email != "" {
		return "email/" + u.Email
	}
	return ""
}

// newMqlZoomUser maps a single Zoom user to its MQL resource.
func newMqlZoomUser(runtime *plugin.Runtime, u *connection.User) (plugin.Resource, error) {
	cacheKey := userCacheKey(u)
	if cacheKey == "" {
		return nil, errors.New("zoom.user requires an id or an email address")
	}

	res, err := CreateResource(runtime, "zoom.user", map[string]*llx.RawData{
		"__id":              llx.StringData(cacheKey),
		"id":                llx.StringData(u.ID),
		"email":             llx.StringData(u.Email),
		"firstName":         llx.StringData(u.FirstName),
		"lastName":          llx.StringData(u.LastName),
		"displayName":       llx.StringData(u.DisplayName),
		"type":              llx.IntData(u.Type),
		"status":            llx.StringData(u.Status),
		"verified":          llx.BoolData(userVerified(u)),
		"loginTypes":        llx.ArrayData(intToAnyList(u.LoginTypes), types.Int),
		"ssoLinked":         llx.BoolData(userSsoLinked(u)),
		"lastLoginTime":     llx.TimeDataPtr(u.LastLoginTime),
		"lastClientVersion": llx.StringData(u.LastClientVersion),
		"createdAt":         llx.TimeDataPtr(u.CreatedAt),
		"userCreatedAt":     llx.TimeDataPtr(u.UserCreatedAt),
		"roleId":            llx.StringData(u.RoleID),
		"groupIds":          llx.ArrayData(strToAnyList(u.GroupIDs), types.String),
	})
	if err != nil {
		return nil, err
	}

	mqlUser := res.(*mqlZoomUser)
	mqlUser.cacheRoleId = u.RoleID
	mqlUser.cacheGroupIds = u.GroupIDs
	return res, nil
}

// id returns the resource-name-prefixed natural key for this user, so
// createZoomUser has a stable fallback even on a path that omits the
// explicit "__id" argument. A pending user has no Zoom ID, so its email
// address stands in.
func (u *mqlZoomUser) id() (string, error) {
	if u.Id.Data != "" {
		return "zoom.user/" + u.Id.Data, nil
	}
	return "zoom.user/email/" + u.Email.Data, nil
}

// initZoomUser resolves a user by ID on demand, for typed references (e.g.
// zoom.role.members) and direct lookups such as zoom.user(id: "...").
func initZoomUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// fast path: the caller already provided a fully populated resource
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, fmt.Errorf("zoom.user requires a valid id")
	}

	conn := runtime.Connection.(*connection.ZoomConnection)
	u, err := conn.Client().GetUser(context.Background(), id)
	if err != nil {
		return nil, nil, fmt.Errorf("zoom.user with id %q not found: %w", id, err)
	}

	res, err := newMqlZoomUser(runtime, u)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// conn returns the Zoom connection backing this resource.
func (u *mqlZoomUser) conn() *connection.ZoomConnection {
	return u.MqlRuntime.Connection.(*connection.ZoomConnection)
}

// role resolves the role assigned to the user, governing their admin
// privileges. The account's role list is read at most once per connection, so
// a roster of N users costs one List Roles call rather than N Get Role calls.
func (u *mqlZoomUser) role() (*mqlZoomRole, error) {
	if u.cacheRoleId == "" {
		u.Role.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	roles, err := resolveZoomRoles(u.MqlRuntime, u.conn(), []string{u.cacheRoleId})
	if err != nil {
		return nil, err
	}
	if len(roles) == 0 {
		// The role the user carries is no longer on the account.
		u.Role.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return roles[0].(*mqlZoomRole), nil
}

// groups resolves the groups the user belongs to, through the same
// once-per-connection group list the two-factor settings resolve against.
func (u *mqlZoomUser) groups() ([]any, error) {
	return resolveZoomGroups(u.MqlRuntime, u.conn(), u.cacheGroupIds)
}
