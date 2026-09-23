// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog/log"
	gitlab "gitlab.com/gitlab-org/api/client-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gitlab/connection"
	"go.mondoo.com/mql/types"
)

// gitlabUserScopeWarn logs once per session when fetching /users/:id is
// denied, so operators running with a non-admin token are alerted that the
// admin-scoped accessors (isAdmin, isAuditor, lastSignInAt, ...) are silently
// returning zero values rather than reflecting actual user state.
var gitlabUserScopeWarn sync.Once

// mqlGitlabUserInternal caches a fetched *gitlab.User so that multiple computed
// methods (externalIdentities, etc.) only trigger a single GetUser API call.
//
// cacheIdentities lets producers (e.g. group/project members()) seed identities
// from the *gitlab.User they already have, so externalIdentities() doesn't need
// to call GetUser at all - eliminating an N+1 across N members.
type mqlGitlabUserInternal struct {
	// fetched is atomic because the unlocked fast-path read below races the
	// locked writes otherwise: llx resolves fields in separate goroutines, so
	// the nineteen accessors that funnel through fetchUser can run
	// concurrently on the same resource.
	fetched         atomic.Bool
	user            *gitlab.User
	cacheIdentities []*gitlab.UserIdentity
	lock            sync.Mutex
}

// initGitlabUser supports `gitlab.user(id: <int>)` lookups so typed back-references
// from sshKey/externalIdentity resolve to the typed user via NewResource.
//
// When called with just an id (or empty args), we lazily fetch the full user
// from the API. If callers already supplied populated args (e.g. from members())
// we leave them alone.
func initGitlabUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Only auto-fetch if just id was provided (avoids re-fetching when members()
	// or other producers already populated all fields). Other init functions in
	// this provider use the same > 2 threshold to account for an implicit __id arg.
	if len(args) > 2 {
		return args, nil, nil
	}
	idArg, ok := args["id"]
	if !ok || idArg == nil || idArg.Error != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.GitLabConnection)
	user, resp, err := conn.Client().Users.GetUser(idArg.Value.(int64), &gitlab.GetUserOptions{})
	if err != nil {
		// Non-admin tokens get 403/404 from /users/:id. Let the resource exist
		// with whatever id was passed in so typed back-refs (sshKey.user, etc.)
		// don't blow up the whole resource graph.
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			return args, nil, nil
		}
		return nil, nil, err
	}

	args["id"] = llx.IntData(user.ID)
	args["username"] = llx.StringData(user.Username)
	args["name"] = llx.StringData(user.Name)
	args["state"] = llx.StringData(user.State)
	args["email"] = llx.StringData(user.Email)
	args["webURL"] = llx.StringData(user.WebURL)
	args["avatarURL"] = llx.StringData(user.AvatarURL)
	args["createdAt"] = llx.TimeDataPtr(user.CreatedAt)
	args["jobTitle"] = llx.StringData(user.JobTitle)
	args["organization"] = llx.StringData(user.Organization)
	args["location"] = llx.StringData(user.Location)
	args["locked"] = llx.BoolData(user.Locked)
	args["bot"] = llx.BoolData(user.Bot)
	args["twoFactorEnabled"] = llx.BoolData(user.TwoFactorEnabled)

	// Seed the Internal cache from the GetUser response we already have so
	// the lazy accessors (isAdmin, isAuditor, lastSignInAt, ...) reuse it
	// instead of issuing another GetUser per access.
	res, err := CreateResource(runtime, "gitlab.user", args)
	if err != nil {
		return nil, nil, err
	}
	mqlUser := res.(*mqlGitlabUser)
	mqlUser.user = user
	mqlUser.fetched.Store(true)
	return args, mqlUser, nil
}

// fetchUser loads the full user record by ID (with double-checked locking).
// Used as a fallback when no creator seeded the user data. Returns (nil, nil)
// on 403/404 - non-admin tokens lack permission to read /users/:id but should
// not fail the whole resource graph. The first such denial in a session emits
// a warning so the operator knows admin-scoped accessors (isAdmin, isAuditor,
// lastSignInAt, ...) are returning zero values rather than reflecting actual
// state.
func (u *mqlGitlabUser) fetchUser() (*gitlab.User, error) {
	if u.fetched.Load() {
		return u.user, nil
	}
	u.lock.Lock()
	defer u.lock.Unlock()
	if u.fetched.Load() {
		return u.user, nil
	}
	conn := u.MqlRuntime.Connection.(*connection.GitLabConnection)
	user, resp, err := conn.Client().Users.GetUser(u.Id.Data, &gitlab.GetUserOptions{})
	if err != nil {
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			gitlabUserScopeWarn.Do(func() {
				log.Warn().Int("status", resp.StatusCode).
					Msg("gitlab token cannot read /users/:id; admin-scoped user fields (isAdmin, isAuditor, lastSignInAt, ...) will return zero values")
			})
			u.fetched.Store(true)
			return nil, nil
		}
		return nil, err
	}
	u.user = user
	u.fetched.Store(true)
	return u.user, nil
}

// The accessors below all defer to fetchUser, which is gated by the user's
// access scope. fetchUser() returns (nil, nil) on 403/404 so non-admin tokens
// don't fail the whole resource graph — in that case the accessor returns the
// type's zero value.

func (u *mqlGitlabUser) isAdmin() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.IsAdmin, nil
}

func (u *mqlGitlabUser) isAuditor() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.IsAuditor, nil
}

func (u *mqlGitlabUser) external() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.External, nil
}

func (u *mqlGitlabUser) privateProfile() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.PrivateProfile, nil
}

func (u *mqlGitlabUser) usingLicenseSeat() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.UsingLicenseSeat, nil
}

func (u *mqlGitlabUser) canCreateGroup() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.CanCreateGroup, nil
}

func (u *mqlGitlabUser) canCreateProject() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.CanCreateProject, nil
}

func (u *mqlGitlabUser) lastSignInAt() (*time.Time, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return nil, err
	}
	return user.LastSignInAt, nil
}

func (u *mqlGitlabUser) currentSignInAt() (*time.Time, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return nil, err
	}
	return user.CurrentSignInAt, nil
}

func (u *mqlGitlabUser) lastActivityOn() (*time.Time, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil || user.LastActivityOn == nil {
		return nil, err
	}
	t := time.Time(*user.LastActivityOn)
	return &t, nil
}

func (u *mqlGitlabUser) confirmedAt() (*time.Time, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return nil, err
	}
	return user.ConfirmedAt, nil
}

func (u *mqlGitlabUser) note() (string, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return "", err
	}
	return user.Note, nil
}

// createdBy returns the account that created this user (admin-only), or null.
func (u *mqlGitlabUser) createdBy() (*mqlGitlabUser, error) {
	user, err := u.fetchUser()
	if err != nil {
		return nil, err
	}
	if user == nil || user.CreatedBy == nil || user.CreatedBy.ID <= 0 {
		u.CreatedBy.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(u.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(user.CreatedBy.ID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGitlabUser), nil
}

func (u *mqlGitlabUser) lastSignInIp() (string, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil || user.LastSignInIP == nil {
		return "", err
	}
	return user.LastSignInIP.String(), nil
}

func (u *mqlGitlabUser) currentSignInIp() (string, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil || user.CurrentSignInIP == nil {
		return "", err
	}
	return user.CurrentSignInIP.String(), nil
}

func (u *mqlGitlabUser) canCreateOrganization() (bool, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return false, err
	}
	return user.CanCreateOrganization, nil
}

func (u *mqlGitlabUser) publicEmail() (string, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return "", err
	}
	return user.PublicEmail, nil
}

func (u *mqlGitlabUser) projectsLimit() (int64, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return 0, err
	}
	return user.ProjectsLimit, nil
}

func (u *mqlGitlabUser) sharedRunnersMinutesLimit() (int64, error) {
	user, err := u.fetchUser()
	if err != nil || user == nil {
		return 0, err
	}
	return user.SharedRunnersMinutesLimit, nil
}

// mqlGitlabUserExternalIdentityInternal carries the parent user ID so the
// `user()` accessor can resolve back to the typed gitlab.user resource.
type mqlGitlabUserExternalIdentityInternal struct {
	userID int64
}

// user returns the typed gitlab.user this external identity is linked to.
func (i *mqlGitlabUserExternalIdentity) user() (*mqlGitlabUser, error) {
	if i.userID == 0 {
		i.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlUser, err := NewResource(i.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(i.userID),
	})
	if err != nil {
		return nil, err
	}
	return mqlUser.(*mqlGitlabUser), nil
}

// externalIdentities lists the SSO/external identities linked to this user.
//
// Uses cacheIdentities seeded by the creator (e.g. members()) to avoid an
// N+1 GetUser call per user. Falls back to fetchUser() only when a user was
// constructed via NewResource (lazy lookup), and that fall-back gracefully
// returns an empty list on 403/404 instead of failing the whole graph.
func (u *mqlGitlabUser) externalIdentities() ([]any, error) {
	identities := u.cacheIdentities
	if identities == nil {
		user, err := u.fetchUser()
		if err != nil {
			return nil, err
		}
		if user != nil {
			identities = user.Identities
		}
	}

	var mqlIdentities []any
	for _, identity := range identities {
		if identity == nil {
			continue
		}
		identityInfo := map[string]*llx.RawData{
			// The owning user belongs in the key: provider+externUID alone
			// aliases whenever a provider reports an empty extern_uid, and the
			// userID assigned just below would then repoint the first user's
			// identity resource at this one.
			"__id":      llx.StringData(userScopedID("gitlab.user.externalIdentity", u.Id.Data, identity.Provider, identity.ExternUID)),
			"provider":  llx.StringData(identity.Provider),
			"externUID": llx.StringData(identity.ExternUID),
		}
		mqlIdentity, err := CreateResource(u.MqlRuntime, "gitlab.user.externalIdentity", identityInfo)
		if err != nil {
			return nil, err
		}
		mqlIdentity.(*mqlGitlabUserExternalIdentity).userID = u.Id.Data
		mqlIdentities = append(mqlIdentities, mqlIdentity)
	}

	return mqlIdentities, nil
}

// id function for gitlab.user.sshKey
func (k *mqlGitlabUserSshKey) id() (string, error) {
	return "gitlab.user.sshKey/" + strconv.FormatInt(k.Id.Data, 10), nil
}

// mqlGitlabUserSshKeyInternal carries the parent user ID for the typed user() accessor.
type mqlGitlabUserSshKeyInternal struct {
	userID int64
}

// daysOld returns the age of the SSH key in days. Returns -1 when createdAt
// isn't set so callers can distinguish "missing data" from "fresh key".
func (k *mqlGitlabUserSshKey) daysOld() (int64, error) {
	if !k.CreatedAt.IsSet() || k.CreatedAt.Data == nil || k.CreatedAt.Data.IsZero() {
		return -1, nil
	}
	return int64(time.Since(*k.CreatedAt.Data).Hours() / 24), nil
}

// user returns the typed gitlab.user that owns this SSH key.
func (k *mqlGitlabUserSshKey) user() (*mqlGitlabUser, error) {
	if k.userID == 0 {
		k.User.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlUser, err := NewResource(k.MqlRuntime, "gitlab.user", map[string]*llx.RawData{
		"id": llx.IntData(k.userID),
	})
	if err != nil {
		return nil, err
	}
	return mqlUser.(*mqlGitlabUser), nil
}

// sshKeys lists SSH keys registered to this user. Requires admin or self-access;
// if the caller lacks permission GitLab returns 403/404 and we surface an empty list.
func (u *mqlGitlabUser) sshKeys() ([]any, error) {
	conn := u.MqlRuntime.Connection.(*connection.GitLabConnection)

	perPage := int64(50)
	page := int64(1)
	var allKeys []*gitlab.SSHKey

	for {
		keys, resp, err := conn.Client().Users.ListSSHKeysForUser(u.Id.Data, &gitlab.ListSSHKeysForUserOptions{
			ListOptions: gitlab.ListOptions{
				Page:    page,
				PerPage: perPage,
			},
		})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil // no permission to list keys for this user
			}
			return nil, err
		}

		allKeys = append(allKeys, keys...)

		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	var mqlKeys []any
	for _, key := range allKeys {
		keyInfo := map[string]*llx.RawData{
			"id":        llx.IntData(key.ID),
			"title":     llx.StringData(key.Title),
			"key":       llx.StringData(key.Key),
			"createdAt": llx.TimeDataPtr(key.CreatedAt),
			"expiresAt": llx.TimeDataPtr(key.ExpiresAt),
			"usageType": llx.StringData(key.UsageType),
		}
		mqlKey, err := CreateResource(u.MqlRuntime, "gitlab.user.sshKey", keyInfo)
		if err != nil {
			return nil, err
		}
		mqlKey.(*mqlGitlabUserSshKey).userID = u.Id.Data
		mqlKeys = append(mqlKeys, mqlKey)
	}

	return mqlKeys, nil
}

func (t *mqlGitlabUserPersonalAccessToken) id() (string, error) {
	return "gitlab.user.personalAccessToken/" + strconv.FormatInt(t.Id.Data, 10), nil
}

// personalAccessTokens lists the user's personal access tokens. Requires an
// admin token (to see other users' tokens) or self-access; on 403/404 it
// returns an empty list rather than failing the resource graph.
func (u *mqlGitlabUser) personalAccessTokens() ([]any, error) {
	conn := u.MqlRuntime.Connection.(*connection.GitLabConnection)
	userID := u.Id.Data

	perPage := int64(50)
	page := int64(1)
	var all []*gitlab.PersonalAccessToken
	for {
		tokens, resp, err := conn.Client().PersonalAccessTokens.ListPersonalAccessTokens(&gitlab.ListPersonalAccessTokensOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage},
			UserID:      &userID,
		})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, tokens...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	out := make([]any, 0, len(all))
	for _, t := range all {
		var expiresAt *time.Time
		if t.ExpiresAt != nil {
			e := time.Time(*t.ExpiresAt)
			expiresAt = &e
		}
		res, err := CreateResource(u.MqlRuntime, "gitlab.user.personalAccessToken", map[string]*llx.RawData{
			"id":          llx.IntData(t.ID),
			"name":        llx.StringData(t.Name),
			"description": llx.StringData(t.Description),
			"active":      llx.BoolData(t.Active),
			"revoked":     llx.BoolData(t.Revoked),
			"scopes":      llx.ArrayData(convert.SliceAnyToInterface(t.Scopes), types.String),
			"createdAt":   llx.TimeDataPtr(t.CreatedAt),
			"expiresAt":   llx.TimeDataPtr(expiresAt),
			"lastUsedAt":  llx.TimeDataPtr(t.LastUsedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}

func (e *mqlGitlabUserEmailAddress) id() (string, error) {
	return "gitlab.user.emailAddress/" + strconv.FormatInt(e.Id.Data, 10), nil
}

// emails lists the email addresses registered to the user. Requires an admin
// token (to see other users' emails) or self-access; on 403/404 it returns an
// empty list rather than failing the resource graph.
func (u *mqlGitlabUser) emails() ([]any, error) {
	conn := u.MqlRuntime.Connection.(*connection.GitLabConnection)

	perPage := int64(50)
	page := int64(1)
	var all []*gitlab.Email
	for {
		emails, resp, err := conn.Client().Users.ListEmailsForUser(u.Id.Data, &gitlab.ListEmailsForUserOptions{
			ListOptions: gitlab.ListOptions{Page: page, PerPage: perPage},
		})
		if err != nil {
			if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
				return []any{}, nil
			}
			return nil, err
		}
		all = append(all, emails...)
		if resp.NextPage == 0 {
			break
		}
		page = resp.NextPage
	}

	out := make([]any, 0, len(all))
	for _, e := range all {
		res, err := CreateResource(u.MqlRuntime, "gitlab.user.emailAddress", map[string]*llx.RawData{
			"id":          llx.IntData(e.ID),
			"email":       llx.StringData(e.Email),
			"confirmedAt": llx.TimeDataPtr(e.ConfirmedAt),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, res)
	}
	return out, nil
}
