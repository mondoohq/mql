// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/atlassian/connection/scim"
)

// scimPageSize is the per-request limit used when paginating SCIM endpoints.
// 100 is the conservative ceiling — some Atlassian SCIM deployments cap count
// at 100 server-side.
const scimPageSize = 100

func (a *mqlAtlassianScim) id() (string, error) {
	return "scim", nil
}

func (a *mqlAtlassianScim) users() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*scim.ScimConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow scim access")
	}
	admin := conn.Client()
	directoryID := conn.Directory()
	res := []any{}
	// SCIM 2.0 (RFC 7644 §3.4.2.4) uses 1-based pagination.
	startIndex := 1
	for {
		page, _, err := admin.SCIM.User.Gets(context.Background(), directoryID, nil, startIndex, scimPageSize)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Resources) == 0 {
			break
		}
		for _, scimUser := range page.Resources {
			if scimUser == nil {
				continue
			}
			args := map[string]*llx.RawData{"id": llx.StringData(scimUser.ID)}
			setScimUserFields(args, scimUser)
			mqlUser, err := CreateResource(a.MqlRuntime, "atlassian.scim.user", args)
			if err != nil {
				return nil, err
			}
			// The list response carries the user's group memberships inline, so
			// cache them to serve groups() without a per-user re-fetch.
			u := mqlUser.(*mqlAtlassianScimUser)
			u.cacheGroups = scimUser.Groups
			u.cachedGroups = true
			res = append(res, mqlUser)
		}
		startIndex += len(page.Resources)
		if scimReachedEnd(startIndex, len(page.Resources), page.TotalResults) {
			break
		}
	}
	return res, nil
}

func (a *mqlAtlassianScim) groups() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*scim.ScimConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow scim access")
	}
	admin := conn.Client()
	directoryID := conn.Directory()
	res := []any{}
	// SCIM 2.0 (RFC 7644 §3.4.2.4) uses 1-based pagination.
	startIndex := 1
	for {
		page, _, err := admin.SCIM.Group.Gets(context.Background(), directoryID, "", startIndex, scimPageSize)
		if err != nil {
			return nil, err
		}
		if page == nil || len(page.Resources) == 0 {
			break
		}
		for _, scimGroup := range page.Resources {
			if scimGroup == nil {
				continue
			}
			mqlGroup, err := CreateResource(a.MqlRuntime, "atlassian.scim.group",
				map[string]*llx.RawData{
					"id":   llx.StringData(scimGroup.ID),
					"name": llx.StringData(scimGroup.DisplayName),
				})
			if err != nil {
				return nil, err
			}
			// The list response carries the group's members inline, so cache them
			// to serve members() without a per-group re-fetch.
			g := mqlGroup.(*mqlAtlassianScimGroup)
			g.cacheMembers = scimGroup.Members
			g.cachedMembers = true
			res = append(res, mqlGroup)
		}
		startIndex += len(page.Resources)
		if scimReachedEnd(startIndex, len(page.Resources), page.TotalResults) {
			break
		}
	}
	return res, nil
}

// scimReachedEnd reports whether a SCIM list loop should stop. nextStartIndex is
// the 1-based index of the next page's first resource (already advanced past the
// page just processed), pageLen is that page's resource count, and totalResults
// is the server-reported total.
//
// TotalResults is the authoritative signal: keep paging until nextStartIndex has
// moved past it, regardless of page size. This matters because Atlassian SCIM
// caps count server-side, so a page shorter than the requested scimPageSize does
// NOT mean the end. Only when the server omits a total (<= 0) do we fall back to
// the short-page heuristic.
func scimReachedEnd(nextStartIndex, pageLen, totalResults int) bool {
	if totalResults > 0 {
		return nextStartIndex > totalResults
	}
	return pageLen < scimPageSize
}

func (a *mqlAtlassianScimUser) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianScimGroup) id() (string, error) {
	return a.Id.Data, nil
}

// mqlAtlassianScimUserInternal caches the group memberships returned inline by
// the SCIM user list so groups() can resolve them without a re-fetch. A user
// reached through a typed reference (e.g. scim.group.members) starts with an
// empty cache and triggers a lazy Get on first access.
type mqlAtlassianScimUserInternal struct {
	cacheGroups  []*models.SCIMUserGroupScheme
	cachedGroups bool
	lock         sync.Mutex
}

// mqlAtlassianScimGroupInternal caches the members returned inline by the SCIM
// group list so members() can resolve them without a re-fetch.
type mqlAtlassianScimGroupInternal struct {
	cacheMembers  []*models.ScimGroupMemberScheme
	cachedMembers bool
	lock          sync.Mutex
}

// initAtlassianScimUser resolves a SCIM user referenced only by id (e.g. from
// scim.group.members) into a fully populated resource. When the user is already
// cached from scim.users() the runtime serves the cache and this never runs.
func initAtlassianScimUser(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Fast path: the resource was created inline with its fields already set.
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("atlassian.scim.user requires an id")
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("atlassian.scim.user: id must be a non-empty string")
	}

	conn, ok := runtime.Connection.(*scim.ScimConnection)
	if !ok {
		return nil, nil, errors.New("Current connection does not allow scim access")
	}
	user, _, err := conn.Client().SCIM.User.Get(context.Background(), conn.Directory(), id, nil, nil)
	if err != nil {
		return nil, nil, err
	}
	setScimUserFields(args, user)
	return args, nil, nil
}

// setScimUserFields fills args with every atlassian.scim.user field other than
// id. Both the list path and the single-user init path go through it so the two
// cannot drift apart: a field one sets and the other omits would degrade to
// null for whichever path materializes the user first in a scan.
func setScimUserFields(args map[string]*llx.RawData, user *models.SCIMUserScheme) {
	formatted := ""
	if user.Name != nil {
		formatted = user.Name.Formatted
	}
	// meta is optional in the SCIM response; an absent timestamp stays null
	// rather than becoming the zero time, which would read as a real date in
	// year 1 and make "has not synced since" checks answer nonsense.
	var created, lastModified *time.Time
	if user.Meta != nil {
		created = parseAtlassianTime(user.Meta.Created)
		lastModified = parseAtlassianTime(user.Meta.LastModified)
	}
	args["name"] = llx.StringData(formatted)
	args["displayName"] = llx.StringData(user.DisplayName)
	args["organization"] = llx.StringData(user.Organization)
	args["title"] = llx.StringData(user.Title)
	args["active"] = llx.BoolData(user.Active)
	args["externalId"] = llx.StringDataPtr(nilIfEmpty(user.ExternalID))
	args["created"] = llx.TimeDataPtr(created)
	args["lastModified"] = llx.TimeDataPtr(lastModified)
}

// initAtlassianScimGroup resolves a SCIM group referenced only by id (e.g. from
// scim.user.groups) into a fully populated resource.
func initAtlassianScimGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	idRaw, ok := args["id"]
	if !ok {
		return nil, nil, errors.New("atlassian.scim.group requires an id")
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return nil, nil, errors.New("atlassian.scim.group: id must be a non-empty string")
	}

	conn, ok := runtime.Connection.(*scim.ScimConnection)
	if !ok {
		return nil, nil, errors.New("Current connection does not allow scim access")
	}
	group, _, err := conn.Client().SCIM.Group.Get(context.Background(), conn.Directory(), id)
	if err != nil {
		return nil, nil, err
	}
	args["name"] = llx.StringData(group.DisplayName)
	return args, nil, nil
}

// ensureGroups returns the user's group memberships, fetching the full SCIM user
// record on a cache miss (users reached through a typed reference).
func (a *mqlAtlassianScimUser) ensureGroups() ([]*models.SCIMUserGroupScheme, error) {
	if a.cachedGroups {
		return a.cacheGroups, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.cachedGroups {
		return a.cacheGroups, nil
	}

	conn, ok := a.MqlRuntime.Connection.(*scim.ScimConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow scim access")
	}
	user, _, err := conn.Client().SCIM.User.Get(context.Background(), conn.Directory(), a.Id.Data, nil, nil)
	if err != nil {
		return nil, err
	}
	a.cacheGroups = user.Groups
	a.cachedGroups = true
	return a.cacheGroups, nil
}

func (a *mqlAtlassianScimUser) groups() ([]any, error) {
	groups, err := a.ensureGroups()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(groups))
	for _, g := range groups {
		if g == nil || g.Value == "" {
			continue
		}
		mqlGroup, err := NewResource(a.MqlRuntime, "atlassian.scim.group",
			map[string]*llx.RawData{"id": llx.StringData(g.Value)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}
	return res, nil
}

// ensureMembers returns the group's members, fetching the full SCIM group record
// on a cache miss (groups reached through a typed reference).
func (a *mqlAtlassianScimGroup) ensureMembers() ([]*models.ScimGroupMemberScheme, error) {
	if a.cachedMembers {
		return a.cacheMembers, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.cachedMembers {
		return a.cacheMembers, nil
	}

	conn, ok := a.MqlRuntime.Connection.(*scim.ScimConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow scim access")
	}
	group, _, err := conn.Client().SCIM.Group.Get(context.Background(), conn.Directory(), a.Id.Data)
	if err != nil {
		return nil, err
	}
	a.cacheMembers = group.Members
	a.cachedMembers = true
	return a.cacheMembers, nil
}

func (a *mqlAtlassianScimGroup) members() ([]any, error) {
	members, err := a.ensureMembers()
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(members))
	for _, m := range members {
		if m == nil || m.Value == "" {
			continue
		}
		mqlUser, err := NewResource(a.MqlRuntime, "atlassian.scim.user",
			map[string]*llx.RawData{"id": llx.StringData(m.Value)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}
