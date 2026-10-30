// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/zoom/connection"
)

const groupMembersPageSize = 300

// mqlZoomGroupInternal caches the group's meeting-security overrides behind a
// single lazy fetch. All the settings* accessors share this fetch, so querying
// any subset of them costs exactly one
// GET /groups/{id}/settings?option=meeting_security call, guarded by
// double-check locking against concurrent field reads. Keeping it lazy means
// listing groups by id/name/totalMembers issues no per-group settings call.
type mqlZoomGroupInternal struct {
	fetched         bool
	meetingSecurity *connection.MeetingSecuritySettings
	lock            sync.Mutex

	meetingAuthFetched bool
	meetingAuth        *connection.MeetingAuthenticationSettings
	meetingAuthLock    sync.Mutex
}

// groups lists every user group defined on the account, each carrying its
// own meeting-security overrides.
func (r *mqlZoom) groups() ([]any, error) {
	conn := r.conn()
	client := conn.Client()

	list, err := client.ListGroups(context.Background())
	if err != nil {
		return nil, err
	}

	var all []any
	for _, group := range list.Groups {
		res, err := newMqlZoomGroup(r.MqlRuntime, &group)
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

// newMqlZoomGroup maps a single Zoom group to its MQL resource. The group's
// meeting-security overrides are resolved lazily through the settings*
// accessors, so listing groups issues no per-group settings call.
func newMqlZoomGroup(runtime *plugin.Runtime, group *connection.Group) (plugin.Resource, error) {
	res, err := CreateResource(runtime, "zoom.group", map[string]*llx.RawData{
		"__id":         llx.StringData(group.ID),
		"id":           llx.StringData(group.ID),
		"name":         llx.StringData(group.Name),
		"totalMembers": llx.IntData(group.TotalMembers),
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// id returns the resource-name-prefixed natural key for this group, so
// createZoomGroup has a stable fallback even on a path that omits the
// explicit "__id" argument.
func (g *mqlZoomGroup) id() (string, error) {
	return "zoom.group/" + g.Id.Data, nil
}

// initZoomGroup resolves a group by ID on demand.
func initZoomGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idArg, ok := args["id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idArg.Value.(string)
	if !ok || id == "" {
		return nil, nil, fmt.Errorf("zoom.group requires a valid id")
	}

	conn := runtime.Connection.(*connection.ZoomConnection)
	group, err := conn.Client().GetGroup(context.Background(), id)
	if err != nil {
		return nil, nil, fmt.Errorf("zoom.group with id %q not found: %w", id, err)
	}

	res, err := newMqlZoomGroup(runtime, group)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// members resolves the users belonging to this group.
func (g *mqlZoomGroup) members() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.ZoomConnection)

	memberIds, err := conn.Client().ListAllGroupMembers(context.Background(), g.Id.Data, groupMembersPageSize)
	if err != nil {
		return nil, err
	}
	return resolveZoomUsers(g.MqlRuntime, conn, memberIds)
}

// resolveZoomGroups turns a list of group IDs into typed zoom.group
// resources. The account's group list is read at most once per connection, so
// resolving N references costs one List Groups call rather than N Get Group
// calls. A group the list does not carry falls back to a direct lookup, and an
// ID that resolves to nothing is skipped rather than failing the whole list.
func resolveZoomGroups(runtime *plugin.Runtime, conn *connection.ZoomConnection, groupIds []string) ([]any, error) {
	if len(groupIds) == 0 {
		return []any{}, nil
	}

	index, err := conn.GroupIndex(context.Background())
	if err != nil {
		return nil, err
	}

	all := make([]any, 0, len(groupIds))
	for _, id := range groupIds {
		if group, ok := index[id]; ok {
			res, err := newMqlZoomGroup(runtime, group)
			if err != nil {
				return nil, err
			}
			all = append(all, res)
			continue
		}

		res, err := NewResource(runtime, "zoom.group", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// A stale or deleted group ID should not fail the whole list.
			log.Debug().Err(err).Str("group", id).Msg("zoom> unable to resolve group")
			continue
		}
		all = append(all, res)
	}
	return all, nil
}

// fetchMeetingSecurity performs the single group-settings GET this group's
// settings* fields all read from, caching the result behind double-check
// locking so concurrent field access only fetches once. The meeting_security
// object is absent from the un-optioned response, so the request has to carry
// `?option=meeting_security`.
func (g *mqlZoomGroup) fetchMeetingSecurity() (*connection.MeetingSecuritySettings, error) {
	if g.fetched {
		return g.meetingSecurity, nil
	}
	g.lock.Lock()
	defer g.lock.Unlock()
	if g.fetched {
		return g.meetingSecurity, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.ZoomConnection)
	ms, err := conn.Client().GetGroupMeetingSecurity(context.Background(), g.Id.Data)
	if err != nil {
		return nil, err
	}
	g.meetingSecurity = ms
	g.fetched = true
	return g.meetingSecurity, nil
}

func (g *mqlZoomGroup) settingsWaitingRoomEnabled() (bool, error) {
	s, err := g.fetchMeetingSecurity()
	if err != nil {
		return false, err
	}
	return s.WaitingRoom, nil
}

func (g *mqlZoomGroup) settingsMeetingPasscodeRequired() (bool, error) {
	s, err := g.fetchMeetingSecurity()
	if err != nil {
		return false, err
	}
	return s.MeetingPasswordRequirement, nil
}

func (g *mqlZoomGroup) settingsE2eeAvailable() (bool, error) {
	s, err := g.fetchMeetingSecurity()
	if err != nil {
		return false, err
	}
	return s.E2eeAvailable, nil
}

// fetchMeetingAuthentication performs the `?option=meeting_authentication`
// group-settings GET. Zoom reports the group's meeting-authentication override
// as a top-level boolean of that view, not as a member of meeting_security, so
// it needs its own call.
func (g *mqlZoomGroup) fetchMeetingAuthentication() (*connection.MeetingAuthenticationSettings, error) {
	if g.meetingAuthFetched {
		return g.meetingAuth, nil
	}
	g.meetingAuthLock.Lock()
	defer g.meetingAuthLock.Unlock()
	if g.meetingAuthFetched {
		return g.meetingAuth, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.ZoomConnection)
	auth, err := conn.Client().GetGroupMeetingAuthentication(context.Background(), g.Id.Data)
	if err != nil {
		return nil, err
	}
	g.meetingAuth = auth
	g.meetingAuthFetched = true
	return g.meetingAuth, nil
}

func (g *mqlZoomGroup) settingsOnlyAuthenticatedUsersCanJoin() (bool, error) {
	s, err := g.fetchMeetingAuthentication()
	if err != nil {
		return false, err
	}
	return s.MeetingAuthentication, nil
}
