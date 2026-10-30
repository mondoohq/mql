// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// id returns a cache key composed of the owning member's ID and the session
// ID, since the same session ID space is shared across every member and a
// device resource on its own carries no natural per-member uniqueness
// guarantee.
func (d *mqlDropboxDevice) id() (string, error) {
	return "dropbox.device/" + d.MemberId.Data + "/" + d.Id.Data, nil
}

// devices lists every device and session linked to any team member's
// account, reading from the connection's member-grouped device cache.
func (d *mqlDropbox) devices() ([]any, error) {
	conn := d.conn()
	pages, err := conn.DevicesByMember()
	if err != nil {
		return nil, err
	}

	var all []any
	for _, page := range pages {
		devs, err := mqlDropboxDevicesForMember(d.MqlRuntime, page)
		if err != nil {
			return nil, err
		}
		all = append(all, devs...)
	}
	return all, nil
}

// mqlDropboxDevicesForMember maps one member's web, desktop, and mobile
// sessions to dropbox.device resources.
func mqlDropboxDevicesForMember(runtime *plugin.Runtime, page *team.MemberDevices) ([]any, error) {
	var out []any

	for _, w := range page.WebSessions {
		r, err := CreateResource(runtime, "dropbox.device", map[string]*llx.RawData{
			"__id":                      llx.StringData("dropbox.device/" + page.TeamMemberId + "/" + w.SessionId),
			"id":                        llx.StringData(w.SessionId),
			"memberId":                  llx.StringData(page.TeamMemberId),
			"clientType":                llx.StringData("web"),
			"hostName":                  llx.StringData(w.UserAgent),
			"clientVersion":             llx.StringData(""),
			"platform":                  llx.StringData(w.Os),
			"ipAddress":                 llx.StringData(w.IpAddress),
			"country":                   llx.StringData(w.Country),
			"isDeleteOnUnlinkSupported": llx.BoolData(false),
			"createdAt":                 llx.TimeDataPtr(dbxTimePtr(w.Created)),
			"lastActivity":              llx.TimeDataPtr(dbxTimePtr(w.Updated)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	for _, dsk := range page.DesktopClients {
		var clientType string
		if dsk.ClientType != nil {
			clientType = dsk.ClientType.Tag
		}
		r, err := CreateResource(runtime, "dropbox.device", map[string]*llx.RawData{
			"__id":                      llx.StringData("dropbox.device/" + page.TeamMemberId + "/" + dsk.SessionId),
			"id":                        llx.StringData(dsk.SessionId),
			"memberId":                  llx.StringData(page.TeamMemberId),
			"clientType":                llx.StringData("desktop"),
			"hostName":                  llx.StringData(dsk.HostName),
			"clientVersion":             llx.StringData(dsk.ClientVersion),
			"platform":                  llx.StringData(firstNonEmpty(dsk.Platform, clientType)),
			"ipAddress":                 llx.StringData(dsk.IpAddress),
			"country":                   llx.StringData(dsk.Country),
			"isDeleteOnUnlinkSupported": llx.BoolData(dsk.IsDeleteOnUnlinkSupported),
			"createdAt":                 llx.TimeDataPtr(dbxTimePtr(dsk.Created)),
			"lastActivity":              llx.TimeDataPtr(dbxTimePtr(dsk.Updated)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	for _, mob := range page.MobileClients {
		var clientType string
		if mob.ClientType != nil {
			clientType = mob.ClientType.Tag
		}
		r, err := CreateResource(runtime, "dropbox.device", map[string]*llx.RawData{
			"__id":                      llx.StringData("dropbox.device/" + page.TeamMemberId + "/" + mob.SessionId),
			"id":                        llx.StringData(mob.SessionId),
			"memberId":                  llx.StringData(page.TeamMemberId),
			"clientType":                llx.StringData("mobile"),
			"hostName":                  llx.StringData(mob.DeviceName),
			"clientVersion":             llx.StringData(mob.ClientVersion),
			"platform":                  llx.StringData(clientType),
			"ipAddress":                 llx.StringData(mob.IpAddress),
			"country":                   llx.StringData(mob.Country),
			"isDeleteOnUnlinkSupported": llx.BoolData(false),
			"createdAt":                 llx.TimeDataPtr(dbxTimePtr(mob.Created)),
			"lastActivity":              llx.TimeDataPtr(dbxTimePtr(mob.Updated)),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}

	return out, nil
}

// firstNonEmpty returns a if it is non-empty, otherwise b.
func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
