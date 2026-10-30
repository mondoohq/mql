// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/team"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// id returns a cache key composed of the owning member's ID and the app ID,
// since the same third-party app can be linked by multiple members and each
// link is a distinct record; the app ID alone is not unique across members.
func (a *mqlDropboxLinkedApp) id() (string, error) {
	return "dropbox.linkedApp/" + a.MemberId.Data + "/" + a.AppId.Data, nil
}

// linkedApps lists every third-party app linked to any team member's
// account, reading from the connection's member-grouped linked-app cache.
func (d *mqlDropbox) linkedApps() ([]any, error) {
	conn := d.conn()
	pages, err := conn.LinkedAppsByMember()
	if err != nil {
		return nil, err
	}

	var all []any
	for _, page := range pages {
		apps, err := mqlDropboxLinkedAppsForMember(d.MqlRuntime, page)
		if err != nil {
			return nil, err
		}
		all = append(all, apps...)
	}
	return all, nil
}

// mqlDropboxLinkedAppsForMember maps one member's linked third-party apps to
// dropbox.linkedApp resources.
func mqlDropboxLinkedAppsForMember(runtime *plugin.Runtime, page *team.MemberLinkedApps) ([]any, error) {
	var out []any
	for _, app := range page.LinkedApiApps {
		if app == nil {
			continue
		}
		r, err := CreateResource(runtime, "dropbox.linkedApp", map[string]*llx.RawData{
			"__id":          llx.StringData("dropbox.linkedApp/" + page.TeamMemberId + "/" + app.AppId),
			"appId":         llx.StringData(app.AppId),
			"memberId":      llx.StringData(page.TeamMemberId),
			"appName":       llx.StringData(app.AppName),
			"publisherName": llx.StringData(app.Publisher),
			"publisherUrl":  llx.StringData(app.PublisherUrl),
			"linked":        llx.TimeDataPtr(dbxTimePtr(app.Linked)),
			"isAppFolder":   llx.BoolData(app.IsAppFolder),
		})
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
