// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	"google.golang.org/api/calendar/v3"
)

func (g *mqlGoogleworkspace) calendars() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	calendarService, err := calendarService(conn, calendar.CalendarReadonlyScope, calendar.CalendarSettingsReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	calendars, err := calendarService.CalendarList.List().Do()
	if err != nil {
		return nil, err
	}
	for {
		for _, c := range calendars.Items {
			r, err := CreateResource(g.MqlRuntime, "googleworkspace.calendar", map[string]*llx.RawData{
				"__id":            llx.StringData(c.Id),
				"id":              llx.StringData(c.Id),
				"summary":         llx.StringData(c.Summary),
				"summaryOverride": llx.StringData(c.SummaryOverride),
				"primary":         llx.BoolData(c.Primary),
				"accessRole":      llx.StringData(c.AccessRole),
				"description":     llx.StringData(c.Description),
				"timeZone":        llx.StringData(c.TimeZone),
				"location":        llx.StringData(c.Location),
				"hidden":          llx.BoolData(c.Hidden),
				"deleted":         llx.BoolData(c.Deleted),
				"selected":        llx.BoolData(c.Selected),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if calendars.NextPageToken == "" {
			break
		}
		calendars, err = calendarService.CalendarList.List().PageToken(calendars.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}

func (g *mqlGoogleworkspaceCalendar) acl() ([]any, error) {
	conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
	// acl.list accepts calendar, calendar.acls or calendar.acls.readonly. Ask
	// for the read-only one so the domain-wide delegation grant never needs
	// read/write access to every calendar in the domain.
	calendarService, err := calendarService(conn, calendar.CalendarAclsReadonlyScope)
	if err != nil {
		return nil, err
	}

	res := []any{}
	acls, err := calendarService.Acl.List(g.__id).Do()
	if err != nil {
		return nil, err
	}
	for {
		for _, a := range acls.Items {
			var scopeType, scopeValue string
			if a.Scope != nil {
				scopeType = a.Scope.Type
				scopeValue = a.Scope.Value
			}
			scope, err := CreateResource(g.MqlRuntime, "googleworkspace.calendar.aclRule.scope", map[string]*llx.RawData{
				"__id":  llx.StringData(a.Id + "/" + scopeType + "/" + scopeValue),
				"type":  llx.StringData(scopeType),
				"value": llx.StringData(scopeValue),
			})
			if err != nil {
				return nil, err
			}

			r, err := CreateResource(g.MqlRuntime, "googleworkspace.calendar.aclRule", map[string]*llx.RawData{
				"__id":  llx.StringData(a.Id),
				"id":    llx.StringData(a.Id),
				"role":  llx.StringData(a.Role),
				"scope": llx.ResourceData(scope, "googleworkspace.calendar.aclRule.scope"),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, r)
		}

		if acls.NextPageToken == "" {
			break
		}
		acls, err = calendarService.Acl.List(g.__id).PageToken(acls.NextPageToken).Do()
		if err != nil {
			return nil, err
		}
	}
	return res, nil
}
