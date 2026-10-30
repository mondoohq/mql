// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/google-workspace/connection"
	directory "google.golang.org/api/admin/directory/v1"
	reports "google.golang.org/api/admin/reports/v1"
	"google.golang.org/api/calendar/v3"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/groupssettings/v1"
	"google.golang.org/api/option"
)

// workspaceResource fetches (or creates) the singleton `googleworkspace`
// resource so child resources can reach shared parent caches (user index,
// usage-report batch, etc.) without re-issuing API calls.
func workspaceResource(runtime *plugin.Runtime) (*mqlGoogleworkspace, error) {
	obj, err := CreateResource(runtime, "googleworkspace", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlGoogleworkspace), nil
}

type mqlGoogleworkspaceInternal struct {
	usersByEmailOnce sync.Once
	usersByEmail     map[string]*mqlGoogleworkspaceUser
	usersByEmailErr  error

	// usersById indexes the customer's users by their unique directory ID so
	// role-assignment accessors (assignedTo is an ID, not an email) resolve to
	// a typed user via a single shared Users.List instead of one Get per
	// assignment.
	usersByIdOnce sync.Once
	usersById     map[string]*mqlGoogleworkspaceUser
	usersByIdErr  error

	// rolesById indexes the customer's admin roles by ID so role-assignment
	// accessors resolve roleId -> role via a single shared Roles.List.
	rolesByIdOnce sync.Once
	rolesById     map[int64]*mqlGoogleworkspaceRole
	rolesByIdErr  error

	// usageReportsOnce guards a single batched UserUsageReport.Get("all", date)
	// fetch that returns every user's usage report. user.usageReport() and
	// report.users.list() both look up by primary email instead of issuing
	// their own per-user API call.
	usageReportsOnce    sync.Once
	usageReportsByEmail map[string]*reports.UsageReport
	usageReportsDate    string
	usageReportsErr     error
}

func (g *mqlGoogleworkspace) userByEmail(email string) (*mqlGoogleworkspaceUser, error) {
	g.usersByEmailOnce.Do(func() {
		// Go through GetUsers() so the lazily-computed users field is resolved
		// even when the caller never touched googleworkspace.users directly.
		users := g.GetUsers()
		if users.Error != nil {
			g.usersByEmailErr = users.Error
			return
		}
		m := make(map[string]*mqlGoogleworkspaceUser, len(users.Data))
		for _, u := range users.Data {
			user := u.(*mqlGoogleworkspaceUser)
			if user.PrimaryEmail.Error != nil {
				g.usersByEmailErr = user.PrimaryEmail.Error
				return
			}
			m[user.PrimaryEmail.Data] = user
		}
		g.usersByEmail = m
	})
	if g.usersByEmailErr != nil {
		return nil, g.usersByEmailErr
	}
	return g.usersByEmail[email], nil
}

func (g *mqlGoogleworkspace) userById(id string) (*mqlGoogleworkspaceUser, error) {
	g.usersByIdOnce.Do(func() {
		// Go through GetUsers() so the lazily-computed users field is resolved
		// even when the caller never touched googleworkspace.users directly.
		users := g.GetUsers()
		if users.Error != nil {
			g.usersByIdErr = users.Error
			return
		}
		m := make(map[string]*mqlGoogleworkspaceUser, len(users.Data))
		for _, u := range users.Data {
			user := u.(*mqlGoogleworkspaceUser)
			if user.Id.Error != nil {
				g.usersByIdErr = user.Id.Error
				return
			}
			m[user.Id.Data] = user
		}
		g.usersById = m
	})
	if g.usersByIdErr != nil {
		return nil, g.usersByIdErr
	}
	return g.usersById[id], nil
}

func (g *mqlGoogleworkspace) roleById(id int64) (*mqlGoogleworkspaceRole, error) {
	g.rolesByIdOnce.Do(func() {
		// Go through GetRoles() so the lazily-computed roles field is resolved
		// even when the caller never touched googleworkspace.roles directly.
		roles := g.GetRoles()
		if roles.Error != nil {
			g.rolesByIdErr = roles.Error
			return
		}
		m := make(map[int64]*mqlGoogleworkspaceRole, len(roles.Data))
		for _, r := range roles.Data {
			role := r.(*mqlGoogleworkspaceRole)
			if role.Id.Error != nil {
				g.rolesByIdErr = role.Id.Error
				return
			}
			m[role.Id.Data] = role
		}
		g.rolesById = m
	})
	if g.rolesByIdErr != nil {
		return nil, g.rolesByIdErr
	}
	return g.rolesById[id], nil
}

func (r *mqlGoogleworkspace) id() (string, error) {
	return "google-workspace", nil
}

// loadUsageReports lazily fetches the entire customer's user usage reports
// in a single batched `UserUsageReport.Get("all", date)` call (paginated),
// guarded by sync.Once so the result is shared across every consumer in the
// query. Returns the keyed-by-email map plus the date the data is for
// (Google's reports API lags 1–3 days behind today; we walk back day-by-day
// to find the most recent published date).
func (g *mqlGoogleworkspace) loadUsageReports() (map[string]*reports.UsageReport, string, error) {
	g.usageReportsOnce.Do(func() {
		conn := g.MqlRuntime.Connection.(*connection.GoogleWorkspaceConnection)
		svc, err := reportsService(conn)
		if err != nil {
			g.usageReportsErr = err
			return
		}
		m, date, err := fetchAllUsageReports(svc, conn.CustomerID())
		if err != nil {
			g.usageReportsErr = err
			return
		}
		g.usageReportsByEmail = m
		g.usageReportsDate = date
	})
	return g.usageReportsByEmail, g.usageReportsDate, g.usageReportsErr
}

func reportsService(conn *connection.GoogleWorkspaceConnection) (*reports.Service, error) {
	client, err := conn.Client(reports.AdminReportsAuditReadonlyScope, reports.AdminReportsUsageReadonlyScope)
	if err != nil {
		return nil, err
	}

	service, err := reports.NewService(context.Background(), option.WithHTTPClient(client))
	return service, err
}

func directoryService(conn *connection.GoogleWorkspaceConnection, scopes ...string) (*directory.Service, error) {
	client, err := conn.Client(scopes...)
	if err != nil {
		return nil, err
	}

	directoryService, err := directory.NewService(context.Background(), option.WithHTTPClient(client))
	return directoryService, err
}

func calendarService(conn *connection.GoogleWorkspaceConnection, scopes ...string) (*calendar.Service, error) {
	client, err := conn.Client(scopes...)
	if err != nil {
		return nil, err
	}

	calendarsService, err := calendar.NewService(context.Background(), option.WithHTTPClient(client))
	return calendarsService, err
}

func cloudIdentityService(conn *connection.GoogleWorkspaceConnection, scopes ...string) (*cloudidentity.Service, error) {
	client, err := conn.Client(scopes...)
	if err != nil {
		return nil, err
	}

	cloudIdentityService, err := cloudidentity.NewService(context.Background(), option.WithHTTPClient(client))
	return cloudIdentityService, err
}

func groupSettingsService(conn *connection.GoogleWorkspaceConnection, scopes ...string) (*groupssettings.Service, error) {
	client, err := conn.Client(scopes...)
	if err != nil {
		return nil, err
	}

	groupssettingsService, err := groupssettings.NewService(context.Background(), option.WithHTTPClient(client))
	return groupssettingsService, err
}
