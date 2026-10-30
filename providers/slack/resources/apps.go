// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/slack-go/slack"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/slack/connection"
	"go.mondoo.com/mql/types"
)

const (
	adminAppsReadScope = "admin.apps:read"
	// admin.apps.*.list accepts 1 to 1000 items per page
	adminAppsPageLimit = 1000

	appStatusApproved   = "approved"
	appStatusRestricted = "restricted"
)

type mqlSlackAppResolutionInternal struct {
	cacheResolvedByID string
}

type mqlSlackAppRequestInternal struct {
	cacheRequesterID string
}

func (x *mqlSlackApp) id() (string, error) {
	return "slack.app/" + x.Id.Data, nil
}

func (x *mqlSlackAppResolution) id() (string, error) {
	return "slack.appResolution/" + x.Status.Data + "/" + x.App.Data.Id.Data, nil
}

func (x *mqlSlackAppRequest) id() (string, error) {
	return "slack.appRequest/" + x.Id.Data, nil
}

func adminClient(runtime *plugin.Runtime) (*slack.Client, *connection.SlackConnection, error) {
	conn := runtime.Connection.(*connection.SlackConnection)
	client := conn.Client()
	if client == nil {
		return nil, nil, errors.New("cannot retrieve new data while using a mock connection")
	}
	return client, conn, nil
}

func (s *mqlSlack) approvedApps() ([]any, error) {
	return s.appResolutions(appStatusApproved)
}

func (s *mqlSlack) restrictedApps() ([]any, error) {
	return s.appResolutions(appStatusRestricted)
}

func (s *mqlSlack) appResolutions(status string) ([]any, error) {
	client, conn, err := adminClient(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	teamID := conn.TeamInfo().ID

	res := []any{}
	err = walkCursor(func(cursor string) (string, error) {
		opts := []slack.AdminAppsListOption{
			slack.AdminAppsListOptionLimit(adminAppsPageLimit),
			slack.AdminAppsListOptionTeamID(teamID),
			slack.AdminAppsListOptionCursor(cursor),
		}
		var items []slack.AdminAppListItem
		var next string
		if status == appStatusApproved {
			resp, err := client.AdminAppsApprovedListContext(ctx, opts...)
			if err != nil {
				return "", classifyError(err, adminAppsReadScope)
			}
			items, next = resp.ApprovedApps, resp.ResponseMetadata.Cursor
		} else {
			resp, err := client.AdminAppsRestrictedListContext(ctx, opts...)
			if err != nil {
				return "", classifyError(err, adminAppsReadScope)
			}
			items, next = resp.RestrictedApps, resp.ResponseMetadata.Cursor
		}
		for i := range items {
			r, err := newMqlSlackAppResolution(s.MqlRuntime, status, items[i])
			if err != nil {
				return "", err
			}
			res = append(res, r)
		}
		return next, nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (s *mqlSlack) appRequests() ([]any, error) {
	client, conn, err := adminClient(s.MqlRuntime)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	teamID := conn.TeamInfo().ID

	res := []any{}
	err = walkCursor(func(cursor string) (string, error) {
		resp, err := client.AdminAppsRequestsListContext(ctx,
			slack.AdminAppsListOptionLimit(adminAppsPageLimit),
			slack.AdminAppsListOptionTeamID(teamID),
			slack.AdminAppsListOptionCursor(cursor),
		)
		if err != nil {
			return "", classifyError(err, adminAppsReadScope)
		}
		for i := range resp.AppRequests {
			r, err := newMqlSlackAppRequest(s.MqlRuntime, resp.AppRequests[i])
			if err != nil {
				return "", err
			}
			res = append(res, r)
		}
		return resp.ResponseMetadata.Cursor, nil
	})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// appArgs maps the app metadata of an admin.apps listing onto slack.app.
func appArgs(app slack.AdminApp) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":                     llx.StringData(app.ID),
		"name":                   llx.StringData(app.Name),
		"description":            llx.StringData(app.Description),
		"helpUrl":                llx.StringData(app.HelpURL),
		"privacyPolicyUrl":       llx.StringData(app.PrivacyPolicyURL),
		"homepageUrl":            llx.StringData(app.AppHomepageURL),
		"appDirectoryUrl":        llx.StringData(app.AppDirectoryURL),
		"isAppDirectoryApproved": llx.BoolData(app.IsAppDirectoryApproved),
		"isGranularBotApp":       llx.BoolData(app.IsGranularBotApp),
		"isInternal":             llx.BoolData(app.IsInternal),
		"developerType":          llx.StringData(app.DeveloperType),
		"socketModeEnabled":      llx.BoolData(app.SocketModeEnabled),
		"additionalInfo":         llx.StringData(app.AdditionalInfo),
	}
}

func newMqlSlackApp(runtime *plugin.Runtime, app slack.AdminApp) (*mqlSlackApp, error) {
	r, err := CreateResource(runtime, "slack.app", appArgs(app))
	if err != nil {
		return nil, err
	}
	return r.(*mqlSlackApp), nil
}

// scopeNames returns the names of all scopes and of the ones Slack marks as
// sensitive, in the order Slack listed them.
func scopeNames(scopes []slack.AdminAppScope) (all []any, sensitive []any) {
	all, sensitive = []any{}, []any{}
	for _, s := range scopes {
		all = append(all, s.Name)
		if s.IsSensitive {
			sensitive = append(sensitive, s.Name)
		}
	}
	return all, sensitive
}

// requestScopeNames is scopeNames for the scope shape of an app request.
func requestScopeNames(scopes []slack.AdminAppRequestScope) (all []any, sensitive []any) {
	all, sensitive = []any{}, []any{}
	for _, s := range scopes {
		all = append(all, s.Name)
		if s.IsSensitive {
			sensitive = append(sensitive, s.Name)
		}
	}
	return all, sensitive
}

// appResolutionArgs maps one admin.apps.approved.list or
// admin.apps.restricted.list entry onto slack.appResolution, without the app.
func appResolutionArgs(status string, item slack.AdminAppListItem) map[string]*llx.RawData {
	scopes, sensitive := scopeNames(item.Scopes)
	return map[string]*llx.RawData{
		"status":             llx.StringData(status),
		"scopes":             llx.ArrayData(scopes, types.String),
		"sensitiveScopes":    llx.ArrayData(sensitive, types.String),
		"updated":            unixTimeData(item.DateUpdated),
		"lastResolvedByType": llx.StringData(item.LastResolvedBy.ActorType),
	}
}

// resolvedByUserID returns the user ID of the actor that last resolved an app,
// or "" when the actor is not a user.
func resolvedByUserID(actor slack.AdminAppResolutionActor) string {
	if actor.ActorType != "" && actor.ActorType != "user" {
		return ""
	}
	return actor.ActorID
}

func newMqlSlackAppResolution(runtime *plugin.Runtime, status string, item slack.AdminAppListItem) (*mqlSlackAppResolution, error) {
	app, err := newMqlSlackApp(runtime, item.App)
	if err != nil {
		return nil, err
	}
	args := appResolutionArgs(status, item)
	args["app"] = llx.ResourceData(app, "slack.app")
	r, err := CreateResource(runtime, "slack.appResolution", args)
	if err != nil {
		return nil, err
	}
	res := r.(*mqlSlackAppResolution)
	res.cacheResolvedByID = resolvedByUserID(item.LastResolvedBy)
	return res, nil
}

func (x *mqlSlackAppResolution) lastResolvedBy() (*mqlSlackUser, error) {
	return slackUserRef(x.MqlRuntime, x.cacheResolvedByID, &x.LastResolvedBy)
}

// appRequestArgs maps one admin.apps.requests.list entry onto
// slack.appRequest, without the app.
func appRequestArgs(req slack.AdminAppRequest) map[string]*llx.RawData {
	scopes, sensitive := requestScopeNames(req.Scopes)
	previous := llx.NilData
	if req.PreviousResolution != nil && req.PreviousResolution.Status != "" {
		previous = llx.StringData(req.PreviousResolution.Status)
	}
	return map[string]*llx.RawData{
		"id":                       llx.StringData(req.ID),
		"message":                  llx.StringData(req.Message),
		"scopes":                   llx.ArrayData(scopes, types.String),
		"sensitiveScopes":          llx.ArrayData(sensitive, types.String),
		"isUserAppCollaborator":    llx.BoolData(req.IsUserAppCollaborator),
		"previousResolutionStatus": previous,
		"created":                  unixTimeData(req.DateCreated),
	}
}

func newMqlSlackAppRequest(runtime *plugin.Runtime, req slack.AdminAppRequest) (*mqlSlackAppRequest, error) {
	app, err := newMqlSlackApp(runtime, req.App)
	if err != nil {
		return nil, err
	}
	args := appRequestArgs(req)
	args["app"] = llx.ResourceData(app, "slack.app")
	r, err := CreateResource(runtime, "slack.appRequest", args)
	if err != nil {
		return nil, err
	}
	res := r.(*mqlSlackAppRequest)
	res.cacheRequesterID = req.User.ID
	return res, nil
}

func (x *mqlSlackAppRequest) requestedBy() (*mqlSlackUser, error) {
	return slackUserRef(x.MqlRuntime, x.cacheRequesterID, &x.RequestedBy)
}
