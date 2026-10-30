// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
)

type mqlOktaApplicationScopeConsentGrantInternal struct {
	cacheUserID string
}

// --- application user assignments ---

func (a *mqlOktaApplication) assignedUsers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	appID := a.Id.Data
	slice, resp, err := client.ApplicationUsersAPI.ListApplicationUsers(ctx, appID).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.AppUser) error {
		for i := range datalist {
			r, err := newMqlOktaApplicationUser(a.MqlRuntime, appID, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.AppUser
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaApplicationUser(runtime *plugin.Runtime, appID string, entry *okta.AppUser) (any, error) {
	credentials, err := convert.JsonToDict(entry.Credentials)
	if err != nil {
		return nil, err
	}
	profile, err := convert.JsonToDict(entry.Profile)
	if err != nil {
		return nil, err
	}

	userID := oktaStr(entry.Id)
	r, err := CreateResource(runtime, "okta.application.user", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("%s/%s", appID, userID)),
		"id":          llx.StringData(userID),
		"scope":       llx.StringData(oktaStr(entry.Scope)),
		"status":      llx.StringData(oktaStr(entry.Status)),
		"syncState":   llx.StringData(oktaStr(entry.SyncState)),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
		"lastSync":    llx.TimeDataPtr(entry.LastSync),
		"credentials": llx.DictData(credentials),
		"profile":     llx.DictData(profile),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOktaApplicationUser), nil
}

func (a *mqlOktaApplicationUser) user() (*mqlOktaUser, error) {
	return resolveOktaUserRef(a.MqlRuntime, a.Id.Data, &a.User)
}

// --- application group assignments ---

func (a *mqlOktaApplication) assignedGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	appID := a.Id.Data
	slice, resp, err := client.ApplicationGroupsAPI.ListApplicationGroupAssignments(ctx, appID).Limit(queryLimit).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.ApplicationGroupAssignment) error {
		for i := range datalist {
			r, err := newMqlOktaApplicationGroupAssignment(a.MqlRuntime, appID, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.ApplicationGroupAssignment
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaApplicationGroupAssignment(runtime *plugin.Runtime, appID string, entry *okta.ApplicationGroupAssignment) (any, error) {
	profile, err := convert.JsonToDict(entry.Profile)
	if err != nil {
		return nil, err
	}

	var priority int64
	if entry.Priority != nil {
		priority = int64(*entry.Priority)
	}

	groupID := oktaStr(entry.Id)
	r, err := CreateResource(runtime, "okta.application.groupAssignment", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("%s/%s", appID, groupID)),
		"id":          llx.StringData(groupID),
		"priority":    llx.IntData(priority),
		"profile":     llx.DictData(profile),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlOktaApplicationGroupAssignment), nil
}

func (a *mqlOktaApplicationGroupAssignment) group() (*mqlOktaGroup, error) {
	return resolveOktaGroupRef(a.MqlRuntime, a.Id.Data, &a.Group)
}

// --- application scope consent grants ---

func (a *mqlOktaApplication) scopeConsentGrants() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	appID := a.Id.Data

	slice, resp, err := client.ApplicationGrantsAPI.ListScopeConsentGrants(ctx, appID).Execute()
	if err != nil {
		// The grants collection belongs to the OAuth 2.0 client, so Okta answers
		// 404 for an application that is not one (a bookmark or SAML app). That
		// describes the app's type rather than a failure, and erroring here
		// would take down every other application in the same query.
		if isOktaFeatureUnavailable(resp, err) {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.OAuth2ScopeConsentGrant) error {
		for i := range datalist {
			r, err := newMqlOktaApplicationScopeConsentGrant(a.MqlRuntime, appID, &datalist[i])
			if err != nil {
				return err
			}
			list = append(list, r)
		}
		return nil
	}

	if err := appendEntry(slice); err != nil {
		return nil, err
	}
	for resp != nil && resp.HasNextPage() {
		var page []okta.OAuth2ScopeConsentGrant
		resp, err = resp.Next(&page)
		if err != nil {
			return nil, err
		}
		if err := appendEntry(page); err != nil {
			return nil, err
		}
	}
	return list, nil
}

func newMqlOktaApplicationScopeConsentGrant(runtime *plugin.Runtime, appID string, entry *okta.OAuth2ScopeConsentGrant) (any, error) {
	r, err := CreateResource(runtime, "okta.application.scopeConsentGrant", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("%s/%s", appID, oktaStr(entry.Id))),
		"id":          llx.StringData(oktaStr(entry.Id)),
		"scopeId":     llx.StringData(entry.ScopeId),
		"issuer":      llx.StringData(entry.Issuer),
		"status":      llx.StringData(oktaStr(entry.Status)),
		"source":      llx.StringData(oktaStr(entry.Source)),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
	if err != nil {
		return nil, err
	}
	grant := r.(*mqlOktaApplicationScopeConsentGrant)
	grant.cacheUserID = oktaStr(entry.UserId)
	return grant, nil
}

func (a *mqlOktaApplicationScopeConsentGrant) user() (*mqlOktaUser, error) {
	return resolveOktaUserRef(a.MqlRuntime, a.cacheUserID, &a.User)
}

// --- application admin (client) roles ---

func (a *mqlOktaApplication) adminRoles() ([]any, error) {
	clientID := a.oauthClientID()
	if clientID == "" {
		// App is not an OAuth service client; no client role assignments.
		return nil, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.OktaConnection)
	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	roles, resp, err := apiSupplement.ListClientRoles(ctx, clientID)
	if err != nil {
		// Apps without service-client role assignments 404 here.
		if resp != nil && resp.StatusCode == http.StatusNotFound {
			return nil, nil
		}
		return nil, err
	}

	list := []any{}
	for i := range roles {
		r, err := newMqlOktaRole(a.MqlRuntime, roles[i], "client", clientID)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

// oauthClientID reads the app's OAuth client_id from its credentials, which is
// present only for OIDC / API service client apps.
func (a *mqlOktaApplication) oauthClientID() string {
	creds := a.GetCredentials()
	if creds.Error != nil {
		return ""
	}
	return oktaOAuthClientID(creds.Data)
}

// oktaOAuthClientID extracts credentials.oauthClient.client_id from an
// application credentials dict, returning "" when any level is missing or not
// the expected shape.
func oktaOAuthClientID(creds any) string {
	credMap, ok := creds.(map[string]any)
	if !ok {
		return ""
	}
	oauthClient, ok := credMap["oauthClient"].(map[string]any)
	if !ok {
		return ""
	}
	clientID, ok := oauthClient["client_id"].(string)
	if !ok {
		return ""
	}
	return clientID
}
