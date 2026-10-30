// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/okta/connection"
)

// oktaAppLinkRaw is the app link wire shape, with each value as a plain type
// rather than a pointer. The SDK models every attribute as optional, so
// normalizing through JSON gives the mapper one shape to read and keeps the
// zero-value semantics the resource fields already report.
//
// The tags carry no omitempty: this struct is only ever decoded into, where the
// option has no effect, and every zero value here is a real reading. A link at
// the top of the dashboard has sortOrder 0, and false is the ordinary answer
// for both booleans, so an omitempty that ever reached a marshal would drop
// exactly the values worth reporting.
type oktaAppLinkRaw struct {
	Id               string `json:"id"`
	Label            string `json:"label"`
	LinkUrl          string `json:"linkUrl"`
	LogoUrl          string `json:"logoUrl"`
	AppName          string `json:"appName"`
	AppInstanceId    string `json:"appInstanceId"`
	AppAssignmentId  string `json:"appAssignmentId"`
	CredentialsSetup bool   `json:"credentialsSetup"`
	Hidden           bool   `json:"hidden"`
	SortOrder        int64  `json:"sortOrder"`
}

// mqlOktaUserAppLinkInternal caches the application id behind the application
// reference. It is not a public field: the reference carries the same value,
// and the link's own id already names the application instance.
type mqlOktaUserAppLinkInternal struct {
	cacheAppInstanceId string
}

// decodeOktaAppLink normalizes an SDK app link through JSON into the wire
// shape the mapper reads. See oktaAppLinkRaw.
func decodeOktaAppLink(src *okta.AssignedAppLink) (*oktaAppLinkRaw, error) {
	raw, err := json.Marshal(src)
	if err != nil {
		return nil, err
	}
	entry := &oktaAppLinkRaw{}
	if err := json.Unmarshal(raw, entry); err != nil {
		return nil, err
	}
	return entry, nil
}

// appInstanceId returns the id of the application a link points at. Okta
// repeats it as the link's own `id`, but only `appInstanceId` is documented to
// carry it, so the dedicated field wins and `id` is the fallback.
func (l *oktaAppLinkRaw) appInstanceId() string {
	if l.AppInstanceId != "" {
		return l.AppInstanceId
	}
	return l.Id
}

func (o *mqlOktaUser) appLinks() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	userID := o.Id.Data

	ctx := context.Background()
	// No .Limit here: the SDK request type for this endpoint offers only
	// Execute, so the API sets the page size. The paging loop below still
	// applies, since the response can carry a next link either way.
	slice, resp, err := client.UserResourcesAPI.ListAppLinks(ctx, userID).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.AppLinks)
		}
		return nil, err
	}

	all, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(all))
	for i := range all {
		entry, err := decodeOktaAppLink(&all[i])
		if err != nil {
			return nil, err
		}
		r, err := newMqlOktaUserAppLink(o.MqlRuntime, userID, entry)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func newMqlOktaUserAppLink(runtime *plugin.Runtime, userID string, entry *oktaAppLinkRaw) (*mqlOktaUserAppLink, error) {
	appInstanceId := entry.appInstanceId()
	r, err := CreateResource(runtime, "okta.user.appLink", map[string]*llx.RawData{
		"__id":             llx.StringData(fmt.Sprintf("%s/%s", userID, appInstanceId)),
		"id":               llx.StringData(appInstanceId),
		"label":            llx.StringData(entry.Label),
		"linkUrl":          llx.StringData(entry.LinkUrl),
		"logoUrl":          llx.StringData(entry.LogoUrl),
		"appName":          llx.StringData(entry.AppName),
		"appAssignmentId":  llx.StringData(entry.AppAssignmentId),
		"credentialsSetup": llx.BoolData(entry.CredentialsSetup),
		"hidden":           llx.BoolData(entry.Hidden),
		"sortOrder":        llx.IntData(entry.SortOrder),
	})
	if err != nil {
		return nil, err
	}
	link := r.(*mqlOktaUserAppLink)
	link.cacheAppInstanceId = appInstanceId
	return link, nil
}

func (o *mqlOktaUserAppLink) application() (*mqlOktaApplication, error) {
	return resolveOktaApplicationRef(o.MqlRuntime, o.cacheAppInstanceId, &o.Application)
}

func (o *mqlOktaUser) grants() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	userID := o.Id.Data

	ctx := context.Background()
	slice, resp, err := client.UserGrantAPI.ListUserGrants(ctx, userID).Limit(queryLimit).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.Grants)
		}
		return nil, err
	}

	all, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(all))
	for i := range all {
		r, err := newMqlOktaUserGrant(o.MqlRuntime, userID, &all[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func newMqlOktaUserGrant(runtime *plugin.Runtime, userID string, entry *okta.OAuth2ScopeConsentGrant) (any, error) {
	return CreateResource(runtime, "okta.user.grant", map[string]*llx.RawData{
		"__id":        llx.StringData(fmt.Sprintf("%s/%s", userID, oktaStr(entry.Id))),
		"id":          llx.StringData(oktaStr(entry.Id)),
		"scopeId":     llx.StringData(entry.ScopeId),
		"clientId":    llx.StringData(oktaStr(entry.ClientId)),
		"issuer":      llx.StringData(entry.Issuer),
		"status":      llx.StringData(oktaStr(entry.Status)),
		"source":      llx.StringData(oktaStr(entry.Source)),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
	})
}

func (o *mqlOktaUser) clients() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()
	if o.Id.Error != nil {
		return nil, o.Id.Error
	}
	userID := o.Id.Data

	ctx := context.Background()
	// No .Limit here, for the same reason as appLinks above.
	slice, resp, err := client.UserResourcesAPI.ListUserClients(ctx, userID).Execute()
	if err != nil {
		if isOktaFeatureUnavailable(resp, err) {
			return oktaUnreadableList(&o.Clients)
		}
		return nil, err
	}

	all, err := oktaCollectPages(slice, resp)
	if err != nil {
		return nil, err
	}

	list := make([]any, 0, len(all))
	for i := range all {
		r, err := newMqlOktaUserClient(o.MqlRuntime, userID, &all[i])
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func newMqlOktaUserClient(runtime *plugin.Runtime, userID string, entry *okta.OAuth2Client) (any, error) {
	return CreateResource(runtime, "okta.user.client", map[string]*llx.RawData{
		"__id":       llx.StringData(fmt.Sprintf("%s/%s", userID, oktaStr(entry.ClientId))),
		"clientId":   llx.StringData(oktaStr(entry.ClientId)),
		"clientName": llx.StringData(oktaStr(entry.ClientName)),
		"clientUri":  llx.StringData(oktaStr(entry.ClientUri)),
		"logoUri":    llx.StringData(oktaStr(entry.LogoUri)),
	})
}
