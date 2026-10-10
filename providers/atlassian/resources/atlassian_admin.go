// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/url"
	"time"

	model "github.com/ctreminiom/go-atlassian/v2/pkg/infra/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/atlassian/connection/admin"
	"go.mondoo.com/mql/types"
)

// extractAtlassianCursor parses the `cursor` query parameter out of a page's
// Links.Next URL. The admin API paginates by cursor and the SDK list methods
// take the raw cursor value (re-encoding it as ?cursor=…), so the full Next URL
// must not be passed back verbatim.
func extractAtlassianCursor(nextURL string) string {
	if nextURL == "" {
		return ""
	}
	u, err := url.Parse(nextURL)
	if err != nil {
		return ""
	}
	return u.Query().Get("cursor")
}

// parseAtlassianTime parses Atlassian Admin API timestamps (RFC3339). Returns
// nil for empty or unparseable input — the API returns "" for never-active
// accounts, which should surface as a null time, not a zero-value.
func parseAtlassianTime(s string) *time.Time {
	if s == "" {
		return nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil
	}
	return &t
}

// productAccess is one entry of a managed user's product-access list,
// flattened to the name and the (nullable) last-active timestamp.
type productAccess struct {
	Name       string
	LastActive *time.Time
}

func initAtlassianAdminOrganization(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn, ok := runtime.Connection.(*admin.AdminConnection)
	if !ok {
		return nil, nil, errors.New("Current connection does not allow admin access")
	}
	admin := conn.Client()
	organization, _, err := admin.Organization.Gets(context.Background(), "")
	if err != nil {
		return nil, nil, err
	}

	// We should only ever receive one organization that is scoped to the api key
	// https://community.atlassian.com/forums/discussion/1541337/can-we-access-multiple-organisations-using-one-api-token
	if len(organization.Data) == 0 {
		return nil, nil, errors.New("no organization found for this API key")
	}
	if len(organization.Data) > 1 {
		return nil, nil, errors.New("unexpectedly received more than 1 organization")
	}
	org := organization.Data[0]

	args["id"] = llx.StringData(org.ID)
	args["name"] = llx.StringData(org.Attributes.Name)
	args["type"] = llx.StringData(org.Type)

	return args, nil, nil
}

func (a *mqlAtlassianAdminOrganization) managedUsers() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*admin.AdminConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow admin access")
	}

	admin := conn.Client()

	res := []any{}
	cursor := ""
	for {
		managedUsers, _, err := admin.Organization.Users(context.Background(), a.Id.Data, cursor)
		if err != nil {
			return nil, err
		}
		for _, user := range managedUsers.Data {
			var products []productAccess

			for i := range user.ProductAccess {
				products = append(products, productAccess{
					Name:       user.ProductAccess[i].Name,
					LastActive: parseAtlassianTime(user.ProductAccess[i].LastActive),
				})
			}

			lastActive := parseAtlassianTime(user.LastActive)

			productArray, err := convert.JsonToDictSlice(products)
			if err != nil {
				return nil, err
			}

			mqlAtlassianAdminManagedUser, err := CreateResource(a.MqlRuntime, "atlassian.admin.organization.managedUser",
				map[string]*llx.RawData{
					"id":             llx.StringData(user.AccountID),
					"name":           llx.StringData(user.Name),
					"type":           llx.StringData(user.AccountType),
					"status":         llx.StringData(user.AccountStatus),
					"email":          llx.StringData(user.Email),
					"lastActive":     llx.TimeDataPtr(lastActive),
					"productAccess":  llx.ArrayData(productArray, types.Dict),
					"organizationId": llx.StringData(a.Id.Data),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAtlassianAdminManagedUser)
		}
		if managedUsers.Links == nil || managedUsers.Links.Next == "" {
			break
		}
		cursor = extractAtlassianCursor(managedUsers.Links.Next)
		if cursor == "" {
			break
		}
	}
	return res, nil
}

func (a *mqlAtlassianAdminOrganizationManagedUser) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianAdminOrganization) policies() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*admin.AdminConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow admin access")
	}
	admin := conn.Client()
	orgId := a.Id.Data
	res := []any{}
	cursor := ""
	for {
		policies, _, err := admin.Organization.Policy.Gets(context.Background(), orgId, "", cursor)
		if err != nil {
			return nil, err
		}
		for _, policy := range policies.Data {
			var createdAt *time.Time
			if !policy.Attributes.CreatedAt.IsZero() {
				createdAt = &policy.Attributes.CreatedAt
			}
			var updatedAt *time.Time
			if !policy.Attributes.UpdatedAt.IsZero() {
				updatedAt = &policy.Attributes.UpdatedAt
			}
			resources := make([]any, 0, len(policy.Attributes.Resources))
			for _, r := range policy.Attributes.Resources {
				if r == nil {
					continue
				}
				resources = append(resources, map[string]any{
					"id":                r.ID,
					"applicationStatus": r.ApplicationStatus,
				})
			}

			mqlAtlassianAdminPolicy, err := CreateResource(a.MqlRuntime, "atlassian.admin.organization.policy",
				map[string]*llx.RawData{
					"id":         llx.StringData(policy.ID),
					"type":       llx.StringData(policy.Type),
					"name":       llx.StringData(policy.Attributes.Name),
					"status":     llx.StringData(policy.Attributes.Status),
					"policyType": llx.StringData(policy.Attributes.Type),
					"createdAt":  llx.TimeDataPtr(createdAt),
					"updatedAt":  llx.TimeDataPtr(updatedAt),
					"resources":  llx.ArrayData(resources, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAtlassianAdminPolicy)
		}
		if policies.Links == nil || policies.Links.Next == "" {
			break
		}
		cursor = extractAtlassianCursor(policies.Links.Next)
		if cursor == "" {
			break
		}
	}
	return res, nil
}

func (a *mqlAtlassianAdminOrganization) domains() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*admin.AdminConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow admin access")
	}
	admin := conn.Client()
	orgId := a.Id.Data
	res := []any{}
	cursor := ""
	for {
		domains, resp, err := admin.Organization.Domains(context.Background(), orgId, cursor)
		// A 404 means the org has no verified domains — that's a valid empty
		// state, not an error. Anything else (transport failure, 5xx, 403) should
		// surface so callers can't mistake it for "no domains."
		if resp != nil && resp.StatusCode == 404 {
			return []any{}, nil
		}
		if err != nil {
			return nil, err
		}
		if domains == nil {
			break
		}
		for _, domain := range domains.Data {
			mqlAtlassianAdminDomain, err := CreateResource(a.MqlRuntime, "atlassian.admin.organization.domain",
				map[string]*llx.RawData{
					"id":   llx.StringData(domain.ID),
					"name": llx.StringData(domain.Attributes.Name),
					"type": llx.StringData(domain.Type),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAtlassianAdminDomain)
		}
		if domains.Links == nil || domains.Links.Next == "" {
			break
		}
		cursor = extractAtlassianCursor(domains.Links.Next)
		if cursor == "" {
			break
		}
	}
	return res, nil
}

func (a *mqlAtlassianAdminOrganizationDomain) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianAdminOrganizationPolicy) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianAdminOrganization) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAtlassianAdminOrganizationManagedUser) apiTokens() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*admin.AdminConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow admin access")
	}
	client := conn.Client()

	tokens, resp, err := client.User.Token.Gets(context.Background(), a.Id.Data)
	if err != nil {
		// Some accounts (apps, customers) don't expose token APIs; surface as empty rather than fail the whole query.
		if resp != nil && (resp.StatusCode == 403 || resp.StatusCode == 404) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(tokens))
	for _, t := range tokens {
		if t == nil {
			continue
		}
		var createdAt *time.Time
		if !t.CreatedAt.IsZero() {
			createdAt = &t.CreatedAt
		}
		var lastAccess *time.Time
		if !t.LastAccess.IsZero() {
			lastAccess = &t.LastAccess
		}
		mqlToken, err := CreateResource(a.MqlRuntime, "atlassian.admin.organization.managedUser.apiToken",
			map[string]*llx.RawData{
				"id":         llx.StringData(t.ID),
				"label":      llx.StringData(t.Label),
				"createdAt":  llx.TimeDataPtr(createdAt),
				"lastAccess": llx.TimeDataPtr(lastAccess),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlToken)
	}
	return res, nil
}

func (a *mqlAtlassianAdminOrganizationManagedUserApiToken) id() (string, error) {
	return "atlassian.admin.organization.managedUser.apiToken/" + a.Id.Data, nil
}

// maxAdminEventPages bounds the organization audit-event walk. The admin API
// retains events for a bounded window but a busy organization can still produce
// a very large number of pages, and a server that keeps handing back a fresh
// cursor would otherwise page forever.
const maxAdminEventPages = 200

// mqlAtlassianAdminOrganizationEventInternal carries what the event needs to
// resolve its actor without a per-event API call: the account ID recorded on
// the event, and the organization resource the event was listed from, whose
// managedUsers list the runtime memoizes after the first read.
type mqlAtlassianAdminOrganizationEventInternal struct {
	actorID string
	org     *mqlAtlassianAdminOrganization
}

// nilIfEmpty returns nil for an empty string so an absent API value surfaces as
// a null field rather than an invented "".
func nilIfEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// eventObjects flattens the context/container object lists of an audit event.
// Each object keeps its id, its type, and the API's own link to it.
func eventObjects(objects []*model.OrganizationEventObjectModel) []any {
	res := make([]any, 0, len(objects))
	for _, o := range objects {
		if o == nil {
			continue
		}
		link := o.Links.Self
		if link == "" {
			link = o.Links.Alt
		}
		res = append(res, map[string]any{
			"id":   o.ID,
			"type": o.Type,
			"link": link,
		})
	}
	return res
}

func (a *mqlAtlassianAdminOrganization) events() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*admin.AdminConnection)
	if !ok {
		return nil, errors.New("Current connection does not allow admin access")
	}
	client := conn.Client()
	orgID := a.Id.Data

	res := []any{}
	err := walkAdminEvents(
		func(cursor string) (*model.OrganizationEventPageScheme, error) {
			page, _, err := client.Organization.Events(context.Background(), orgID, nil, cursor)
			return page, err
		},
		func(event *model.OrganizationEventModelScheme) error {
			attrs := event.Attributes
			if attrs == nil {
				// Without attributes there is no action, actor or timestamp to
				// report; an id alone would be an empty row, so skip it.
				return nil
			}

			var actorID, actorName string
			if attrs.Actor != nil {
				actorID = attrs.Actor.ID
				actorName = attrs.Actor.Name
			}
			var ip, geo string
			if attrs.Location != nil {
				ip = attrs.Location.IP
				geo = attrs.Location.Geo
			}

			mqlEvent, err := CreateResource(a.MqlRuntime, "atlassian.admin.organization.event",
				map[string]*llx.RawData{
					"__id":      llx.StringData("atlassian.admin.organization.event/" + orgID + "/" + event.ID),
					"id":        llx.StringData(event.ID),
					"type":      llx.StringData(event.Type),
					"action":    llx.StringData(attrs.Action),
					"createdAt": llx.TimeDataPtr(parseAtlassianTime(attrs.Time)),
					"actorName": llx.StringDataPtr(nilIfEmpty(actorName)),
					"context":   llx.ArrayData(eventObjects(attrs.Context), types.Dict),
					"container": llx.ArrayData(eventObjects(attrs.Container), types.Dict),
					"ip":        llx.StringDataPtr(nilIfEmpty(ip)),
					"location":  llx.StringDataPtr(nilIfEmpty(geo)),
				})
			if err != nil {
				return err
			}
			e := mqlEvent.(*mqlAtlassianAdminOrganizationEvent)
			e.actorID = actorID
			e.org = a
			res = append(res, mqlEvent)
			return nil
		})
	if err != nil {
		return nil, err
	}
	return res, nil
}

// walkAdminEvents pages the organization audit log, handing each event to
// visit. Paging stops at the last page, at an empty or repeated cursor, and at
// maxAdminEventPages. The repeated-cursor guard matters because a server that
// keeps echoing the cursor it was given would otherwise re-read the same page
// until the bound is reached, multiplying every event on it.
func walkAdminEvents(
	fetch func(cursor string) (*model.OrganizationEventPageScheme, error),
	visit func(event *model.OrganizationEventModelScheme) error,
) error {
	cursor := ""
	for page := 0; page < maxAdminEventPages; page++ {
		events, err := fetch(cursor)
		if err != nil {
			return err
		}
		if events == nil {
			return nil
		}
		for _, event := range events.Data {
			if event == nil {
				continue
			}
			if err := visit(event); err != nil {
				return err
			}
		}
		if events.Links == nil {
			return nil
		}
		next := extractAtlassianCursor(events.Links.Next)
		if next == "" || next == cursor {
			return nil
		}
		cursor = next
	}
	return nil
}

// actor resolves the acting account against the organization's managed
// accounts. The managed-user list is read through the parent organization
// resource so the runtime memoizes it: resolving actors for a page of events
// costs one list call, not one call per event.
func (a *mqlAtlassianAdminOrganizationEvent) actor() (*mqlAtlassianAdminOrganizationManagedUser, error) {
	if a.actorID == "" || a.org == nil {
		a.Actor.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	users := a.org.GetManagedUsers()
	if users.Error != nil {
		return nil, users.Error
	}
	for _, raw := range users.Data {
		user, ok := raw.(*mqlAtlassianAdminOrganizationManagedUser)
		if !ok {
			continue
		}
		if user.Id.Data == a.actorID {
			return user, nil
		}
	}
	// Atlassian system processes and accounts outside this organization appear
	// as actors but are not managed accounts, so there is nothing to point at.
	a.Actor.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
