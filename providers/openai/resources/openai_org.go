// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/openai/openai-go/v3"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func (r *mqlOpenai) users() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.users")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Users.ListAutoPaging(ctx, openai.AdminOrganizationUserListParams{})
	var res []any
	for iter.Next() {
		u := iter.Current()
		mqlUser, err := CreateResource(r.MqlRuntime, "openai.organizationUser", map[string]*llx.RawData{
			"__id":             llx.StringData(u.ID),
			"id":               llx.StringData(u.ID),
			"email":            llx.StringData(u.Email),
			"name":             llx.StringData(u.Name),
			"role":             llx.StringData(u.Role),
			"isDefault":        llx.BoolData(u.IsDefault),
			"isScimManaged":    llx.BoolData(u.IsScimManaged),
			"isServiceAccount": llx.BoolData(u.IsServiceAccount),
			"addedAt":          llx.TimeDataPtr(unixToNullableTime(u.AddedAt)),
			"createdAt":        llx.TimeDataPtr(unixToNullableTime(u.Created)),
			"apiKeyLastUsedAt": llx.TimeDataPtr(unixToNullableTime(u.APIKeyLastUsedAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list organization users: %w", err)
	}
	return res, nil
}

func (r *mqlOpenai) invites() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.invites")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	iter := client.Admin.Organization.Invites.ListAutoPaging(ctx, openai.AdminOrganizationInviteListParams{})
	var res []any
	for iter.Next() {
		inv := iter.Current()
		mqlInvite, err := CreateResource(r.MqlRuntime, "openai.invite", map[string]*llx.RawData{
			"__id":       llx.StringData(inv.ID),
			"id":         llx.StringData(inv.ID),
			"email":      llx.StringData(inv.Email),
			"role":       llx.StringData(string(inv.Role)),
			"status":     llx.StringData(string(inv.Status)),
			"createdAt":  llx.TimeDataPtr(unixToNullableTime(inv.CreatedAt)),
			"acceptedAt": llx.TimeDataPtr(unixToNullableTime(inv.AcceptedAt)),
			"expiresAt":  llx.TimeDataPtr(unixToNullableTime(inv.ExpiresAt)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInvite)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list invites: %w", err)
	}
	return res, nil
}

// auditLogActor derives the actor type and a human-readable actor identifier
// from an audit log entry's actor. For a session the identifier is the user's
// email; for an API key it is the key ID; otherwise it falls back to the actor
// type string.
func auditLogActor(actor openai.AdminOrganizationAuditLogListResponseActor) (actorType string, actorID string) {
	actorType = actor.Type
	switch actorType {
	case "session":
		actorID = actor.Session.User.Email
	case "api_key":
		actorID = actor.APIKey.ID
	default:
		actorID = actorType
	}
	return actorType, actorID
}

// auditLogActorUserID returns the id of the organization member behind an
// audit log actor. A browser session always names its user; an API key names
// one only when the key was issued to a person, so a key belonging to a
// service account reports no user at all.
func auditLogActorUserID(actor openai.AdminOrganizationAuditLogListResponseActor) string {
	switch actor.Type {
	case "session":
		return actor.Session.User.ID
	case "api_key":
		if actor.APIKey.Type == "user" {
			return actor.APIKey.User.ID
		}
	}
	return ""
}

// auditLogActorIPAddress returns the source address of a browser session
// actor. Actions performed with an API key carry no address, and reporting ""
// for them would read as an event that came from an unknown address rather
// than one the API never records an address for.
func auditLogActorIPAddress(actor openai.AdminOrganizationAuditLogListResponseActor) *string {
	if actor.Type != "session" || actor.Session.IPAddress == "" {
		return nil
	}
	return &actor.Session.IPAddress
}

// auditLogActorAPIKeyType returns the credential class behind an API key
// actor, and nil for a browser session, which has no key.
func auditLogActorAPIKeyType(actor openai.AdminOrganizationAuditLogListResponseActor) *string {
	if actor.Type != "api_key" || actor.APIKey.Type == "" {
		return nil
	}
	return &actor.APIKey.Type
}

// auditLogDetails pulls the change record an entry carries for its own event
// type. The API nests each payload under a key equal to the event type
// ("api_key.created", "ip_allowlist.updated", "workload_identity_provider.created",
// and so on), so reading the raw document by key covers every event type,
// including the ones the generated response has no field for. Entries whose
// type carries no payload, such as login.succeeded, decode to nil.
func auditLogDetails(raw string, eventType string) (any, error) {
	if raw == "" || eventType == "" {
		return nil, nil
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &doc); err != nil {
		return nil, fmt.Errorf("failed to read the payload of audit log event %s: %w", eventType, err)
	}
	payload, ok := doc[eventType]
	if !ok {
		return nil, nil
	}
	var details any
	if err := json.Unmarshal(payload, &details); err != nil {
		return nil, fmt.Errorf("failed to read the payload of audit log event %s: %w", eventType, err)
	}
	return details, nil
}

type mqlOpenaiAuditLogInternal struct {
	cacheActorUserId string
	cacheProjectId   string
}

func (r *mqlOpenaiAuditLog) actorUser() (*mqlOpenaiOrganizationUser, error) {
	if r.cacheActorUserId == "" {
		r.ActorUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// an entry outlives the member who caused it, so a departed member nulls
	// the reference instead of failing the whole log
	user, err := findOrganizationUser(r.MqlRuntime, r.cacheActorUserId)
	if err != nil {
		return nil, err
	}
	if user == nil {
		r.ActorUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return user, nil
}

func (r *mqlOpenaiAuditLog) project() (*mqlOpenaiProject, error) {
	if r.cacheProjectId == "" {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	project, err := resolveProject(r.MqlRuntime, r.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if project == nil {
		r.Project.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return project, nil
}

func (r *mqlOpenai) auditLogs() ([]any, error) {
	conn := openaiConn(r.MqlRuntime)
	client, err := adminPlaneClient(conn, "openai.auditLogs")
	if err != nil {
		return nil, err
	}
	if client == nil {
		return []any{}, nil
	}
	ctx := context.Background()

	since := time.Now().AddDate(0, 0, -30)
	iter := client.Admin.Organization.AuditLogs.ListAutoPaging(ctx, openai.AdminOrganizationAuditLogListParams{
		EffectiveAt: openai.AdminOrganizationAuditLogListParamsEffectiveAt{
			Gte: openai.Int(since.Unix()),
		},
	})
	var res []any
	for iter.Next() {
		entry := iter.Current()
		actorType, actorID := auditLogActor(entry.Actor)

		details, err := auditLogDetails(entry.RawJSON(), string(entry.Type))
		if err != nil {
			return nil, err
		}

		mqlLog, err := CreateResource(r.MqlRuntime, "openai.auditLog", map[string]*llx.RawData{
			"__id":            llx.StringData(entry.ID),
			"id":              llx.StringData(entry.ID),
			"type":            llx.StringData(string(entry.Type)),
			"effectiveAt":     llx.TimeDataPtr(unixToNullableTime(entry.EffectiveAt)),
			"actorType":       llx.StringData(actorType),
			"actorId":         llx.StringData(actorID),
			"actorIpAddress":  llx.StringDataPtr(auditLogActorIPAddress(entry.Actor)),
			"actorApiKeyType": llx.StringDataPtr(auditLogActorAPIKeyType(entry.Actor)),
			"details":         llx.DictData(details),
		})
		if err != nil {
			return nil, err
		}
		auditLog := mqlLog.(*mqlOpenaiAuditLog)
		auditLog.cacheActorUserId = auditLogActorUserID(entry.Actor)
		auditLog.cacheProjectId = entry.Project.ID
		res = append(res, mqlLog)
	}
	if err := iter.Err(); err != nil {
		if isAccessDenied(err) {
			return []any{}, nil
		}
		return nil, fmt.Errorf("failed to list audit logs: %w", err)
	}
	return res, nil
}
