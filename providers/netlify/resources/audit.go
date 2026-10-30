// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/url"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/netlify/connection"
)

// maxAuditEventsPerAccount bounds how far back an account's audit log is read.
// The log is append-only and grows without limit on a busy account, and Netlify
// returns it newest first, so the bound keeps the most recent events. The
// schema states the bound so a truncated list reads as a documented window
// rather than as an account with no older history.
const maxAuditEventsPerAccount = 1000

// mqlNetlifyAccountAuditEventInternal caches what the event's actor reference
// resolves against: the account whose roster holds the members, and the
// identifier of the user that made the change.
type mqlNetlifyAccountAuditEventInternal struct {
	cacheAccountID string
	cacheActorID   string
}

// auditLogRecord is one recorded change. Everything about the change beyond its
// identity sits under payload, which also carries whatever else the event type
// recorded, so only the documented keys are read out of it.
type auditLogRecord struct {
	ID        string          `json:"id"`
	AccountID string          `json:"account_id"`
	Payload   auditLogPayload `json:"payload"`
}

type auditLogPayload struct {
	ActorID    string      `json:"actor_id"`
	ActorName  string      `json:"actor_name"`
	ActorEmail string      `json:"actor_email"`
	Action     string      `json:"action"`
	Timestamp  netlifyTime `json:"timestamp"`
	LogType    string      `json:"log_type"`
}

// auditEvents lists the account's recorded changes, newest first and bounded to
// maxAuditEventsPerAccount.
func (a *mqlNetlifyAccount) auditEvents() ([]any, error) {
	c := netlifyConn(a.MqlRuntime)

	accountID := a.Id.Data
	if accountID == "" {
		a.AuditEvents = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
		return nil, nil
	}

	records, err := connection.GetPagedLimit[auditLogRecord](context.Background(), c,
		"/accounts/"+url.PathEscape(accountID)+"/audit", nil, maxAuditEventsPerAccount)
	if err != nil {
		// The audit log is plan-gated and requires administrative rights, so
		// both a plan without it and a token without those rights answer with
		// a denial. Reporting the list as null keeps either apart from an
		// account on which nothing has ever been changed.
		if connection.IsForbidden(err) || connection.IsNotFound(err) {
			a.AuditEvents = plugin.TValue[[]any]{State: plugin.StateIsSet | plugin.StateIsNull}
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		rec := records[i]
		event, err := CreateResource(a.MqlRuntime, "netlify.account.auditEvent", map[string]*llx.RawData{
			"__id":       llx.StringData(accountID + "/auditEvent/" + rec.ID),
			"id":         llx.StringData(rec.ID),
			"action":     llx.StringData(rec.Payload.Action),
			"logType":    llx.StringData(rec.Payload.LogType),
			"actorName":  llx.StringData(rec.Payload.ActorName),
			"actorEmail": llx.StringData(rec.Payload.ActorEmail),
			"timestamp":  llx.TimeDataPtr(rec.Payload.Timestamp.Time()),
		})
		if err != nil {
			return nil, err
		}
		mqlEvent := event.(*mqlNetlifyAccountAuditEvent)
		mqlEvent.cacheAccountID = accountID
		mqlEvent.cacheActorID = rec.Payload.ActorID
		res = append(res, mqlEvent)
	}
	return res, nil
}

func (e *mqlNetlifyAccountAuditEvent) id() (string, error) {
	return e.Id.Data, e.Id.Error
}

// actor resolves the member that made the change against the roster of the
// account the event belongs to, which is fetched once for the whole scan rather
// than once per event.
//
// The recorded actor identifier names the user behind a membership rather than
// the membership itself, so the match runs against userId, the same way the
// account's owners resolve. An actor who has since left the account is not on
// the roster and reports as null; actorName and actorEmail still attribute the
// change in that case.
func (e *mqlNetlifyAccountAuditEvent) actor() (*mqlNetlifyAccountMember, error) {
	if e.cacheActorID == "" || e.cacheAccountID == "" {
		e.Actor.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	root, err := getNetlify(e.MqlRuntime)
	if err != nil {
		return nil, err
	}
	account, ok := findCachedResource(root.GetAccounts(), netlifyAccountID, e.cacheAccountID)
	if !ok {
		e.Actor.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	members := account.GetMembers()
	if members.Error != nil || members.State&plugin.StateIsNull != 0 {
		e.Actor.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	for _, it := range members.Data {
		member, ok := it.(*mqlNetlifyAccountMember)
		if ok && member.UserId.Data == e.cacheActorID {
			return member, nil
		}
	}

	e.Actor.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
