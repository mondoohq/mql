// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/cockroachdb/errors"
	"github.com/microsoftgraph/msgraph-sdk-go/auditlogs"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

const (
	// auditLogDefaultWindow is how far back the audit log lists reach when no
	// `since` argument is given. The logs are unbounded within the tenant's
	// retention, so the default must never be "everything".
	auditLogDefaultWindow = 7 * 24 * time.Hour
	// auditLogPageSize is the $top page size requested from the audit log
	// endpoints. Every page is still followed; this only reduces round trips.
	auditLogPageSize = int32(999)

	auditLogReadPermission = "AuditLog.Read.All"

	// graphCodeNonPremiumTenant is the Graph error code returned with a 403
	// when the tenant lacks the Microsoft Entra ID P1/P2 license an audit log
	// endpoint needs.
	graphCodeNonPremiumTenant = "Authentication_RequestFromNonPremiumTenantOrB2CTenant"
)

// auditLogWindow is the time window and extra filter an audit log list was
// initialized with.
type auditLogWindow struct {
	since         time.Time
	sinceExplicit bool
	filter        string
}

// auditLogWindowFromArgs reads the `since` and `filter` init arguments,
// applying the default window when `since` is absent. now is injected so the
// default can be tested.
func auditLogWindowFromArgs(args map[string]*llx.RawData, now time.Time) (auditLogWindow, error) {
	w := auditLogWindow{since: now.Add(-auditLogDefaultWindow)}
	if raw, ok := args["since"]; ok && raw != nil && raw.Value != nil {
		switch v := raw.Value.(type) {
		case *time.Time:
			if v == nil {
				return w, errors.New("since must be a time")
			}
			w.since = *v
		case time.Time:
			w.since = v
		default:
			return w, errors.Newf("since must be a time, got %T", raw.Value)
		}
		w.sinceExplicit = true
	}
	if raw, ok := args["filter"]; ok && raw != nil && raw.Value != nil {
		f, ok := raw.Value.(string)
		if !ok {
			return w, errors.Newf("filter must be a string, got %T", raw.Value)
		}
		w.filter = strings.TrimSpace(f)
	}
	return w, nil
}

// odataFilter builds the $filter sent to Graph: the time window, joined with
// the caller's own condition when one was given. The caller's condition is
// parenthesized so an `or` in it cannot escape the window.
func (w auditLogWindow) odataFilter() string {
	f := "activityDateTime ge " + w.since.UTC().Format(time.RFC3339)
	if w.filter != "" {
		f += " and (" + w.filter + ")"
	}
	return f
}

// cacheID builds the resource __id. Lists with different arguments must not
// share a cache entry. Every argument-less list in a scan shares one, so its
// default window is computed once rather than once per query.
func (w auditLogWindow) cacheID(resource string) string {
	since := "default"
	if w.sinceExplicit {
		since = w.since.UTC().Format(time.RFC3339Nano)
	}
	return resource + "/since/" + since + "/filter/" + filterID(w.filter)
}

func initAuditLogList(resource string, args map[string]*llx.RawData) (map[string]*llx.RawData, error) {
	w, err := auditLogWindowFromArgs(args, time.Now())
	if err != nil {
		return nil, err
	}
	args["since"] = llx.TimeData(w.since)
	args["filter"] = llx.StringData(w.filter)
	args["__id"] = llx.StringData(w.cacheID(resource))
	return args, nil
}

func initMicrosoftAuditLogsDirectoryAudits(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	args, err := initAuditLogList(ResourceMicrosoftAuditLogsDirectoryAudits, args)
	return args, nil, err
}

func initMicrosoftAuditLogsProvisioningEvents(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	args, err := initAuditLogList(ResourceMicrosoftAuditLogsProvisioningEvents, args)
	return args, nil, err
}

// windowOf rebuilds the window from a list resource's fields.
func windowOf(since plugin.TValue[*time.Time], filter plugin.TValue[string]) auditLogWindow {
	w := auditLogWindow{filter: filter.Data}
	if since.Data != nil {
		w.since = *since.Data
	}
	return w
}

// classifyAuditLogError turns a failed audit log request into the error the
// list reports. A tenant without the Entra ID license the endpoint needs gets
// NotApplicable; any other 403 is a missing AuditLog.Read.All grant.
func classifyAuditLogError(err error) error {
	if err == nil {
		return nil
	}
	if graphStatusCode(err) == http.StatusForbidden && graphErrorCode(err) == graphCodeNonPremiumTenant {
		return llx.NotApplicable(transformError(err))
	}
	return classifyGraphError(err, auditLogReadPermission)
}

// auditLogRefs resolves the directory objects named by audit events against
// the tenant's user and service principal lists, which are fetched once and
// shared by every event of a list, never looked up per event.
type auditLogRefs struct {
	runtime *plugin.Runtime

	usersOnce sync.Once
	usersErr  error
	ms        *mqlMicrosoft

	spOnce sync.Once
	spErr  error
	spByID map[string]*mqlMicrosoftServiceprincipal
}

func (r *auditLogRefs) microsoft() (*mqlMicrosoft, error) {
	res, err := CreateResource(r.runtime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return res.(*mqlMicrosoft), nil
}

// user returns the user with the given object id, or nil when no such user
// exists in the directory.
func (r *auditLogRefs) user(id string) (*mqlMicrosoftUser, error) {
	if id == "" {
		return nil, nil
	}
	r.usersOnce.Do(func() {
		ms, err := r.microsoft()
		if err != nil {
			r.usersErr = err
			return
		}
		users := ms.GetUsers()
		if users.Error != nil {
			r.usersErr = users.Error
			return
		}
		// Listing the users indexes every one of them on the microsoft resource.
		if list := users.Data.GetList(); list.Error != nil {
			r.usersErr = list.Error
			return
		}
		r.ms = ms
	})
	if r.usersErr != nil {
		return nil, r.usersErr
	}
	u, ok := r.ms.userById(id)
	if !ok {
		return nil, nil
	}
	return u, nil
}

// servicePrincipal returns the service principal with the given object id,
// or nil when no such service principal exists in the directory.
func (r *auditLogRefs) servicePrincipal(id string) (*mqlMicrosoftServiceprincipal, error) {
	if id == "" {
		return nil, nil
	}
	r.spOnce.Do(func() {
		ms, err := r.microsoft()
		if err != nil {
			r.spErr = err
			return
		}
		sps := ms.GetServiceprincipals()
		if sps.Error != nil {
			r.spErr = sps.Error
			return
		}
		r.spByID = make(map[string]*mqlMicrosoftServiceprincipal, len(sps.Data))
		for _, raw := range sps.Data {
			if sp, ok := raw.(*mqlMicrosoftServiceprincipal); ok {
				r.spByID[sp.Id.Data] = sp
			}
		}
	})
	if r.spErr != nil {
		return nil, r.spErr
	}
	return r.spByID[id], nil
}

// directory audits

type mqlMicrosoftAuditLogsDirectoryAuditsInternal struct {
	refs *auditLogRefs
}

type mqlMicrosoftAuditLogsDirectoryAuditInternal struct {
	refs                 *auditLogRefs
	initiatorUserID      string
	initiatorServicePrID string
}

// list fetches the directory audit events in the window.
//
// Permissions: AuditLog.Read.All
// see https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0
func (a *mqlMicrosoftAuditLogsDirectoryAudits) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	filter := windowOf(a.Since, a.Filter).odataFilter()
	top := auditLogPageSize
	resp, err := graphClient.AuditLogs().DirectoryAudits().Get(ctx, &auditlogs.DirectoryAuditsRequestBuilderGetRequestConfiguration{
		QueryParameters: &auditlogs.DirectoryAuditsRequestBuilderGetQueryParameters{
			Filter: &filter,
			Top:    &top,
		},
	})
	if err != nil {
		return nil, classifyAuditLogError(err)
	}
	audits, err := iterate[models.DirectoryAuditable](ctx, resp, graphClient.GetAdapter(), models.CreateDirectoryAuditCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyAuditLogError(err)
	}

	if a.refs == nil {
		a.refs = &auditLogRefs{runtime: a.MqlRuntime}
	}
	res := make([]any, 0, len(audits))
	for _, audit := range audits {
		if audit == nil {
			continue
		}
		r, err := newMqlMicrosoftDirectoryAudit(a.MqlRuntime, audit, a.refs)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// directoryAuditArgs maps a directory audit event onto the resource's fields
// and returns the initiator ids backing the reference accessors.
func directoryAuditArgs(audit models.DirectoryAuditable) (args map[string]*llx.RawData, userID string, spID string, err error) {
	var initiatedBy map[string]any
	if ib := audit.GetInitiatedBy(); ib != nil {
		if initiatedBy, err = kiotaToDict(ib); err != nil {
			return nil, "", "", err
		}
		if u := ib.GetUser(); u != nil && u.GetId() != nil {
			userID = *u.GetId()
		}
		if app := ib.GetApp(); app != nil && app.GetServicePrincipalId() != nil {
			spID = *app.GetServicePrincipalId()
		}
	}

	targets := []any{}
	for _, t := range audit.GetTargetResources() {
		d, err := kiotaToDict(t)
		if err != nil {
			return nil, "", "", err
		}
		if d != nil {
			targets = append(targets, d)
		}
	}

	details := map[string]any{}
	for _, kv := range audit.GetAdditionalDetails() {
		if kv == nil || kv.GetKey() == nil {
			continue
		}
		// Keep the first value of a repeated key.
		if _, seen := details[*kv.GetKey()]; seen {
			continue
		}
		if v := kv.GetValue(); v != nil {
			details[*kv.GetKey()] = *v
		} else {
			details[*kv.GetKey()] = ""
		}
	}

	var result *string
	if r := audit.GetResult(); r != nil {
		s := r.String()
		result = &s
	}

	args = map[string]*llx.RawData{
		"__id":                llx.StringDataPtr(audit.GetId()),
		"id":                  llx.StringDataPtr(audit.GetId()),
		"activityDateTime":    graphTimeData(audit.GetActivityDateTime()),
		"activityDisplayName": llx.StringDataPtr(audit.GetActivityDisplayName()),
		"category":            llx.StringDataPtr(audit.GetCategory()),
		"correlationId":       llx.StringDataPtr(audit.GetCorrelationId()),
		"loggedByService":     llx.StringDataPtr(audit.GetLoggedByService()),
		"operationType":       llx.StringDataPtr(audit.GetOperationType()),
		"result":              llx.StringDataPtr(result),
		"resultReason":        llx.StringDataPtr(audit.GetResultReason()),
		"initiatedBy":         dictOrNil(initiatedBy),
		"targetResources":     llx.ArrayData(targets, types.Dict),
		"additionalDetails":   llx.MapData(details, types.String),
	}
	return args, userID, spID, nil
}

func newMqlMicrosoftDirectoryAudit(runtime *plugin.Runtime, audit models.DirectoryAuditable, refs *auditLogRefs) (*mqlMicrosoftAuditLogsDirectoryAudit, error) {
	args, userID, spID, err := directoryAuditArgs(audit)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceMicrosoftAuditLogsDirectoryAudit, args)
	if err != nil {
		return nil, err
	}
	r := res.(*mqlMicrosoftAuditLogsDirectoryAudit)
	r.refs = refs
	r.initiatorUserID = userID
	r.initiatorServicePrID = spID
	return r, nil
}

func (a *mqlMicrosoftAuditLogsDirectoryAudit) initiatedByUser() (*mqlMicrosoftUser, error) {
	var u *mqlMicrosoftUser
	if a.refs != nil {
		var err error
		if u, err = a.refs.user(a.initiatorUserID); err != nil {
			return nil, err
		}
	}
	if u == nil {
		a.InitiatedByUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return u, nil
}

func (a *mqlMicrosoftAuditLogsDirectoryAudit) initiatedByServicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	var sp *mqlMicrosoftServiceprincipal
	if a.refs != nil {
		var err error
		if sp, err = a.refs.servicePrincipal(a.initiatorServicePrID); err != nil {
			return nil, err
		}
	}
	if sp == nil {
		a.InitiatedByServicePrincipal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return sp, nil
}

// provisioning events

type mqlMicrosoftAuditLogsProvisioningEventsInternal struct {
	refs *auditLogRefs
}

type mqlMicrosoftAuditLogsProvisioningEventInternal struct {
	refs               *auditLogRefs
	servicePrincipalID string
}

// list fetches the provisioning events in the window.
//
// Permissions: AuditLog.Read.All
// see https://learn.microsoft.com/en-us/graph/api/provisioningobjectsummary-list?view=graph-rest-1.0
func (a *mqlMicrosoftAuditLogsProvisioningEvents) list() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.Ms365Connection)
	graphClient, err := conn.GraphClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	filter := windowOf(a.Since, a.Filter).odataFilter()
	top := auditLogPageSize
	resp, err := graphClient.AuditLogs().Provisioning().Get(ctx, &auditlogs.ProvisioningRequestBuilderGetRequestConfiguration{
		QueryParameters: &auditlogs.ProvisioningRequestBuilderGetQueryParameters{
			Filter: &filter,
			Top:    &top,
		},
	})
	if err != nil {
		return nil, classifyAuditLogError(err)
	}
	events, err := iterate[models.ProvisioningObjectSummaryable](ctx, resp, graphClient.GetAdapter(), models.CreateProvisioningObjectSummaryCollectionResponseFromDiscriminatorValue)
	if err != nil {
		return nil, classifyAuditLogError(err)
	}

	if a.refs == nil {
		a.refs = &auditLogRefs{runtime: a.MqlRuntime}
	}
	res := make([]any, 0, len(events))
	for _, ev := range events {
		if ev == nil {
			continue
		}
		r, err := newMqlMicrosoftProvisioningEvent(a.MqlRuntime, ev, a.refs)
		if err != nil {
			return nil, err
		}
		res = append(res, r)
	}
	return res, nil
}

// provisioningEventArgs maps a provisioning event onto the resource's fields
// and returns the service principal id backing the reference accessor.
func provisioningEventArgs(ev models.ProvisioningObjectSummaryable) (map[string]*llx.RawData, string, error) {
	var status *string
	var errorInfo map[string]any
	if info := ev.GetProvisioningStatusInfo(); info != nil {
		if s := info.GetStatus(); s != nil {
			v := s.String()
			status = &v
		}
		var err error
		if errorInfo, err = kiotaToDict(info.GetErrorInformation()); err != nil {
			return nil, "", err
		}
	}

	var action *string
	if a := ev.GetProvisioningAction(); a != nil {
		v := a.String()
		action = &v
	}

	var spID string
	if sp := ev.GetServicePrincipal(); sp != nil && sp.GetId() != nil {
		spID = *sp.GetId()
	}

	sourceSystem, err := kiotaToDict(ev.GetSourceSystem())
	if err != nil {
		return nil, "", err
	}
	targetSystem, err := kiotaToDict(ev.GetTargetSystem())
	if err != nil {
		return nil, "", err
	}
	sourceIdentity, err := kiotaToDict(ev.GetSourceIdentity())
	if err != nil {
		return nil, "", err
	}
	targetIdentity, err := kiotaToDict(ev.GetTargetIdentity())
	if err != nil {
		return nil, "", err
	}

	args := map[string]*llx.RawData{
		"__id":                   llx.StringDataPtr(ev.GetId()),
		"id":                     llx.StringDataPtr(ev.GetId()),
		"activityDateTime":       graphTimeData(ev.GetActivityDateTime()),
		"changeId":               llx.StringDataPtr(ev.GetChangeId()),
		"cycleId":                llx.StringDataPtr(ev.GetCycleId()),
		"jobId":                  llx.StringDataPtr(ev.GetJobId()),
		"durationInMilliseconds": llx.IntDataPtr(ev.GetDurationInMilliseconds()),
		"provisioningAction":     llx.StringDataPtr(action),
		"status":                 llx.StringDataPtr(status),
		"errorInformation":       dictOrNil(errorInfo),
		"sourceSystem":           dictOrNil(sourceSystem),
		"targetSystem":           dictOrNil(targetSystem),
		"sourceIdentity":         dictOrNil(sourceIdentity),
		"targetIdentity":         dictOrNil(targetIdentity),
	}
	return args, spID, nil
}

func newMqlMicrosoftProvisioningEvent(runtime *plugin.Runtime, ev models.ProvisioningObjectSummaryable, refs *auditLogRefs) (*mqlMicrosoftAuditLogsProvisioningEvent, error) {
	args, spID, err := provisioningEventArgs(ev)
	if err != nil {
		return nil, err
	}
	res, err := CreateResource(runtime, ResourceMicrosoftAuditLogsProvisioningEvent, args)
	if err != nil {
		return nil, err
	}
	r := res.(*mqlMicrosoftAuditLogsProvisioningEvent)
	r.refs = refs
	r.servicePrincipalID = spID
	return r, nil
}

func (a *mqlMicrosoftAuditLogsProvisioningEvent) servicePrincipal() (*mqlMicrosoftServiceprincipal, error) {
	var sp *mqlMicrosoftServiceprincipal
	if a.refs != nil {
		var err error
		if sp, err = a.refs.servicePrincipal(a.servicePrincipalID); err != nil {
			return nil, err
		}
	}
	if sp == nil {
		a.ServicePrincipal.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return sp, nil
}

// dictOrNil returns a dict value, or a null for an absent object.
func dictOrNil(d map[string]any) *llx.RawData {
	if d == nil {
		return llx.NilData
	}
	return llx.DictData(d)
}
