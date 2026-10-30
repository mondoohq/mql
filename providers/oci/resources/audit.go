// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/audit"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// ociAuditEventWindow is how far back oci.audit.events looks.
//
// The Audit API requires an explicit start and end time, so some window has to
// be chosen. 24 hours is the detection-relevant one, and it keeps a single
// query bounded: an unbounded range would pull the tenancy's entire retention
// period - up to 365 days of every control-plane call - on every evaluation.
const ociAuditEventWindow = 24 * time.Hour

func (o *mqlOciAudit) id() (string, error) {
	return "oci.audit", nil
}

func (o *mqlOciAudit) retentionPeriodDays() (int64, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Audit configuration is tenancy-level; use home region
	tenancy, err := conn.Tenant(context.Background())
	if err != nil {
		return 0, err
	}

	region := ""
	if tenancy.HomeRegionKey != nil {
		region = *tenancy.HomeRegionKey
	}

	client, err := conn.AuditClient(region)
	if err != nil {
		return 0, err
	}

	resp, err := client.GetConfiguration(context.Background(), audit.GetConfigurationRequest{
		CompartmentId: new(conn.TenantID()),
	})
	if err != nil {
		return 0, err
	}

	if resp.RetentionPeriodDays == nil {
		return 0, nil
	}
	return int64(*resp.RetentionPeriodDays), nil
}

func (o *mqlOciAudit) events() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Audit events are recorded per region and per compartment, and the API
	// offers no subtree flag, so both dimensions have to be walked.
	// Truncated to the minute because the Audit API requires it: both bounds
	// are documented as accepting minute granularity only, with seconds and
	// milliseconds set to zero. The SDK serializes an SDKTime with RFC3339Nano,
	// so an untruncated time.Now() puts seconds and nanoseconds on the wire.
	endTime := time.Now().UTC().Truncate(time.Minute)
	startTime := endTime.Add(-ociAuditEventWindow)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.AuditClient(region)
			if err != nil {
				return nil, err
			}

			events, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]audit.AuditEvent, *string, error) {
				response, err := client.ListEvents(ctx, audit.ListEventsRequest{
					CompartmentId: new(compartmentID),
					StartTime:     &common.SDKTime{Time: startTime},
					EndTime:       &common.SDKTime{Time: endTime},
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			return o.newAuditEvents(events)
		})
}

func (o *mqlOciAudit) newAuditEvents(events []audit.AuditEvent) ([]any, error) {
	res := make([]any, 0, len(events))
	for i := range events {
		event := events[i]

		// Data carries everything worth auditing. An event without it is a
		// malformed record rather than a meaningful one, so skip it instead of
		// emitting a resource whose every field is null.
		if event.Data == nil {
			continue
		}
		data := event.Data

		var (
			principalName, principalId, authType   string
			callerName, callerId                   string
			ipAddress, userAgent, consoleSessionId string
			requestAction, requestPath, requestId  string
			responseStatus, responseMessage        string
			responseTime                           *time.Time
			requestParameters                      map[string]any
			stateChange, additionalDetails         map[string]any
			err                                    error
		)

		if data.Identity != nil {
			principalName = stringValue(data.Identity.PrincipalName)
			principalId = stringValue(data.Identity.PrincipalId)
			authType = stringValue(data.Identity.AuthType)
			callerName = stringValue(data.Identity.CallerName)
			callerId = stringValue(data.Identity.CallerId)
			ipAddress = stringValue(data.Identity.IpAddress)
			userAgent = stringValue(data.Identity.UserAgent)
			consoleSessionId = stringValue(data.Identity.ConsoleSessionId)
		}

		if data.Request != nil {
			requestAction = stringValue(data.Request.Action)
			requestPath = stringValue(data.Request.Path)
			requestId = stringValue(data.Request.Id)
			requestParameters = make(map[string]any, len(data.Request.Parameters))
			for k, v := range data.Request.Parameters {
				requestParameters[k] = stringsToAny(v)
			}
		}

		if data.Response != nil {
			responseStatus = stringValue(data.Response.Status)
			responseMessage = stringValue(data.Response.Message)
			if data.Response.ResponseTime != nil {
				responseTime = &data.Response.ResponseTime.Time
			}
		}

		if data.StateChange != nil {
			stateChange, err = convert.JsonToDict(data.StateChange)
			if err != nil {
				return nil, err
			}
		}

		if data.AdditionalDetails != nil {
			additionalDetails, err = convert.JsonToDict(data.AdditionalDetails)
			if err != nil {
				return nil, err
			}
		}

		mqlEvent, err := CreateResource(o.MqlRuntime, "oci.audit.event", map[string]*llx.RawData{
			"id":                 llx.StringDataPtr(event.EventId),
			"eventName":          llx.StringDataPtr(data.EventName),
			"eventType":          llx.StringDataPtr(event.EventType),
			"eventTime":          sdkTimeData(event.EventTime),
			"source":             llx.StringDataPtr(event.Source),
			"eventGroupingId":    llx.StringDataPtr(data.EventGroupingId),
			"compartmentName":    llx.StringDataPtr(data.CompartmentName),
			"resourceName":       llx.StringDataPtr(data.ResourceName),
			"resourceId":         llx.StringDataPtr(data.ResourceId),
			"availabilityDomain": llx.StringDataPtr(data.AvailabilityDomain),
			"principalName":      llx.StringData(principalName),
			"principalId":        llx.StringData(principalId),
			"authType":           llx.StringData(authType),
			"callerName":         llx.StringData(callerName),
			"callerId":           llx.StringData(callerId),
			"ipAddress":          llx.StringData(ipAddress),
			"userAgent":          llx.StringData(userAgent),
			"consoleSessionId":   llx.StringData(consoleSessionId),
			"requestAction":      llx.StringData(requestAction),
			"requestPath":        llx.StringData(requestPath),
			"requestId":          llx.StringData(requestId),
			"requestParameters":  llx.MapData(requestParameters, types.Array(types.String)),
			"responseStatus":     llx.StringData(responseStatus),
			"responseMessage":    llx.StringData(responseMessage),
			"responseTime":       llx.TimeDataPtr(responseTime),
			"stateChange":        llx.DictData(stateChange),
			"additionalDetails":  llx.DictData(additionalDetails),
		})
		if err != nil {
			return nil, err
		}
		mqlEventTyped := mqlEvent.(*mqlOciAuditEvent)
		mqlEventTyped.cacheCompartmentID = stringValue(data.CompartmentId)
		res = append(res, mqlEventTyped)
	}

	return res, nil
}

type mqlOciAuditEventInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciAuditEvent) id() (string, error) {
	return "oci.audit.event/" + o.Id.Data, nil
}

func (o *mqlOciAuditEvent) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciAuditEvent) principal() (*mqlOciIdentityUser, error) {
	return resolveOciAuditUser(o.MqlRuntime, o.PrincipalId.Data, &o.Principal)
}

func (o *mqlOciAuditEvent) caller() (*mqlOciIdentityUser, error) {
	return resolveOciAuditUser(o.MqlRuntime, o.CallerId.Data, &o.Caller)
}

// resolveOciAuditUser resolves an audit event's principal OCID to an IAM user.
//
// Audit records the acting principal whatever it was, so the OCID here is
// routinely not a user at all - an instance principal, a service principal, or
// a user deleted since the call. None of those are errors, and none should
// take the surrounding query down, so anything that is not a live user OCID
// reports null. The raw OCID stays available on principalId and callerId.
func resolveOciAuditUser(runtime *plugin.Runtime, id string, field *plugin.TValue[*mqlOciIdentityUser]) (*mqlOciIdentityUser, error) {
	if !strings.HasPrefix(id, "ocid1.user.") {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, "oci.identity.user", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		log.Debug().Err(err).Str("user", id).Msg("skipping unresolvable oci audit principal")
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res.(*mqlOciIdentityUser), nil
}
