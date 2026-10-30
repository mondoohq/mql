// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"net/http"
	"strconv"
	"sync"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV1"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/datadog/connection"
)

// isNotFound reports a 404, which the restriction policy endpoint returns for a
// resource that simply has no policy attached rather than for a bad request.
func isNotFound(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusNotFound
}

// --- Restriction policies ---

// Datadog addresses a restricted resource as type:identifier. The prefixes are
// fixed by the API and differ from our resource names, so they are spelled out
// here rather than derived.
const (
	restrictionTypeDashboard    = "dashboard"
	restrictionTypeMonitor      = "monitor"
	restrictionTypeSlo          = "slo"
	restrictionTypeSecurityRule = "security-rule"
)

// restrictionPolicyFor fetches the access control list attached to one
// resource. A resource with no policy is the common case and reports null
// rather than an error, so a query over every dashboard does not fail on the
// unrestricted ones.
func restrictionPolicyFor(runtime *plugin.Runtime, resourceType, resourceId string, field *plugin.TValue[*mqlDatadogRestrictionPolicy]) (*mqlDatadogRestrictionPolicy, error) {
	if resourceId == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn := runtime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewRestrictionPoliciesApi(conn.ApiClient())

	target := resourceType + ":" + resourceId
	resp, httpResp, err := api.GetRestrictionPolicy(conn.AuthCtx(), target)
	if err != nil {
		if isNotFound(httpResp) {
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		if isForbidden(httpResp) {
			log.Warn().Str("resource", target).Msg("datadog> restriction policies not available (403 Forbidden)")
			field.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	data := resp.GetData()
	attrs := data.GetAttributes()

	bindings := []any{}
	for _, binding := range attrs.GetBindings() {
		bindings = append(bindings, map[string]any{
			"relation":   binding.GetRelation(),
			"principals": toAnyStrings(binding.GetPrincipals()),
		})
	}

	res, err := CreateResource(runtime, "datadog.restrictionPolicy", map[string]*llx.RawData{
		"id":       llx.StringData(data.GetId()),
		"bindings": llx.ArrayData(bindings, "\x13"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatadogRestrictionPolicy), nil
}

func (r *mqlDatadogRestrictionPolicy) id() (string, error) {
	return "datadog.restrictionPolicy/" + r.Id.Data, nil
}

func (r *mqlDatadogDashboard) restrictionPolicy() (*mqlDatadogRestrictionPolicy, error) {
	return restrictionPolicyFor(r.MqlRuntime, restrictionTypeDashboard, r.Id.Data, &r.RestrictionPolicy)
}

func (r *mqlDatadogMonitor) restrictionPolicy() (*mqlDatadogRestrictionPolicy, error) {
	return restrictionPolicyFor(r.MqlRuntime, restrictionTypeMonitor, strconv.FormatInt(r.Id.Data, 10), &r.RestrictionPolicy)
}

func (r *mqlDatadogSlo) restrictionPolicy() (*mqlDatadogRestrictionPolicy, error) {
	return restrictionPolicyFor(r.MqlRuntime, restrictionTypeSlo, r.Id.Data, &r.RestrictionPolicy)
}

func (r *mqlDatadogSecurityRule) restrictionPolicy() (*mqlDatadogRestrictionPolicy, error) {
	return restrictionPolicyFor(r.MqlRuntime, restrictionTypeSecurityRule, r.Id.Data, &r.RestrictionPolicy)
}

// --- Shared dashboards ---

func (r *mqlDatadogDashboard) sharedDashboards() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewDashboardSharingApi(conn.ApiClient())

	resp, httpResp, err := api.ListSharedDashboardsByDashboardId(conn.AuthCtx(), r.Id.Data)
	if err != nil {
		if isNotFound(httpResp) {
			return []any{}, nil
		}
		if isForbidden(httpResp) {
			log.Warn().Str("dashboard", r.Id.Data).Msg("datadog> dashboard shares not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	all := []any{}
	for _, share := range resp.GetData() {
		attrs := share.GetAttributes()
		rels := share.GetRelationships()

		invitees := []any{}
		for _, invitee := range attrs.GetInvitees() {
			invitees = append(invitees, invitee.GetEmail())
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.sharedDashboard", map[string]*llx.RawData{
			"token":             llx.StringData(attrs.GetToken()),
			"title":             llx.StringData(attrs.GetTitle()),
			"publicUrl":         llx.StringData(attrs.GetUrl()),
			"shareType":         llx.StringData(string(attrs.GetShareType())),
			"status":            llx.StringData(string(attrs.GetStatus())),
			"embeddableDomains": llx.ArrayData(toAnyStrings(attrs.GetEmbeddableDomains()), "\x02"),
			"invitees":          llx.ArrayData(invitees, "\x02"),
			"expiration":        llx.TimeDataPtr(timePtr(attrs.GetExpiration())),
			"lastAccessed":      llx.TimeDataPtr(timePtr(attrs.GetLastAccessed())),
			"createdAt":         llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
			"sharerDisabled":    llx.BoolData(attrs.GetSharerDisabled()),
		})
		if err != nil {
			return nil, err
		}

		mqlShare := res.(*mqlDatadogSharedDashboard)
		mqlShare.cacheSharerId = rels.Sharer.Data.GetId()
		mqlShare.cacheDashboardId = rels.Dashboard.Data.GetId()
		all = append(all, mqlShare)
	}
	return all, nil
}

type mqlDatadogSharedDashboardInternal struct {
	cacheSharerId    string
	cacheDashboardId string
}

func (r *mqlDatadogSharedDashboard) id() (string, error) {
	return "datadog.sharedDashboard/" + r.Token.Data, nil
}

func (r *mqlDatadogSharedDashboard) sharer() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheSharerId, &r.Sharer)
}

func (r *mqlDatadogSharedDashboard) dashboard() (*mqlDatadogDashboard, error) {
	if r.cacheDashboardId == "" {
		r.Dashboard.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(r.MqlRuntime, "datadog.dashboard", map[string]*llx.RawData{
		"id": llx.StringData(r.cacheDashboardId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatadogDashboard), nil
}

// --- Identity provider attribute mappings ---

func (r *mqlDatadog) authnMappings() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewAuthNMappingsApi(conn.ApiClient())

	var all []any
	pageSize := int64(100)
	page := int64(0)

	for {
		resp, httpResp, err := api.ListAuthNMappings(conn.AuthCtx(),
			*datadogV2.NewListAuthNMappingsOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Msg("datadog> identity provider mappings not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, mapping := range data {
			attrs := mapping.GetAttributes()
			res, err := CreateResource(r.MqlRuntime, "datadog.authnMapping", map[string]*llx.RawData{
				"id":             llx.StringData(mapping.GetId()),
				"attributeKey":   llx.StringData(attrs.GetAttributeKey()),
				"attributeValue": llx.StringData(attrs.GetAttributeValue()),
				"createdAt":      llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
				"modifiedAt":     llx.TimeDataPtr(timePtr(attrs.GetModifiedAt())),
			})
			if err != nil {
				return nil, err
			}

			// The list response carries the role and team relationships, so
			// seed them here rather than making the accessors re-fetch each
			// mapping one at a time.
			mqlMapping := res.(*mqlDatadogAuthnMapping)
			if rels, ok := mapping.GetRelationshipsOk(); ok && rels != nil {
				mqlMapping.cacheRoleId, mqlMapping.cacheTeamId = authnMappingGrants(mapping)
				mqlMapping.grantsSeeded = true
			}
			all = append(all, mqlMapping)
		}

		if int64(len(data)) < pageSize {
			break
		}
		page++
	}
	return all, nil
}

type mqlDatadogAuthnMappingInternal struct {
	grantsOnce   sync.Once
	grantsSeeded bool
	cacheRoleId  string
	cacheTeamId  string
	grantsErr    error
}

func (r *mqlDatadogAuthnMapping) id() (string, error) {
	return "datadog.authnMapping/" + r.Id.Data, nil
}

func (r *mqlDatadogAuthnMapping) role() (*mqlDatadogRole, error) {
	roleId, _, err := r.grants()
	if err != nil {
		return nil, err
	}
	if roleId == "" {
		r.Role.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(r.MqlRuntime, "datadog.role", map[string]*llx.RawData{
		"id": llx.StringData(roleId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatadogRole), nil
}

func (r *mqlDatadogAuthnMapping) team() (*mqlDatadogTeam, error) {
	_, teamId, err := r.grants()
	if err != nil {
		return nil, err
	}
	if teamId == "" {
		r.Team.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(r.MqlRuntime, "datadog.team", map[string]*llx.RawData{
		"id": llx.StringData(teamId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlDatadogTeam), nil
}

// grants returns the role and team a mapping grants. A mapping grants one or
// the other, so at most one of the two is set.
//
// The list response carries the relationships, so the lister seeds them and no
// request is made here. The per-mapping fetch is a fallback for a response that
// omitted the relationships block, and runs at most once no matter how many of
// the accessors read it.
func (r *mqlDatadogAuthnMapping) grants() (string, string, error) {
	r.grantsOnce.Do(func() {
		if r.grantsSeeded {
			return
		}

		conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
		api := datadogV2.NewAuthNMappingsApi(conn.ApiClient())

		resp, httpResp, err := api.GetAuthNMapping(conn.AuthCtx(), r.Id.Data)
		if err != nil {
			if isNotFound(httpResp) || isForbidden(httpResp) {
				log.Debug().Str("authnMapping", r.Id.Data).
					Msg("datadog> cannot read the mapping, its role and team report null")
				return
			}
			r.grantsErr = err
			return
		}
		r.cacheRoleId, r.cacheTeamId = authnMappingGrants(resp.GetData())
	})
	return r.cacheRoleId, r.cacheTeamId, r.grantsErr
}

// authnMappingGrants extracts the role and team IDs from a mapping's
// relationships, tolerating either being absent.
func authnMappingGrants(mapping datadogV2.AuthNMapping) (string, string) {
	rels, ok := mapping.GetRelationshipsOk()
	if !ok || rels == nil {
		return "", ""
	}

	roleId := ""
	if role, ok := rels.GetRoleOk(); ok && role != nil {
		if data, ok := role.GetDataOk(); ok && data != nil {
			roleId = data.GetId()
		}
	}

	teamId := ""
	if team, ok := rels.GetTeamOk(); ok && team != nil {
		if data, ok := team.GetDataOk(); ok && data != nil {
			teamId = data.GetId()
		}
	}
	return roleId, teamId
}

// --- Log processing pipelines ---

func (r *mqlDatadog) logsPipelines() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV1.NewLogsPipelinesApi(conn.ApiClient())

	pipelines, httpResp, err := api.ListLogsPipelines(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> log pipelines not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, pipeline := range pipelines {
		filterQuery := ""
		if filter, ok := pipeline.GetFilterOk(); ok && filter != nil {
			filterQuery = filter.GetQuery()
		}

		res, err := CreateResource(r.MqlRuntime, "datadog.logsPipeline", map[string]*llx.RawData{
			"id":          llx.StringData(pipeline.GetId()),
			"name":        llx.StringData(pipeline.GetName()),
			"type":        llx.StringData(pipeline.GetType()),
			"isEnabled":   llx.BoolData(pipeline.GetIsEnabled()),
			"isReadOnly":  llx.BoolData(pipeline.GetIsReadOnly()),
			"filterQuery": llx.StringData(filterQuery),
			"tags":        llx.ArrayData(toAnyStrings(pipeline.GetTags()), "\x02"),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogLogsPipeline) id() (string, error) {
	return "datadog.logsPipeline/" + r.Id.Data, nil
}

// --- Log forwarding destinations ---

func (r *mqlDatadog) logsCustomDestinations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewLogsCustomDestinationsApi(conn.ApiClient())

	resp, httpResp, err := api.ListLogsCustomDestinations(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> log forwarding destinations not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, dest := range resp.GetData() {
		attrs := dest.GetAttributes()
		forwarder := destinationForwarder(attrs)

		res, err := CreateResource(r.MqlRuntime, "datadog.logsCustomDestination", map[string]*llx.RawData{
			"id":                             llx.StringData(dest.GetId()),
			"name":                           llx.StringData(attrs.GetName()),
			"enabled":                        llx.BoolData(attrs.GetEnabled()),
			"query":                          llx.StringData(attrs.GetQuery()),
			"destinationType":                llx.StringData(forwarder.destinationType),
			"endpoint":                       llx.StringData(forwarder.endpoint),
			"authType":                       llx.StringData(forwarder.authType),
			"indexName":                      llx.StringData(forwarder.indexName),
			"forwardTags":                    llx.BoolData(attrs.GetForwardTags()),
			"forwardTagsRestrictionList":     llx.ArrayData(toAnyStrings(attrs.GetForwardTagsRestrictionList()), "\x02"),
			"forwardTagsRestrictionListType": llx.StringData(string(attrs.GetForwardTagsRestrictionListType())),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}
	return all, nil
}

func (r *mqlDatadogLogsCustomDestination) id() (string, error) {
	return "datadog.logsCustomDestination/" + r.Id.Data, nil
}

// forwarderDetails holds the fields that identify where a destination sends
// logs, flattened out of the union the API returns.
type forwarderDetails struct {
	destinationType string
	endpoint        string
	authType        string
	indexName       string
}

// destinationForwarder flattens the forwarder union into the fields common
// enough to audit across destination types. An unrecognized variant yields an
// empty destinationType rather than a partially filled record, so a new
// variant added by Datadog reads as unknown rather than as an HTTP endpoint.
func destinationForwarder(attrs datadogV2.CustomDestinationResponseAttributes) forwarderDetails {
	forwarder, ok := attrs.GetForwarderDestinationOk()
	if !ok || forwarder == nil {
		return forwarderDetails{}
	}

	switch {
	case forwarder.CustomDestinationResponseForwardDestinationHttp != nil:
		httpDest := forwarder.CustomDestinationResponseForwardDestinationHttp
		details := forwarderDetails{
			destinationType: string(httpDest.Type),
			endpoint:        httpDest.Endpoint,
		}
		switch {
		case httpDest.Auth.CustomDestinationResponseHttpDestinationAuthBasic != nil:
			details.authType = string(httpDest.Auth.CustomDestinationResponseHttpDestinationAuthBasic.Type)
		case httpDest.Auth.CustomDestinationResponseHttpDestinationAuthCustomHeader != nil:
			details.authType = string(httpDest.Auth.CustomDestinationResponseHttpDestinationAuthCustomHeader.Type)
		}
		return details

	case forwarder.CustomDestinationResponseForwardDestinationSplunk != nil:
		splunk := forwarder.CustomDestinationResponseForwardDestinationSplunk
		return forwarderDetails{
			destinationType: string(splunk.Type),
			endpoint:        splunk.Endpoint,
		}

	case forwarder.CustomDestinationResponseForwardDestinationElasticsearch != nil:
		elastic := forwarder.CustomDestinationResponseForwardDestinationElasticsearch
		return forwarderDetails{
			destinationType: string(elastic.Type),
			endpoint:        elastic.Endpoint,
			indexName:       elastic.IndexName,
		}

	case forwarder.CustomDestinationResponseForwardDestinationMicrosoftSentinel != nil:
		sentinel := forwarder.CustomDestinationResponseForwardDestinationMicrosoftSentinel
		return forwarderDetails{
			destinationType: string(sentinel.Type),
			endpoint:        sentinel.DataCollectionEndpoint,
		}
	}
	return forwarderDetails{}
}

// --- Log restriction queries ---

func (r *mqlDatadog) logsRestrictionQueries() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewLogsRestrictionQueriesApi(conn.ApiClient())

	var all []any
	pageSize := int64(100)
	page := int64(0)

	for {
		resp, httpResp, err := api.ListRestrictionQueries(conn.AuthCtx(),
			*datadogV2.NewListRestrictionQueriesOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Msg("datadog> log restriction queries not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, query := range data {
			attrs := query.GetAttributes()
			res, err := CreateResource(r.MqlRuntime, "datadog.logsRestrictionQuery", map[string]*llx.RawData{
				"id":                llx.StringData(query.GetId()),
				"restrictionQuery":  llx.StringData(attrs.GetRestrictionQuery()),
				"roleCount":         llx.IntData(attrs.GetRoleCount()),
				"userCount":         llx.IntData(attrs.GetUserCount()),
				"lastModifierEmail": llx.StringData(attrs.GetLastModifierEmail()),
				"lastModifierName":  llx.StringData(attrs.GetLastModifierName()),
				"createdAt":         llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
				"modifiedAt":        llx.TimeDataPtr(timePtr(attrs.GetModifiedAt())),
			})
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}

		if int64(len(data)) < pageSize {
			break
		}
		page++
	}
	return all, nil
}

func (r *mqlDatadogLogsRestrictionQuery) id() (string, error) {
	return "datadog.logsRestrictionQuery/" + r.Id.Data, nil
}

func (r *mqlDatadogLogsRestrictionQuery) roles() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewLogsRestrictionQueriesApi(conn.ApiClient())

	all := []any{}
	pageSize := int64(100)
	page := int64(0)

	for {
		resp, httpResp, err := api.ListRestrictionQueryRoles(conn.AuthCtx(), r.Id.Data,
			*datadogV2.NewListRestrictionQueryRolesOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Str("restrictionQuery", r.Id.Data).
					Msg("datadog> restriction query roles not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, role := range data {
			res, err := NewResource(r.MqlRuntime, "datadog.role", map[string]*llx.RawData{
				"id": llx.StringData(role.GetId()),
			})
			if err != nil {
				return nil, err
			}
			all = append(all, res)
		}

		if int64(len(data)) < pageSize {
			break
		}
		page++
	}
	return all, nil
}
