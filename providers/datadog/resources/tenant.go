// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"time"

	"github.com/DataDog/datadog-api-client-go/v2/api/datadog"
	"github.com/DataDog/datadog-api-client-go/v2/api/datadogV2"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/datadog/connection"
)

// nullableTimePtr unwraps a nullable timestamp. Datadog sends these fields
// explicitly as null rather than omitting them, so an unset value has to be
// distinguished from a zero time to keep "never used" from reading as the
// Unix epoch.
func nullableTimePtr(t datadog.NullableTime) *time.Time {
	if !t.IsSet() {
		return nil
	}
	v := t.Get()
	if v == nil || v.IsZero() {
		return nil
	}
	return v
}

// --- OAuth clients ---

type mqlDatadogOauthClientAuthorizationInternal struct {
	cacheUserId string
}

func (r *mqlDatadog) oauthClients() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewOrgAuthorizedClientsApi(conn.ApiClient())

	var all []any
	pageSize := int64(100)
	page := int64(0)

	for {
		resp, httpResp, err := api.ListOrgAuthorizedClients(conn.AuthCtx(),
			*datadogV2.NewListOrgAuthorizedClientsOptionalParameters().WithPageSize(pageSize).WithPageNumber(page))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Msg("datadog> authorized OAuth clients not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, c := range data {
			attrs := c.GetAttributes()
			rels := c.GetRelationships()
			oauth2Client := rels.Oauth2Client.GetData()
			res, err := CreateResource(r.MqlRuntime, "datadog.oauthClient", map[string]*llx.RawData{
				"id":       llx.StringData(c.GetId()),
				"clientId": llx.StringData(oauth2Client.GetId()),
				"disabled": llx.BoolData(attrs.GetDisabled()),
				// UserCount is an int64 in the SDK and counts the members who
				// authorized the client, so it stays a plain integer.
				"userCount":     llx.IntData(attrs.GetUserCount()),
				"lastExercised": llx.TimeDataPtr(nullableTimePtr(attrs.LastExercised)),
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

func (r *mqlDatadogOauthClient) id() (string, error) {
	return "datadog.oauthClient/" + r.Id.Data, nil
}

// authorizations lists the per-member grants made to this client. It is
// deliberately fetched per client rather than pre-loaded for every client at
// once, so querying one application does not pay for the whole org's grants.
func (r *mqlDatadogOauthClient) authorizations() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewOrgAuthorizedClientsApi(conn.ApiClient())

	var all []any
	pageSize := int64(100)
	page := int64(0)

	for {
		resp, httpResp, err := api.ListOrgAuthorizedClientUserAuthorizations(conn.AuthCtx(), r.Id.Data,
			*datadogV2.NewListOrgAuthorizedClientUserAuthorizationsOptionalParameters().
				WithPageSize(pageSize).WithPageNumber(page))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Str("client", r.Id.Data).Msg("datadog> OAuth client authorizations not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, a := range data {
			attrs := a.GetAttributes()
			rels := a.GetRelationships()

			scopes := make([]any, 0, len(rels.Scopes.GetData()))
			for _, s := range rels.Scopes.GetData() {
				scopes = append(scopes, s.GetId())
			}

			res, err := CreateResource(r.MqlRuntime, "datadog.oauthClient.authorization", map[string]*llx.RawData{
				"id":            llx.StringData(a.GetId()),
				"scopes":        llx.ArrayData(scopes, "\x02"),
				"disabled":      llx.BoolData(attrs.GetDisabled()),
				"orgDisabled":   llx.BoolData(attrs.GetOrgDisabled()),
				"createdAt":     llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
				"modifiedAt":    llx.TimeDataPtr(timePtr(attrs.GetModifiedAt())),
				"lastExercised": llx.TimeDataPtr(nullableTimePtr(attrs.LastExercised)),
			})
			if err != nil {
				return nil, err
			}
			grantee := rels.User.GetData()
			res.(*mqlDatadogOauthClientAuthorization).cacheUserId = grantee.GetId()
			all = append(all, res)
		}

		if int64(len(data)) < pageSize {
			break
		}
		page++
	}

	return all, nil
}

func (r *mqlDatadogOauthClientAuthorization) id() (string, error) {
	return "datadog.oauthClient.authorization/" + r.Id.Data, nil
}

func (r *mqlDatadogOauthClientAuthorization) user() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheUserId, &r.User)
}

// --- Identity providers ---

func (r *mqlDatadog) identityProviders() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewIdentityProvidersApi(conn.ApiClient())

	resp, httpResp, err := api.ListIdentityProviders(conn.AuthCtx())
	if err != nil {
		if isForbidden(httpResp) {
			log.Warn().Msg("datadog> identity providers not available (403 Forbidden)")
			return nil, nil
		}
		return nil, err
	}

	var all []any
	for _, p := range resp.GetData() {
		attrs := p.GetAttributes()
		res, err := CreateResource(r.MqlRuntime, "datadog.identityProvider", map[string]*llx.RawData{
			"id":                   llx.StringData(p.GetId()),
			"authenticationMethod": llx.StringData(attrs.GetAuthenticationMethod()),
			"enabled":              llx.BoolData(attrs.GetEnabled()),
		})
		if err != nil {
			return nil, err
		}
		all = append(all, res)
	}

	return all, nil
}

func (r *mqlDatadogIdentityProvider) id() (string, error) {
	return "datadog.identityProvider/" + r.Id.Data, nil
}

// --- Organization connections ---

type mqlDatadogOrgConnectionInternal struct {
	cacheCreatedById string
}

func (r *mqlDatadog) orgConnections() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.DatadogConnection)
	api := datadogV2.NewOrgConnectionsApi(conn.ApiClient())

	var all []any
	limit := int64(100)
	offset := int64(0)

	for {
		resp, httpResp, err := api.ListOrgConnections(conn.AuthCtx(),
			*datadogV2.NewListOrgConnectionsOptionalParameters().WithLimit(limit).WithOffset(offset))
		if err != nil {
			if isForbidden(httpResp) {
				log.Warn().Msg("datadog> organization connections not available (403 Forbidden)")
				return nil, nil
			}
			return nil, err
		}

		data := resp.GetData()
		for _, c := range data {
			attrs := c.GetAttributes()
			rels := c.GetRelationships()

			connectionTypes := make([]any, 0, len(attrs.GetConnectionTypes()))
			for _, t := range attrs.GetConnectionTypes() {
				connectionTypes = append(connectionTypes, string(t))
			}

			sourceOrgRel := rels.GetSourceOrg()
			sinkOrgRel := rels.GetSinkOrg()
			sourceOrg := sourceOrgRel.GetData()
			sinkOrg := sinkOrgRel.GetData()

			res, err := CreateResource(r.MqlRuntime, "datadog.orgConnection", map[string]*llx.RawData{
				"id":              llx.StringData(c.GetId().String()),
				"connectionTypes": llx.ArrayData(connectionTypes, "\x02"),
				"createdAt":       llx.TimeDataPtr(timePtr(attrs.GetCreatedAt())),
				"sourceOrgId":     llx.StringData(sourceOrg.GetId()),
				"sourceOrgName":   llx.StringData(sourceOrg.GetName()),
				"sinkOrgId":       llx.StringData(sinkOrg.GetId()),
				"sinkOrgName":     llx.StringData(sinkOrg.GetName()),
			})
			if err != nil {
				return nil, err
			}
			createdByRel := rels.GetCreatedBy()
			creator := createdByRel.GetData()
			res.(*mqlDatadogOrgConnection).cacheCreatedById = creator.GetId()
			all = append(all, res)
		}

		if int64(len(data)) < limit {
			break
		}
		offset += limit
	}

	return all, nil
}

func (r *mqlDatadogOrgConnection) id() (string, error) {
	return "datadog.orgConnection/" + r.Id.Data, nil
}

func (r *mqlDatadogOrgConnection) createdBy() (*mqlDatadogUser, error) {
	return resolveUserRef(r.MqlRuntime, r.cacheCreatedById, &r.CreatedBy)
}
