// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/auth0/go-auth0/management"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/auth0/connection"
	"go.mondoo.com/mql/types"
)

// organizations lists every B2B organization defined in the tenant.
func (a *mqlAuth0) organizations() ([]any, error) {
	conn := a.conn()
	client := conn.Client()

	var all []any
	page := 0
	for {
		list, err := client.Organization.List(context.Background(),
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, o := range list.Organizations {
			r, err := newMqlAuth0Organization(a.MqlRuntime, o)
			if err != nil {
				return nil, err
			}
			all = append(all, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return all, nil
}

// newMqlAuth0Organization maps a single SDK organization to its MQL resource.
func newMqlAuth0Organization(runtime *plugin.Runtime, o *management.Organization) (plugin.Resource, error) {
	var logoURL *string
	if o.Branding != nil {
		logoURL = o.Branding.LogoURL
	}

	metadata := map[string]any{}
	if o.Metadata != nil {
		for k, v := range *o.Metadata {
			metadata[k] = v
		}
	}

	r, err := CreateResource(runtime, "auth0.organization", map[string]*llx.RawData{
		"id":              llx.StringDataPtr(o.ID),
		"name":            llx.StringDataPtr(o.Name),
		"displayName":     llx.StringDataPtr(o.DisplayName),
		"brandingLogoUrl": llx.StringDataPtr(logoURL),
		"metadata":        llx.MapData(metadata, types.String),
	})
	if err != nil {
		return nil, err
	}
	return r, nil
}

// connections resolves the identity connections enabled for this organization
// into typed auth0.connection references.
func (o *mqlAuth0Organization) connections() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.Auth0Connection)
	client := conn.Client()

	var result []any
	page := 0
	for {
		list, err := client.Organization.Connections(context.Background(), o.Id.Data,
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, oc := range list.OrganizationConnections {
			if oc.ConnectionID == nil {
				continue
			}
			r, err := NewResource(o.MqlRuntime, "auth0.connection",
				map[string]*llx.RawData{"id": llx.StringData(*oc.ConnectionID)})
			if err != nil {
				log.Debug().Err(err).Str("connection", *oc.ConnectionID).Msg("auth0> unable to resolve organization connection")
				continue
			}
			result = append(result, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return result, nil
}

// members resolves the users who belong to this organization into typed
// auth0.user references.
func (o *mqlAuth0Organization) members() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.Auth0Connection)
	client := conn.Client()

	var result []any
	page := 0
	for {
		list, err := client.Organization.Members(context.Background(), o.Id.Data,
			management.Page(page),
			management.PerPage(50),
			management.IncludeTotals(true),
		)
		if err != nil {
			return nil, err
		}
		for _, m := range list.Members {
			if m.UserID == nil {
				continue
			}
			r, err := NewResource(o.MqlRuntime, "auth0.user",
				map[string]*llx.RawData{"id": llx.StringData(*m.UserID)})
			if err != nil {
				log.Debug().Err(err).Str("user", *m.UserID).Msg("auth0> unable to resolve organization member")
				continue
			}
			result = append(result, r)
		}
		if !list.HasNext() {
			break
		}
		page++
	}
	return result, nil
}

func (o *mqlAuth0Organization) id() (string, error) {
	return "auth0.organization/" + o.Id.Data, nil
}
