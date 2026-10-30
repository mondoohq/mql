// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/okta/okta-sdk-golang/v6/okta"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOkta) apiServiceIntegrations() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)
	client := conn.Client()

	ctx := context.Background()
	slice, resp, err := client.ApiServiceIntegrationsAPI.ListApiServiceIntegrationInstances(ctx).Execute()
	if err != nil {
		return nil, err
	}

	list := []any{}
	appendEntry := func(datalist []okta.APIServiceIntegrationInstance) error {
		for i := range datalist {
			r, err := newMqlOktaApiServiceIntegration(o.MqlRuntime, &datalist[i])
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
		var page []okta.APIServiceIntegrationInstance
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

func newMqlOktaApiServiceIntegration(runtime *plugin.Runtime, entry *okta.APIServiceIntegrationInstance) (any, error) {
	// The SDK types createdAt as a plain string, but Okta returns an RFC3339
	// timestamp; parse it so the field matches the time type used elsewhere.
	var created *time.Time
	if entry.CreatedAt != nil {
		if t, err := time.Parse(time.RFC3339, *entry.CreatedAt); err == nil {
			created = &t
		}
	}

	// Properties are a name-to-value list on the wire; the name is the key a
	// query would look the value up by.
	properties := map[string]any{}
	if entry.Properties != nil {
		for key, prop := range *entry.Properties {
			properties[key] = oktaStr(prop.Value)
		}
	}

	return CreateResource(runtime, "okta.apiServiceIntegration", map[string]*llx.RawData{
		"id":             llx.StringData(oktaStr(entry.Id)),
		"name":           llx.StringData(oktaStr(entry.Name)),
		"type":           llx.StringData(oktaStr(entry.Type)),
		"grantedScopes":  llx.ArrayData(convert.SliceAnyToInterface(entry.GrantedScopes), types.String),
		"configGuideUrl": llx.StringData(oktaStr(entry.ConfigGuideUrl)),
		"createdBy":      llx.StringData(oktaStr(entry.CreatedBy)),
		"createdAt":      llx.TimeDataPtr(created),
		"properties":     llx.MapData(properties, types.String),
	})
}

func (o *mqlOktaApiServiceIntegration) id() (string, error) {
	return "okta.apiServiceIntegration/" + o.Id.Data, o.Id.Error
}
