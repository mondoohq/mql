// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/okta/connection"
	"go.mondoo.com/mql/providers/okta/resources/sdk"
	"go.mondoo.com/mql/types"
)

func (o *mqlOkta) networks() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OktaConnection)

	ctx := context.Background()
	apiSupplement := conn.ApiExtension()

	zones, err := apiSupplement.ListNetworkZones(ctx, queryLimit)
	if err != nil {
		return nil, err
	}

	if len(zones) == 0 {
		return nil, nil
	}

	list := make([]any, 0, len(zones))
	for _, entry := range zones {
		r, err := newMqlOktaNetworkZone(o.MqlRuntime, entry)
		if err != nil {
			return nil, err
		}
		list = append(list, r)
	}
	return list, nil
}

func newMqlOktaNetworkZone(runtime *plugin.Runtime, entry *sdk.NetworkZone) (any, error) {
	proxies, err := sdk.NormalizeArrayField(entry.Proxies)
	if err != nil {
		return nil, err
	}

	locations, err := sdk.NormalizeArrayField(entry.Locations)
	if err != nil {
		return nil, err
	}

	gateways, err := sdk.NormalizeArrayField(entry.Gateways)
	if err != nil {
		return nil, err
	}

	asns, err := sdk.NormalizeStringArrayField(entry.Asns)
	if err != nil {
		return nil, err
	}

	system := false
	if entry.System != nil {
		system = *entry.System
	}

	return CreateResource(runtime, "okta.network", map[string]*llx.RawData{
		"id":          llx.StringData(entry.Id),
		"name":        llx.StringData(entry.Name),
		"type":        llx.StringData(entry.Type),
		"created":     llx.TimeDataPtr(entry.Created),
		"lastUpdated": llx.TimeDataPtr(entry.LastUpdated),
		"status":      llx.StringData(entry.Status),
		"system":      llx.BoolData(system),
		"asns":        llx.ArrayData(convert.SliceAnyToInterface(asns), types.String),
		"usage":       llx.StringData(entry.Usage),
		"proxyType":   llx.StringData(entry.ProxyType),
		"proxies":     llx.ArrayData(proxies, types.Dict),
		"locations":   llx.ArrayData(locations, types.Dict),
		"gateways":    llx.ArrayData(gateways, types.Dict),
	})
}

func (o *mqlOktaNetwork) id() (string, error) {
	return "okta.network/" + o.Id.Data, o.Id.Error
}
