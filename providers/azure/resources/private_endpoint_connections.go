// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/types"
)

// azurePrivateEndpointConnectionsToMql converts a slice of Azure SDK private
// endpoint connection values into shared azure.subscription.privateEndpointConnection
// resources. Every Azure SDK models private endpoint connections with the same
// JSON shape (id, name, type, properties.privateEndpoint.id,
// properties.privateLinkServiceConnectionState, properties.provisioningState),
// so the values are normalized through a dict rather than accessed per SDK type.
// This lets one helper serve resources whose SDK connection type differs
// (armservicebus.PrivateEndpointConnection, armappconfiguration.PrivateEndpointConnectionReference,
// armapimanagement.RemotePrivateEndpointConnectionWrapper, and so on).
func azurePrivateEndpointConnectionsToMql[T any](runtime *plugin.Runtime, entries []T) ([]any, error) {
	res := make([]any, 0, len(entries))
	for _, entry := range entries {
		mqlConn, err := azurePrivateEndpointConnectionToMql(runtime, entry)
		if err != nil {
			return nil, err
		}
		if mqlConn != nil {
			res = append(res, mqlConn)
		}
	}
	return res, nil
}

// azurePrivateEndpointConnectionToMql builds a single shared private endpoint
// connection resource from any Azure SDK connection value. It returns nil when
// the value carries no usable data (e.g. a nil pointer in the slice).
type mqlAzureSubscriptionPrivateEndpointConnectionInternal struct {
	cachePrivateEndpointId string
}

// newAzurePrivateEndpointConnection creates the shared private endpoint
// connection resource. The linked private endpoint's ARM ID is kept off the
// schema and cached here so privateEndpoint() can resolve it on demand.
func newAzurePrivateEndpointConnection(runtime *plugin.Runtime, args map[string]*llx.RawData, privateEndpointID string) (plugin.Resource, error) {
	res, err := CreateResource(runtime, ResourceAzureSubscriptionPrivateEndpointConnection, args)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionPrivateEndpointConnection).cachePrivateEndpointId = privateEndpointID
	return res, nil
}

// newPrivateLinkServiceConnectionState builds the typed connection-state
// resource for a private endpoint connection.
//
// connectionID must be the parent connection's ARM ID. The connection state
// has no identity of its own, so without a parent-qualified __id every state
// in a scan collides on one cache key and every connection reports whichever
// one happened to resolve first. All three fields are set unconditionally so
// an absent value reads as null rather than staying unset.
func newPrivateLinkServiceConnectionState(runtime *plugin.Runtime, connectionID string, actionsRequired, description, status *string) (plugin.Resource, error) {
	return CreateResource(runtime, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState,
		map[string]*llx.RawData{
			"__id":            llx.StringData(connectionID + "/privateLinkServiceConnectionState"),
			"actionsRequired": llx.StringDataPtr(actionsRequired),
			"description":     llx.StringDataPtr(description),
			"status":          llx.StringDataPtr(status),
		})
}

// dictStringPtr returns a pointer to the string at key, and nil when the key is
// absent or holds something other than a string.
//
// It keeps two different answers apart. A key ARM never sent is unknown, and
// reads as null. A key ARM sent as "" is a value it reported, and reads as the
// empty string.
func dictStringPtr(m map[string]any, key string) *string {
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}

func azurePrivateEndpointConnectionToMql(runtime *plugin.Runtime, entry any) (plugin.Resource, error) {
	dict, err := convert.JsonToDict(entry)
	if err != nil {
		return nil, err
	}
	if len(dict) == 0 {
		return nil, nil
	}

	// A connection with no ID has no stable cache key, and everything useful
	// about it (name, navigation) derives from that ID. Skip it rather than
	// letting multiple ID-less entries collide on an empty __id.
	id, _ := dict["id"].(string)
	if id == "" {
		return nil, nil
	}
	var privateEndpointID string
	// Seed every declared field with an explicit default. A key that never
	// lands in args leaves its TValue unset rather than null, which crosses
	// the plugin boundary as an empty DataRes and surfaces client-side as
	// "primitive with no type information" with no attribution.
	args := map[string]*llx.RawData{
		"__id":                              llx.StringData(id),
		"id":                                llx.StringData(id),
		"name":                              llx.NilData,
		"type":                              llx.NilData,
		"ipAddresses":                       llx.ArrayData([]any{}, types.String),
		"provisioningState":                 llx.NilData,
		"properties":                        llx.NilData,
		"privateLinkServiceConnectionState": llx.NilData,
	}

	// Prefer the SDK-provided name; most connection types leave it empty on
	// read, so fall back to deriving it from the resource ID.
	name, _ := dict["name"].(string)
	if name == "" && id != "" {
		if rid, err := ParseResourceID(id); err == nil {
			if comp, err := rid.Component("privateEndpointConnections"); err == nil {
				name = comp
			}
		}
		if name == "" {
			parts := strings.Split(id, "/")
			name = parts[len(parts)-1]
		}
	}
	if name != "" {
		args["name"] = llx.StringData(name)
	}
	if typ, _ := dict["type"].(string); typ != "" {
		args["type"] = llx.StringData(typ)
	}

	if props, ok := dict["properties"].(map[string]any); ok && props != nil {
		args["properties"] = llx.DictData(props)

		// Only a few services report allocated addresses on the connection
		// itself; the rest leave the seeded empty list in place.
		if ips, ok := props["ipAddresses"].([]any); ok {
			addrs := []any{}
			for _, ip := range ips {
				if s, ok := ip.(string); ok {
					addrs = append(addrs, s)
				}
			}
			args["ipAddresses"] = llx.ArrayData(addrs, types.String)
		}
		if pe, ok := props["privateEndpoint"].(map[string]any); ok {
			privateEndpointID, _ = pe["id"].(string)
		}
		if provState, _ := props["provisioningState"].(string); provState != "" {
			args["provisioningState"] = llx.StringData(provState)
		}
		if cs, ok := props["privateLinkServiceConnectionState"].(map[string]any); ok && cs != nil {
			// Through the same helper the per-SDK callers use. Building the args
			// here instead is what left an absent field unset rather than null:
			// a key that never lands in args crosses the plugin boundary as an
			// empty DataRes. actionsRequired is the one that showed it, because
			// a connection needing no action is the normal case.
			stateRes, err := newPrivateLinkServiceConnectionState(runtime, id,
				dictStringPtr(cs, "actionsRequired"),
				dictStringPtr(cs, "description"),
				dictStringPtr(cs, "status"))
			if err != nil {
				return nil, err
			}
			args["privateLinkServiceConnectionState"] = llx.ResourceData(stateRes, ResourceAzureSubscriptionPrivateEndpointConnectionConnectionState)
		}
	}

	return newAzurePrivateEndpointConnection(runtime, args, privateEndpointID)
}
