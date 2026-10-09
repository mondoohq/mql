// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
)

// azureListedResource is any resource that a service-level list returns and
// that carries the ARM id its asset is discovered under.
type azureListedResource interface {
	plugin.Resource
	GetId() *plugin.TValue[string]
}

// azureListService is any of the azure.subscription.*Service resources, all of
// which are keyed on the subscription alone.
type azureListService interface {
	plugin.Resource
}

// initFromServiceList resolves a resource by its ARM id out of the list its
// parent service has already fetched, instead of asking ARM for that one
// resource.
//
// Every discovered asset resolves its own resource through its init, once per
// asset, so a per-resource Get costs one API call per asset of that type: a
// subscription with 150 VMs pays 150 of them. The service's list is a single
// call that already contains every one of those resources, and during a scan it
// has usually been fetched already, because discovery itself walks the same
// list to find the assets. Worse, NewResource runs the init *before* it
// consults the resource cache, so a Get here is spent even when the resource is
// already built, and its result is then thrown away in favour of the cached
// one.
//
// This mirrors the k8s provider's initNamespacedResource.
//
// The trade is deliberate: resolving a single asset in isolation now pulls the
// whole subscription's list rather than one record. During a scan that list is
// wanted anyway and is very likely already cached; for a one-off query against
// one asset it is the more expensive path.
func initFromServiceList[S azureListService](
	runtime *plugin.Runtime,
	args map[string]*llx.RawData,
	serviceName string,
	entries func(S) *plugin.TValue[[]any],
	resourceName string,
) (map[string]*llx.RawData, plugin.Resource, error) {
	// the args are already complete; nothing to resolve
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, missingResourceID(resourceName)
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	res, err := NewResource(runtime, serviceName, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc, ok := res.(S)
	if !ok {
		return nil, nil, fmt.Errorf("unexpected resource type for %s", serviceName)
	}

	list := entries(svc)
	if list.Error != nil {
		return nil, nil, list.Error
	}
	for i := range list.Data {
		item, ok := list.Data[i].(azureListedResource)
		if !ok {
			continue
		}
		// Case-insensitively, because the two ids come from different ARM
		// endpoints and ARM does not agree with itself on the casing of the
		// type segment. A container app is
		// ".../Microsoft.App/containerApps/..." in the generic resources
		// listing an asset's platform id comes from, and
		// ".../Microsoft.App/containerapps/..." in the service listing matched
		// here. ARM treats ids as case-insensitive, so an exact comparison
		// reports a resource that plainly exists as not found.
		if strings.EqualFold(item.GetId().Data, id) {
			return args, item, nil
		}
	}

	// A tag filter may have left it out of the list it was read from.
	if filtered := tagFilteredOut(runtime, resourceName, id); filtered != nil {
		return args, filtered, nil
	}

	// Deliberately an error rather than falling through with (args, nil, nil):
	// that would have the runtime build the resource from the id alone, leaving
	// every other field unset rather than null, which reaches the client as an
	// untyped null with nothing pointing at the cause.
	return nil, nil, fmt.Errorf("%s with id %q not found", resourceName, id)
}

// cachedResource returns a resource already in this runtime's cache, or nil.
//
// NewResource consults the cache only *after* the init has returned, so an init
// that fetches unconditionally pays for a resource the runtime is holding and
// then has its result discarded in favour of the cached one. Calling this first
// makes a reference cost one fetch for the whole scan rather than one per
// reference.
//
// Reach for this when there is no list to resolve from -- otherwise prefer
// lookupInServiceList, which answers for resources nothing has fetched yet as
// well. The two compose: check the cache, then the list, then fetch.
//
// The lookup is exact, because that is how the runtime keys the cache. A
// reference whose casing differs from the stored resource's own id misses and
// falls through to the fetch, which is what happens today anyway.
func cachedResource(runtime *plugin.Runtime, resourceName, id string) plugin.Resource {
	if id == "" || runtime == nil || runtime.Resources == nil {
		return nil
	}
	if res, ok := runtime.Resources.Get(resourceName + "\x00" + id); ok {
		return res
	}
	return nil
}

// lookupInServiceList finds a resource by ARM id in the list its parent service
// has already fetched, and returns nil when it is not there.
//
// This is the half of the pattern for typed references rather than for assets.
// A reference resolves through NewResource once per referring resource, and
// because NewResource runs the init before it consults the cache, the same
// target is re-fetched for every reference to it -- 30 network interfaces
// referenced twice each cost 60 Gets, all of which the service's own list
// already answered.
//
// Unlike initFromServiceList, a miss here is not an error. A typed reference
// may legitimately point outside the current scope: at another subscription, or
// at a resource since deleted, or at one the caller cannot read. Callers keep
// their own fetch as the fallback and degrade the way they always did.
func lookupInServiceList[S azureListService](
	runtime *plugin.Runtime,
	serviceName string,
	entries func(S) *plugin.TValue[[]any],
	id string,
) plugin.Resource {
	if id == "" {
		return nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil
	}

	// Only this connection's own subscription has a list to consult. A
	// reference into another subscription has to fall through to the caller's
	// fetch, or we would report it missing when it is merely elsewhere.
	resourceID, err := ParseResourceID(id)
	if err != nil || !strings.EqualFold(resourceID.SubscriptionID, conn.SubId()) {
		return nil
	}

	res, err := NewResource(runtime, serviceName, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil
	}
	svc, ok := res.(S)
	if !ok {
		return nil
	}
	list := entries(svc)
	if list.Error != nil {
		return nil
	}
	for i := range list.Data {
		item, ok := list.Data[i].(azureListedResource)
		if !ok {
			continue
		}
		if strings.EqualFold(item.GetId().Data, id) {
			return item
		}
	}
	return nil
}
