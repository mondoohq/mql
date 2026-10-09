// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"
	"sync"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/utils/syncx"
)

// taggedListedResource is a listed resource that carries its ARM tags.
type taggedListedResource interface {
	azureListedResource
	GetTags() *plugin.TValue[map[string]any]
}

// The entries of every list keepTagMatches narrows. An entry that does not carry
// tags would pass the filter unseen.
var _ = []taggedListedResource{
	(*mqlAzureSubscriptionAksServiceCluster)(nil),
	(*mqlAzureSubscriptionBatchServiceAccount)(nil),
	(*mqlAzureSubscriptionCacheServiceRedisInstance)(nil),
	(*mqlAzureSubscriptionCognitiveServicesServiceAccount)(nil),
	(*mqlAzureSubscriptionComputeServiceVm)(nil),
	(*mqlAzureSubscriptionContainerAppServiceContainerApp)(nil),
	(*mqlAzureSubscriptionContainerRegistryServiceRegistry)(nil),
	(*mqlAzureSubscriptionCosmosDbServiceAccount)(nil),
	(*mqlAzureSubscriptionDataFactoryServiceFactory)(nil),
	(*mqlAzureSubscriptionFunctionsServiceFunctionApp)(nil),
	(*mqlAzureSubscriptionIotServiceIotHub)(nil),
	(*mqlAzureSubscriptionKeyVaultServiceManagedHsm)(nil),
	(*mqlAzureSubscriptionKeyVaultServiceVault)(nil),
	(*mqlAzureSubscriptionMySqlServiceFlexibleServer)(nil),
	(*mqlAzureSubscriptionNetworkServiceApplicationGateway)(nil),
	(*mqlAzureSubscriptionNetworkServiceFirewall)(nil),
	(*mqlAzureSubscriptionNetworkServiceSecurityGroup)(nil),
	(*mqlAzureSubscriptionNetworkServiceVirtualNetwork)(nil),
	(*mqlAzureSubscriptionPostgreSqlServiceFlexibleServer)(nil),
	(*mqlAzureSubscriptionRecoveryServicesServiceVault)(nil),
	(*mqlAzureSubscriptionSqlServiceServer)(nil),
	(*mqlAzureSubscriptionStorageServiceAccount)(nil),
	(*mqlAzureSubscriptionSynapseServiceWorkspace)(nil),
	(*mqlAzureSubscriptionWebServiceAppsite)(nil),
}

// keepTagMatches narrows a subscription list to the entries that pass the
// connection's tag filters (--filters tag:<key>=<value>), the same rule
// discovery applies when it creates assets. Without it a query on the
// subscription asset reported resources the filter had excluded.
//
// The entries left out are remembered, so a reference from a resource that
// passed the filter to one that did not (a VM's network security group, a
// cluster's registry) still resolves through tagFilteredOut.
//
// Every listed resource this is applied to sets its tags from the list call
// itself, so filtering costs no extra API calls.
func keepTagMatches(runtime *plugin.Runtime, list []any) []any {
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok || !conn.Filters.General.HasTags() {
		return list
	}

	var index *tagFilteredOutIndex
	kept := make([]any, 0, len(list))
	for _, entry := range list {
		res, ok := entry.(taggedListedResource)
		if !ok || !conn.Filters.General.IsFilteredOutByTags(interfaceMapToStr(res.GetTags().Data)) {
			kept = append(kept, entry)
			continue
		}
		if index == nil {
			index = tagFilteredOutIndexOf(runtime)
		}
		index.entries.Set(tagFilteredOutKey(res.MqlName(), res.GetId().Data), res)
	}
	return kept
}

// tagFilteredOut returns the resource with this id that keepTagMatches left
// out of its list, or nil. Inits that resolve a resource out of a filtered list
// consult it once the list itself has no match.
func tagFilteredOut(runtime *plugin.Runtime, resourceName, id string) plugin.Resource {
	if id == "" {
		return nil
	}
	if res, ok := tagFilteredOutIndexOf(runtime).entries.Get(tagFilteredOutKey(resourceName, id)); ok {
		return res
	}
	return nil
}

// tagFilteredOutOfType returns every resource of this type that keepTagMatches
// left out of its list, for the lookups that match on something other than the
// id (a storage account by name, a container inside an account).
func tagFilteredOutOfType(runtime *plugin.Runtime, resourceName string) []plugin.Resource {
	prefix := resourceName + "\x00"
	var res []plugin.Resource
	tagFilteredOutIndexOf(runtime).entries.Range(func(key, value any) bool {
		if k, ok := key.(string); ok && strings.HasPrefix(k, prefix) {
			if r, ok := value.(plugin.Resource); ok {
				res = append(res, r)
			}
		}
		return true
	})
	return res
}

// tagFilteredOutKey lower-cases the id: ARM ids are case-insensitive, and a
// reference often spells the resource group or type segment differently from
// the list that returned the resource.
func tagFilteredOutKey(resourceName, id string) string {
	return resourceName + "\x00" + strings.ToLower(id)
}

// tagFilteredOutIndex holds what keepTagMatches left out of the lists.
//
// It lives in the runtime's resource cache rather than on the connection: a
// discovered asset's runtime shares its parent's cache, so a lookup on that
// asset is handed the subscription asset's service resources, lists already
// narrowed, while running on a connection of its own that never saw them
// narrowed. The cache is the one place both runtimes read.
type tagFilteredOutIndex struct {
	entries syncx.Map[plugin.Resource]
}

func (*tagFilteredOutIndex) MqlName() string { return tagFilteredOutIndexKey }
func (*tagFilteredOutIndex) MqlID() string   { return "" }

// tagFilteredOutIndexKey cannot collide with a resource the runtime caches,
// which are keyed by a resource name, a NUL, and an id.
const tagFilteredOutIndexKey = "\x00azure.tagFilteredOut"

var tagFilteredOutIndexMu sync.Mutex

func tagFilteredOutIndexOf(runtime *plugin.Runtime) *tagFilteredOutIndex {
	if res, ok := runtime.Resources.Get(tagFilteredOutIndexKey); ok {
		return res.(*tagFilteredOutIndex)
	}
	tagFilteredOutIndexMu.Lock()
	defer tagFilteredOutIndexMu.Unlock()
	if res, ok := runtime.Resources.Get(tagFilteredOutIndexKey); ok {
		return res.(*tagFilteredOutIndex)
	}
	index := &tagFilteredOutIndex{}
	runtime.Resources.Set(tagFilteredOutIndexKey, index)
	return index
}
