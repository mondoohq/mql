// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"

	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/managementgroups/armmanagementgroups/v2"
)

// TODO: we should look into restructuring resources for v11.
// we should be able to define the subscription as a property on the azure one, i.e.
//
//	azure {
//	  subscription() azure.subscription
//	}
//
// right now this isn't possible as the resource lookup gets confused between trying to directly create azure.subscription
// or create azure and then do azure.subscription()
type mqlAzureInternal struct {
	sub *mqlAzureSubscription

	// The tenant's management group hierarchy. It lives here rather than on a
	// subscription because it spans every subscription in the tenant, and one
	// entities listing answers parentage, children, and subtree counts for the
	// whole tree.
	//
	// Fetched at most once per resource cache, which under staged discovery is
	// once per subscription: the assets inside a subscription share their
	// subscription's cache, so the first of them to ask pays for the listing
	// and the rest read this.
	mgOnce     sync.Once
	mgEntities []*armmanagementgroups.EntityInfo
	mgErr      error
}
