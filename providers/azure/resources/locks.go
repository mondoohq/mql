// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resources/armlocks"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// lockProviderPath is the segment a lock's resource ID appends to the ID of
// whatever it protects.
const lockProviderPath = "/providers/microsoft.authorization/locks/"

// lockScopeFromID recovers the scope a lock applies to from the lock's own
// resource ID, which is the protected scope with the lock's provider path
// appended. The search runs from the right and case-insensitively: a resource
// ID contains its own "/providers/..." segment, and Azure does not guarantee
// the casing it echoes back. Returns "" when the ID does not carry the lock
// provider path.
func lockScopeFromID(id string) string {
	idx := strings.LastIndex(strings.ToLower(id), lockProviderPath)
	if idx < 0 {
		return ""
	}
	return id[:idx]
}

func (a *mqlAzureSubscription) locks() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	client, err := armlocks.NewManagementLocksClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	// The subscription-level listing covers every lock in the subscription,
	// including locks placed on resource groups and on individual resources, so
	// resourcegroup.locks() filters this one fetch rather than paging per group.
	pager := client.NewListAtSubscriptionLevelPager(&armlocks.ManagementLocksClientListAtSubscriptionLevelOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, lock := range page.Value {
			if lock == nil {
				continue
			}
			mqlLock, err := newMqlLock(a.MqlRuntime, lock)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlLock)
		}
	}
	return res, nil
}

func newMqlLock(runtime *plugin.Runtime, lock *armlocks.ManagementLockObject) (plugin.Resource, error) {
	// Properties is REQUIRED per the SDK but nullable in Go; normalize so the
	// args map below can dereference it unconditionally.
	props := lock.Properties
	if props == nil {
		props = &armlocks.ManagementLockProperties{}
	}

	owners := []any{}
	for _, o := range props.Owners {
		if o != nil && o.ApplicationID != nil {
			owners = append(owners, *o.ApplicationID)
		}
	}

	return CreateResource(runtime, "azure.subscription.lock",
		map[string]*llx.RawData{
			"__id":   llx.StringDataPtr(lock.ID),
			"id":     llx.StringDataPtr(lock.ID),
			"name":   llx.StringDataPtr(lock.Name),
			"type":   llx.StringDataPtr(lock.Type),
			"level":  llx.StringData(string(convert.ToValue(props.Level))),
			"notes":  llx.StringDataPtr(props.Notes),
			"owners": llx.ArrayData(owners, types.String),
			"scope":  llx.StringData(lockScopeFromID(convert.ToValue(lock.ID))),
		})
}

func (a *mqlAzureSubscriptionResourcegroup) locks() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	// Resolve the subscription's lock list and narrow it to this group. Reusing
	// the cached subscription-wide fetch keeps this free of extra API calls even
	// when every group in a large subscription is queried.
	r, err := CreateResource(a.MqlRuntime, ResourceAzureSubscription, map[string]*llx.RawData{
		"__id":           llx.StringData("/subscriptions/" + conn.SubId()),
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	all := r.(*mqlAzureSubscription).GetLocks()
	if all.Error != nil {
		return nil, all.Error
	}

	// A lock protecting this group has a scope of either the group itself or a
	// resource inside it, so match on the group ID followed by a separator (or
	// nothing) to avoid matching a sibling group whose name shares this prefix.
	groupID := strings.ToLower(a.Id.Data)
	res := []any{}
	for _, l := range all.Data {
		lock, ok := l.(*mqlAzureSubscriptionLock)
		if !ok {
			continue
		}
		scope := strings.ToLower(lock.Scope.Data)
		if scope == groupID || strings.HasPrefix(scope, groupID+"/") {
			res = append(res, lock)
		}
	}
	return res, nil
}
