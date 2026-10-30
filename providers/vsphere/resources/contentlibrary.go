// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/vmware/govmomi/vapi/library"
	vmwaretypes "github.com/vmware/govmomi/vim25/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers/vsphere/connection"
	"go.mondoo.com/mql/types"
)

func (v *mqlVsphere) contentLibraries() ([]any, error) {
	conn := v.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	rc, err := conn.RestClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vAPI: %w", err)
	}

	libs, err := library.NewManager(rc).GetLibraries(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list content libraries: %w", err)
	}

	res := make([]any, 0, len(libs))
	for i := range libs {
		lib := libs[i]

		var published bool
		var publishUrl string
		if lib.Publication != nil {
			if lib.Publication.Published != nil {
				published = *lib.Publication.Published
			}
			publishUrl = lib.Publication.PublishURL
		}

		var subscriptionUrl, subscriptionAuthMethod string
		var subscriptionAutomaticSync, subscriptionOnDemand bool
		if lib.Subscription != nil {
			subscriptionUrl = lib.Subscription.SubscriptionURL
			subscriptionAuthMethod = lib.Subscription.AuthenticationMethod
			if lib.Subscription.AutomaticSyncEnabled != nil {
				subscriptionAutomaticSync = *lib.Subscription.AutomaticSyncEnabled
			}
			if lib.Subscription.OnDemand != nil {
				subscriptionOnDemand = *lib.Subscription.OnDemand
			}
		}

		storageBackings := make([]any, 0, len(lib.Storage))
		for _, s := range lib.Storage {
			storageBackings = append(storageBackings, map[string]any{
				"type":        s.Type,
				"datastoreId": s.DatastoreID,
			})
		}

		mqlLib, err := CreateResource(v.MqlRuntime, "vsphere.contentLibrary", map[string]*llx.RawData{
			"__id":                      llx.StringData(lib.ID),
			"id":                        llx.StringData(lib.ID),
			"name":                      llx.StringData(lib.Name),
			"type":                      llx.StringData(lib.Type),
			"description":               llx.StringDataPtr(lib.Description),
			"creationTime":              llx.TimeDataPtr(lib.CreationTime),
			"lastModifiedTime":          llx.TimeDataPtr(lib.LastModifiedTime),
			"lastSyncTime":              llx.TimeDataPtr(lib.LastSyncTime),
			"version":                   llx.StringData(lib.Version),
			"published":                 llx.BoolData(published),
			"publishUrl":                llx.StringData(publishUrl),
			"subscriptionUrl":           llx.StringData(subscriptionUrl),
			"subscriptionAutomaticSync": llx.BoolData(subscriptionAutomaticSync),
			"subscriptionOnDemand":      llx.BoolData(subscriptionOnDemand),
			"subscriptionAuthMethod":    llx.StringData(subscriptionAuthMethod),
			"storageBackings":           llx.ArrayData(storageBackings, types.Dict),
			"securityPolicyId":          llx.StringData(lib.SecurityPolicyID),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlLib)
	}
	return res, nil
}

func (l *mqlVsphereContentLibrary) datastores() ([]any, error) {
	backings := l.GetStorageBackings()
	if backings.Error != nil {
		return nil, backings.Error
	}

	inv, err := loadVsphereInventory(l.MqlRuntime)
	if err != nil {
		return nil, err
	}

	res := []any{}
	seen := map[string]struct{}{}
	for _, b := range backings.Data {
		m, ok := b.(map[string]any)
		if !ok {
			continue
		}
		dsID, _ := m["datastoreId"].(string)
		if dsID == "" {
			continue
		}
		key := vmwaretypes.ManagedObjectReference{Type: "Datastore", Value: dsID}.Encode()
		ds, ok := inv.datastores[key]
		if !ok {
			continue
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		res = append(res, ds)
	}
	return res, nil
}

func (l *mqlVsphereContentLibrary) items() ([]any, error) {
	conn := l.MqlRuntime.Connection.(*connection.VsphereConnection)
	ctx := context.Background()

	rc, err := conn.RestClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to vAPI: %w", err)
	}

	items, err := library.NewManager(rc).GetLibraryItems(ctx, l.Id.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to list content library items: %w", err)
	}

	res := make([]any, 0, len(items))
	for i := range items {
		item := items[i]

		args := map[string]*llx.RawData{
			"__id":             llx.StringData(item.ID),
			"id":               llx.StringData(item.ID),
			"name":             llx.StringData(item.Name),
			"type":             llx.StringData(item.Type),
			"description":      llx.StringDataPtr(item.Description),
			"version":          llx.StringData(item.Version),
			"contentVersion":   llx.StringData(item.ContentVersion),
			"metadataVersion":  llx.StringData(item.MetadataVersion),
			"size":             llx.IntData(item.Size),
			"cached":           llx.BoolData(item.Cached),
			"creationTime":     llx.TimeDataPtr(item.CreationTime),
			"lastModifiedTime": llx.TimeDataPtr(item.LastModifiedTime),
			"lastSyncTime":     llx.TimeDataPtr(item.LastSyncTime),
			"sourceId":         llx.StringData(item.SourceID),
			// *bool: nil (item not evaluated for a security policy) surfaces as
			// MQL null, distinct from an evaluated false. See the field's null
			// semantics in the .lr doc comment.
			"securityCompliant": llx.BoolDataPtr(item.SecurityCompliance),
		}

		mqlItem, err := CreateResource(l.MqlRuntime, "vsphere.contentLibrary.item", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlItem)
	}
	return res, nil
}
