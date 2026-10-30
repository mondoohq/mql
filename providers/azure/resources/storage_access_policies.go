// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strconv"
	"time"

	armstorage "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storage/armstorage/v4"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azblob/container"
	"github.com/Azure/azure-sdk-for-go/sdk/storage/azqueue/v2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// storedAccessPolicy is one stored access policy in the shape the three
// storage services agree on. Blob, queue and table each ship their own
// SignedIdentifier type with the same four values, so the readers below
// normalize into this before the resource is built.
type storedAccessPolicy struct {
	id         *string
	permission *string
	startTime  *time.Time
	expiryTime *time.Time
}

// storedAccessPoliciesToMql builds the stored access policy resources for one
// container, queue or table.
//
// The times stay `time` values rather than the RFC3339 strings the dict form
// carried, which is the point of the promotion: `expiryTime > time.now` is a
// question you can ask of a time and cannot ask of a string. An absent
// timestamp reads as null rather than as the zero time, so a policy with no
// expiry is distinguishable from one that expired in year 1.
//
// A policy carries no ARM identifier, so the cache key is the parent resource
// plus the policy id, falling back to the position in the list for a policy
// the service returned without one.
func storedAccessPoliciesToMql(runtime *plugin.Runtime, parentID string, policies []storedAccessPolicy) ([]any, error) {
	res := []any{}
	for i, p := range policies {
		key := ""
		if p.id != nil && *p.id != "" {
			key = *p.id
		} else {
			key = strconv.Itoa(i)
		}
		mqlPolicy, err := CreateResource(runtime, "azure.subscription.storageService.account.storedAccessPolicy",
			map[string]*llx.RawData{
				"__id":       llx.StringData(subResourceCacheID(nil, parentID, "storedAccessPolicies", key)),
				"id":         llx.StringDataPtr(p.id),
				"permission": llx.StringDataPtr(p.permission),
				"startTime":  llx.TimeDataPtr(p.startTime),
				"expiryTime": llx.TimeDataPtr(p.expiryTime),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPolicy)
	}
	return res, nil
}

// blobStoredAccessPolicies normalizes the blob service's signed identifiers.
func blobStoredAccessPolicies(identifiers []*container.SignedIdentifier) []storedAccessPolicy {
	res := make([]storedAccessPolicy, 0, len(identifiers))
	for _, si := range identifiers {
		if si == nil {
			continue
		}
		p := storedAccessPolicy{id: si.ID}
		if si.AccessPolicy != nil {
			p.permission = si.AccessPolicy.Permission
			p.startTime = si.AccessPolicy.Start
			p.expiryTime = si.AccessPolicy.Expiry
		}
		res = append(res, p)
	}
	return res
}

// queueStoredAccessPolicies normalizes the queue service's signed identifiers.
func queueStoredAccessPolicies(identifiers []*azqueue.SignedIdentifier) []storedAccessPolicy {
	res := make([]storedAccessPolicy, 0, len(identifiers))
	for _, si := range identifiers {
		if si == nil {
			continue
		}
		p := storedAccessPolicy{id: si.ID}
		if si.AccessPolicy != nil {
			p.permission = si.AccessPolicy.Permission
			p.startTime = si.AccessPolicy.Start
			p.expiryTime = si.AccessPolicy.Expiry
		}
		res = append(res, p)
	}
	return res
}

// tableStoredAccessPolicies normalizes the table service's signed identifiers,
// which armstorage names StartTime/ExpiryTime rather than Start/Expiry.
func tableStoredAccessPolicies(identifiers []*armstorage.TableSignedIdentifier) []storedAccessPolicy {
	res := make([]storedAccessPolicy, 0, len(identifiers))
	for _, si := range identifiers {
		if si == nil {
			continue
		}
		p := storedAccessPolicy{id: si.ID}
		if si.AccessPolicy != nil {
			p.permission = si.AccessPolicy.Permission
			p.startTime = si.AccessPolicy.StartTime
			p.expiryTime = si.AccessPolicy.ExpiryTime
		}
		res = append(res, p)
	}
	return res
}
