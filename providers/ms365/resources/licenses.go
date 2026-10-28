// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/microsoftgraph/msgraph-sdk-go/models"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/ms365/connection"
	"go.mondoo.com/mql/types"
)

// A tenant buys a handful of SKUs and every user references them through
// assignedLicenses. user.licenseDetails is built from those two instead of a
// Graph call per user: fetching licenseDetails for every user took one $batch
// round trip per 19 users and kept every response in memory, which ran large
// tenants out of memory. Only servicePlans needs the user's own
// licenseDetails (its provisioningStatus is per user), so it is fetched for a
// single user when queried.

// subscribedSkuCache holds the tenant's subscribed SKUs, fetched once.
type subscribedSkuCache struct {
	once    sync.Once
	skus    []models.SubscribedSkuable
	bySkuID map[string]models.SubscribedSkuable
	err     error
}

// userLicenseDetailsCache holds each user's licenseDetails from Graph, fetched
// once per user and only for users whose servicePlans are queried.
type userLicenseDetailsCache struct {
	mu     sync.Mutex
	byUser map[string]*userLicenseDetails
}

type userLicenseDetails struct {
	once  sync.Once
	bySku map[string]models.LicenseDetailsable
	err   error
}

type mqlMicrosoftUserLicenseDetailInternal struct {
	userID string
}

// loadSubscribedSkus returns the tenant's subscribed SKUs, indexed by
// lower-case SKU id as well.
//
// Permissions: LicenseAssignment.Read.All, Organization.Read.All, or Directory.Read.All
func (m *mqlMicrosoft) loadSubscribedSkus() ([]models.SubscribedSkuable, map[string]models.SubscribedSkuable, error) {
	c := &m.subscribedSkus
	c.once.Do(func() {
		conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			c.err = err
			return
		}
		ctx := context.Background()
		resp, err := graphClient.SubscribedSkus().Get(ctx, nil)
		if err != nil {
			c.err = transformError(err)
			return
		}
		skus, err := iterate[models.SubscribedSkuable](ctx, resp, graphClient.GetAdapter(), models.CreateSubscribedSkuCollectionResponseFromDiscriminatorValue)
		if err != nil {
			c.err = err
			return
		}
		c.setSkus(skus)
	})
	return c.skus, c.bySkuID, c.err
}

func (c *subscribedSkuCache) setSkus(skus []models.SubscribedSkuable) {
	c.skus = skus
	c.bySkuID = make(map[string]models.SubscribedSkuable, len(skus))
	for _, sku := range skus {
		if sku.GetSkuId() != nil {
			c.bySkuID[strings.ToLower(sku.GetSkuId().String())] = sku
		}
	}
}

func (a *mqlMicrosoftTenant) subscribedSkus() ([]any, error) {
	res, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	skus, _, err := res.(*mqlMicrosoft).loadSubscribedSkus()
	if err != nil {
		return nil, err
	}
	out := make([]any, 0, len(skus))
	for _, sku := range skus {
		r, err := newMqlMicrosoftTenantSubscribedSku(a.MqlRuntime, sku)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func newMqlMicrosoftTenantSubscribedSku(runtime *plugin.Runtime, sku models.SubscribedSkuable) (*mqlMicrosoftTenantSubscribedSku, error) {
	if sku.GetId() == nil {
		return nil, errors.New("subscribed SKU response is missing an ID")
	}
	servicePlans, err := convert.JsonToDictSlice(newServicePlanInfos(sku.GetServicePlans()))
	if err != nil {
		return nil, err
	}
	prepaid := map[string]any{}
	if p := sku.GetPrepaidUnits(); p != nil {
		prepaid["enabled"] = int64(convert.ToValue(p.GetEnabled()))
		prepaid["suspended"] = int64(convert.ToValue(p.GetSuspended()))
		prepaid["warning"] = int64(convert.ToValue(p.GetWarning()))
		prepaid["lockedOut"] = int64(convert.ToValue(p.GetLockedOut()))
	}
	r, err := CreateResource(runtime, "microsoft.tenant.subscribedSku", map[string]*llx.RawData{
		"__id":             llx.StringDataPtr(sku.GetId()),
		"id":               llx.StringDataPtr(sku.GetId()),
		"skuId":            llx.StringDataPtr(newUuidString(sku.GetSkuId())),
		"skuPartNumber":    llx.StringDataPtr(sku.GetSkuPartNumber()),
		"appliesTo":        llx.StringDataPtr(sku.GetAppliesTo()),
		"capabilityStatus": llx.StringDataPtr(sku.GetCapabilityStatus()),
		"consumedUnits":    llx.IntData(int64(convert.ToValue(sku.GetConsumedUnits()))),
		"prepaidUnits":     llx.DictData(prepaid),
		"servicePlans":     llx.ArrayData(servicePlans, types.Dict),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlMicrosoftTenantSubscribedSku), nil
}

// licenseDetails lists the user's licenses from assignedLicenses and the
// tenant's subscribed SKUs. An assigned SKU the tenant does not hold (for
// example a retired free SKU such as TEAMS_FREE) is left out, as Graph leaves
// it out of the user's licenseDetails.
func (a *mqlMicrosoftUser) licenseDetails() ([]any, error) {
	ms, err := a.microsoftParent()
	if err != nil {
		return nil, err
	}
	_, bySkuID, err := ms.loadSubscribedSkus()
	if err != nil {
		return nil, err
	}
	assigned := a.GetAssignedLicenses()
	if assigned.Error != nil {
		return nil, assigned.Error
	}
	res := []any{}
	for _, raw := range assigned.Data {
		lic, ok := raw.(*mqlMicrosoftUserAssignedLicense)
		if !ok {
			continue
		}
		sku, ok := bySkuID[strings.ToLower(lic.SkuId.Data)]
		if !ok {
			continue
		}
		d, err := newMqlMicrosoftUserLicenseDetail(a.MqlRuntime, a.Id.Data, sku)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func newMqlMicrosoftUserLicenseDetail(runtime *plugin.Runtime, userID string, sku models.SubscribedSkuable) (*mqlMicrosoftUserLicenseDetail, error) {
	graphID, err := graphLicenseDetailID(sku)
	if err != nil {
		return nil, err
	}
	r, err := CreateResource(runtime, "microsoft.user.licenseDetail", map[string]*llx.RawData{
		"__id":          llx.StringData(userLicenseDetailID(userID, graphID)),
		"id":            llx.StringData(graphID),
		"skuId":         llx.StringDataPtr(newUuidString(sku.GetSkuId())),
		"skuPartNumber": llx.StringDataPtr(sku.GetSkuPartNumber()),
	})
	if err != nil {
		return nil, err
	}
	d := r.(*mqlMicrosoftUserLicenseDetail)
	d.userID = userID
	return d, nil
}

// userLicenseDetailID is the cache key for a microsoft.user.licenseDetail.
//
// The Graph licenseDetail id is not unique per user: it is derived from the
// tenant and the SKU, so every user holding the same SKU gets the same id.
// CreateResource is first-wins, so keying on that id alone would report the
// first user's servicePlans for everyone else on that SKU. The key carries the
// user id as well, like userAssignedLicenseID.
func userLicenseDetailID(userID, licenseDetailID string) string {
	return userID + "/" + licenseDetailID
}

// graphLicenseDetailID reproduces the id Graph gives a user's licenseDetails
// entry for a SKU: the tenant and SKU GUIDs in Microsoft's mixed-endian byte
// order, base64url-encoded without padding. Graph does not document this; it
// matches every licenseDetails id we have seen. The tenant id is the first
// part of the subscribed SKU's id, "<tenantId>_<skuId>".
func graphLicenseDetailID(sku models.SubscribedSkuable) (string, error) {
	if sku.GetId() == nil || sku.GetSkuId() == nil {
		return "", errors.New("subscribed SKU response is missing an ID")
	}
	tenantPart, _, ok := strings.Cut(*sku.GetId(), "_")
	if !ok {
		return "", fmt.Errorf("unexpected subscribed SKU id %q", *sku.GetId())
	}
	tenantID, err := uuid.Parse(tenantPart)
	if err != nil {
		return "", fmt.Errorf("unexpected subscribed SKU id %q: %w", *sku.GetId(), err)
	}
	raw := append(microsoftGUIDBytes(tenantID), microsoftGUIDBytes(*sku.GetSkuId())...)
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// microsoftGUIDBytes returns u in the byte order Windows stores a GUID: the
// first three fields little-endian, the rest as is.
func microsoftGUIDBytes(u uuid.UUID) []byte {
	b := u
	b[0], b[1], b[2], b[3] = b[3], b[2], b[1], b[0]
	b[4], b[5] = b[5], b[4]
	b[6], b[7] = b[7], b[6]
	return b[:]
}

// servicePlans reads the user's own licenseDetails from Graph, so
// provisioningStatus is the user's status (for example PendingInput) and not
// the tenant-wide one.
//
// Permissions: User.Read.All, Directory.Read.All
func (a *mqlMicrosoftUserLicenseDetail) servicePlans() ([]any, error) {
	res, err := CreateResource(a.MqlRuntime, "microsoft", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	bySku, err := res.(*mqlMicrosoft).loadUserLicenseDetails(a.userID)
	if err != nil {
		return nil, err
	}
	d, ok := bySku[strings.ToLower(a.SkuId.Data)]
	if !ok {
		return []any{}, nil
	}
	return newMqlServicePlanInfos(a.MqlRuntime, a.__id, d.GetServicePlans())
}

func (m *mqlMicrosoft) loadUserLicenseDetails(userID string) (map[string]models.LicenseDetailsable, error) {
	c := &m.userLicenseDetails
	c.mu.Lock()
	if c.byUser == nil {
		c.byUser = map[string]*userLicenseDetails{}
	}
	entry, ok := c.byUser[userID]
	if !ok {
		entry = &userLicenseDetails{}
		c.byUser[userID] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		conn := m.MqlRuntime.Connection.(*connection.Ms365Connection)
		graphClient, err := conn.GraphClient()
		if err != nil {
			entry.err = err
			return
		}
		ctx := context.Background()
		resp, err := graphClient.Users().ByUserId(userID).LicenseDetails().Get(ctx, nil)
		if err != nil {
			entry.err = transformError(err)
			return
		}
		details, err := iterate[models.LicenseDetailsable](ctx, resp, graphClient.GetAdapter(), models.CreateLicenseDetailsCollectionResponseFromDiscriminatorValue)
		if err != nil {
			entry.err = err
			return
		}
		entry.bySku = make(map[string]models.LicenseDetailsable, len(details))
		for _, d := range details {
			if d.GetSkuId() != nil {
				entry.bySku[strings.ToLower(d.GetSkuId().String())] = d
			}
		}
	})
	return entry.bySku, entry.err
}

func newMqlServicePlanInfos(runtime *plugin.Runtime, detailKey string, plans []models.ServicePlanInfoable) ([]any, error) {
	res := make([]any, 0, len(plans))
	for i, sp := range plans {
		servicePlan, err := CreateResource(runtime, "microsoft.user.licenseDetail.servicePlanInfo",
			map[string]*llx.RawData{
				"__id":               llx.StringData(fmt.Sprintf("%s-service-plans-%d", detailKey, i)),
				"appliesTo":          llx.StringDataPtr(sp.GetAppliesTo()),
				"provisioningStatus": llx.StringDataPtr(sp.GetProvisioningStatus()),
				"servicePlanId":      llx.StringDataPtr(newUuidString(sp.GetServicePlanId())),
				"servicePlanName":    llx.StringDataPtr(sp.GetServicePlanName()),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, servicePlan)
	}
	return res, nil
}
