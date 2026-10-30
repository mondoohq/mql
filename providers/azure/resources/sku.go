// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const (
	resourceSkuResource      = "azure.subscription.resourceSku"
	resourceIdentityResource = "azure.subscription.resourceIdentity"
)

// subResourceParentKey returns the cache key of the resource currently being
// built, so a child resource can be keyed off it. Callers always set one of
// these before the child is created; reporting the miss keeps a child that
// would otherwise collide with every other parent's out of the cache.
func subResourceParentKey(args map[string]*llx.RawData) string {
	for _, key := range []string{"__id", "id"} {
		if v, ok := args[key]; ok {
			if s, ok := v.Value.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

// allMembersNull reports whether every member the caller passed is null, which
// is how an absent ARM block arrives: the struct pointer is nil, so every
// member read off it is nil.
func allMembersNull(args map[string]*llx.RawData) bool {
	for _, v := range args {
		if v.Value != nil {
			return false
		}
	}
	return true
}

// skuOption sets one member of the shared SKU resource.
type skuOption func(map[string]*llx.RawData)

// setSkuData publishes an ARM SKU as an azure.subscription.resourceSku child of
// the resource being built.
//
// ARM models a different subset of {Name, Tier, Size, Family, Model, Capacity}
// per service: armredis.SKU and armautomation.SKU carry no Tier, and
// armsearch.SKU, armcdn.SKU, armappconfiguration.SKU and the armnetwork
// bastion SKU carry Name alone. A member the caller does not pass is never
// written, so it resolves to null rather than to an empty string that would
// read as "the tier is blank". A service that reported no SKU at all leaves
// every member null, and skuData itself is then null rather than a resource
// full of nulls.
func setSkuData(runtime *plugin.Runtime, args map[string]*llx.RawData, opts ...skuOption) error {
	data, err := skuDataFor(runtime, subResourceParentKey(args), opts...)
	if err != nil {
		return err
	}
	args["skuData"] = data
	return nil
}

// skuDataFor is setSkuData for a caller that passes its argument map inline to
// CreateResource and so cannot have the map written to.
func skuDataFor(runtime *plugin.Runtime, parentID string, opts ...skuOption) (*llx.RawData, error) {
	skuArgs := skuFields(opts...)
	if allMembersNull(skuArgs) {
		return llx.NilData, nil
	}
	if parentID == "" {
		return nil, errors.New("cannot key a SKU resource: the parent has no id")
	}
	skuArgs["__id"] = llx.StringData(parentID + "/sku")
	res, err := CreateResource(runtime, resourceSkuResource, skuArgs)
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, resourceSkuResource), nil
}

// skuFields builds the member map the shared SKU resource is created from.
// Exported to the package for the tests, which assert on which members a
// service publishes.
func skuFields(opts ...skuOption) map[string]*llx.RawData {
	args := make(map[string]*llx.RawData, len(opts)+1)
	for _, opt := range opts {
		opt(args)
	}
	return args
}

// skuName publishes SKU.Name. The type parameter accepts the named string
// types ARM uses for SKU name enums as well as a plain *string.
func skuName[T ~string](v *T) skuOption {
	return func(args map[string]*llx.RawData) {
		args["name"] = llx.StringDataPtr(stringEnumPtr(v))
	}
}

// skuTier publishes SKU.Tier.
func skuTier[T ~string](v *T) skuOption {
	return func(args map[string]*llx.RawData) {
		args["tier"] = llx.StringDataPtr(stringEnumPtr(v))
	}
}

// skuSize publishes SKU.Size.
func skuSize[T ~string](v *T) skuOption {
	return func(args map[string]*llx.RawData) {
		args["size"] = llx.StringDataPtr(stringEnumPtr(v))
	}
}

// skuFamily publishes SKU.Family.
func skuFamily[T ~string](v *T) skuOption {
	return func(args map[string]*llx.RawData) {
		args["family"] = llx.StringDataPtr(stringEnumPtr(v))
	}
}

// skuModel publishes SKU.Model, which only the generic ARM resource SKU and a
// handful of services report.
func skuModel[T ~string](v *T) skuOption {
	return func(args map[string]*llx.RawData) {
		args["model"] = llx.StringDataPtr(stringEnumPtr(v))
	}
}

// skuCapacity publishes SKU.Capacity. ARM types it *int64 on armcompute.SKU
// and armiothub.SKUInfo and *int32 nearly everywhere else.
func skuCapacity[T int32 | int64 | int](v *T) skuOption {
	return func(args map[string]*llx.RawData) {
		args["capacity"] = llx.IntDataPtr(v)
	}
}

// identityOption sets one member of the shared managed-identity resource.
type identityOption func(map[string]*llx.RawData)

// setResourceIdentity publishes an ARM managed-identity block as an
// azure.subscription.resourceIdentity child of the resource being built.
//
// The ARM identity block is {Type, PrincipalID, TenantID,
// UserAssignedIdentities} across armcompute, armcontainerservice,
// armcontainerinstance, armappservice, armredis, armsearch, armmachinelearning,
// armbatch and armresources. It is not universal: armbatch.PoolIdentity carries
// neither PrincipalID nor TenantID, and armdesktopvirtualization carries no
// UserAssignedIdentities. A member the caller does not pass resolves to null,
// so a Batch pool never reports a blank principal that Azure did not give.
//
// userAssignedIDs are the ARM resource IDs of the attached user-assigned
// identities, in stable order. They are held on the identity resource and
// resolved on demand, because resolving them eagerly would run one
// managedIdentity init per attached identity per resource in the scan.
//
// A resource with no identity block at all reports resourceIdentity as null rather
// than as a resource whose every member is null.
func setResourceIdentity(runtime *plugin.Runtime, args map[string]*llx.RawData, userAssignedIDs []string, opts ...identityOption) error {
	data, err := resourceIdentityData(runtime, subResourceParentKey(args), userAssignedIDs, opts...)
	if err != nil {
		return err
	}
	args["resourceIdentity"] = data
	return nil
}

// resourceIdentityData is setResourceIdentity for a caller that passes its argument map
// inline to CreateResource and so cannot have the map written to.
func resourceIdentityData(runtime *plugin.Runtime, parentID string, userAssignedIDs []string, opts ...identityOption) (*llx.RawData, error) {
	idArgs := identityFields(opts...)
	if allMembersNull(idArgs) && len(userAssignedIDs) == 0 {
		return llx.NilData, nil
	}
	if parentID == "" {
		return nil, errors.New("cannot key a managed-identity resource: the parent has no id")
	}
	idArgs["__id"] = llx.StringData(parentID + "/identity")
	res, err := CreateResource(runtime, resourceIdentityResource, idArgs)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionResourceIdentity).cacheUserAssignedIdentityIds = userAssignedIDs
	return llx.ResourceData(res, resourceIdentityResource), nil
}

// identityFields builds the member map the shared identity resource is created
// from. Exported to the package for the tests.
func identityFields(opts ...identityOption) map[string]*llx.RawData {
	args := make(map[string]*llx.RawData, len(opts)+1)
	for _, opt := range opts {
		opt(args)
	}
	return args
}

// identityType publishes Identity.Type.
func identityType[T ~string](v *T) identityOption {
	return func(args map[string]*llx.RawData) {
		args["type"] = llx.StringDataPtr(stringEnumPtr(v))
	}
}

// identityPrincipalId publishes Identity.PrincipalID, the object ID of the
// system-assigned identity.
func identityPrincipalId(v *string) identityOption {
	return func(args map[string]*llx.RawData) {
		args["principalId"] = llx.StringDataPtr(v)
	}
}

// identityTenantId publishes Identity.TenantID.
func identityTenantId(v *string) identityOption {
	return func(args map[string]*llx.RawData) {
		args["tenantId"] = llx.StringDataPtr(v)
	}
}

type mqlAzureSubscriptionResourceIdentityInternal struct {
	cacheUserAssignedIdentityIds []string
}

func (a *mqlAzureSubscriptionResourceIdentity) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}
