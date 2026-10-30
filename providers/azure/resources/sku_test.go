// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	armautomation "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/automation/armautomation"
	armbatch "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/batch/armbatch/v4"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	armredis "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/redis/armredis/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// azureTestRuntime is enough runtime to run CreateResource, which the shared
// SKU and identity resources are built through.
func azureTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

// The point of the per-member options is that a resource publishes only what
// its ARM SKU struct models. Publishing the union instead would report an
// empty tier on every Redis cache and every Automation account, which reads as
// "the tier is blank" rather than as "this service has no tier".
func TestSkuFieldsPublishOnlyTheMembersPassed(t *testing.T) {
	t.Run("a SKU with no tier never publishes a tier", func(t *testing.T) {
		sku := armredis.SKU{
			Name:     ptr(armredis.SKUNamePremium),
			Family:   ptr(armredis.SKUFamilyP),
			Capacity: new(int32(3)),
		}
		args := skuFields(skuName(sku.Name), skuFamily(sku.Family), skuCapacity(sku.Capacity))

		assert.NotContains(t, args, "tier")
		assert.NotContains(t, args, "size")
		require.Contains(t, args, "name")
		assert.Equal(t, "Premium", args["name"].Value)
		assert.Equal(t, "P", args["family"].Value)
		assert.Equal(t, int64(3), args["capacity"].Value)
	})

	t.Run("a name-only SKU publishes name alone", func(t *testing.T) {
		name := armautomation.SKUNameEnumBasic
		args := skuFields(skuName(&name))

		require.Len(t, args, 1)
		assert.Equal(t, "Basic", args["name"].Value)
	})

	// armcompute types Capacity as *int64 where nearly every other service
	// types it *int32; both have to land on the same int64 field.
	t.Run("capacity is published from either width", func(t *testing.T) {
		wide := skuFields(skuCapacity(new(int64(12))))
		narrow := skuFields(skuCapacity(new(int32(12))))

		assert.Equal(t, int64(12), wide["capacity"].Value)
		assert.Equal(t, int64(12), narrow["capacity"].Value)
	})

	// An absent member is still declared, so the field resolves to null rather
	// than failing with "no type information".
	t.Run("an absent member is set and null, not missing", func(t *testing.T) {
		var sku compute.SKU
		args := skuFields(skuName(sku.Name), skuTier(sku.Tier), skuCapacity(sku.Capacity))

		require.Contains(t, args, "name")
		assert.Nil(t, args["name"].Value)
		assert.Nil(t, args["tier"].Value)
		assert.Nil(t, args["capacity"].Value)
	})
}

// setSkuData hangs the SKU off the parent's cache key, so two resources of the
// same kind do not share one SKU row, and a service that reported no SKU reads
// null rather than a resource whose every member is null.
func TestSetSkuRef(t *testing.T) {
	t.Run("a reported SKU is keyed off the parent", func(t *testing.T) {
		runtime := azureTestRuntime()
		args := map[string]*llx.RawData{"id": llx.StringData("/subscriptions/s/rg/disks/one")}
		require.NoError(t, setSkuData(runtime, args, skuName(new("Premium_LRS")), skuTier(new("Premium"))))

		res, ok := args["skuData"].Value.(*mqlAzureSubscriptionResourceSku)
		require.True(t, ok, "skuData should hold a resourceSku")
		assert.Equal(t, "/subscriptions/s/rg/disks/one/sku", res.MqlID())
		assert.Equal(t, "Premium_LRS", res.GetName().Data)
		assert.Equal(t, "Premium", res.GetTier().Data)
		// Nothing passed for size, so it never becomes an empty string.
		assert.True(t, res.Size.State&plugin.StateIsNull != 0 || res.Size.Data == "")
	})

	t.Run("a resource with no SKU reports null, not an empty SKU", func(t *testing.T) {
		runtime := azureTestRuntime()
		var sku *compute.SKU
		args := map[string]*llx.RawData{"id": llx.StringData("/subscriptions/s/rg/disks/two")}
		require.NoError(t, setSkuData(runtime, args, skuName(orZero(sku).Name), skuTier(orZero(sku).Tier)))

		assert.Nil(t, args["skuData"].Value)
	})

	// A parent with no key would give every SKU in the scan the same cache id,
	// and every resource would then report the first one's tier.
	t.Run("a parent with no key is an error, not a shared cache row", func(t *testing.T) {
		runtime := azureTestRuntime()
		args := map[string]*llx.RawData{}
		assert.Error(t, setSkuData(runtime, args, skuName(new("Standard"))))
	})
}

func TestIdentityFieldsPublishOnlyTheMembersPassed(t *testing.T) {
	t.Run("the shared shape publishes all three scalars", func(t *testing.T) {
		identity := compute.VirtualMachineIdentity{
			Type:        ptr(compute.ResourceIdentityTypeSystemAssignedUserAssigned),
			PrincipalID: new("principal-1"),
			TenantID:    new("tenant-1"),
			UserAssignedIdentities: map[string]*compute.UserAssignedIdentitiesValue{
				"/subscriptions/s/b": {},
				"/subscriptions/s/a": {},
			},
		}
		got := identityFields(
			identityType(identity.Type),
			identityPrincipalId(identity.PrincipalID),
			identityTenantId(identity.TenantID),
		)

		assert.Equal(t, "SystemAssigned, UserAssigned", got["type"].Value)
		assert.Equal(t, "principal-1", got["principalId"].Value)
		assert.Equal(t, "tenant-1", got["tenantId"].Value)
		// Sorted, so the attached identities do not reorder between scans.
		assert.Equal(t,
			[]string{"/subscriptions/s/a", "/subscriptions/s/b"},
			sortedUserAssignedIdentityIDs(identity.UserAssignedIdentities))
	})

	// armbatch.PoolIdentity has no PrincipalID or TenantID. Publishing them
	// anyway would report every Batch pool as having a system-assigned
	// identity with a blank principal, which is not what Azure said.
	t.Run("a batch pool identity publishes the type alone", func(t *testing.T) {
		identity := armbatch.PoolIdentity{
			Type: ptr(armbatch.PoolIdentityTypeUserAssigned),
			UserAssignedIdentities: map[string]*armbatch.UserAssignedIdentities{
				"/subscriptions/s/a": {},
			},
		}
		got := identityFields(identityType(identity.Type))

		require.Len(t, got, 1)
		assert.Equal(t, "UserAssigned", got["type"].Value)
		assert.NotContains(t, got, "principalId")
		assert.NotContains(t, got, "tenantId")
	})

	t.Run("no attached identities is nil, not an empty entry", func(t *testing.T) {
		assert.Nil(t, sortedUserAssignedIdentityIDs(map[string]*compute.UserAssignedIdentitiesValue{}))
		assert.Nil(t, sortedUserAssignedIdentityIDs[*compute.UserAssignedIdentitiesValue](nil))
	})
}

func TestSetIdentityRef(t *testing.T) {
	// A Batch pool reports a type and attached identities but no principal, so
	// principalId has to read null. Publishing an empty string there would
	// report a system-assigned identity the pool does not have.
	t.Run("a batch pool leaves the principal null", func(t *testing.T) {
		runtime := azureTestRuntime()
		identity := armbatch.PoolIdentity{
			Type: ptr(armbatch.PoolIdentityTypeUserAssigned),
			UserAssignedIdentities: map[string]*armbatch.UserAssignedIdentities{
				"/subscriptions/s/a": {},
			},
		}
		args := map[string]*llx.RawData{"__id": llx.StringData("/pools/one")}
		require.NoError(t, setResourceIdentity(runtime, args,
			sortedUserAssignedIdentityIDs(identity.UserAssignedIdentities),
			identityType(identity.Type)))

		res, ok := args["resourceIdentity"].Value.(*mqlAzureSubscriptionResourceIdentity)
		require.True(t, ok, "resourceIdentity should hold a resourceIdentity")
		assert.Equal(t, "/pools/one/identity", res.MqlID())
		assert.Equal(t, "UserAssigned", res.GetType().Data)
		assert.Equal(t, "", res.PrincipalId.Data)
		assert.NotEqual(t, 0, res.PrincipalId.State&plugin.StateIsNull)
		assert.Equal(t, []string{"/subscriptions/s/a"}, res.cacheUserAssignedIdentityIds)
	})

	// A resource ARM returns with no identity block at all must not report an
	// identity resource whose members are all null; that reads as "there is an
	// identity and Azure told us nothing about it".
	t.Run("no identity block reports null", func(t *testing.T) {
		runtime := azureTestRuntime()
		var identity *compute.VirtualMachineIdentity
		args := map[string]*llx.RawData{"id": llx.StringData("/vms/one")}
		require.NoError(t, setResourceIdentity(runtime, args, nil,
			identityType(orZero(identity).Type),
			identityPrincipalId(orZero(identity).PrincipalID),
			identityTenantId(orZero(identity).TenantID)))

		assert.Nil(t, args["resourceIdentity"].Value)
	})

	// A user-assigned-only identity reports no principal but does report the
	// attached identities, so the resource still has to be published.
	t.Run("attached identities alone still publish the resource", func(t *testing.T) {
		runtime := azureTestRuntime()
		args := map[string]*llx.RawData{"id": llx.StringData("/vms/two")}
		require.NoError(t, setResourceIdentity(runtime, args, []string{"/subscriptions/s/a"}))

		res, ok := args["resourceIdentity"].Value.(*mqlAzureSubscriptionResourceIdentity)
		require.True(t, ok)
		assert.Equal(t, []string{"/subscriptions/s/a"}, res.cacheUserAssignedIdentityIds)
	})
}
