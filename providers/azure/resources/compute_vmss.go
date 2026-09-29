// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v8"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSetInstance) id() (string, error) {
	return a.Id.Data, nil
}

func initAzureSubscriptionComputeServiceVmScaleSet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure compute virtual machine scale set")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.computeService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	computeSvc := res.(*mqlAzureSubscriptionComputeService)
	scaleSets := computeSvc.GetVmScaleSets()
	if scaleSets.Error != nil {
		return nil, nil, scaleSets.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	if vmss := findVmScaleSetByID(scaleSets.Data, id); vmss != nil {
		return args, vmss, nil
	}
	return nil, nil, errors.New("azure virtual machine scale set does not exist")
}

// findVmScaleSetByID returns the VMSS in scaleSets whose Id matches id
// case-insensitively. Azure ARM resource IDs are case-insensitive, so callers
// that pass an ID with different casing (e.g. from a VM's managedBy) must
// still resolve. Returns nil when no entry matches.
func findVmScaleSetByID(scaleSets []any, id string) *mqlAzureSubscriptionComputeServiceVmScaleSet {
	for _, entry := range scaleSets {
		vmss, ok := entry.(*mqlAzureSubscriptionComputeServiceVmScaleSet)
		if !ok {
			continue
		}
		if strings.EqualFold(vmss.Id.Data, id) {
			return vmss
		}
	}
	return nil
}

func (a *mqlAzureSubscriptionComputeService) vmScaleSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewVirtualMachineScaleSetsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListAllPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list virtual machine scale sets due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, vmss := range page.Value {
			if vmss == nil {
				continue
			}
			mqlVmss, err := vmScaleSetToMql(a.MqlRuntime, *vmss)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVmss)
		}
	}

	return res, nil
}

func vmScaleSetToMql(runtime *plugin.Runtime, vmss compute.VirtualMachineScaleSet) (*mqlAzureSubscriptionComputeServiceVmScaleSet, error) {
	properties, err := convert.JsonToDict(vmss.Properties)
	if err != nil {
		return nil, err
	}
	sku, err := convert.JsonToDict(vmss.SKU)
	if err != nil {
		return nil, err
	}

	systemData, err := convert.JsonToDict(vmss.SystemData)
	if err != nil {
		return nil, err
	}

	identityDict, err := convert.JsonToDict(vmss.Identity)
	if err != nil {
		return nil, err
	}
	vmssIdentity := orZero(vmss.Identity)
	userAssignedIdentityIds := sortedUserAssignedIdentityIDs(vmssIdentity.UserAssignedIdentities)

	args := map[string]*llx.RawData{
		"id":          llx.StringDataPtr(vmss.ID),
		"name":        llx.StringDataPtr(vmss.Name),
		"location":    llx.StringDataPtr(vmss.Location),
		"tags":        llx.MapData(convert.PtrMapStrToInterface(vmss.Tags), types.String),
		"type":        llx.StringDataPtr(vmss.Type),
		"zones":       llx.ArrayData(strPtrsToAny(vmss.Zones), types.String),
		"sku":         llx.DictData(sku),
		"properties":  llx.DictData(properties),
		"identity":    llx.DictData(identityDict),
		"principalId": llx.StringDataPtr(vmssIdentity.PrincipalID),
	}
	vmssSku := orZero(vmss.SKU)
	if err := setSkuData(runtime, args, skuName(vmssSku.Name), skuTier(vmssSku.Tier), skuCapacity(vmssSku.Capacity)); err != nil {
		return nil, err
	}
	if err := setResourceIdentity(runtime, args, userAssignedIdentityIds,
		identityType(vmssIdentity.Type), identityPrincipalId(vmssIdentity.PrincipalID), identityTenantId(vmssIdentity.TenantID)); err != nil {
		return nil, err
	}

	if vmss.Properties != nil {
		props := vmss.Properties
		args["orchestrationMode"] = llx.StringDataPtr(stringEnumPtr(props.OrchestrationMode))
		args["provisioningState"] = llx.StringDataPtr(props.ProvisioningState)
		args["timeCreated"] = llx.TimeDataPtr(props.TimeCreated)
		args["uniqueId"] = llx.StringDataPtr(props.UniqueID)
		args["singlePlacementGroup"] = llx.BoolDataPtr(props.SinglePlacementGroup)
		args["overprovision"] = llx.BoolDataPtr(props.Overprovision)
		args["platformFaultDomainCount"] = llx.IntDataPtr(props.PlatformFaultDomainCount)
		args["zonalPlatformFaultDomainAlignMode"] = llx.StringDataPtr(stringEnumPtr(props.ZonalPlatformFaultDomainAlignMode))
		upgradePolicy, err := convert.JsonToDict(props.UpgradePolicy)
		if err != nil {
			return nil, err
		}
		args["upgradePolicy"] = llx.DictData(upgradePolicy)
		repairPolicy, err := convert.JsonToDict(props.AutomaticRepairsPolicy)
		if err != nil {
			return nil, err
		}
		args["automaticRepairsPolicy"] = llx.DictData(repairPolicy)
		resiliencyPolicy, err := convert.JsonToDict(props.ResiliencyPolicy)
		if err != nil {
			return nil, err
		}
		args["resiliencyPolicy"] = llx.DictData(resiliencyPolicy)
		scheduledEventsPolicy, err := convert.JsonToDict(props.ScheduledEventsPolicy)
		if err != nil {
			return nil, err
		}
		args["scheduledEventsPolicy"] = llx.DictData(scheduledEventsPolicy)
		priorityMixPolicy, err := convert.JsonToDict(props.PriorityMixPolicy)
		if err != nil {
			return nil, err
		}
		args["priorityMixPolicy"] = llx.DictData(priorityMixPolicy)
		spotRestorePolicy, err := convert.JsonToDict(props.SpotRestorePolicy)
		if err != nil {
			return nil, err
		}
		args["spotRestorePolicy"] = llx.DictData(spotRestorePolicy)
		skuProfile, err := convert.JsonToDict(props.SKUProfile)
		if err != nil {
			return nil, err
		}
		args["skuProfile"] = llx.DictData(skuProfile)
		var securityPosture map[string]any
		var encryptionAtHost, secureBootEnabled, vtpmEnabled *bool
		var securityType *string
		if props.VirtualMachineProfile != nil {
			securityPosture, err = convert.JsonToDict(props.VirtualMachineProfile.SecurityPostureReference)
			if err != nil {
				return nil, err
			}
			if sp := props.VirtualMachineProfile.SecurityProfile; sp != nil {
				encryptionAtHost = sp.EncryptionAtHost
				securityType = (*string)(sp.SecurityType)
				if sp.UefiSettings != nil {
					secureBootEnabled = sp.UefiSettings.SecureBootEnabled
					vtpmEnabled = sp.UefiSettings.VTpmEnabled
				}
			}
		}
		args["securityPostureReference"] = llx.DictData(securityPosture)
		args["encryptionAtHost"] = llx.BoolDataPtr(encryptionAtHost)
		args["securityType"] = llx.StringDataPtr(securityType)
		args["secureBootEnabled"] = llx.BoolDataPtr(secureBootEnabled)
		args["vtpmEnabled"] = llx.BoolDataPtr(vtpmEnabled)
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.vmScaleSet", args)
	if err != nil {
		return nil, err
	}
	mqlVmss := res.(*mqlAzureSubscriptionComputeServiceVmScaleSet)
	mqlVmss.cacheUserAssignedIdentityIds = userAssignedIdentityIds
	mqlVmss.cacheSystemData = systemData
	return mqlVmss, nil
}

type mqlAzureSubscriptionComputeServiceVmScaleSetInternal struct {
	cacheUserAssignedIdentityIds []string
	cacheSystemData              any

	extensionsMu     sync.Mutex
	extensionsLoaded atomic.Bool
	extensionsList   []*compute.VirtualMachineScaleSetExtension
	extensionsErr    error
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) systemAssignedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return newSystemAssignedManagedIdentity(a.MqlRuntime, a.Id.Data, a.PrincipalId.Data, tenantIDFromIdentityDict(a.Identity), &a.SystemAssignedIdentity)
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	vmssName, err := resourceID.Component("virtualMachineScaleSets")
	if err != nil {
		return nil, err
	}

	client, err := compute.NewVirtualMachineScaleSetVMsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, vmssName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msgf("could not list virtual machine scale set instances for %s due to access denied", vmssName)
				return res, nil
			}
			return nil, err
		}
		for _, inst := range page.Value {
			if inst == nil {
				continue
			}
			mqlInst, err := vmScaleSetInstanceToMql(a.MqlRuntime, *inst)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlInst)
		}
	}

	return res, nil
}

func vmScaleSetInstanceToMql(runtime *plugin.Runtime, inst compute.VirtualMachineScaleSetVM) (*mqlAzureSubscriptionComputeServiceVmScaleSetInstance, error) {
	properties, err := convert.JsonToDict(inst.Properties)
	if err != nil {
		return nil, err
	}
	sku, err := convert.JsonToDict(inst.SKU)
	if err != nil {
		return nil, err
	}

	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(inst.ID),
		"instanceId": llx.StringDataPtr(inst.InstanceID),
		"name":       llx.StringDataPtr(inst.Name),
		"location":   llx.StringDataPtr(inst.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(inst.Tags), types.String),
		"zones":      llx.ArrayData(strPtrsToAny(inst.Zones), types.String),
		"properties": llx.DictData(properties),
		"sku":        llx.DictData(sku),
	}
	instSku := orZero(inst.SKU)
	if err := setSkuData(runtime, args, skuName(instSku.Name), skuTier(instSku.Tier), skuCapacity(instSku.Capacity)); err != nil {
		return nil, err
	}

	if inst.Properties != nil {
		props := inst.Properties
		args["latestModelApplied"] = llx.BoolDataPtr(props.LatestModelApplied)
		args["provisioningState"] = llx.StringDataPtr(props.ProvisioningState)
		args["modelDefinitionApplied"] = llx.StringDataPtr(props.ModelDefinitionApplied)
		args["vmId"] = llx.StringDataPtr(props.VMID)
		args["timeCreated"] = llx.TimeDataPtr(props.TimeCreated)
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.vmScaleSet.instance", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(inst.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceVmScaleSetInstance).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceVmScaleSetInstance), nil
}

type mqlAzureSubscriptionComputeServiceVmScaleSetInstanceInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSetInstance) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) extensions() ([]any, error) {
	list, err := a.fetchExtensions()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, ext := range list {
		d, err := convert.JsonToDict(ext.Properties)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

// fetchExtensions lists the scale set's extensions once and shares the result
// between extensions and installedExtensions.
func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) fetchExtensions() ([]*compute.VirtualMachineScaleSetExtension, error) {
	if a.extensionsLoaded.Load() {
		return a.extensionsList, a.extensionsErr
	}
	a.extensionsMu.Lock()
	defer a.extensionsMu.Unlock()
	if a.extensionsLoaded.Load() {
		return a.extensionsList, a.extensionsErr
	}
	list, err := a.loadExtensions()
	a.extensionsList = list
	a.extensionsErr = err
	a.extensionsLoaded.Store(true)
	return list, err
}

func (a *mqlAzureSubscriptionComputeServiceVmScaleSet) loadExtensions() ([]*compute.VirtualMachineScaleSetExtension, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}
	vmssName, err := resourceID.Component("virtualMachineScaleSets")
	if err != nil {
		return nil, err
	}

	client, err := compute.NewVirtualMachineScaleSetExtensionsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, vmssName, nil)
	res := []*compute.VirtualMachineScaleSetExtension{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden && !plugin.StructuredErrors() {
				log.Warn().Err(err).Msgf("could not list virtual machine scale set extensions for %s due to access denied", vmssName)
				return res, nil
			}
			return nil, classifyAzureRefusal(err, "Microsoft.Compute/virtualMachineScaleSets/extensions/read")
		}
		for _, ext := range page.Value {
			if ext == nil {
				continue
			}
			res = append(res, ext)
		}
	}
	return res, nil
}

// vmScaleSetIDFromManagedBy returns the VMSS ARM ID to look up from a VM's
// managedBy value, truncated to the VMSS segment and lowercased so callers
// can compare case-insensitively against a VMSS's own Id. Returns "" when
// managedBy is empty, malformed, or points to a non-VMSS resource.
func vmScaleSetIDFromManagedBy(managedBy string) string {
	if managedBy == "" {
		return ""
	}
	parsed, err := ParseResourceID(managedBy)
	if err != nil {
		return ""
	}
	vmssName, ok := parsed.Path["virtualmachinescalesets"]
	if !ok {
		return ""
	}
	return strings.ToLower(fmt.Sprintf(
		"/subscriptions/%s/resourceGroups/%s/providers/Microsoft.Compute/virtualMachineScaleSets/%s",
		parsed.SubscriptionID, parsed.ResourceGroup, vmssName,
	))
}

// vmScaleSet returns the VMSS that manages this VM, derived from the existing
// managedBy field. Returns nil with StateIsSet|StateIsNull when the VM is not
// managed by a VMSS or managedBy points to something else.
func (a *mqlAzureSubscriptionComputeServiceVm) vmScaleSet() (*mqlAzureSubscriptionComputeServiceVmScaleSet, error) {
	id := vmScaleSetIDFromManagedBy(a.ManagedBy.Data)
	if id == "" {
		a.VmScaleSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.vmScaleSet", map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceVmScaleSet), nil
}
