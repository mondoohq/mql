// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	compute "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v9"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// ----- Dedicated Host Groups + Hosts -----

func (a *mqlAzureSubscriptionComputeServiceDedicatedHostGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceDedicatedHost) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeService) dedicatedHostGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewDedicatedHostGroupsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list dedicated host groups due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, hg := range page.Value {
			if hg == nil {
				continue
			}
			mqlHg, err := dedicatedHostGroupToMql(a.MqlRuntime, *hg)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlHg)
		}
	}
	return res, nil
}

func dedicatedHostGroupToMql(runtime *plugin.Runtime, hg compute.DedicatedHostGroup) (*mqlAzureSubscriptionComputeServiceDedicatedHostGroup, error) {
	properties, err := convert.JsonToDict(hg.Properties)
	if err != nil {
		return nil, err
	}
	zones := []any{}
	for _, z := range hg.Zones {
		if z != nil {
			zones = append(zones, *z)
		}
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(hg.ID),
		"name":       llx.StringDataPtr(hg.Name),
		"location":   llx.StringDataPtr(hg.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(hg.Tags), types.String),
		"type":       llx.StringDataPtr(hg.Type),
		"zones":      llx.ArrayData(zones, types.String),
		"properties": llx.DictData(properties),
	}

	args["platformFaultDomainCount"] = llx.IntDataPtr[int32](nil)
	args["supportAutomaticPlacement"] = llx.BoolDataPtr(nil)
	args["additionalCapabilities"] = llx.DictData(map[string]any{})
	args["instanceView"] = llx.DictData(map[string]any{})

	if hg.Properties != nil {
		props := hg.Properties
		args["platformFaultDomainCount"] = llx.IntDataPtr(props.PlatformFaultDomainCount)
		args["supportAutomaticPlacement"] = llx.BoolDataPtr(props.SupportAutomaticPlacement)
		if props.AdditionalCapabilities != nil {
			d, err := convert.JsonToDict(props.AdditionalCapabilities)
			if err != nil {
				return nil, err
			}
			args["additionalCapabilities"] = llx.DictData(d)
		}
		if props.InstanceView != nil {
			d, err := convert.JsonToDict(props.InstanceView)
			if err != nil {
				return nil, err
			}
			args["instanceView"] = llx.DictData(d)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.dedicatedHostGroup", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(hg.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceDedicatedHostGroup).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceDedicatedHostGroup), nil
}

type mqlAzureSubscriptionComputeServiceDedicatedHostGroupInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceDedicatedHostGroup) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceDedicatedHostGroup) hosts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := compute.NewDedicatedHostsClient(parsed.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListByHostGroupPager(parsed.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list dedicated hosts due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, host := range page.Value {
			if host == nil {
				continue
			}
			mqlHost, err := dedicatedHostToMql(a.MqlRuntime, *host)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlHost)
		}
	}
	return res, nil
}

func dedicatedHostToMql(runtime *plugin.Runtime, host compute.DedicatedHost) (*mqlAzureSubscriptionComputeServiceDedicatedHost, error) {
	properties, err := convert.JsonToDict(host.Properties)
	if err != nil {
		return nil, err
	}
	sku, err := convert.JsonToDict(host.SKU)
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(host.ID),
		"name":       llx.StringDataPtr(host.Name),
		"location":   llx.StringDataPtr(host.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(host.Tags), types.String),
		"type":       llx.StringDataPtr(host.Type),
		"sku":        llx.DictData(sku),
		"properties": llx.DictData(properties),
	}
	hostSku := orZero(host.SKU)
	if err := setSkuData(runtime, args, skuName(hostSku.Name), skuTier(hostSku.Tier), skuCapacity(hostSku.Capacity)); err != nil {
		return nil, err
	}

	args["platformFaultDomain"] = llx.IntDataPtr[int32](nil)
	args["autoReplaceOnFailure"] = llx.BoolDataPtr(nil)
	args["hostId"] = llx.StringDataPtr(nil)
	args["licenseType"] = llx.StringDataPtr(nil)
	args["provisioningTime"] = llx.TimeDataPtr(nil)
	args["provisioningState"] = llx.StringDataPtr(nil)
	args["timeCreated"] = llx.TimeDataPtr(nil)
	args["instanceView"] = llx.DictData(map[string]any{})

	if host.Properties != nil {
		p := host.Properties
		args["platformFaultDomain"] = llx.IntDataPtr(p.PlatformFaultDomain)
		args["autoReplaceOnFailure"] = llx.BoolDataPtr(p.AutoReplaceOnFailure)
		args["hostId"] = llx.StringDataPtr(p.HostID)
		args["licenseType"] = llx.StringDataPtr(stringEnumPtr(p.LicenseType))
		args["provisioningTime"] = llx.TimeDataPtr(p.ProvisioningTime)
		args["provisioningState"] = llx.StringDataPtr(p.ProvisioningState)
		args["timeCreated"] = llx.TimeDataPtr(p.TimeCreated)
		if p.InstanceView != nil {
			d, err := convert.JsonToDict(p.InstanceView)
			if err != nil {
				return nil, err
			}
			args["instanceView"] = llx.DictData(d)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.dedicatedHost", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(host.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceDedicatedHost).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceDedicatedHost), nil
}

type mqlAzureSubscriptionComputeServiceDedicatedHostInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceDedicatedHost) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// ----- Proximity Placement Groups -----

func (a *mqlAzureSubscriptionComputeServiceProximityPlacementGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeService) proximityPlacementGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewProximityPlacementGroupsClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListBySubscriptionPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list proximity placement groups due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ppg := range page.Value {
			if ppg == nil {
				continue
			}
			mqlPpg, err := proximityPlacementGroupToMql(a.MqlRuntime, *ppg)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPpg)
		}
	}
	return res, nil
}

func proximityPlacementGroupToMql(runtime *plugin.Runtime, ppg compute.ProximityPlacementGroup) (*mqlAzureSubscriptionComputeServiceProximityPlacementGroup, error) {
	properties, err := convert.JsonToDict(ppg.Properties)
	if err != nil {
		return nil, err
	}
	zones := []any{}
	for _, z := range ppg.Zones {
		if z != nil {
			zones = append(zones, *z)
		}
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(ppg.ID),
		"name":       llx.StringDataPtr(ppg.Name),
		"location":   llx.StringDataPtr(ppg.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(ppg.Tags), types.String),
		"type":       llx.StringDataPtr(ppg.Type),
		"zones":      llx.ArrayData(zones, types.String),
		"properties": llx.DictData(properties),
	}

	args["proximityPlacementGroupType"] = llx.StringDataPtr(nil)
	args["intent"] = llx.DictData(map[string]any{})
	args["virtualMachineIds"] = llx.ArrayData([]any{}, types.String)
	args["virtualMachineScaleSetIds"] = llx.ArrayData([]any{}, types.String)
	args["availabilitySetIds"] = llx.ArrayData([]any{}, types.String)

	if ppg.Properties != nil {
		p := ppg.Properties
		args["proximityPlacementGroupType"] = llx.StringDataPtr(stringEnumPtr(p.ProximityPlacementGroupType))
		if p.Intent != nil {
			d, err := convert.JsonToDict(p.Intent)
			if err != nil {
				return nil, err
			}
			args["intent"] = llx.DictData(d)
		}
		args["virtualMachineIds"] = llx.ArrayData(colocSubResourceIDs(p.VirtualMachines), types.String)
		args["virtualMachineScaleSetIds"] = llx.ArrayData(colocSubResourceIDs(p.VirtualMachineScaleSets), types.String)
		args["availabilitySetIds"] = llx.ArrayData(colocSubResourceIDs(p.AvailabilitySets), types.String)
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.proximityPlacementGroup", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(ppg.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceProximityPlacementGroup).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceProximityPlacementGroup), nil
}

type mqlAzureSubscriptionComputeServiceProximityPlacementGroupInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceProximityPlacementGroup) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// colocSubResourceIDs flattens a slice of *SubResourceWithColocationStatus
// into the underlying ID strings. Used by proximityPlacementGroup, where the
// member references are returned as colocation-status sub-resources.
func colocSubResourceIDs(items []*compute.SubResourceWithColocationStatus) []any {
	res := make([]any, 0, len(items))
	for _, it := range items {
		if it == nil || it.ID == nil || *it.ID == "" {
			continue
		}
		res = append(res, *it.ID)
	}
	return res
}

// ----- Managed Images -----

func (a *mqlAzureSubscriptionComputeServiceImage) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeService) images() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewImagesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list managed images due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, img := range page.Value {
			if img == nil {
				continue
			}
			mqlImg, err := imageToMql(a.MqlRuntime, *img)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlImg)
		}
	}
	return res, nil
}

func imageToMql(runtime *plugin.Runtime, img compute.Image) (*mqlAzureSubscriptionComputeServiceImage, error) {
	properties, err := convert.JsonToDict(img.Properties)
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(img.ID),
		"name":       llx.StringDataPtr(img.Name),
		"location":   llx.StringDataPtr(img.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(img.Tags), types.String),
		"type":       llx.StringDataPtr(img.Type),
		"properties": llx.DictData(properties),
	}

	args["sourceVirtualMachineId"] = llx.StringDataPtr(nil)
	args["storageProfile"] = llx.DictData(map[string]any{})
	args["provisioningState"] = llx.StringDataPtr(nil)
	args["hyperVGeneration"] = llx.StringDataPtr(nil)

	if img.Properties != nil {
		p := img.Properties
		if p.SourceVirtualMachine != nil {
			args["sourceVirtualMachineId"] = llx.StringDataPtr(p.SourceVirtualMachine.ID)
		}
		if p.StorageProfile != nil {
			d, err := convert.JsonToDict(p.StorageProfile)
			if err != nil {
				return nil, err
			}
			args["storageProfile"] = llx.DictData(d)
		}
		args["provisioningState"] = llx.StringDataPtr(p.ProvisioningState)
		args["hyperVGeneration"] = llx.StringDataPtr(stringEnumPtr(p.HyperVGeneration))
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.image", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(img.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceImage).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceImage), nil
}

type mqlAzureSubscriptionComputeServiceImageInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceImage) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceImage) sourceVirtualMachine() (*mqlAzureSubscriptionComputeServiceVm, error) {
	id := a.SourceVirtualMachineId.Data
	if id == "" {
		a.SourceVirtualMachine.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.vm", map[string]*llx.RawData{
		"id": llx.StringData(strings.ToLower(id)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceVm), nil
}

// ----- Compute Galleries (Shared Image Gallery) -----

func (a *mqlAzureSubscriptionComputeServiceGallery) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceGalleryImage) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeServiceGalleryImageVersion) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionComputeService) galleries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := compute.NewGalleriesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list compute galleries due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, g := range page.Value {
			if g == nil {
				continue
			}
			mqlG, err := galleryToMql(a.MqlRuntime, *g)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlG)
		}
	}
	return res, nil
}

func galleryToMql(runtime *plugin.Runtime, g compute.Gallery) (*mqlAzureSubscriptionComputeServiceGallery, error) {
	properties, err := convert.JsonToDict(g.Properties)
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(g.ID),
		"name":       llx.StringDataPtr(g.Name),
		"location":   llx.StringDataPtr(g.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(g.Tags), types.String),
		"type":       llx.StringDataPtr(g.Type),
		"properties": llx.DictData(properties),
	}

	args["description"] = llx.StringDataPtr(nil)
	args["uniqueName"] = llx.StringDataPtr(nil)
	args["provisioningState"] = llx.StringDataPtr(nil)
	args["sharingProfile"] = llx.DictData(map[string]any{})
	args["softDeletePolicy"] = llx.DictData(map[string]any{})
	args["sharingStatus"] = llx.DictData(map[string]any{})

	if g.Properties != nil {
		p := g.Properties
		args["description"] = llx.StringDataPtr(p.Description)
		args["provisioningState"] = llx.StringDataPtr(stringEnumPtr(p.ProvisioningState))
		if p.Identifier != nil {
			args["uniqueName"] = llx.StringDataPtr(p.Identifier.UniqueName)
		}
		if p.SharingProfile != nil {
			d, err := convert.JsonToDict(p.SharingProfile)
			if err != nil {
				return nil, err
			}
			args["sharingProfile"] = llx.DictData(d)
		}
		if p.SoftDeletePolicy != nil {
			d, err := convert.JsonToDict(p.SoftDeletePolicy)
			if err != nil {
				return nil, err
			}
			args["softDeletePolicy"] = llx.DictData(d)
		}
		if p.SharingStatus != nil {
			d, err := convert.JsonToDict(p.SharingStatus)
			if err != nil {
				return nil, err
			}
			args["sharingStatus"] = llx.DictData(d)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.gallery", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(g.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceGallery).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceGallery), nil
}

type mqlAzureSubscriptionComputeServiceGalleryInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceGallery) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceGallery) images() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := compute.NewGalleryImagesClient(parsed.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListByGalleryPager(parsed.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list gallery images due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, img := range page.Value {
			if img == nil {
				continue
			}
			mqlImg, err := galleryImageToMql(a.MqlRuntime, *img)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlImg)
		}
	}
	return res, nil
}

func galleryImageToMql(runtime *plugin.Runtime, img compute.GalleryImage) (*mqlAzureSubscriptionComputeServiceGalleryImage, error) {
	properties, err := convert.JsonToDict(img.Properties)
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(img.ID),
		"name":       llx.StringDataPtr(img.Name),
		"location":   llx.StringDataPtr(img.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(img.Tags), types.String),
		"type":       llx.StringDataPtr(img.Type),
		"properties": llx.DictData(properties),
	}

	args["description"] = llx.StringDataPtr(nil)
	args["osType"] = llx.StringDataPtr(nil)
	args["osState"] = llx.StringDataPtr(nil)
	args["hyperVGeneration"] = llx.StringDataPtr(nil)
	args["architecture"] = llx.StringDataPtr(nil)
	args["identifier"] = llx.DictData(map[string]any{})
	args["recommended"] = llx.DictData(map[string]any{})
	args["disallowed"] = llx.DictData(map[string]any{})
	args["features"] = llx.ArrayData([]any{}, types.Dict)
	args["purchasePlan"] = llx.DictData(map[string]any{})
	args["endOfLifeDate"] = llx.TimeDataPtr(nil)
	args["provisioningState"] = llx.StringDataPtr(nil)
	args["privacyStatementUri"] = llx.StringDataPtr(nil)
	args["eula"] = llx.StringDataPtr(nil)
	args["releaseNoteUri"] = llx.StringDataPtr(nil)

	if img.Properties != nil {
		p := img.Properties
		args["description"] = llx.StringDataPtr(p.Description)
		args["osType"] = llx.StringDataPtr(stringEnumPtr(p.OSType))
		args["osState"] = llx.StringDataPtr(stringEnumPtr(p.OSState))
		args["hyperVGeneration"] = llx.StringDataPtr(stringEnumPtr(p.HyperVGeneration))
		args["architecture"] = llx.StringDataPtr(stringEnumPtr(p.Architecture))
		args["endOfLifeDate"] = llx.TimeDataPtr(p.EndOfLifeDate)
		args["provisioningState"] = llx.StringDataPtr(stringEnumPtr(p.ProvisioningState))
		args["privacyStatementUri"] = llx.StringDataPtr(p.PrivacyStatementURI)
		args["eula"] = llx.StringDataPtr(p.Eula)
		args["releaseNoteUri"] = llx.StringDataPtr(p.ReleaseNoteURI)
		if p.Identifier != nil {
			d, err := convert.JsonToDict(p.Identifier)
			if err != nil {
				return nil, err
			}
			args["identifier"] = llx.DictData(d)
		}
		if p.Recommended != nil {
			d, err := convert.JsonToDict(p.Recommended)
			if err != nil {
				return nil, err
			}
			args["recommended"] = llx.DictData(d)
		}
		if p.Disallowed != nil {
			d, err := convert.JsonToDict(p.Disallowed)
			if err != nil {
				return nil, err
			}
			args["disallowed"] = llx.DictData(d)
		}
		features := []any{}
		for _, f := range p.Features {
			if f == nil {
				continue
			}
			d, err := convert.JsonToDict(f)
			if err != nil {
				return nil, err
			}
			features = append(features, d)
		}
		args["features"] = llx.ArrayData(features, types.Dict)
		if p.PurchasePlan != nil {
			d, err := convert.JsonToDict(p.PurchasePlan)
			if err != nil {
				return nil, err
			}
			args["purchasePlan"] = llx.DictData(d)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.gallery.image", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(img.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceGalleryImage).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceGalleryImage), nil
}

type mqlAzureSubscriptionComputeServiceGalleryImageInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceGalleryImage) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionComputeServiceGalleryImage) versions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	galleryName, err := parsed.Component("galleries")
	if err != nil {
		return nil, err
	}
	imageName, err := parsed.Component("images")
	if err != nil {
		return nil, err
	}

	client, err := compute.NewGalleryImageVersionsClient(parsed.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListByGalleryImagePager(parsed.ResourceGroup, galleryName, imageName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list gallery image versions due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, v := range page.Value {
			if v == nil {
				continue
			}
			mqlV, err := galleryImageVersionToMql(a.MqlRuntime, *v)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlV)
		}
	}
	return res, nil
}

func galleryImageVersionToMql(runtime *plugin.Runtime, v compute.GalleryImageVersion) (*mqlAzureSubscriptionComputeServiceGalleryImageVersion, error) {
	properties, err := convert.JsonToDict(v.Properties)
	if err != nil {
		return nil, err
	}
	args := map[string]*llx.RawData{
		"id":         llx.StringDataPtr(v.ID),
		"name":       llx.StringDataPtr(v.Name),
		"location":   llx.StringDataPtr(v.Location),
		"tags":       llx.MapData(convert.PtrMapStrToInterface(v.Tags), types.String),
		"type":       llx.StringDataPtr(v.Type),
		"properties": llx.DictData(properties),
	}

	args["publishingProfile"] = llx.DictData(map[string]any{})
	args["storageProfile"] = llx.DictData(map[string]any{})
	args["safetyProfile"] = llx.DictData(map[string]any{})
	args["securityProfile"] = llx.DictData(map[string]any{})
	args["replicationStatus"] = llx.DictData(map[string]any{})
	args["provisioningState"] = llx.StringDataPtr(nil)

	if v.Properties != nil {
		p := v.Properties
		args["provisioningState"] = llx.StringDataPtr(stringEnumPtr(p.ProvisioningState))
		if p.PublishingProfile != nil {
			d, err := convert.JsonToDict(p.PublishingProfile)
			if err != nil {
				return nil, err
			}
			args["publishingProfile"] = llx.DictData(d)
		}
		if p.StorageProfile != nil {
			d, err := convert.JsonToDict(p.StorageProfile)
			if err != nil {
				return nil, err
			}
			args["storageProfile"] = llx.DictData(d)
		}
		if p.SafetyProfile != nil {
			d, err := convert.JsonToDict(p.SafetyProfile)
			if err != nil {
				return nil, err
			}
			args["safetyProfile"] = llx.DictData(d)
		}
		if p.SecurityProfile != nil {
			d, err := convert.JsonToDict(p.SecurityProfile)
			if err != nil {
				return nil, err
			}
			args["securityProfile"] = llx.DictData(d)
		}
		if p.ReplicationStatus != nil {
			d, err := convert.JsonToDict(p.ReplicationStatus)
			if err != nil {
				return nil, err
			}
			args["replicationStatus"] = llx.DictData(d)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.computeService.gallery.image.version", args)
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(v.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionComputeServiceGalleryImageVersion).cacheSystemData = sysData
	return res.(*mqlAzureSubscriptionComputeServiceGalleryImageVersion), nil
}

type mqlAzureSubscriptionComputeServiceGalleryImageVersionInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionComputeServiceGalleryImageVersion) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
