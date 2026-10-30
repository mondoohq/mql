// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

const (
	permVirtualNetworkAppliancesRead            = "Microsoft.Network/virtualNetworkAppliances/read"
	permVirtualNetworkApplianceCapabilitiesRead = "Microsoft.Network/virtualNetworkAppliances/capabilities/read"
)

type mqlAzureSubscriptionNetworkServiceVirtualNetworkApplianceInternal struct {
	cacheSubnetId  *string
	cacheIPConfigs []*network.VirtualNetworkApplianceIPConfiguration
}

type mqlAzureSubscriptionNetworkServiceVirtualNetworkApplianceCapabilityInternal struct {
	cacheLinkedResourceId *string
	cacheSystemData       any
}

// virtualNetworkApplianceUnavailable decides what a failed virtual network
// appliance read reports. The resource type is new and not offered in every
// region or subscription, and ARM answers a subscription that cannot have one
// with a 404 or a "not supported" code. That is an absence: v13 behavior
// reports it as an empty list, structured errors as NotApplicable. A refusal
// is never an absence and stays an error.
func virtualNetworkApplianceUnavailable(err error, what string, permission string) ([]any, error) {
	if isAzureFeatureUnavailable(err) {
		if !plugin.StructuredErrors() {
			log.Debug().Err(err).Str("collection", what).
				Msg("azure> virtual network appliances not available, reporting an empty list")
			return []any{}, nil
		}
		return nil, llx.NotApplicable(err)
	}
	return nil, classifyAzureRefusal(err, permission)
}

func (a *mqlAzureSubscriptionNetworkService) virtualNetworkAppliances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewVirtualNetworkAppliancesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListAllPager(&network.VirtualNetworkAppliancesClientListAllOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return virtualNetworkApplianceUnavailable(err, "virtualNetworkAppliances", permVirtualNetworkAppliancesRead)
		}
		for _, vna := range page.Value {
			if vna == nil || vna.ID == nil || *vna.ID == "" {
				continue
			}
			args, subnetId, ipConfigs := virtualNetworkApplianceArgs(vna)
			mqlVna, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceVirtualNetworkAppliance, args)
			if err != nil {
				return nil, err
			}
			r := mqlVna.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkAppliance)
			r.cacheSubnetId = subnetId
			r.cacheIPConfigs = ipConfigs
			res = append(res, mqlVna)
		}
	}
	return res, nil
}

// virtualNetworkApplianceArgs maps a listed appliance onto its resource
// arguments, and returns the subnet reference and IP configurations the
// accessors resolve later. Values the API leaves out stay null.
func virtualNetworkApplianceArgs(vna *network.VirtualNetworkAppliance) (map[string]*llx.RawData, *string, []*network.VirtualNetworkApplianceIPConfiguration) {
	var provisioningState, resourceGuid, ipVersion, capacityProviderId, subnetId *string
	var bandwidth *float64
	var ipConfigs []*network.VirtualNetworkApplianceIPConfiguration
	if p := vna.Properties; p != nil {
		provisioningState = stringEnumPtr(p.ProvisioningState)
		resourceGuid = p.ResourceGUID
		ipVersion = stringEnumPtr(p.PrivateIPAddressVersion)
		bandwidth = p.BandwidthInGbps
		if p.CapacityProvider != nil {
			capacityProviderId = p.CapacityProvider.ID
		}
		if p.Subnet != nil {
			subnetId = p.Subnet.ID
		}
		ipConfigs = p.IPConfigurations
	}
	args := map[string]*llx.RawData{
		"id":                      llx.StringDataPtr(vna.ID),
		"name":                    llx.StringDataPtr(vna.Name),
		"location":                llx.StringDataPtr(vna.Location),
		"tags":                    llx.MapData(convert.PtrMapStrToInterface(vna.Tags), types.String),
		"type":                    llx.StringDataPtr(vna.Type),
		"etag":                    llx.StringDataPtr(vna.Etag),
		"provisioningState":       llx.StringDataPtr(provisioningState),
		"resourceGuid":            llx.StringDataPtr(resourceGuid),
		"bandwidthInGbps":         llx.FloatDataPtr(bandwidth),
		"privateIpAddressVersion": llx.StringDataPtr(ipVersion),
		"capacityProviderId":      llx.StringDataPtr(capacityProviderId),
	}
	return args, subnetId, ipConfigs
}

func initAzureSubscriptionNetworkServiceVirtualNetworkAppliance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionNetworkService,
		func(s *mqlAzureSubscriptionNetworkService) *plugin.TValue[[]any] {
			return s.GetVirtualNetworkAppliances()
		},
		ResourceAzureSubscriptionNetworkServiceVirtualNetworkAppliance)
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkAppliance) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkAppliance) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheSubnetId, &a.Subnet)
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkAppliance) ipConfigurations() ([]any, error) {
	res := []any{}
	for _, ipc := range a.cacheIPConfigs {
		if ipc == nil || ipc.ID == nil || *ipc.ID == "" {
			continue
		}
		mqlIpc, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceVirtualNetworkApplianceIpConfiguration,
			virtualNetworkApplianceIPConfigArgs(ipc))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIpc)
	}
	return res, nil
}

// virtualNetworkApplianceIPConfigArgs maps one appliance IP configuration onto
// its resource arguments. Values the API leaves out stay null.
func virtualNetworkApplianceIPConfigArgs(ipc *network.VirtualNetworkApplianceIPConfiguration) map[string]*llx.RawData {
	var primary *bool
	var privateIp, ipVersion, allocation, provisioningState *string
	if p := ipc.Properties; p != nil {
		primary = p.Primary
		privateIp = p.PrivateIPAddress
		ipVersion = stringEnumPtr(p.PrivateIPAddressVersion)
		allocation = stringEnumPtr(p.PrivateIPAllocationMethod)
		provisioningState = stringEnumPtr(p.ProvisioningState)
	}
	return map[string]*llx.RawData{
		"id":                        llx.StringDataPtr(ipc.ID),
		"name":                      llx.StringDataPtr(ipc.Name),
		"type":                      llx.StringDataPtr(ipc.Type),
		"etag":                      llx.StringDataPtr(ipc.Etag),
		"primary":                   llx.BoolDataPtr(primary),
		"privateIpAddress":          llx.StringDataPtr(privateIp),
		"privateIpAddressVersion":   llx.StringDataPtr(ipVersion),
		"privateIpAllocationMethod": llx.StringDataPtr(allocation),
		"provisioningState":         llx.StringDataPtr(provisioningState),
	}
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkApplianceIpConfiguration) id() (string, error) {
	return a.Id.Data, nil
}

// capabilities lists the capabilities enabled on the appliance. They are a
// child resource type that the appliance GET and list responses do not carry,
// so this is one call per appliance, made only when the field is queried.
func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkAppliance) capabilities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	name, err := resourceID.Component("virtualNetworkAppliances")
	if err != nil {
		return nil, err
	}
	client, err := network.NewVirtualNetworkApplianceCapabilitiesClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListPager(resourceID.ResourceGroup, name, &network.VirtualNetworkApplianceCapabilitiesClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return virtualNetworkApplianceUnavailable(err, "virtualNetworkAppliance.capabilities", permVirtualNetworkApplianceCapabilitiesRead)
		}
		for _, c := range page.Value {
			args, linkedId, systemData, ok := virtualNetworkApplianceCapabilityArgs(c)
			if !ok {
				continue
			}
			mqlCap, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceVirtualNetworkApplianceCapability, args)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(systemData)
			if err != nil {
				return nil, err
			}
			r := mqlCap.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkApplianceCapability)
			r.cacheLinkedResourceId = linkedId
			r.cacheSystemData = sysData
			res = append(res, mqlCap)
		}
	}
	return res, nil
}

// virtualNetworkApplianceCapabilityArgs maps one capability onto its resource
// arguments. Every kind shares one shape, so the polymorphic value is read
// through its common base; a kind this SDK does not know yet still decodes
// into the base and keeps its kind. It reports false for an entry without an
// id, which cannot be keyed.
func virtualNetworkApplianceCapabilityArgs(c network.VirtualNetworkApplianceCapabilityClassification) (map[string]*llx.RawData, *string, *network.SystemData, bool) {
	if c == nil {
		return nil, nil, nil, false
	}
	base := c.GetVirtualNetworkApplianceCapability()
	if base == nil || base.ID == nil || *base.ID == "" {
		return nil, nil, nil, false
	}
	var ipVersion, provisioningState, linkedId *string
	if p := base.Properties; p != nil {
		ipVersion = stringEnumPtr(p.IPVersion)
		provisioningState = stringEnumPtr(p.ProvisioningState)
		linkedId = p.LinkedResourceID
	}
	args := map[string]*llx.RawData{
		"id":                llx.StringDataPtr(base.ID),
		"name":              llx.StringDataPtr(base.Name),
		"type":              llx.StringDataPtr(base.Type),
		"kind":              llx.StringDataPtr(stringEnumPtr(base.Kind)),
		"ipVersion":         llx.StringDataPtr(ipVersion),
		"provisioningState": llx.StringDataPtr(provisioningState),
	}
	return args, linkedId, base.SystemData, true
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkApplianceCapability) id() (string, error) {
	return a.Id.Data, nil
}

// virtualNetwork resolves the virtual network the capability is linked to
// through the network service's virtual network list.
func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkApplianceCapability) virtualNetwork() (*mqlAzureSubscriptionNetworkServiceVirtualNetwork, error) {
	if a.cacheLinkedResourceId == nil || *a.cacheLinkedResourceId == "" {
		a.VirtualNetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	id := *a.cacheLinkedResourceId
	if found := lookupInServiceList(a.MqlRuntime, ResourceAzureSubscriptionNetworkService,
		func(s *mqlAzureSubscriptionNetworkService) *plugin.TValue[[]any] { return s.GetVirtualNetworks() },
		id); found != nil {
		return found.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork), nil
	}
	r, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceVirtualNetwork, map[string]*llx.RawData{
		"id": llx.StringData(id),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceVirtualNetwork), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkApplianceCapability) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
