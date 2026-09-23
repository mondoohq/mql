// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	network "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v12"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

// -----------------------------------------------------------------------------
// Network virtual appliances
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceVirtualApplianceInternal struct {
	cacheVirtualHubId *string
}

func (a *mqlAzureSubscriptionNetworkService) virtualAppliances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewVirtualAppliancesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.VirtualAppliancesClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, nva := range page.Value {
			if nva == nil {
				continue
			}
			var provisioningState, addressPrefix, deploymentType, sshPublicKey string
			var vendor, bundledScaleUnit, marketplaceVersion string
			var addressPrefixV6, privateIpAddressV6 string
			var migrationPhase, migrationPhaseStatus, migrationType string
			addressFamily := []any{}
			var asn int64
			var virtualHubId *string
			if p := nva.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				addressPrefixV6 = convert.ToValue(p.AddressPrefixV6)
				privateIpAddressV6 = convert.ToValue(p.PrivateIPAddressV6)
				for _, af := range p.AddressFamily {
					if af != nil {
						addressFamily = append(addressFamily, string(*af))
					}
				}
				if ms := p.MigrationStatus; ms != nil {
					migrationPhase = convert.ToValue(ms.MigrationPhase)
					migrationPhaseStatus = convert.ToValue(ms.MigrationPhaseStatus)
					if ms.MigrationType != nil {
						migrationType = string(*ms.MigrationType)
					}
				}
				addressPrefix = convert.ToValue(p.AddressPrefix)
				deploymentType = convert.ToValue(p.DeploymentType)
				sshPublicKey = convert.ToValue(p.SSHPublicKey)
				if p.VirtualApplianceAsn != nil {
					asn = *p.VirtualApplianceAsn
				}
				if p.NvaSKU != nil {
					vendor = convert.ToValue(p.NvaSKU.Vendor)
					bundledScaleUnit = convert.ToValue(p.NvaSKU.BundledScaleUnit)
					marketplaceVersion = convert.ToValue(p.NvaSKU.MarketPlaceVersion)
				}
				if p.VirtualHub != nil {
					virtualHubId = p.VirtualHub.ID
				}
			}
			mqlNva, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualAppliance",
				map[string]*llx.RawData{
					"id":                 llx.StringDataPtr(nva.ID),
					"name":               llx.StringDataPtr(nva.Name),
					"location":           llx.StringDataPtr(nva.Location),
					"tags":               llx.MapData(convert.PtrMapStrToInterface(nva.Tags), types.String),
					"type":               llx.StringDataPtr(nva.Type),
					"etag":               llx.StringDataPtr(nva.Etag),
					"provisioningState":  llx.StringData(provisioningState),
					"asn":                llx.IntData(asn),
					"vendor":             llx.StringData(vendor),
					"bundledScaleUnit":   llx.StringData(bundledScaleUnit),
					"marketplaceVersion": llx.StringData(marketplaceVersion),
					"addressPrefix":      llx.StringData(addressPrefix),
					"deploymentType":     llx.StringData(deploymentType),
					"sshPublicKey":       llx.StringData(sshPublicKey),

					"addressPrefixV6":      llx.StringData(addressPrefixV6),
					"privateIpAddressV6":   llx.StringData(privateIpAddressV6),
					"addressFamily":        llx.ArrayData(addressFamily, types.String),
					"migrationPhase":       llx.StringData(migrationPhase),
					"migrationPhaseStatus": llx.StringData(migrationPhaseStatus),
					"migrationType":        llx.StringData(migrationType),
				})
			if err != nil {
				return nil, err
			}
			mqlNva.(*mqlAzureSubscriptionNetworkServiceVirtualAppliance).cacheVirtualHubId = virtualHubId
			res = append(res, mqlNva)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualAppliance) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualAppliance) virtualHub() (*mqlAzureSubscriptionNetworkServiceVirtualHub, error) {
	if a.cacheVirtualHubId == nil || *a.cacheVirtualHubId == "" {
		a.VirtualHub.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.virtualHub", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheVirtualHubId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceVirtualHub), nil
}

// -----------------------------------------------------------------------------
// Virtual routers
// -----------------------------------------------------------------------------

type mqlAzureSubscriptionNetworkServiceVirtualRouterInternal struct {
	cacheHostedSubnetId *string
}

func (a *mqlAzureSubscriptionNetworkService) virtualRouters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewVirtualRoutersClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListPager(&network.VirtualRoutersClientListOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, vr := range page.Value {
			if vr == nil {
				continue
			}
			var provisioningState string
			var asn int64
			ips := []any{}
			var hostedSubnetId *string
			if p := vr.Properties; p != nil {
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				if p.VirtualRouterAsn != nil {
					asn = *p.VirtualRouterAsn
				}
				for _, ip := range p.VirtualRouterIPs {
					if ip != nil {
						ips = append(ips, *ip)
					}
				}
				if p.HostedSubnet != nil {
					hostedSubnetId = p.HostedSubnet.ID
				}
			}
			mqlVr, err := CreateResource(a.MqlRuntime, "azure.subscription.networkService.virtualRouter",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(vr.ID),
					"name":              llx.StringDataPtr(vr.Name),
					"location":          llx.StringDataPtr(vr.Location),
					"tags":              llx.MapData(convert.PtrMapStrToInterface(vr.Tags), types.String),
					"type":              llx.StringDataPtr(vr.Type),
					"etag":              llx.StringDataPtr(vr.Etag),
					"provisioningState": llx.StringData(provisioningState),
					"asn":               llx.IntData(asn),
					"ips":               llx.ArrayData(ips, types.String),
				})
			if err != nil {
				return nil, err
			}
			mqlVr.(*mqlAzureSubscriptionNetworkServiceVirtualRouter).cacheHostedSubnetId = hostedSubnetId
			res = append(res, mqlVr)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualRouter) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualRouter) hostedSubnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheHostedSubnetId == nil || *a.cacheHostedSubnetId == "" {
		a.HostedSubnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	r, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.subnet", map[string]*llx.RawData{
		"id": llx.StringDataPtr(a.cacheHostedSubnetId),
	})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}

// -----------------------------------------------------------------------------
// Virtual network taps
// -----------------------------------------------------------------------------

func (a *mqlAzureSubscriptionNetworkService) virtualNetworkTaps() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	client, err := network.NewVirtualNetworkTapsClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	pager := client.NewListAllPager(&network.VirtualNetworkTapsClientListAllOptions{})
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tap := range page.Value {
			if tap == nil {
				continue
			}
			mqlTap, err := azureVirtualNetworkTapToMql(a.MqlRuntime, tap)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTap)
		}
	}
	return res, nil
}

// azureVirtualNetworkTapToMql maps a virtual network tap into its MQL resource.
// Shared by the list accessor and the by-ID init.
func azureVirtualNetworkTapToMql(runtime *plugin.Runtime, tap *network.VirtualNetworkTap) (*mqlAzureSubscriptionNetworkServiceVirtualNetworkTap, error) {
	var provisioningState, resourceGuid string
	var destinationPort int64
	if p := tap.Properties; p != nil {
		if p.ProvisioningState != nil {
			provisioningState = string(*p.ProvisioningState)
		}
		resourceGuid = convert.ToValue(p.ResourceGUID)
		if p.DestinationPort != nil {
			destinationPort = int64(*p.DestinationPort)
		}
	}
	mqlTap, err := CreateResource(runtime, "azure.subscription.networkService.virtualNetworkTap",
		map[string]*llx.RawData{
			"id":                llx.StringDataPtr(tap.ID),
			"name":              llx.StringDataPtr(tap.Name),
			"location":          llx.StringDataPtr(tap.Location),
			"tags":              llx.MapData(convert.PtrMapStrToInterface(tap.Tags), types.String),
			"type":              llx.StringDataPtr(tap.Type),
			"etag":              llx.StringDataPtr(tap.Etag),
			"provisioningState": llx.StringData(provisioningState),
			"destinationPort":   llx.IntData(destinationPort),
			"resourceGuid":      llx.StringData(resourceGuid),
		})
	if err != nil {
		return nil, err
	}
	return mqlTap.(*mqlAzureSubscriptionNetworkServiceVirtualNetworkTap), nil
}

func (a *mqlAzureSubscriptionNetworkServiceVirtualNetworkTap) id() (string, error) {
	return a.Id.Data, nil
}

// initAzureSubscriptionNetworkServiceVirtualNetworkTap resolves a virtual
// network tap by its ARM ID so typed references to it (e.g. from a NIC IP
// configuration) populate fully.
func initAzureSubscriptionNetworkServiceVirtualNetworkTap(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	name, err := azureId.Component("virtualNetworkTaps")
	if err != nil {
		return nil, nil, err
	}
	// Already fetched by an earlier reference: NewResource consults the
	// cache only after this init returns, so without this the same target is
	// re-fetched once per reference and the result thrown away.
	if cached := cachedResource(runtime, ResourceAzureSubscriptionNetworkServiceVirtualNetworkTap, id); cached != nil {
		return args, cached, nil
	}

	client, err := network.NewVirtualNetworkTapsClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, name, nil)
	if err != nil {
		return nil, nil, err
	}
	mql, err := azureVirtualNetworkTapToMql(runtime, &resp.VirtualNetworkTap)
	if err != nil {
		return nil, nil, err
	}
	return args, mql, nil
}
