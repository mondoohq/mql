// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns/v2"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionDnsService) id() (string, error) {
	return "azure.subscription.dns/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionDnsService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	args["subscriptionId"] = llx.StringData(conn.SubId())
	return args, nil, nil
}

func (a *mqlAzureSubscriptionDnsServiceZone) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDnsServiceZoneRecordSet) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDnsServicePrivateZone) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDnsServicePrivateZoneVirtualNetworkLink) id() (string, error) {
	return a.Id.Data, nil
}

// ===== Public DNS Zones =====

func (a *mqlAzureSubscriptionDnsService) zones() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := armdns.NewZonesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, zone := range page.Value {
			if zone == nil {
				continue
			}

			var numberOfRecordSets, maxNumberOfRecordSets int64
			var nameServers []any
			if zone.Properties != nil {
				if zone.Properties.NumberOfRecordSets != nil {
					numberOfRecordSets = *zone.Properties.NumberOfRecordSets
				}
				if zone.Properties.MaxNumberOfRecordSets != nil {
					maxNumberOfRecordSets = *zone.Properties.MaxNumberOfRecordSets
				}
				if zone.Properties.NameServers != nil {
					for _, ns := range zone.Properties.NameServers {
						if ns != nil {
							nameServers = append(nameServers, *ns)
						}
					}
				}
			}

			mqlZone, err := CreateResource(a.MqlRuntime, "azure.subscription.dnsService.zone", map[string]*llx.RawData{
				"id":                    llx.StringDataPtr(zone.ID),
				"name":                  llx.StringDataPtr(zone.Name),
				"location":              llx.StringDataPtr(zone.Location),
				"tags":                  llx.MapData(convert.PtrMapStrToInterface(zone.Tags), types.String),
				"numberOfRecordSets":    llx.IntData(numberOfRecordSets),
				"maxNumberOfRecordSets": llx.IntData(maxNumberOfRecordSets),
				"nameServers":           llx.ArrayData(nameServers, types.String),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlZone)
		}
	}

	return res, nil
}

func (a *mqlAzureSubscriptionDnsServiceZone) recordSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	zoneName := a.Name.Data

	client, err := armdns.NewRecordSetsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByDNSZonePager(resourceID.ResourceGroup, zoneName, nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, rs := range page.Value {
			if rs == nil {
				continue
			}

			properties, err := convert.JsonToDict(rs.Properties)
			if err != nil {
				return nil, err
			}

			var ttl int64
			var fqdn string
			if rs.Properties != nil {
				if rs.Properties.TTL != nil {
					ttl = *rs.Properties.TTL
				}
				if rs.Properties.Fqdn != nil {
					fqdn = *rs.Properties.Fqdn
				}
			}

			// Derive the takeover-relevant view of the record from the same
			// properties bag rather than a second API call: which hostname a
			// CNAME points at, whether that hostname belongs to an Azure
			// service, and whether the record is an alias (which Azure cleans
			// up on its own).
			cnameTarget := cnameTargetFromProperties(properties)

			recordArgs, err := dnsRecordSetTypedArgs(a.MqlRuntime, convert.ToValue(rs.ID), rs.Properties)
			if err != nil {
				return nil, err
			}
			recordArgs["id"] = llx.StringDataPtr(rs.ID)
			recordArgs["name"] = llx.StringDataPtr(rs.Name)
			recordArgs["type"] = llx.StringDataPtr(rs.Type)
			recordArgs["ttl"] = llx.IntData(ttl)
			recordArgs["fqdn"] = llx.StringData(fqdn)
			recordArgs["properties"] = llx.DictData(properties)
			recordArgs["cnameTarget"] = llx.StringData(cnameTarget)
			recordArgs["targetAzureService"] = llx.StringData(azureServiceForHostname(cnameTarget))
			recordArgs["targetResourceId"] = llx.StringData(targetResourceIDFromProperties(properties))

			mqlRs, err := CreateResource(a.MqlRuntime, "azure.subscription.dnsService.zone.recordSet", recordArgs)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRs)
		}
	}

	return res, nil
}

// ===== Private DNS Zones =====

func (a *mqlAzureSubscriptionDnsService) privateZones() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data

	client, err := armprivatedns.NewPrivateZonesClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, zone := range page.Value {
			if zone == nil {
				continue
			}

			var numberOfRecordSets, maxNumberOfRecordSets, numberOfVirtualNetworkLinks int64
			if zone.Properties != nil {
				if zone.Properties.NumberOfRecordSets != nil {
					numberOfRecordSets = *zone.Properties.NumberOfRecordSets
				}
				if zone.Properties.MaxNumberOfRecordSets != nil {
					maxNumberOfRecordSets = *zone.Properties.MaxNumberOfRecordSets
				}
				if zone.Properties.NumberOfVirtualNetworkLinks != nil {
					numberOfVirtualNetworkLinks = *zone.Properties.NumberOfVirtualNetworkLinks
				}
			}

			mqlZone, err := CreateResource(a.MqlRuntime, "azure.subscription.dnsService.privateZone", map[string]*llx.RawData{
				"id":                          llx.StringDataPtr(zone.ID),
				"name":                        llx.StringDataPtr(zone.Name),
				"location":                    llx.StringDataPtr(zone.Location),
				"tags":                        llx.MapData(convert.PtrMapStrToInterface(zone.Tags), types.String),
				"numberOfRecordSets":          llx.IntData(numberOfRecordSets),
				"maxNumberOfRecordSets":       llx.IntData(maxNumberOfRecordSets),
				"numberOfVirtualNetworkLinks": llx.IntData(numberOfVirtualNetworkLinks),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(zone.SystemData)
			if err != nil {
				return nil, err
			}
			mqlZone.(*mqlAzureSubscriptionDnsServicePrivateZone).cacheSystemData = sysData
			res = append(res, mqlZone)
		}
	}

	return res, nil
}

// initAzureSubscriptionDnsServicePrivateZone resolves a private DNS zone by its
// resource ID, so references to one (for example the zone a flexible server
// registers in) resolve without listing every zone in the subscription.
func initAzureSubscriptionDnsServicePrivateZone(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	azureId, err := ParseResourceID(id)
	if err != nil {
		return nil, nil, err
	}
	zoneName, err := azureId.Component("privateDnsZones")
	if err != nil {
		return nil, nil, err
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	// Already fetched by an earlier reference: NewResource consults the cache
	// only after this init returns, so without this a zone shared by many
	// servers is fetched once per server.
	if cached := cachedResource(runtime, "azure.subscription.dnsService.privateZone", id); cached != nil {
		return args, cached, nil
	}

	client, err := armprivatedns.NewPrivateZonesClient(azureId.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Get(context.Background(), azureId.ResourceGroup, zoneName, nil)
	if err != nil {
		return nil, nil, err
	}

	var numberOfRecordSets, maxNumberOfRecordSets, numberOfVirtualNetworkLinks int64
	if resp.Properties != nil {
		numberOfRecordSets = convert.ToValue(resp.Properties.NumberOfRecordSets)
		maxNumberOfRecordSets = convert.ToValue(resp.Properties.MaxNumberOfRecordSets)
		numberOfVirtualNetworkLinks = convert.ToValue(resp.Properties.NumberOfVirtualNetworkLinks)
	}
	res, err := CreateResource(runtime, "azure.subscription.dnsService.privateZone", map[string]*llx.RawData{
		"id":                          llx.StringDataPtr(resp.ID),
		"name":                        llx.StringDataPtr(resp.Name),
		"location":                    llx.StringDataPtr(resp.Location),
		"tags":                        llx.MapData(convert.PtrMapStrToInterface(resp.Tags), types.String),
		"numberOfRecordSets":          llx.IntData(numberOfRecordSets),
		"maxNumberOfRecordSets":       llx.IntData(maxNumberOfRecordSets),
		"numberOfVirtualNetworkLinks": llx.IntData(numberOfVirtualNetworkLinks),
	})
	if err != nil {
		return nil, nil, err
	}
	sysData, err := convert.JsonToDict(resp.SystemData)
	if err != nil {
		return nil, nil, err
	}
	res.(*mqlAzureSubscriptionDnsServicePrivateZone).cacheSystemData = sysData
	return args, res, nil
}

type mqlAzureSubscriptionDnsServicePrivateZoneInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionDnsServicePrivateZone) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDnsServicePrivateZone) virtualNetworkLinks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	id := a.Id.Data

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return nil, err
	}

	zoneName := a.Name.Data

	client, err := armprivatedns.NewVirtualNetworkLinksClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, zoneName, nil)
	var res []any

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, link := range page.Value {
			if link == nil {
				continue
			}

			var registrationEnabled bool
			var provisioningState string
			if link.Properties != nil {
				if link.Properties.RegistrationEnabled != nil {
					registrationEnabled = *link.Properties.RegistrationEnabled
				}
				if link.Properties.ProvisioningState != nil {
					provisioningState = string(*link.Properties.ProvisioningState)
				}
			}

			mqlLink, err := CreateResource(a.MqlRuntime, "azure.subscription.dnsService.privateZone.virtualNetworkLink", map[string]*llx.RawData{
				"id":                  llx.StringDataPtr(link.ID),
				"name":                llx.StringDataPtr(link.Name),
				"location":            llx.StringDataPtr(link.Location),
				"tags":                llx.MapData(convert.PtrMapStrToInterface(link.Tags), types.String),
				"registrationEnabled": llx.BoolData(registrationEnabled),
				"provisioningState":   llx.StringData(provisioningState),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(link.SystemData)
			if err != nil {
				return nil, err
			}
			mqlLink.(*mqlAzureSubscriptionDnsServicePrivateZoneVirtualNetworkLink).cacheSystemData = sysData
			res = append(res, mqlLink)
		}
	}

	return res, nil
}

type mqlAzureSubscriptionDnsServicePrivateZoneVirtualNetworkLinkInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionDnsServicePrivateZoneVirtualNetworkLink) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
