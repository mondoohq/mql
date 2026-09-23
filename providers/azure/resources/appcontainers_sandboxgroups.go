// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	apps "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/appcontainers/armappcontainers/v5"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionContainerAppServiceSandboxGroupInternal struct {
	cacheSystemData    any
	cacheEnvironmentID string
}

type mqlAzureSubscriptionContainerAppServiceSandboxGroupVnetConnectionInternal struct {
	cacheSystemData any
	cacheSubnetID   string
}

func (a *mqlAzureSubscriptionContainerAppServiceSandboxGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionContainerAppServiceSandboxGroupVnetConnection) id() (string, error) {
	return a.Id.Data, nil
}

// initAzureSubscriptionContainerAppServiceSandboxGroup resolves a single
// sandbox group by its ARM resource ID out of the subscription list.
func initAzureSubscriptionContainerAppServiceSandboxGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	return initFromServiceList(runtime, args,
		ResourceAzureSubscriptionContainerAppService,
		func(s *mqlAzureSubscriptionContainerAppService) *plugin.TValue[[]any] { return s.GetSandboxGroups() },
		ResourceAzureSubscriptionContainerAppServiceSandboxGroup)
}

func (a *mqlAzureSubscriptionContainerAppService) sandboxGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	client, err := apps.NewSandboxGroupsClient(a.SubscriptionId.Data, conn.Token(), acaClientOptions(conn))
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListBySubscriptionPager(nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure container apps sandbox groups, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlGroup, err := acaSandboxGroupToMQL(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlGroup)
		}
	}
	return res, nil
}

func acaSandboxGroupToMQL(runtime *plugin.Runtime, entry *apps.SandboxGroup) (*mqlAzureSubscriptionContainerAppServiceSandboxGroup, error) {
	var provisioningState, defaultDomain *string
	var environmentID string
	if p := entry.Properties; p != nil {
		provisioningState = stringEnumPtr(p.ProvisioningState)
		defaultDomain = p.DefaultDomain
		if p.EnvironmentID != nil {
			environmentID = *p.EnvironmentID
		}
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionContainerAppServiceSandboxGroup, map[string]*llx.RawData{
		"id":                llx.StringDataPtr(entry.ID),
		"name":              llx.StringDataPtr(entry.Name),
		"location":          llx.StringDataPtr(entry.Location),
		"tags":              llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
		"provisioningState": llx.StringDataPtr(provisioningState),
		"defaultDomain":     llx.StringDataPtr(defaultDomain),
	})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(entry.SystemData)
	if err != nil {
		return nil, err
	}
	group := res.(*mqlAzureSubscriptionContainerAppServiceSandboxGroup)
	group.cacheSystemData = sysData
	group.cacheEnvironmentID = environmentID
	return group, nil
}

func (a *mqlAzureSubscriptionContainerAppServiceSandboxGroup) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// managedEnvironment resolves the linked environment by its ARM resource ID.
// Environments already listed by managedEnvironments() come from the cache.
func (a *mqlAzureSubscriptionContainerAppServiceSandboxGroup) managedEnvironment() (*mqlAzureSubscriptionContainerAppServiceManagedEnvironment, error) {
	if a.cacheEnvironmentID == "" {
		a.ManagedEnvironment.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerAppServiceManagedEnvironment,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheEnvironmentID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionContainerAppServiceManagedEnvironment), nil
}

func (a *mqlAzureSubscriptionContainerAppServiceSandboxGroup) vnetConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()

	rg, groupName := resourceGroupAndName(a.Id.Data, "sandboxGroups")
	client, err := apps.NewVnetConnectionsClient(conn.SubId(), conn.Token(), acaClientOptions(conn))
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListBySandboxGroupPager(rg, groupName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			mqlConn, err := acaSandboxVnetConnectionToMQL(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlConn)
		}
	}
	return res, nil
}

func acaSandboxVnetConnectionToMQL(runtime *plugin.Runtime, entry *apps.VnetConnection) (*mqlAzureSubscriptionContainerAppServiceSandboxGroupVnetConnection, error) {
	var provisioningState *string
	var subnetID string
	if p := entry.Properties; p != nil {
		provisioningState = stringEnumPtr(p.ProvisioningState)
		if p.SubnetID != nil {
			subnetID = *p.SubnetID
		}
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionContainerAppServiceSandboxGroupVnetConnection, map[string]*llx.RawData{
		"id":                llx.StringDataPtr(entry.ID),
		"name":              llx.StringDataPtr(entry.Name),
		"provisioningState": llx.StringDataPtr(provisioningState),
	})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(entry.SystemData)
	if err != nil {
		return nil, err
	}
	vc := res.(*mqlAzureSubscriptionContainerAppServiceSandboxGroupVnetConnection)
	vc.cacheSystemData = sysData
	vc.cacheSubnetID = subnetID
	return vc, nil
}

func (a *mqlAzureSubscriptionContainerAppServiceSandboxGroupVnetConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// subnet resolves the connected subnet by its ARM resource ID; the subnet init
// reuses an already-fetched subnet from the cache.
func (a *mqlAzureSubscriptionContainerAppServiceSandboxGroupVnetConnection) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	if a.cacheSubnetID == "" {
		a.Subnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionNetworkServiceSubnet,
		map[string]*llx.RawData{"id": llx.StringData(a.cacheSubnetID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServiceSubnet), nil
}
