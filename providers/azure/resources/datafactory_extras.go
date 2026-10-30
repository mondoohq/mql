// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"slices"
	"sort"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/datafactory/armdatafactory/v11"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryLinkedService) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryIntegrationRuntime) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryManagedVirtualNetwork) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryManagedPrivateEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionDataFactoryServiceFactoryLinkedServiceInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionDataFactoryServiceFactoryIntegrationRuntimeInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionDataFactoryServiceFactoryManagedVirtualNetworkInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionDataFactoryServiceFactoryManagedPrivateEndpointInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryLinkedService) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryIntegrationRuntime) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryManagedVirtualNetwork) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryManagedPrivateEndpoint) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// linkedServiceAuthType extracts the connector's declared authentication mode
// from the linked-service body. Data Factory names this field differently per
// connector (authenticationType for most, clusterAuthType /
// clusterResourceGroupAuthType for the HDInsight connectors), so we probe the
// known keys inside typeProperties and return the first present value.
func linkedServiceAuthType(typeProps map[string]any) string {
	inner, ok := typeProps["typeProperties"].(map[string]any)
	if !ok {
		return ""
	}
	for _, key := range []string{"authenticationType", "clusterAuthType", "clusterResourceGroupAuthType"} {
		if v, ok := inner[key].(string); ok && v != "" {
			return v
		}
	}
	return ""
}

// factoryResourceGroup parses the factory ARM id to {resourceGroup, factoryName}.
func factoryResourceGroup(factoryId string) (string, string, error) {
	parsed, err := ParseResourceID(factoryId)
	if err != nil {
		return "", "", err
	}
	name, err := parsed.Component("factories")
	if err != nil {
		return "", "", err
	}
	return parsed.ResourceGroup, name, nil
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactory) linkedServices() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, factoryName, err := factoryResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := armdatafactory.NewLinkedServicesClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListByFactoryPager(rg, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFactoryAccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, ls := range page.Value {
			if ls == nil {
				continue
			}
			mqlLs, err := linkedServiceToMQL(a.MqlRuntime, ls)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlLs)
		}
	}
	return res, nil
}

func linkedServiceToMQL(runtime *plugin.Runtime, ls *armdatafactory.LinkedServiceResource) (plugin.Resource, error) {
	var serviceType, description, version, irName string
	parameterNames := []any{}
	annotations := []any{}
	typeProps := map[string]any{}
	usesKV := false

	if ls.Properties != nil {
		base := ls.Properties.GetLinkedService()
		if base != nil {
			if base.Type != nil {
				serviceType = *base.Type
			}
			if base.Description != nil {
				description = *base.Description
			}
			if base.Version != nil {
				version = *base.Version
			}
			if base.ConnectVia != nil && base.ConnectVia.ReferenceName != nil {
				irName = *base.ConnectVia.ReferenceName
			}
			parameterNames = sortedParameterNames(base.Parameters)
			anns, err := convert.JsonToDictSlice(base.Annotations)
			if err == nil {
				annotations = anns
			}
		}
		// Serialize the full polymorphic body to a dict so the SDK-specific typeProperties
		// remain queryable, then walk the structure for Key Vault references.
		full, err := convert.JsonToDict(ls.Properties)
		if err == nil {
			typeProps = full
			usesKV = dictReferencesAzureKeyVaultSecret(typeProps)
		}
	}

	res, err := CreateResource(runtime, "azure.subscription.dataFactoryService.factory.linkedService",
		map[string]*llx.RawData{
			"id":                     llx.StringDataPtr(ls.ID),
			"name":                   llx.StringDataPtr(ls.Name),
			"type":                   llx.StringDataPtr(ls.Type),
			"serviceType":            llx.StringData(serviceType),
			"description":            llx.StringData(description),
			"version":                llx.StringData(version),
			"integrationRuntimeName": llx.StringData(irName),
			"parameterNames":         llx.ArrayData(parameterNames, types.String),
			"usesKeyVaultReference":  llx.BoolData(usesKV),
			"authenticationType":     llx.StringData(linkedServiceAuthType(typeProps)),
			"annotations":            llx.ArrayData(annotations, types.Dict),
			"typeProperties":         llx.DictData(typeProps),
		})
	if err != nil {
		return nil, err
	}
	sysData, err := convert.JsonToDict(ls.SystemData)
	if err != nil {
		return nil, err
	}
	res.(*mqlAzureSubscriptionDataFactoryServiceFactoryLinkedService).cacheSystemData = sysData
	return res, nil
}

// sortedParameterNames returns the keys of the parameter map in sorted order so
// query output stays deterministic across runs.
func sortedParameterNames(params map[string]*armdatafactory.ParameterSpecification) []any {
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, k)
	}
	return out
}

// dictReferencesAzureKeyVaultSecret recursively scans the dict produced from a
// linked-service body looking for any object with `"type": "AzureKeyVaultSecret"`.
// That marker is how Data Factory linked services indicate a credential field
// is resolved through Key Vault rather than stored inline.
func dictReferencesAzureKeyVaultSecret(v any) bool {
	switch t := v.(type) {
	case map[string]any:
		if typeVal, ok := t["type"].(string); ok && typeVal == "AzureKeyVaultSecret" {
			return true
		}
		for _, child := range t {
			if dictReferencesAzureKeyVaultSecret(child) {
				return true
			}
		}
	case []any:
		if slices.ContainsFunc(t, dictReferencesAzureKeyVaultSecret) {
			return true
		}
	}
	return false
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactory) integrationRuntimes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, factoryName, err := factoryResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := armdatafactory.NewIntegrationRuntimesClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListByFactoryPager(rg, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFactoryAccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, ir := range page.Value {
			if ir == nil {
				continue
			}
			var runtimeType, description string
			typeProps := map[string]any{}
			if ir.Properties != nil {
				base := ir.Properties.GetIntegrationRuntime()
				if base != nil {
					if base.Type != nil {
						runtimeType = string(*base.Type)
					}
					if base.Description != nil {
						description = *base.Description
					}
				}
				full, err := convert.JsonToDict(ir.Properties)
				if err == nil {
					typeProps = full
				}
			}

			mqlIr, err := CreateResource(a.MqlRuntime, "azure.subscription.dataFactoryService.factory.integrationRuntime",
				map[string]*llx.RawData{
					"id":             llx.StringDataPtr(ir.ID),
					"name":           llx.StringDataPtr(ir.Name),
					"type":           llx.StringDataPtr(ir.Type),
					"runtimeType":    llx.StringData(runtimeType),
					"description":    llx.StringData(description),
					"typeProperties": llx.DictData(typeProps),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ir.SystemData)
			if err != nil {
				return nil, err
			}
			mqlIr.(*mqlAzureSubscriptionDataFactoryServiceFactoryIntegrationRuntime).cacheSystemData = sysData
			res = append(res, mqlIr)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactory) managedVirtualNetwork() (*mqlAzureSubscriptionDataFactoryServiceFactoryManagedVirtualNetwork, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	rg, factoryName, err := factoryResourceGroup(a.Id.Data)
	if err != nil {
		return nil, err
	}
	client, err := armdatafactory.NewManagedVirtualNetworksClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByFactoryPager(rg, factoryName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFactoryAccessDeniedError(err) {
				a.ManagedVirtualNetwork.State = plugin.StateIsNull | plugin.StateIsSet
				return nil, nil
			}
			return nil, err
		}
		for _, mvn := range page.Value {
			if mvn == nil {
				continue
			}
			var alias, vnetID string
			if mvn.Properties != nil {
				if mvn.Properties.Alias != nil {
					alias = *mvn.Properties.Alias
				}
				if mvn.Properties.VNetID != nil {
					vnetID = *mvn.Properties.VNetID
				}
			}
			mqlMvn, err := CreateResource(a.MqlRuntime, "azure.subscription.dataFactoryService.factory.managedVirtualNetwork",
				map[string]*llx.RawData{
					"id":     llx.StringDataPtr(mvn.ID),
					"name":   llx.StringDataPtr(mvn.Name),
					"type":   llx.StringDataPtr(mvn.Type),
					"alias":  llx.StringData(alias),
					"vnetId": llx.StringData(vnetID),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(mvn.SystemData)
			if err != nil {
				return nil, err
			}
			mqlMvnRes := mqlMvn.(*mqlAzureSubscriptionDataFactoryServiceFactoryManagedVirtualNetwork)
			mqlMvnRes.cacheSystemData = sysData
			return mqlMvnRes, nil
		}
	}

	a.ManagedVirtualNetwork.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAzureSubscriptionDataFactoryServiceFactoryManagedVirtualNetwork) privateEndpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	// The MVN ARM id has the form
	//   /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.DataFactory/factories/{factory}/managedVirtualNetworks/{mvn}
	// Extract resource group + factory name + mvn name in one parse.
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	factoryName, err := parsed.Component("factories")
	if err != nil {
		return nil, err
	}
	mvnName, err := parsed.Component("managedVirtualNetworks")
	if err != nil {
		return nil, err
	}
	rg := parsed.ResourceGroup

	client, err := armdatafactory.NewManagedPrivateEndpointsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	pager := client.NewListByFactoryPager(rg, factoryName, mvnName, nil)
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isFactoryAccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, ep := range page.Value {
			if ep == nil {
				continue
			}
			var groupId, privateLinkResourceId string
			var connectionStatus, description, actionsRequired, provisioningState string
			fqdns := []any{}
			reserved := false
			if ep.Properties != nil {
				p := ep.Properties
				if p.GroupID != nil {
					groupId = *p.GroupID
				}
				if p.PrivateLinkResourceID != nil {
					privateLinkResourceId = *p.PrivateLinkResourceID
				}
				if p.ConnectionState != nil {
					if p.ConnectionState.Status != nil {
						connectionStatus = *p.ConnectionState.Status
					}
					if p.ConnectionState.Description != nil {
						description = *p.ConnectionState.Description
					}
					if p.ConnectionState.ActionsRequired != nil {
						actionsRequired = *p.ConnectionState.ActionsRequired
					}
				}
				if p.ProvisioningState != nil {
					provisioningState = *p.ProvisioningState
				}
				for _, fqdn := range p.Fqdns {
					if fqdn != nil {
						fqdns = append(fqdns, *fqdn)
					}
				}
				if p.IsReserved != nil {
					reserved = *p.IsReserved
				}
			}

			mqlEp, err := CreateResource(a.MqlRuntime, "azure.subscription.dataFactoryService.factory.managedPrivateEndpoint",
				map[string]*llx.RawData{
					"id":                    llx.StringDataPtr(ep.ID),
					"name":                  llx.StringDataPtr(ep.Name),
					"type":                  llx.StringDataPtr(ep.Type),
					"groupId":               llx.StringData(groupId),
					"privateLinkResourceId": llx.StringData(privateLinkResourceId),
					"connectionStatus":      llx.StringData(connectionStatus),
					"description":           llx.StringData(description),
					"actionsRequired":       llx.StringData(actionsRequired),
					"fqdns":                 llx.ArrayData(fqdns, types.String),
					"reserved":              llx.BoolData(reserved),
					"provisioningState":     llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ep.SystemData)
			if err != nil {
				return nil, err
			}
			mqlEp.(*mqlAzureSubscriptionDataFactoryServiceFactoryManagedPrivateEndpoint).cacheSystemData = sysData
			res = append(res, mqlEp)
		}
	}
	return res, nil
}

// isFactoryAccessDeniedError reports whether the err is an Azure 403 we should
// treat as an empty list rather than fatal — common when scanning a subscription
// where some factories are read-only or in a different RBAC scope.
func isFactoryAccessDeniedError(err error) bool {
	if rerr, ok := errors.AsType[*azcore.ResponseError](err); ok {
		return rerr.StatusCode == 403
	}
	return false
}
