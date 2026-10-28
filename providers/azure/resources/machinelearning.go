// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	ml "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/machinelearning/armmachinelearning/v4"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionMachineLearningServiceWorkspaceInternal struct {
	cacheEncryptionKeyUri              string
	cacheSystemData                    any
	cacheOutboundRules                 map[string]ml.OutboundRuleClassification
	cacheServerlessComputeSubnetId     *string
	cachePrimaryUserAssignedIdentityId *string
}

// serverlessComputeSubnet resolves the subnet serverless jobs attach to. Null
// when serverless compute uses the Microsoft-managed network.
func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) serverlessComputeSubnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheServerlessComputeSubnetId, &a.ServerlessComputeSubnet)
}

// primaryUserAssignedIdentity resolves the identity the workspace acts through
// for managed resources. Null when it acts through its system-assigned
// identity.
func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) primaryUserAssignedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cachePrimaryUserAssignedIdentityId == nil || *a.cachePrimaryUserAssignedIdentityId == "" {
		a.PrimaryUserAssignedIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// "__id", not "id": azure.subscription.managedIdentity declares no id field,
	// so SetAllData rejected the arg and this accessor returned an error for
	// every workspace that has a primary user-assigned identity. The other
	// twelve callers all key it this way.
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringDataPtr(a.cachePrimaryUserAssignedIdentityId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func initAzureSubscriptionMachineLearningService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionMachineLearningService) id() (string, error) {
	return "azure.subscription.machineLearningService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) id() (string, error) {
	return a.Id.Data, nil
}

// managedNetworkOutboundRules maps the workspace's managed-network approved
// outbound rules (a name-keyed, type-discriminated map) to the unified rule
// resource. Rules are emitted in name order for stable output.
func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) managedNetworkOutboundRules() ([]any, error) {
	names := make([]string, 0, len(a.cacheOutboundRules))
	for name := range a.cacheOutboundRules {
		names = append(names, name)
	}
	sort.Strings(names)

	res := []any{}
	for _, name := range names {
		rule := a.cacheOutboundRules[name]
		if rule == nil {
			continue
		}
		var ruleType, category, status string
		if base := rule.GetOutboundRule(); base != nil {
			if base.Type != nil {
				ruleType = string(*base.Type)
			}
			if base.Category != nil {
				category = string(*base.Category)
			}
			if base.Status != nil {
				status = string(*base.Status)
			}
		}
		args := map[string]*llx.RawData{
			"__id":                             llx.StringData(a.Id.Data + "/outboundRules/" + name),
			"name":                             llx.StringData(name),
			"type":                             llx.StringData(ruleType),
			"category":                         llx.StringData(category),
			"status":                           llx.StringData(status),
			"destinationFqdn":                  llx.StringData(""),
			"privateEndpointResourceId":        llx.StringData(""),
			"privateEndpointSubresourceTarget": llx.StringData(""),
			"privateEndpointSparkEnabled":      llx.BoolDataPtr(nil),
			"serviceTag":                       llx.StringData(""),
			"serviceTagProtocol":               llx.StringData(""),
			"serviceTagPortRanges":             llx.StringData(""),
		}
		switch r := rule.(type) {
		case *ml.FqdnOutboundRule:
			args["destinationFqdn"] = llx.StringDataPtr(r.Destination)
		case *ml.PrivateEndpointOutboundRule:
			if d := r.Destination; d != nil {
				args["privateEndpointResourceId"] = llx.StringDataPtr(d.ServiceResourceID)
				args["privateEndpointSubresourceTarget"] = llx.StringDataPtr(d.SubresourceTarget)
				args["privateEndpointSparkEnabled"] = llx.BoolDataPtr(d.SparkEnabled)
			}
		case *ml.ServiceTagOutboundRule:
			if d := r.Destination; d != nil {
				args["serviceTag"] = llx.StringDataPtr(d.ServiceTag)
				args["serviceTagProtocol"] = llx.StringDataPtr(d.Protocol)
				args["serviceTagPortRanges"] = llx.StringDataPtr(d.PortRanges)
			}
		}
		mqlRule, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.managedNetworkOutboundRule", args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRule)
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMachineLearningService) workspaces() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := ml.NewWorkspacesClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
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
				log.Warn().Err(err).Msg("could not list machine learning workspaces due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ws := range page.Value {
			if ws == nil {
				continue
			}
			mqlWs, err := machineLearningWorkspaceToMql(a.MqlRuntime, ws)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlWs)
		}
	}
	return res, nil
}

func machineLearningWorkspaceToMql(runtime *plugin.Runtime, ws *ml.Workspace) (*mqlAzureSubscriptionMachineLearningServiceWorkspace, error) {
	sku, err := convert.JsonToDict(ws.SKU)
	if err != nil {
		return nil, err
	}
	wsSku := orZero(ws.SKU)
	identity, err := convert.JsonToDict(ws.Identity)
	if err != nil {
		return nil, err
	}

	props := ws.Properties
	if props == nil {
		props = &ml.WorkspaceProperties{}
	}

	var publicNetworkAccess, provisioningState, managedNetworkIsolationMode string
	if props.PublicNetworkAccess != nil {
		publicNetworkAccess = string(*props.PublicNetworkAccess)
	}
	if props.ProvisioningState != nil {
		provisioningState = string(*props.ProvisioningState)
	}
	var outboundRules map[string]ml.OutboundRuleClassification
	if props.ManagedNetwork != nil {
		if props.ManagedNetwork.IsolationMode != nil {
			managedNetworkIsolationMode = string(*props.ManagedNetwork.IsolationMode)
		}
		outboundRules = props.ManagedNetwork.OutboundRules
	}

	var encryptionStatus, encryptionKeyUri string
	if props.Encryption != nil {
		if props.Encryption.Status != nil {
			encryptionStatus = string(*props.Encryption.Status)
		}
		if props.Encryption.KeyVaultProperties != nil {
			encryptionKeyUri = convert.ToValue(props.Encryption.KeyVaultProperties.KeyIdentifier)
		}
	}

	peConns, err := convert.JsonToDictSlice(props.PrivateEndpointConnections)
	if err != nil {
		return nil, err
	}

	// Serverless compute settings are absent on a workspace that has none, in
	// which case both values stay null rather than reading as "no public IP
	// restriction configured".
	var serverlessComputeNoPublicIp *bool
	var serverlessComputeSubnetId *string
	if scs := props.ServerlessComputeSettings; scs != nil {
		serverlessComputeNoPublicIp = scs.ServerlessComputeNoPublicIP
		serverlessComputeSubnetId = scs.ServerlessComputeCustomSubnet
	}

	args := map[string]*llx.RawData{
		"id":                              llx.StringDataPtr(ws.ID),
		"name":                            llx.StringDataPtr(ws.Name),
		"location":                        llx.StringDataPtr(ws.Location),
		"tags":                            llx.MapData(convert.PtrMapStrToInterface(ws.Tags), types.String),
		"kind":                            llx.StringDataPtr(ws.Kind),
		"sku":                             llx.DictData(sku),
		"identity":                        llx.DictData(identity),
		"workspaceId":                     llx.StringDataPtr(props.WorkspaceID),
		"friendlyName":                    llx.StringDataPtr(props.FriendlyName),
		"description":                     llx.StringDataPtr(props.Description),
		"provisioningState":               llx.StringData(provisioningState),
		"publicNetworkAccess":             llx.StringData(publicNetworkAccess),
		"managedNetworkIsolationMode":     llx.StringData(managedNetworkIsolationMode),
		"hbiWorkspace":                    llx.BoolDataPtr(props.HbiWorkspace),
		"allowPublicAccessWhenBehindVnet": llx.BoolDataPtr(props.AllowPublicAccessWhenBehindVnet),
		"v1LegacyMode":                    llx.BoolDataPtr(props.V1LegacyMode),
		"discoveryUrl":                    llx.StringDataPtr(props.DiscoveryURL),
		"mlFlowTrackingUri":               llx.StringDataPtr(props.MlFlowTrackingURI),
		"imageBuildCompute":               llx.StringDataPtr(props.ImageBuildCompute),
		"encryptionStatus":                llx.StringData(encryptionStatus),
		"privateEndpointConnections":      llx.ArrayData(peConns, types.Dict),
		"keyVaultId":                      llx.StringDataPtr(props.KeyVault),
		"storageAccountId":                llx.StringDataPtr(props.StorageAccount),
		"applicationInsightsId":           llx.StringDataPtr(props.ApplicationInsights),
		"containerRegistryId":             llx.StringDataPtr(props.ContainerRegistry),

		"enableDataIsolation": llx.BoolDataPtr(props.EnableDataIsolation),
		"hubResourceId":       llx.StringDataPtr(props.HubResourceID),
		"associatedWorkspaces": llx.ArrayData(
			strPtrsToAny(props.AssociatedWorkspaces), types.String),
		"privateLinkCount":            llx.IntDataPtr(props.PrivateLinkCount),
		"storageHnsEnabled":           llx.BoolDataPtr(props.StorageHnsEnabled),
		"workspaceTenantId":           llx.StringDataPtr(props.TenantID),
		"serverlessComputeNoPublicIp": llx.BoolDataPtr(serverlessComputeNoPublicIp),
	}
	if err := setSkuData(runtime, args, skuName(wsSku.Name), skuTier(wsSku.Tier), skuSize(wsSku.Size), skuFamily(wsSku.Family), skuCapacity(wsSku.Capacity)); err != nil {
		return nil, err
	}
	wsIdentity := orZero(ws.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(wsIdentity.UserAssignedIdentities),
		identityType(wsIdentity.Type), identityPrincipalId(wsIdentity.PrincipalID), identityTenantId(wsIdentity.TenantID)); err != nil {
		return nil, err
	}
	resource, err := CreateResource(runtime, ResourceAzureSubscriptionMachineLearningServiceWorkspace, args)
	if err != nil {
		return nil, err
	}

	mqlWs := resource.(*mqlAzureSubscriptionMachineLearningServiceWorkspace)
	mqlWs.cacheEncryptionKeyUri = encryptionKeyUri
	mqlWs.cacheOutboundRules = outboundRules
	mqlWs.cacheServerlessComputeSubnetId = serverlessComputeSubnetId
	mqlWs.cachePrimaryUserAssignedIdentityId = props.PrimaryUserAssignedIdentity
	sysData, err := convert.JsonToDict(ws.SystemData)
	if err != nil {
		return nil, err
	}
	mqlWs.cacheSystemData = sysData
	return mqlWs, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) encryptionKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheEncryptionKeyUri == "" {
		a.EncryptionKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheEncryptionKeyUri)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) keyVault() (*mqlAzureSubscriptionKeyVaultServiceVault, error) {
	if a.KeyVaultId.Data == "" {
		a.KeyVault.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionKeyVaultServiceVault,
		map[string]*llx.RawData{"id": llx.StringData(a.KeyVaultId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionKeyVaultServiceVault), nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) storageAccount() (*mqlAzureSubscriptionStorageServiceAccount, error) {
	if a.StorageAccountId.Data == "" {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return getStorageAccount(a.StorageAccountId.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) applicationInsights() (*mqlAzureSubscriptionMonitorServiceApplicationInsight, error) {
	if a.ApplicationInsightsId.Data == "" {
		a.ApplicationInsights.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionMonitorServiceApplicationInsight,
		map[string]*llx.RawData{"id": llx.StringData(a.ApplicationInsightsId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionMonitorServiceApplicationInsight), nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) containerRegistry() (*mqlAzureSubscriptionContainerRegistryServiceRegistry, error) {
	if a.ContainerRegistryId.Data == "" {
		a.ContainerRegistry.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionContainerRegistryServiceRegistry,
		map[string]*llx.RawData{"id": llx.StringData(a.ContainerRegistryId.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionContainerRegistryServiceRegistry), nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpointDeployment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceServerlessEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceCompute) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceModel) id() (string, error) {
	return a.Id.Data, nil
}

func intMapToMql(m map[string]*int32) map[string]any {
	res := map[string]any{}
	for k, v := range m {
		if v != nil {
			res[k] = int64(*v)
		}
	}
	return res
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) onlineEndpoints() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName := parsed.Path["workspaces"]

	ctx := context.Background()
	client, err := ml.NewOnlineEndpointsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, workspaceName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list machine learning online endpoints due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ep := range page.Value {
			if ep == nil {
				continue
			}
			identity, err := convert.JsonToDict(ep.Identity)
			if err != nil {
				return nil, err
			}
			var authMode, publicNetworkAccess, scoringUri, swaggerUri, computeId, description, provisioningState string
			traffic := map[string]any{}
			mirrorTraffic := map[string]any{}
			if p := ep.Properties; p != nil {
				if p.AuthMode != nil {
					authMode = string(*p.AuthMode)
				}
				if p.PublicNetworkAccess != nil {
					publicNetworkAccess = string(*p.PublicNetworkAccess)
				}
				if p.ScoringURI != nil {
					scoringUri = *p.ScoringURI
				}
				if p.SwaggerURI != nil {
					swaggerUri = *p.SwaggerURI
				}
				if p.Compute != nil {
					computeId = *p.Compute
				}
				if p.Description != nil {
					description = *p.Description
				}
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				traffic = intMapToMql(p.Traffic)
				mirrorTraffic = intMapToMql(p.MirrorTraffic)
			}
			epArgs := map[string]*llx.RawData{
				"id":                  llx.StringDataPtr(ep.ID),
				"name":                llx.StringDataPtr(ep.Name),
				"location":            llx.StringDataPtr(ep.Location),
				"tags":                llx.MapData(convert.PtrMapStrToInterface(ep.Tags), types.String),
				"kind":                llx.StringDataPtr(ep.Kind),
				"identity":            llx.DictData(identity),
				"description":         llx.StringData(description),
				"authMode":            llx.StringData(authMode),
				"publicNetworkAccess": llx.StringData(publicNetworkAccess),
				"scoringUri":          llx.StringData(scoringUri),
				"swaggerUri":          llx.StringData(swaggerUri),
				"traffic":             llx.MapData(traffic, types.Int),
				"mirrorTraffic":       llx.MapData(mirrorTraffic, types.Int),
				"provisioningState":   llx.StringData(provisioningState),
			}
			epIdentity := orZero(ep.Identity)
			if err := setResourceIdentity(a.MqlRuntime, epArgs, sortedUserAssignedIdentityIDs(epIdentity.UserAssignedIdentities),
				identityType(epIdentity.Type), identityPrincipalId(epIdentity.PrincipalID), identityTenantId(epIdentity.TenantID)); err != nil {
				return nil, err
			}
			mqlRes, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.onlineEndpoint", epArgs)
			if err != nil {
				return nil, err
			}
			mqlEp := mqlRes.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpoint)
			mqlEp.cacheComputeId = computeId
			sysData, err := convert.JsonToDict(ep.SystemData)
			if err != nil {
				return nil, err
			}
			mqlEp.cacheSystemData = sysData
			res = append(res, mqlEp)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpointInternal struct {
	cacheComputeId  string
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpoint) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// compute resolves the endpoint's serving compute by matching the cached ARM resource ID
// against the workspace's compute targets. Managed online endpoints have no explicit compute
// (Azure provisions it), so this returns null in that case.
func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpoint) compute() (*mqlAzureSubscriptionMachineLearningServiceWorkspaceCompute, error) {
	if a.cacheComputeId == "" {
		a.Compute.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceId := fmt.Sprintf("/subscriptions/%s/resourceGroups/%s/providers/Microsoft.MachineLearningServices/workspaces/%s",
		parsed.SubscriptionID, parsed.ResourceGroup, parsed.Path["workspaces"])

	mqlWs, err := NewResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace",
		map[string]*llx.RawData{"id": llx.StringData(workspaceId)})
	if err != nil {
		return nil, err
	}
	ws := mqlWs.(*mqlAzureSubscriptionMachineLearningServiceWorkspace)
	computes := ws.GetComputes()
	if computes.Error != nil {
		return nil, computes.Error
	}
	for _, c := range computes.Data {
		compute, ok := c.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceCompute)
		if !ok {
			continue
		}
		if strings.EqualFold(compute.Id.Data, a.cacheComputeId) {
			return compute, nil
		}
	}

	a.Compute.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpoint) deployments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName := parsed.Path["workspaces"]
	endpointName := parsed.Path["onlineendpoints"]

	ctx := context.Background()
	client, err := ml.NewOnlineDeploymentsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, workspaceName, endpointName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list machine learning online deployments due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, dep := range page.Value {
			if dep == nil {
				continue
			}
			var skuName string
			var skuCapacity int64
			if dep.SKU != nil {
				if dep.SKU.Name != nil {
					skuName = *dep.SKU.Name
				}
				if dep.SKU.Capacity != nil {
					skuCapacity = int64(*dep.SKU.Capacity)
				}
			}
			var endpointComputeType, model, environmentId, instanceType, egressPublicNetworkAccess, description, provisioningState string
			var appInsightsEnabled bool
			if dep.Properties != nil {
				if p := dep.Properties.GetOnlineDeploymentProperties(); p != nil {
					if p.EndpointComputeType != nil {
						endpointComputeType = string(*p.EndpointComputeType)
					}
					if p.Model != nil {
						model = *p.Model
					}
					if p.EnvironmentID != nil {
						environmentId = *p.EnvironmentID
					}
					if p.InstanceType != nil {
						instanceType = *p.InstanceType
					}
					if p.EgressPublicNetworkAccess != nil {
						egressPublicNetworkAccess = string(*p.EgressPublicNetworkAccess)
					}
					if p.Description != nil {
						description = *p.Description
					}
					if p.AppInsightsEnabled != nil {
						appInsightsEnabled = *p.AppInsightsEnabled
					}
					if p.ProvisioningState != nil {
						provisioningState = string(*p.ProvisioningState)
					}
				}
			}
			mqlDep, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.onlineEndpoint.deployment", map[string]*llx.RawData{
				"id":                        llx.StringDataPtr(dep.ID),
				"name":                      llx.StringDataPtr(dep.Name),
				"location":                  llx.StringDataPtr(dep.Location),
				"tags":                      llx.MapData(convert.PtrMapStrToInterface(dep.Tags), types.String),
				"description":               llx.StringData(description),
				"endpointComputeType":       llx.StringData(endpointComputeType),
				"model":                     llx.StringData(model),
				"environmentId":             llx.StringData(environmentId),
				"instanceType":              llx.StringData(instanceType),
				"skuName":                   llx.StringData(skuName),
				"skuCapacity":               llx.IntData(skuCapacity),
				"appInsightsEnabled":        llx.BoolData(appInsightsEnabled),
				"egressPublicNetworkAccess": llx.StringData(egressPublicNetworkAccess),
				"provisioningState":         llx.StringData(provisioningState),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(dep.SystemData)
			if err != nil {
				return nil, err
			}
			mqlDep.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpointDeployment).cacheSystemData = sysData
			res = append(res, mqlDep)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) serverlessEndpoints() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName := parsed.Path["workspaces"]

	ctx := context.Background()
	client, err := ml.NewServerlessEndpointsClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, workspaceName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list machine learning serverless endpoints due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, ep := range page.Value {
			if ep == nil {
				continue
			}
			identity, err := convert.JsonToDict(ep.Identity)
			if err != nil {
				return nil, err
			}
			var authMode, endpointState, modelId, inferenceUri, marketplaceSubscriptionId, contentSafetyStatus, provisioningState string
			if p := ep.Properties; p != nil {
				if p.AuthMode != nil {
					authMode = string(*p.AuthMode)
				}
				if p.EndpointState != nil {
					endpointState = string(*p.EndpointState)
				}
				if p.ModelSettings != nil && p.ModelSettings.ModelID != nil {
					modelId = *p.ModelSettings.ModelID
				}
				if p.InferenceEndpoint != nil && p.InferenceEndpoint.URI != nil {
					inferenceUri = *p.InferenceEndpoint.URI
				}
				if p.MarketplaceSubscriptionID != nil {
					marketplaceSubscriptionId = *p.MarketplaceSubscriptionID
				}
				if p.ContentSafety != nil && p.ContentSafety.ContentSafetyStatus != nil {
					contentSafetyStatus = string(*p.ContentSafety.ContentSafetyStatus)
				}
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
			}
			slArgs := map[string]*llx.RawData{
				"id":                        llx.StringDataPtr(ep.ID),
				"name":                      llx.StringDataPtr(ep.Name),
				"location":                  llx.StringDataPtr(ep.Location),
				"tags":                      llx.MapData(convert.PtrMapStrToInterface(ep.Tags), types.String),
				"identity":                  llx.DictData(identity),
				"authMode":                  llx.StringData(authMode),
				"endpointState":             llx.StringData(endpointState),
				"modelId":                   llx.StringData(modelId),
				"inferenceUri":              llx.StringData(inferenceUri),
				"marketplaceSubscriptionId": llx.StringData(marketplaceSubscriptionId),
				"contentSafetyStatus":       llx.StringData(contentSafetyStatus),
				"provisioningState":         llx.StringData(provisioningState),
			}
			slIdentity := orZero(ep.Identity)
			if err := setResourceIdentity(a.MqlRuntime, slArgs, sortedUserAssignedIdentityIDs(slIdentity.UserAssignedIdentities),
				identityType(slIdentity.Type), identityPrincipalId(slIdentity.PrincipalID), identityTenantId(slIdentity.TenantID)); err != nil {
				return nil, err
			}
			mqlEp, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.serverlessEndpoint", slArgs)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(ep.SystemData)
			if err != nil {
				return nil, err
			}
			mqlServerless := mqlEp.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceServerlessEndpoint)
			mqlServerless.cacheSystemData = sysData
			res = append(res, mqlEp)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) computes() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName := parsed.Path["workspaces"]

	ctx := context.Background()
	client, err := ml.NewComputeClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, workspaceName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list machine learning computes due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, c := range page.Value {
			if c == nil {
				continue
			}
			identity, err := convert.JsonToDict(c.Identity)
			if err != nil {
				return nil, err
			}
			var computeType, description, resourceId, computeLocation, provisioningState string
			var disableLocalAuth, isAttachedCompute bool
			var createdOn, modifiedOn *time.Time
			if c.Properties != nil {
				if p := c.Properties.GetCompute(); p != nil {
					if p.ComputeType != nil {
						computeType = string(*p.ComputeType)
					}
					if p.Description != nil {
						description = *p.Description
					}
					if p.DisableLocalAuth != nil {
						disableLocalAuth = *p.DisableLocalAuth
					}
					if p.IsAttachedCompute != nil {
						isAttachedCompute = *p.IsAttachedCompute
					}
					if p.ResourceID != nil {
						resourceId = *p.ResourceID
					}
					if p.ComputeLocation != nil {
						computeLocation = *p.ComputeLocation
					}
					if p.ProvisioningState != nil {
						provisioningState = string(*p.ProvisioningState)
					}
					createdOn = p.CreatedOn
					modifiedOn = p.ModifiedOn
				}
			}
			computeArgs := map[string]*llx.RawData{
				"id":                llx.StringDataPtr(c.ID),
				"name":              llx.StringDataPtr(c.Name),
				"location":          llx.StringDataPtr(c.Location),
				"tags":              llx.MapData(convert.PtrMapStrToInterface(c.Tags), types.String),
				"identity":          llx.DictData(identity),
				"computeType":       llx.StringData(computeType),
				"description":       llx.StringData(description),
				"disableLocalAuth":  llx.BoolData(disableLocalAuth),
				"isAttachedCompute": llx.BoolData(isAttachedCompute),
				"resourceId":        llx.StringData(resourceId),
				"computeLocation":   llx.StringData(computeLocation),
				"provisioningState": llx.StringData(provisioningState),
				"createdOn":         llx.TimeDataPtr(createdOn),
				"modifiedOn":        llx.TimeDataPtr(modifiedOn),
			}
			nodeAccess := mlComputeNodeAccessFrom(c.Properties)
			computeArgs["enableNodePublicIp"] = llx.BoolDataPtr(nodeAccess.enableNodePublicIP)
			computeArgs["sshPublicAccess"] = llx.StringDataPtr(nodeAccess.sshPublicAccess)
			computeArgs["assignedUserObjectId"] = llx.StringDataPtr(nodeAccess.assignedUserObjectID)
			computeArgs["assignedUserTenantId"] = llx.StringDataPtr(nodeAccess.assignedUserTenantID)
			computeIdentity := orZero(c.Identity)
			if err := setResourceIdentity(a.MqlRuntime, computeArgs, sortedUserAssignedIdentityIDs(computeIdentity.UserAssignedIdentities),
				identityType(computeIdentity.Type), identityPrincipalId(computeIdentity.PrincipalID), identityTenantId(computeIdentity.TenantID)); err != nil {
				return nil, err
			}
			mqlCompute, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.compute", computeArgs)
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(c.SystemData)
			if err != nil {
				return nil, err
			}
			mqlComputeRes := mqlCompute.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceCompute)
			mqlComputeRes.cacheSystemData = sysData
			mqlComputeRes.cacheSubnetId = nodeAccess.subnetID
			res = append(res, mqlCompute)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) models() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	parsed, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}
	workspaceName := parsed.Path["workspaces"]

	ctx := context.Background()
	client, err := ml.NewModelContainersClient(parsed.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(parsed.ResourceGroup, workspaceName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden {
				log.Warn().Err(err).Msg("could not list machine learning models due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, m := range page.Value {
			if m == nil {
				continue
			}
			var description, latestVersion, nextVersion, provisioningState string
			var isArchived bool
			tags := map[string]any{}
			if p := m.Properties; p != nil {
				if p.Description != nil {
					description = *p.Description
				}
				if p.LatestVersion != nil {
					latestVersion = *p.LatestVersion
				}
				if p.NextVersion != nil {
					nextVersion = *p.NextVersion
				}
				if p.IsArchived != nil {
					isArchived = *p.IsArchived
				}
				if p.ProvisioningState != nil {
					provisioningState = string(*p.ProvisioningState)
				}
				tags = convert.PtrMapStrToInterface(p.Tags)
			}
			mqlModel, err := CreateResource(a.MqlRuntime, "azure.subscription.machineLearningService.workspace.model", map[string]*llx.RawData{
				"id":                llx.StringDataPtr(m.ID),
				"name":              llx.StringDataPtr(m.Name),
				"description":       llx.StringData(description),
				"latestVersion":     llx.StringData(latestVersion),
				"nextVersion":       llx.StringData(nextVersion),
				"isArchived":        llx.BoolData(isArchived),
				"tags":              llx.MapData(tags, types.String),
				"provisioningState": llx.StringData(provisioningState),
			})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(m.SystemData)
			if err != nil {
				return nil, err
			}
			mqlModel.(*mqlAzureSubscriptionMachineLearningServiceWorkspaceModel).cacheSystemData = sysData
			res = append(res, mqlModel)
		}
	}
	return res, nil
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpointDeploymentInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceServerlessEndpointInternal struct {
	cacheSystemData any
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceComputeInternal struct {
	cacheSystemData any
	cacheSubnetId   *string
}

// mlComputeNodeAccess holds the node-level network and access settings of a
// compute target. Only ComputeInstance and AmlCompute carry them; every field
// stays nil for other compute types so the MQL fields read null rather than a
// false or empty value that would claim the setting was measured.
type mlComputeNodeAccess struct {
	enableNodePublicIP   *bool
	sshPublicAccess      *string
	subnetID             *string
	assignedUserObjectID *string
	assignedUserTenantID *string
}

func mlComputeNodeAccessFrom(c ml.ComputeClassification) mlComputeNodeAccess {
	var out mlComputeNodeAccess
	switch v := c.(type) {
	case *ml.ComputeInstance:
		if v == nil || v.Properties == nil {
			return out
		}
		p := v.Properties
		out.enableNodePublicIP = p.EnableNodePublicIP
		if p.SSHSettings != nil && p.SSHSettings.SSHPublicAccess != nil {
			out.sshPublicAccess = new(string(*p.SSHSettings.SSHPublicAccess))
		}
		if p.Subnet != nil {
			out.subnetID = p.Subnet.ID
		}
		if s := p.PersonalComputeInstanceSettings; s != nil && s.AssignedUser != nil {
			out.assignedUserObjectID = s.AssignedUser.ObjectID
			out.assignedUserTenantID = s.AssignedUser.TenantID
		}
	case *ml.AmlCompute:
		if v == nil || v.Properties == nil {
			return out
		}
		p := v.Properties
		out.enableNodePublicIP = p.EnableNodePublicIP
		if p.RemoteLoginPortPublicAccess != nil {
			out.sshPublicAccess = new(string(*p.RemoteLoginPortPublicAccess))
		}
		if p.Subnet != nil {
			out.subnetID = p.Subnet.ID
		}
	}
	return out
}

// subnet resolves the subnet the compute nodes are placed in. Null when the
// compute is not in a customer subnet or its type has no subnet setting.
func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceCompute) subnet() (*mqlAzureSubscriptionNetworkServiceSubnet, error) {
	return resolveDelegatedSubnet(a.MqlRuntime, a.cacheSubnetId, &a.Subnet)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) diagnosticSettings() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	return getDiagnosticSettings(a.Id.Data, a.MqlRuntime, conn)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspace) roleAssignments() ([]any, error) {
	return roleAssignmentsForScope(a.MqlRuntime, a.Id.Data, "machine learning workspace")
}

type mqlAzureSubscriptionMachineLearningServiceWorkspaceModelInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceOnlineEndpointDeployment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceServerlessEndpoint) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceCompute) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionMachineLearningServiceWorkspaceModel) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}
