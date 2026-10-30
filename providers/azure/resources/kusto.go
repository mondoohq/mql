// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto/v2"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionKustoService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionKustoService) id() (string, error) {
	return "azure.subscription.kustoService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionKustoServiceCluster) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKustoService) clusters() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	ctx := context.Background()
	client, err := armkusto.NewClustersClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
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
				log.Warn().Err(err).Msg("could not list Data Explorer clusters due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, cluster := range page.Value {
			if cluster == nil {
				continue
			}
			mqlCluster, err := kustoClusterToMql(a.MqlRuntime, cluster)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCluster)
		}
	}
	return res, nil
}

func kustoClusterToMql(runtime *plugin.Runtime, cluster *armkusto.Cluster) (*mqlAzureSubscriptionKustoServiceCluster, error) {
	sku, err := convert.JsonToDict(cluster.SKU)
	if err != nil {
		return nil, err
	}
	identity, err := convert.JsonToDict(cluster.Identity)
	if err != nil {
		return nil, err
	}

	var uri, dataIngestionURI, state, provisioningState string
	var publicNetworkAccess, publicIPType, restrictOutbound string
	var cmkKeyName, cmkKeyVaultURI, cmkKeyVersion, cmkFederatedIdentityClientID string
	var enableDiskEncryption, enableDoubleEncryption, enableStreamingIngest, enablePurge bool
	allowedIPRangeList := []any{}
	allowedFqdnList := []any{}
	trustedExternalTenants := []any{}

	if p := cluster.Properties; p != nil {
		uri = convert.ToValue(p.URI)
		dataIngestionURI = convert.ToValue(p.DataIngestionURI)
		state = string(convert.ToValue(p.State))
		provisioningState = string(convert.ToValue(p.ProvisioningState))
		publicNetworkAccess = string(convert.ToValue(p.PublicNetworkAccess))
		publicIPType = string(convert.ToValue(p.PublicIPType))
		restrictOutbound = string(convert.ToValue(p.RestrictOutboundNetworkAccess))
		enableDiskEncryption = convert.ToValue(p.EnableDiskEncryption)
		enableDoubleEncryption = convert.ToValue(p.EnableDoubleEncryption)
		enableStreamingIngest = convert.ToValue(p.EnableStreamingIngest)
		enablePurge = convert.ToValue(p.EnablePurge)
		for _, ip := range p.AllowedIPRangeList {
			if ip != nil {
				allowedIPRangeList = append(allowedIPRangeList, *ip)
			}
		}
		for _, fqdn := range p.AllowedFqdnList {
			if fqdn != nil {
				allowedFqdnList = append(allowedFqdnList, *fqdn)
			}
		}
		for _, t := range p.TrustedExternalTenants {
			if t != nil && t.Value != nil {
				trustedExternalTenants = append(trustedExternalTenants, *t.Value)
			}
		}
		if kv := p.KeyVaultProperties; kv != nil {
			cmkKeyName = convert.ToValue(kv.KeyName)
			cmkKeyVaultURI = convert.ToValue(kv.KeyVaultURI)
			cmkKeyVersion = convert.ToValue(kv.KeyVersion)
			cmkFederatedIdentityClientID = convert.ToValue(kv.FederatedIdentityClientID)
		}
	}

	args := map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(cluster.ID),
		"name":                          llx.StringDataPtr(cluster.Name),
		"location":                      llx.StringDataPtr(cluster.Location),
		"tags":                          llx.MapData(convert.PtrMapStrToInterface(cluster.Tags), types.String),
		"sku":                           llx.DictData(sku),
		"identity":                      llx.DictData(identity),
		"uri":                           llx.StringData(uri),
		"dataIngestionUri":              llx.StringData(dataIngestionURI),
		"state":                         llx.StringData(state),
		"provisioningState":             llx.StringData(provisioningState),
		"publicNetworkAccess":           llx.StringData(publicNetworkAccess),
		"publicIpType":                  llx.StringData(publicIPType),
		"restrictOutboundNetworkAccess": llx.StringData(restrictOutbound),
		"enableDiskEncryption":          llx.BoolData(enableDiskEncryption),
		"enableDoubleEncryption":        llx.BoolData(enableDoubleEncryption),
		"enableStreamingIngest":         llx.BoolData(enableStreamingIngest),
		"enablePurge":                   llx.BoolData(enablePurge),
		"allowedIpRangeList":            llx.ArrayData(allowedIPRangeList, types.String),
		"allowedFqdnList":               llx.ArrayData(allowedFqdnList, types.String),
		"trustedExternalTenants":        llx.ArrayData(trustedExternalTenants, types.String),
		"cmkKeyName":                    llx.StringData(cmkKeyName),
		"cmkKeyVaultUri":                llx.StringData(cmkKeyVaultURI),
		"cmkKeyVersion":                 llx.StringData(cmkKeyVersion),
		"cmkFederatedIdentityClientId":  llx.StringData(cmkFederatedIdentityClientID),
	}
	clusterSku := orZero(cluster.SKU)
	if err := setSkuData(runtime, args, skuName(clusterSku.Name), skuTier(clusterSku.Tier), skuCapacity(clusterSku.Capacity)); err != nil {
		return nil, err
	}

	clusterIdentity := orZero(cluster.Identity)
	if err := setResourceIdentity(runtime, args, sortedUserAssignedIdentityIDs(clusterIdentity.UserAssignedIdentities),
		identityType(clusterIdentity.Type), identityPrincipalId(clusterIdentity.PrincipalID), identityTenantId(clusterIdentity.TenantID)); err != nil {
		return nil, err
	}

	res, err := CreateResource(runtime, "azure.subscription.kustoService.cluster", args)
	if err != nil {
		return nil, err
	}
	mqlCluster := res.(*mqlAzureSubscriptionKustoServiceCluster)
	sysData, err := convert.JsonToDict(cluster.SystemData)
	if err != nil {
		return nil, err
	}
	mqlCluster.cacheSystemData = sysData
	return mqlCluster, nil
}

type mqlAzureSubscriptionKustoServiceClusterInternal struct {
	cacheSystemData any
}

// kustoAccessDenied reports whether the error is a 403 from the Azure API, in
// which case a list call returns the rows gathered so far instead of failing.
func kustoAccessDenied(err error) bool {
	var respErr *azcore.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden
}

// clusterScope parses the resource group and cluster name out of the cluster's
// ARM resource ID, which the cluster-scoped sub-resource list calls require.
func (a *mqlAzureSubscriptionKustoServiceCluster) clusterScope() (resourceGroup string, clusterName string, err error) {
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return "", "", err
	}
	clusterName, err = resourceID.Component("clusters")
	if err != nil {
		return "", "", err
	}
	return resourceID.ResourceGroup, clusterName, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabase) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterPrincipalAssignment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabasePrincipalAssignment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterPrivateEndpointConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterManagedPrivateEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabaseDataConnection) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionKustoServiceClusterPrivateEndpointConnectionInternal struct {
	cachePrivateEndpointID string
	cacheSystemData        any
}

type mqlAzureSubscriptionKustoServiceClusterManagedPrivateEndpointInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionKustoServiceClusterPrivateEndpointConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

func (a *mqlAzureSubscriptionKustoServiceClusterManagedPrivateEndpoint) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionKustoServiceClusterDatabaseInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabase) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionKustoServiceClusterPrincipalAssignmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionKustoServiceClusterPrincipalAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionKustoServiceClusterDatabasePrincipalAssignmentInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabasePrincipalAssignment) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionKustoServiceClusterDatabaseDataConnectionInternal struct {
	cacheManagedIdentityID string
	cacheSystemData        any
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabaseDataConnection) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

// initAzureSubscriptionKustoServiceCluster resolves a Data Explorer cluster
// referenced only by its resource ID (for example a follower database's leader
// cluster) by fetching it on demand. When the cluster was already listed by
// clusters(), the runtime cache short-circuits this and the init never runs.
func initAzureSubscriptionKustoServiceCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) != 1 {
		return args, nil, nil
	}
	idRaw, ok := args["__id"]
	if !ok {
		return args, nil, nil
	}
	id, ok := idRaw.Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	resourceID, err := ParseResourceID(id)
	if err != nil {
		return args, nil, nil
	}
	clusterName, err := resourceID.Component("clusters")
	if err != nil {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	client, err := armkusto.NewClustersClient(resourceID.SubscriptionID, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, nil, err
	}
	cluster, err := client.Get(context.Background(), resourceID.ResourceGroup, clusterName, nil)
	if err != nil {
		// The leader cluster may be inaccessible (cross-subscription, deleted,
		// or access denied); fall back to the bare reference rather than
		// failing the surrounding query.
		return args, nil, nil
	}
	mqlCluster, err := kustoClusterToMql(runtime, &cluster.Cluster)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlCluster, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabase) leaderCluster() (*mqlAzureSubscriptionKustoServiceCluster, error) {
	leaderID := a.LeaderClusterResourceId.Data
	if leaderID == "" {
		a.LeaderCluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.kustoService.cluster",
		map[string]*llx.RawData{"__id": llx.StringData(leaderID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionKustoServiceCluster), nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterPrivateEndpointConnection) privateEndpoint() (*mqlAzureSubscriptionNetworkServicePrivateEndpoint, error) {
	if a.cachePrivateEndpointID == "" {
		a.PrivateEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.networkService.privateEndpoint",
		map[string]*llx.RawData{"id": llx.StringData(a.cachePrivateEndpointID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionNetworkServicePrivateEndpoint), nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabaseDataConnection) managedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheManagedIdentityID == "" {
		a.ManagedIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheManagedIdentityID)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionKustoServiceCluster) databases() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	rg, clusterName, err := a.clusterScope()
	if err != nil {
		return nil, err
	}
	client, err := armkusto.NewDatabasesClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByClusterPager(rg, clusterName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if kustoAccessDenied(err) {
				log.Warn().Err(err).Msg("could not list Data Explorer databases due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			db := item.GetDatabase()
			var hotCachePeriod, softDeletePeriod, provisioningState string
			var cmkKeyName, cmkKeyVaultURI, cmkKeyVersion string
			var leaderClusterResourceID, originalDatabaseName string
			switch d := item.(type) {
			case *armkusto.ReadWriteDatabase:
				if p := d.Properties; p != nil {
					hotCachePeriod = convert.ToValue(p.HotCachePeriod)
					softDeletePeriod = convert.ToValue(p.SoftDeletePeriod)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
					if kv := p.KeyVaultProperties; kv != nil {
						cmkKeyName = convert.ToValue(kv.KeyName)
						cmkKeyVaultURI = convert.ToValue(kv.KeyVaultURI)
						cmkKeyVersion = convert.ToValue(kv.KeyVersion)
					}
				}
			case *armkusto.ReadOnlyFollowingDatabase:
				if p := d.Properties; p != nil {
					hotCachePeriod = convert.ToValue(p.HotCachePeriod)
					softDeletePeriod = convert.ToValue(p.SoftDeletePeriod)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
					leaderClusterResourceID = convert.ToValue(p.LeaderClusterResourceID)
					originalDatabaseName = convert.ToValue(p.OriginalDatabaseName)
				}
			}
			mqlDb, err := CreateResource(a.MqlRuntime, "azure.subscription.kustoService.cluster.database",
				map[string]*llx.RawData{
					"id":                      llx.StringDataPtr(db.ID),
					"name":                    llx.StringDataPtr(db.Name),
					"location":                llx.StringDataPtr(db.Location),
					"kind":                    llx.StringData(string(convert.ToValue(db.Kind))),
					"hotCachePeriod":          llx.StringData(hotCachePeriod),
					"softDeletePeriod":        llx.StringData(softDeletePeriod),
					"provisioningState":       llx.StringData(provisioningState),
					"cmkKeyName":              llx.StringData(cmkKeyName),
					"cmkKeyVaultUri":          llx.StringData(cmkKeyVaultURI),
					"cmkKeyVersion":           llx.StringData(cmkKeyVersion),
					"leaderClusterResourceId": llx.StringData(leaderClusterResourceID),
					"originalDatabaseName":    llx.StringData(originalDatabaseName),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(db.SystemData)
			if err != nil {
				return nil, err
			}
			mqlDb.(*mqlAzureSubscriptionKustoServiceClusterDatabase).cacheSystemData = sysData
			res = append(res, mqlDb)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionKustoServiceCluster) principalAssignments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	rg, clusterName, err := a.clusterScope()
	if err != nil {
		return nil, err
	}
	client, err := armkusto.NewClusterPrincipalAssignmentsClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListPager(rg, clusterName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if kustoAccessDenied(err) {
				log.Warn().Err(err).Msg("could not list Data Explorer cluster principal assignments due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, pa := range page.Value {
			if pa == nil {
				continue
			}
			var principalID, principalName, principalType, role, tenantID, provisioningState string
			if p := pa.Properties; p != nil {
				principalID = convert.ToValue(p.PrincipalID)
				principalName = convert.ToValue(p.PrincipalName)
				principalType = string(convert.ToValue(p.PrincipalType))
				role = string(convert.ToValue(p.Role))
				tenantID = convert.ToValue(p.TenantID)
				provisioningState = string(convert.ToValue(p.ProvisioningState))
			}
			mqlPa, err := CreateResource(a.MqlRuntime, "azure.subscription.kustoService.cluster.principalAssignment",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(pa.ID),
					"name":              llx.StringDataPtr(pa.Name),
					"principalId":       llx.StringData(principalID),
					"principalName":     llx.StringData(principalName),
					"principalType":     llx.StringData(principalType),
					"role":              llx.StringData(role),
					"tenantId":          llx.StringData(tenantID),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(pa.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPa.(*mqlAzureSubscriptionKustoServiceClusterPrincipalAssignment).cacheSystemData = sysData
			res = append(res, mqlPa)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionKustoServiceCluster) calloutPolicies() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	rg, clusterName, err := a.clusterScope()
	if err != nil {
		return nil, err
	}
	client, err := armkusto.NewClustersClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListCalloutPoliciesPager(rg, clusterName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if kustoAccessDenied(err) {
				log.Warn().Err(err).Msg("could not list Data Explorer cluster callout policies due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, cp := range page.Value {
			if cp == nil {
				continue
			}
			calloutType := string(convert.ToValue(cp.CalloutType))
			calloutURIRegex := convert.ToValue(cp.CalloutURIRegex)
			mqlCp, err := CreateResource(a.MqlRuntime, "azure.subscription.kustoService.cluster.calloutPolicy",
				map[string]*llx.RawData{
					"__id":            llx.StringData(a.Id.Data + "/calloutPolicies/" + calloutType + "/" + calloutURIRegex),
					"calloutId":       llx.StringData(convert.ToValue(cp.CalloutID)),
					"calloutType":     llx.StringData(calloutType),
					"calloutUriRegex": llx.StringData(calloutURIRegex),
					"outboundAccess":  llx.StringData(string(convert.ToValue(cp.OutboundAccess))),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCp)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionKustoServiceCluster) privateEndpointConnections() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	rg, clusterName, err := a.clusterScope()
	if err != nil {
		return nil, err
	}
	client, err := armkusto.NewPrivateEndpointConnectionsClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListPager(rg, clusterName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if kustoAccessDenied(err) {
				log.Warn().Err(err).Msg("could not list Data Explorer cluster private endpoint connections due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, pec := range page.Value {
			if pec == nil {
				continue
			}
			var groupID, status, statusDescription, privateEndpointID, provisioningState string
			if p := pec.Properties; p != nil {
				groupID = convert.ToValue(p.GroupID)
				provisioningState = convert.ToValue(p.ProvisioningState)
				if s := p.PrivateLinkServiceConnectionState; s != nil {
					status = convert.ToValue(s.Status)
					statusDescription = convert.ToValue(s.Description)
				}
				if pe := p.PrivateEndpoint; pe != nil {
					privateEndpointID = convert.ToValue(pe.ID)
				}
			}
			mqlPec, err := CreateResource(a.MqlRuntime, "azure.subscription.kustoService.cluster.privateEndpointConnection",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(pec.ID),
					"name":              llx.StringDataPtr(pec.Name),
					"groupId":           llx.StringData(groupID),
					"status":            llx.StringData(status),
					"statusDescription": llx.StringData(statusDescription),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			mqlPec.(*mqlAzureSubscriptionKustoServiceClusterPrivateEndpointConnection).cachePrivateEndpointID = privateEndpointID
			sysData, err := convert.JsonToDict(pec.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPec.(*mqlAzureSubscriptionKustoServiceClusterPrivateEndpointConnection).cacheSystemData = sysData
			res = append(res, mqlPec)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionKustoServiceCluster) managedPrivateEndpoints() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	rg, clusterName, err := a.clusterScope()
	if err != nil {
		return nil, err
	}
	client, err := armkusto.NewManagedPrivateEndpointsClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListPager(rg, clusterName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if kustoAccessDenied(err) {
				log.Warn().Err(err).Msg("could not list Data Explorer cluster managed private endpoints due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, mpe := range page.Value {
			if mpe == nil {
				continue
			}
			var groupID, privateLinkResourceID, privateLinkResourceRegion, requestMessage, provisioningState string
			if p := mpe.Properties; p != nil {
				groupID = convert.ToValue(p.GroupID)
				privateLinkResourceID = convert.ToValue(p.PrivateLinkResourceID)
				privateLinkResourceRegion = convert.ToValue(p.PrivateLinkResourceRegion)
				requestMessage = convert.ToValue(p.RequestMessage)
				provisioningState = string(convert.ToValue(p.ProvisioningState))
			}
			mqlMpe, err := CreateResource(a.MqlRuntime, "azure.subscription.kustoService.cluster.managedPrivateEndpoint",
				map[string]*llx.RawData{
					"id":                        llx.StringDataPtr(mpe.ID),
					"name":                      llx.StringDataPtr(mpe.Name),
					"groupId":                   llx.StringData(groupID),
					"privateLinkResourceId":     llx.StringData(privateLinkResourceID),
					"privateLinkResourceRegion": llx.StringData(privateLinkResourceRegion),
					"requestMessage":            llx.StringData(requestMessage),
					"provisioningState":         llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(mpe.SystemData)
			if err != nil {
				return nil, err
			}
			mqlMpe.(*mqlAzureSubscriptionKustoServiceClusterManagedPrivateEndpoint).cacheSystemData = sysData
			res = append(res, mqlMpe)
		}
	}
	return res, nil
}

// databaseScope parses the resource group, cluster name, and database name out
// of the database's ARM resource ID, which database-scoped sub-resource list
// calls require.
func (a *mqlAzureSubscriptionKustoServiceClusterDatabase) databaseScope() (resourceGroup string, clusterName string, databaseName string, err error) {
	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return "", "", "", err
	}
	clusterName, err = resourceID.Component("clusters")
	if err != nil {
		return "", "", "", err
	}
	databaseName, err = resourceID.Component("databases")
	if err != nil {
		return "", "", "", err
	}
	return resourceID.ResourceGroup, clusterName, databaseName, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabase) principalAssignments() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	rg, clusterName, dbName, err := a.databaseScope()
	if err != nil {
		return nil, err
	}
	client, err := armkusto.NewDatabasePrincipalAssignmentsClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListPager(rg, clusterName, dbName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if kustoAccessDenied(err) {
				log.Warn().Err(err).Msg("could not list Data Explorer database principal assignments due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, pa := range page.Value {
			if pa == nil {
				continue
			}
			var principalID, principalName, principalType, role, tenantID, provisioningState string
			if p := pa.Properties; p != nil {
				principalID = convert.ToValue(p.PrincipalID)
				principalName = convert.ToValue(p.PrincipalName)
				principalType = string(convert.ToValue(p.PrincipalType))
				role = string(convert.ToValue(p.Role))
				tenantID = convert.ToValue(p.TenantID)
				provisioningState = string(convert.ToValue(p.ProvisioningState))
			}
			mqlPa, err := CreateResource(a.MqlRuntime, "azure.subscription.kustoService.cluster.database.principalAssignment",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(pa.ID),
					"name":              llx.StringDataPtr(pa.Name),
					"principalId":       llx.StringData(principalID),
					"principalName":     llx.StringData(principalName),
					"principalType":     llx.StringData(principalType),
					"role":              llx.StringData(role),
					"tenantId":          llx.StringData(tenantID),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			sysData, err := convert.JsonToDict(pa.SystemData)
			if err != nil {
				return nil, err
			}
			mqlPa.(*mqlAzureSubscriptionKustoServiceClusterDatabasePrincipalAssignment).cacheSystemData = sysData
			res = append(res, mqlPa)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionKustoServiceClusterDatabase) dataConnections() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	rg, clusterName, dbName, err := a.databaseScope()
	if err != nil {
		return nil, err
	}
	client, err := armkusto.NewDataConnectionsClient(conn.SubId(), conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	pager := client.NewListByDatabasePager(rg, clusterName, dbName, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if kustoAccessDenied(err) {
				log.Warn().Err(err).Msg("could not list Data Explorer data connections due to access denied")
				return res, nil
			}
			return nil, err
		}
		for _, item := range page.Value {
			if item == nil {
				continue
			}
			dc := item.GetDataConnection()
			var tableName, dataFormat, mappingRuleName, consumerGroup, databaseRouting string
			var sourceResourceID, managedIdentityResourceID, provisioningState string
			switch d := item.(type) {
			case *armkusto.EventHubDataConnection:
				if p := d.Properties; p != nil {
					tableName = convert.ToValue(p.TableName)
					dataFormat = string(convert.ToValue(p.DataFormat))
					mappingRuleName = convert.ToValue(p.MappingRuleName)
					consumerGroup = convert.ToValue(p.ConsumerGroup)
					databaseRouting = string(convert.ToValue(p.DatabaseRouting))
					sourceResourceID = convert.ToValue(p.EventHubResourceID)
					managedIdentityResourceID = convert.ToValue(p.ManagedIdentityResourceID)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
				}
			case *armkusto.EventGridDataConnection:
				if p := d.Properties; p != nil {
					tableName = convert.ToValue(p.TableName)
					dataFormat = string(convert.ToValue(p.DataFormat))
					mappingRuleName = convert.ToValue(p.MappingRuleName)
					consumerGroup = convert.ToValue(p.ConsumerGroup)
					databaseRouting = string(convert.ToValue(p.DatabaseRouting))
					sourceResourceID = convert.ToValue(p.StorageAccountResourceID)
					managedIdentityResourceID = convert.ToValue(p.ManagedIdentityResourceID)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
				}
			case *armkusto.IotHubDataConnection:
				if p := d.Properties; p != nil {
					tableName = convert.ToValue(p.TableName)
					dataFormat = string(convert.ToValue(p.DataFormat))
					mappingRuleName = convert.ToValue(p.MappingRuleName)
					consumerGroup = convert.ToValue(p.ConsumerGroup)
					databaseRouting = string(convert.ToValue(p.DatabaseRouting))
					sourceResourceID = convert.ToValue(p.IotHubResourceID)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
				}
			case *armkusto.CosmosDbDataConnection:
				if p := d.Properties; p != nil {
					tableName = convert.ToValue(p.TableName)
					mappingRuleName = convert.ToValue(p.MappingRuleName)
					sourceResourceID = convert.ToValue(p.CosmosDbAccountResourceID)
					managedIdentityResourceID = convert.ToValue(p.ManagedIdentityResourceID)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
				}
			case *armkusto.EventHubDataConnectionWithManagedIdentity:
				if p := d.Properties; p != nil {
					tableName = convert.ToValue(p.TableName)
					dataFormat = string(convert.ToValue(p.DataFormat))
					mappingRuleName = convert.ToValue(p.MappingRuleName)
					consumerGroup = convert.ToValue(p.ConsumerGroup)
					databaseRouting = string(convert.ToValue(p.DatabaseRouting))
					sourceResourceID = convert.ToValue(p.EventHubResourceIDForManagedIdentity)
					managedIdentityResourceID = convert.ToValue(p.ManagedIdentityResourceID)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
				}
			case *armkusto.EventGridDataConnectionWithManagedIdentity:
				if p := d.Properties; p != nil {
					tableName = convert.ToValue(p.TableName)
					dataFormat = string(convert.ToValue(p.DataFormat))
					mappingRuleName = convert.ToValue(p.MappingRuleName)
					consumerGroup = convert.ToValue(p.ConsumerGroup)
					databaseRouting = string(convert.ToValue(p.DatabaseRouting))
					sourceResourceID = convert.ToValue(p.StorageAccountResourceIDForManagedIdentity)
					managedIdentityResourceID = convert.ToValue(p.ManagedIdentityResourceID)
					provisioningState = string(convert.ToValue(p.ProvisioningState))
				}
			}
			mqlDc, err := CreateResource(a.MqlRuntime, "azure.subscription.kustoService.cluster.database.dataConnection",
				map[string]*llx.RawData{
					"id":                llx.StringDataPtr(dc.ID),
					"name":              llx.StringDataPtr(dc.Name),
					"location":          llx.StringDataPtr(dc.Location),
					"kind":              llx.StringData(string(convert.ToValue(dc.Kind))),
					"tableName":         llx.StringData(tableName),
					"dataFormat":        llx.StringData(dataFormat),
					"mappingRuleName":   llx.StringData(mappingRuleName),
					"consumerGroup":     llx.StringData(consumerGroup),
					"databaseRouting":   llx.StringData(databaseRouting),
					"sourceResourceId":  llx.StringData(sourceResourceID),
					"provisioningState": llx.StringData(provisioningState),
				})
			if err != nil {
				return nil, err
			}
			mqlDc.(*mqlAzureSubscriptionKustoServiceClusterDatabaseDataConnection).cacheManagedIdentityID = managedIdentityResourceID
			sysData, err := convert.JsonToDict(dc.SystemData)
			if err != nil {
				return nil, err
			}
			mqlDc.(*mqlAzureSubscriptionKustoServiceClusterDatabaseDataConnection).cacheSystemData = sysData
			res = append(res, mqlDc)
		}
	}
	return res, nil
}
