// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/servicefabric/armservicefabric/v2"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

func initAzureSubscriptionServiceFabricService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (a *mqlAzureSubscriptionServiceFabricService) id() (string, error) {
	return "azure.subscription.serviceFabricService/" + a.SubscriptionId.Data, nil
}

func (a *mqlAzureSubscriptionServiceFabricServiceCluster) id() (string, error) {
	return a.Id.Data, nil
}

type mqlAzureSubscriptionServiceFabricServiceClusterInternal struct {
	cacheSystemData any
}

func (a *mqlAzureSubscriptionServiceFabricServiceCluster) systemMetadata() (*mqlAzureSubscriptionSystemData, error) {
	return systemMetadataFromRaw(a.MqlRuntime, a.Id.Data, a.cacheSystemData, &a.SystemMetadata)
}

type mqlAzureSubscriptionServiceFabricServiceClusterDiagnosticsStorageAccountConfigInternal struct {
	cacheStorageAccountName string
}

func (a *mqlAzureSubscriptionServiceFabricService) clusters() ([]any, error) {
	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	ctx := context.Background()
	client, err := armservicefabric.NewClustersClient(a.SubscriptionId.Data, conn.Token(), &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(&armservicefabric.ClustersClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, entry := range page.Value {
			if entry == nil {
				continue
			}

			cluster, err := serviceFabricClusterToMql(a.MqlRuntime, entry)
			if err != nil {
				return nil, err
			}
			res = append(res, cluster)
		}
	}

	return res, nil
}

// serviceFabricManagementEndpointHTTPS reports whether the cluster publishes
// its management endpoint over TLS. It stays nil when the endpoint itself is
// absent, so an unread endpoint reads as null rather than claiming the
// cluster serves the administrative API in the clear.
func serviceFabricManagementEndpointHTTPS(endpoint *string) *bool {
	if endpoint == nil {
		return nil
	}
	https := strings.HasPrefix(strings.ToLower(strings.TrimSpace(*endpoint)), "https://")
	return &https
}

// serviceFabricAddOnFeatures flattens the add-on feature enums, skipping nil
// entries rather than dereferencing them.
func serviceFabricAddOnFeatures(features []*armservicefabric.AddOnFeatures) []any {
	res := []any{}
	for _, f := range features {
		if f == nil {
			continue
		}
		res = append(res, string(*f))
	}
	return res
}

// serviceFabricSettingParameters turns a configuration section's parameter
// list into a name to value map, skipping entries with no name.
func serviceFabricSettingParameters(params []*armservicefabric.SettingsParameterDescription) map[string]any {
	res := map[string]any{}
	for _, p := range params {
		if p == nil || p.Name == nil {
			continue
		}
		if p.Value == nil {
			res[*p.Name] = ""
			continue
		}
		res[*p.Name] = *p.Value
	}
	return res
}

func serviceFabricClusterToMql(runtime *plugin.Runtime, cluster *armservicefabric.Cluster) (*mqlAzureSubscriptionServiceFabricServiceCluster, error) {
	clusterID := derefStr(cluster.ID)

	// Every property-derived field starts null. A cluster whose properties
	// block is missing reports "not read" rather than a zero value that would
	// read as a measured setting.
	args := map[string]*llx.RawData{
		"id":                            llx.StringDataPtr(cluster.ID),
		"name":                          llx.StringDataPtr(cluster.Name),
		"location":                      llx.StringDataPtr(cluster.Location),
		"type":                          llx.StringDataPtr(cluster.Type),
		"tags":                          llx.MapData(convert.PtrMapStrToInterface(cluster.Tags), types.String),
		"etag":                          llx.StringDataPtr(cluster.Etag),
		"clusterId":                     llx.NilData,
		"managementEndpoint":            llx.NilData,
		"managementEndpointHttps":       llx.NilData,
		"clusterEndpoint":               llx.NilData,
		"clusterState":                  llx.NilData,
		"provisioningState":             llx.NilData,
		"clusterCodeVersion":            llx.NilData,
		"upgradeMode":                   llx.NilData,
		"upgradeWave":                   llx.NilData,
		"waveUpgradePaused":             llx.NilData,
		"upgradePauseStartTimestampUtc": llx.NilData,
		"upgradePauseEndTimestampUtc":   llx.NilData,
		"reliabilityLevel":              llx.NilData,
		"vmImage":                       llx.NilData,
		"addOnFeatures":                 llx.ArrayData([]any{}, types.String),
		"eventStoreServiceEnabled":      llx.NilData,
		"infrastructureServiceManager":  llx.NilData,
		"sfZonalUpgradeMode":            llx.NilData,
		"vmssZonalUpgradeMode":          llx.NilData,
		"azureActiveDirectory":          llx.NilData,
		"certificate":                   llx.NilData,
		// Azure Resource Manager returns null and [] interchangeably for these
		// lists: this cluster reports certificateCommonNames as null and
		// clientCertificateCommonNames as [], and both mean "none configured".
		// They are emitted as empty lists so that
		// clientCertificateThumbprints.none(isAdmin) answers the question it
		// looks like it answers instead of failing on a null.
		"certificateCommonNames":                      llx.ArrayData([]any{}, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterServerCertificateCommonName)),
		"certificateCommonNamesStoreName":             llx.NilData,
		"reverseProxyCertificate":                     llx.NilData,
		"reverseProxyCertificateCommonNames":          llx.ArrayData([]any{}, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterServerCertificateCommonName)),
		"reverseProxyCertificateCommonNamesStoreName": llx.NilData,
		"clientCertificateThumbprints":                llx.ArrayData([]any{}, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterClientCertificateThumbprint)),
		"clientCertificateCommonNames":                llx.ArrayData([]any{}, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterClientCertificateCommonName)),
		"nodeTypes":                                   llx.ArrayData([]any{}, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterNodeType)),
		"fabricSettings":                              llx.ArrayData([]any{}, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterFabricSetting)),
		"diagnosticsStorageAccountConfig":             llx.NilData,
	}

	if props := cluster.Properties; props != nil {
		args["clusterId"] = llx.StringDataPtr(props.ClusterID)
		args["managementEndpoint"] = llx.StringDataPtr(props.ManagementEndpoint)
		args["managementEndpointHttps"] = llx.BoolDataPtr(serviceFabricManagementEndpointHTTPS(props.ManagementEndpoint))
		args["clusterEndpoint"] = llx.StringDataPtr(props.ClusterEndpoint)
		args["clusterState"] = llx.StringDataPtr((*string)(props.ClusterState))
		args["provisioningState"] = llx.StringDataPtr((*string)(props.ProvisioningState))
		args["clusterCodeVersion"] = llx.StringDataPtr(props.ClusterCodeVersion)
		args["upgradeMode"] = llx.StringDataPtr((*string)(props.UpgradeMode))
		args["upgradeWave"] = llx.StringDataPtr((*string)(props.UpgradeWave))
		args["waveUpgradePaused"] = llx.BoolDataPtr(props.WaveUpgradePaused)
		args["upgradePauseStartTimestampUtc"] = llx.TimeDataPtr(props.UpgradePauseStartTimestampUTC)
		args["upgradePauseEndTimestampUtc"] = llx.TimeDataPtr(props.UpgradePauseEndTimestampUTC)
		args["reliabilityLevel"] = llx.StringDataPtr((*string)(props.ReliabilityLevel))
		args["vmImage"] = llx.StringDataPtr(props.VMImage)
		args["addOnFeatures"] = llx.ArrayData(serviceFabricAddOnFeatures(props.AddOnFeatures), types.String)
		args["eventStoreServiceEnabled"] = llx.BoolDataPtr(props.EventStoreServiceEnabled)
		args["infrastructureServiceManager"] = llx.BoolDataPtr(props.InfrastructureServiceManager)
		args["sfZonalUpgradeMode"] = llx.StringDataPtr((*string)(props.SfZonalUpgradeMode))
		args["vmssZonalUpgradeMode"] = llx.StringDataPtr((*string)(props.VmssZonalUpgradeMode))

		if props.AzureActiveDirectory != nil {
			aad, err := serviceFabricAadToMql(runtime, clusterID, props.AzureActiveDirectory)
			if err != nil {
				return nil, err
			}
			args["azureActiveDirectory"] = llx.ResourceData(aad, aad.MqlName())
		}

		if props.Certificate != nil {
			cert, err := serviceFabricCertificateToMql(runtime, clusterID+"/certificate", props.Certificate)
			if err != nil {
				return nil, err
			}
			args["certificate"] = llx.ResourceData(cert, cert.MqlName())
		}

		if props.ReverseProxyCertificate != nil {
			cert, err := serviceFabricCertificateToMql(runtime, clusterID+"/reverseProxyCertificate", props.ReverseProxyCertificate)
			if err != nil {
				return nil, err
			}
			args["reverseProxyCertificate"] = llx.ResourceData(cert, cert.MqlName())
		}

		if props.CertificateCommonNames != nil {
			names, err := serviceFabricServerCommonNamesToMql(runtime, clusterID+"/certificateCommonNames", props.CertificateCommonNames.CommonNames)
			if err != nil {
				return nil, err
			}
			args["certificateCommonNames"] = llx.ArrayData(names, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterServerCertificateCommonName))
			args["certificateCommonNamesStoreName"] = llx.StringDataPtr((*string)(props.CertificateCommonNames.X509StoreName))
		}

		if props.ReverseProxyCertificateCommonNames != nil {
			names, err := serviceFabricServerCommonNamesToMql(runtime, clusterID+"/reverseProxyCertificateCommonNames", props.ReverseProxyCertificateCommonNames.CommonNames)
			if err != nil {
				return nil, err
			}
			args["reverseProxyCertificateCommonNames"] = llx.ArrayData(names, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterServerCertificateCommonName))
			args["reverseProxyCertificateCommonNamesStoreName"] = llx.StringDataPtr((*string)(props.ReverseProxyCertificateCommonNames.X509StoreName))
		}

		thumbprints, err := serviceFabricClientThumbprintsToMql(runtime, clusterID, props.ClientCertificateThumbprints)
		if err != nil {
			return nil, err
		}
		args["clientCertificateThumbprints"] = llx.ArrayData(thumbprints, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterClientCertificateThumbprint))

		clientNames, err := serviceFabricClientCommonNamesToMql(runtime, clusterID, props.ClientCertificateCommonNames)
		if err != nil {
			return nil, err
		}
		args["clientCertificateCommonNames"] = llx.ArrayData(clientNames, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterClientCertificateCommonName))

		nodeTypes, err := serviceFabricNodeTypesToMql(runtime, clusterID, props.NodeTypes)
		if err != nil {
			return nil, err
		}
		args["nodeTypes"] = llx.ArrayData(nodeTypes, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterNodeType))

		settings, err := serviceFabricSettingsToMql(runtime, clusterID, props.FabricSettings)
		if err != nil {
			return nil, err
		}
		args["fabricSettings"] = llx.ArrayData(settings, types.Resource(ResourceAzureSubscriptionServiceFabricServiceClusterFabricSetting))

		if props.DiagnosticsStorageAccountConfig != nil {
			diag, err := serviceFabricDiagnosticsToMql(runtime, clusterID, props.DiagnosticsStorageAccountConfig)
			if err != nil {
				return nil, err
			}
			args["diagnosticsStorageAccountConfig"] = llx.ResourceData(diag, diag.MqlName())
		}
	}

	res, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceCluster, args)
	if err != nil {
		return nil, err
	}

	sysData, err := convert.JsonToDict(cluster.SystemData)
	if err != nil {
		return nil, err
	}
	mqlCluster := res.(*mqlAzureSubscriptionServiceFabricServiceCluster)
	mqlCluster.cacheSystemData = sysData

	return mqlCluster, nil
}

func serviceFabricAadToMql(runtime *plugin.Runtime, clusterID string, aad *armservicefabric.AzureActiveDirectory) (*mqlAzureSubscriptionServiceFabricServiceClusterAzureActiveDirectory, error) {
	res, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterAzureActiveDirectory, map[string]*llx.RawData{
		"__id":               llx.StringData(clusterID + "/azureActiveDirectory"),
		"tenantId":           llx.StringDataPtr(aad.TenantID),
		"clusterApplication": llx.StringDataPtr(aad.ClusterApplication),
		"clientApplication":  llx.StringDataPtr(aad.ClientApplication),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionServiceFabricServiceClusterAzureActiveDirectory), nil
}

// serviceFabricCertificateToMql builds the certificate resource under a caller
// supplied id. The cluster certificate and the reverse proxy certificate share
// this shape, so the id has to carry which of the two it is or the second one
// would resolve to the first from the resource cache.
func serviceFabricCertificateToMql(runtime *plugin.Runtime, id string, cert *armservicefabric.CertificateDescription) (*mqlAzureSubscriptionServiceFabricServiceClusterCertificate, error) {
	res, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterCertificate, map[string]*llx.RawData{
		"__id":                llx.StringData(id),
		"thumbprint":          llx.StringDataPtr(cert.Thumbprint),
		"thumbprintSecondary": llx.StringDataPtr(cert.ThumbprintSecondary),
		"x509StoreName":       llx.StringDataPtr((*string)(cert.X509StoreName)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionServiceFabricServiceClusterCertificate), nil
}

// serviceFabricServerCommonNamesToMql builds one resource per server
// certificate common name. The same common name may be listed twice under
// different issuers during a certificate authority migration, and the same
// name may appear in both the cluster and the reverse proxy list, so the id
// carries the list prefix, the common name and the issuer thumbprint.
func serviceFabricServerCommonNamesToMql(runtime *plugin.Runtime, prefix string, names []*armservicefabric.ServerCertificateCommonName) ([]any, error) {
	res := []any{}
	for _, name := range names {
		if name == nil {
			continue
		}
		entry, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterServerCertificateCommonName, map[string]*llx.RawData{
			"__id":             llx.StringData(prefix + "/" + derefStr(name.CertificateCommonName) + "/" + derefStr(name.CertificateIssuerThumbprint)),
			"commonName":       llx.StringDataPtr(name.CertificateCommonName),
			"issuerThumbprint": llx.StringDataPtr(name.CertificateIssuerThumbprint),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

func serviceFabricClientThumbprintsToMql(runtime *plugin.Runtime, clusterID string, thumbprints []*armservicefabric.ClientCertificateThumbprint) ([]any, error) {
	res := []any{}
	for _, tp := range thumbprints {
		if tp == nil {
			continue
		}
		entry, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterClientCertificateThumbprint, map[string]*llx.RawData{
			"__id":       llx.StringData(clusterID + "/clientCertificateThumbprints/" + derefStr(tp.CertificateThumbprint)),
			"thumbprint": llx.StringDataPtr(tp.CertificateThumbprint),
			"isAdmin":    llx.BoolDataPtr(tp.IsAdmin),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

// serviceFabricClientCommonNamesToMql keys each client certificate on both the
// common name and the issuer thumbprint. One common name issued by two
// authorities is a supported configuration, and keying on the name alone would
// report the first entry twice and hide the second one's admin flag.
func serviceFabricClientCommonNamesToMql(runtime *plugin.Runtime, clusterID string, names []*armservicefabric.ClientCertificateCommonName) ([]any, error) {
	res := []any{}
	for _, name := range names {
		if name == nil {
			continue
		}
		entry, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterClientCertificateCommonName, map[string]*llx.RawData{
			"__id":             llx.StringData(clusterID + "/clientCertificateCommonNames/" + derefStr(name.CertificateCommonName) + "/" + derefStr(name.CertificateIssuerThumbprint)),
			"commonName":       llx.StringDataPtr(name.CertificateCommonName),
			"issuerThumbprint": llx.StringDataPtr(name.CertificateIssuerThumbprint),
			"isAdmin":          llx.BoolDataPtr(name.IsAdmin),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

func serviceFabricNodeTypesToMql(runtime *plugin.Runtime, clusterID string, nodeTypes []*armservicefabric.NodeTypeDescription) ([]any, error) {
	res := []any{}
	for _, nt := range nodeTypes {
		if nt == nil {
			continue
		}

		args := map[string]*llx.RawData{
			"__id":                         llx.StringData(clusterID + "/nodeTypes/" + derefStr(nt.Name)),
			"name":                         llx.StringDataPtr(nt.Name),
			"isPrimary":                    llx.BoolDataPtr(nt.IsPrimary),
			"isStateless":                  llx.BoolDataPtr(nt.IsStateless),
			"vmInstanceCount":              llx.IntDataPtr(nt.VMInstanceCount),
			"clientConnectionEndpointPort": llx.IntDataPtr(nt.ClientConnectionEndpointPort),
			"httpGatewayEndpointPort":      llx.IntDataPtr(nt.HTTPGatewayEndpointPort),
			"reverseProxyEndpointPort":     llx.IntDataPtr(nt.ReverseProxyEndpointPort),
			"applicationStartPort":         llx.NilData,
			"applicationEndPort":           llx.NilData,
			"ephemeralStartPort":           llx.NilData,
			"ephemeralEndPort":             llx.NilData,
			"durabilityLevel":              llx.StringDataPtr((*string)(nt.DurabilityLevel)),
			"multipleAvailabilityZones":    llx.BoolDataPtr(nt.MultipleAvailabilityZones),
			"capacities":                   llx.MapData(convert.PtrMapStrToInterface(nt.Capacities), types.String),
			"placementProperties":          llx.MapData(convert.PtrMapStrToInterface(nt.PlacementProperties), types.String),
		}

		if nt.ApplicationPorts != nil {
			args["applicationStartPort"] = llx.IntDataPtr(nt.ApplicationPorts.StartPort)
			args["applicationEndPort"] = llx.IntDataPtr(nt.ApplicationPorts.EndPort)
		}
		if nt.EphemeralPorts != nil {
			args["ephemeralStartPort"] = llx.IntDataPtr(nt.EphemeralPorts.StartPort)
			args["ephemeralEndPort"] = llx.IntDataPtr(nt.EphemeralPorts.EndPort)
		}

		entry, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterNodeType, args)
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

func serviceFabricSettingsToMql(runtime *plugin.Runtime, clusterID string, settings []*armservicefabric.SettingsSectionDescription) ([]any, error) {
	res := []any{}
	for _, section := range settings {
		if section == nil {
			continue
		}
		entry, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterFabricSetting, map[string]*llx.RawData{
			"__id":       llx.StringData(clusterID + "/fabricSettings/" + derefStr(section.Name)),
			"name":       llx.StringDataPtr(section.Name),
			"parameters": llx.MapData(serviceFabricSettingParameters(section.Parameters), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, entry)
	}
	return res, nil
}

// serviceFabricDiagnosticsToMql maps the diagnostics storage configuration
// field by field rather than through convert.JsonToDict.
//
// The Azure Resource Manager response for this block carries primaryAccessKey
// and secondaryAccessKey alongside the endpoints. Both come back empty on a
// read today, and armservicefabric v2.0.0 does not model either one, but a
// dict would publish whatever the struct grows next: an SDK release that adds
// those two members would start emitting storage account keys into every scan
// result with no change on our side. Only the endpoints, the account name and
// the *names* of the protected keys are listed below, and the key values are
// deliberately omitted.
func serviceFabricDiagnosticsToMql(runtime *plugin.Runtime, clusterID string, cfg *armservicefabric.DiagnosticsStorageAccountConfig) (*mqlAzureSubscriptionServiceFabricServiceClusterDiagnosticsStorageAccountConfig, error) {
	res, err := CreateResource(runtime, ResourceAzureSubscriptionServiceFabricServiceClusterDiagnosticsStorageAccountConfig, map[string]*llx.RawData{
		"__id":                     llx.StringData(clusterID + "/diagnosticsStorageAccountConfig"),
		"storageAccountName":       llx.StringDataPtr(cfg.StorageAccountName),
		"blobEndpoint":             llx.StringDataPtr(cfg.BlobEndpoint),
		"queueEndpoint":            llx.StringDataPtr(cfg.QueueEndpoint),
		"tableEndpoint":            llx.StringDataPtr(cfg.TableEndpoint),
		"protectedAccountKeyName":  llx.StringDataPtr(cfg.ProtectedAccountKeyName),
		"protectedAccountKeyName2": llx.StringDataPtr(cfg.ProtectedAccountKeyName2),
	})
	if err != nil {
		return nil, err
	}
	mqlCfg := res.(*mqlAzureSubscriptionServiceFabricServiceClusterDiagnosticsStorageAccountConfig)
	mqlCfg.cacheStorageAccountName = derefStr(cfg.StorageAccountName)
	return mqlCfg, nil
}

// storageAccount resolves the diagnostics account by name against the
// subscription's storage account list. The diagnostics config carries only the
// account name, not its resource ID, and walking the already fetched list
// keeps this to one call for every cluster in the subscription.
func (a *mqlAzureSubscriptionServiceFabricServiceClusterDiagnosticsStorageAccountConfig) storageAccount() (*mqlAzureSubscriptionStorageServiceAccount, error) {
	if a.cacheStorageAccountName == "" {
		a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn, ok := a.MqlRuntime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not an Azure connection")
	}

	res, err := NewResource(a.MqlRuntime, ResourceAzureSubscriptionStorageService, map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, err
	}
	storage, ok := res.(*mqlAzureSubscriptionStorageService)
	if !ok {
		return nil, errors.New("could not resolve the azure storage service")
	}

	accounts := storage.GetAccounts()
	if accounts.Error != nil {
		return nil, accounts.Error
	}

	for _, entry := range accounts.Data {
		account, ok := entry.(*mqlAzureSubscriptionStorageServiceAccount)
		if ok && account.Name.Data == a.cacheStorageAccountName {
			return account, nil
		}
	}
	// A tag filter may have left the account out of the list.
	for _, entry := range tagFilteredOutOfType(a.MqlRuntime, ResourceAzureSubscriptionStorageServiceAccount) {
		account, ok := entry.(*mqlAzureSubscriptionStorageServiceAccount)
		if ok && account.Name.Data == a.cacheStorageAccountName {
			return account, nil
		}
	}

	// The diagnostics account may live in another subscription, which this
	// connection cannot enumerate. That is a legitimate null, not a failure.
	a.StorageAccount.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
