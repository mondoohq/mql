// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	clusters "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v9"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/azure/connection"
	"go.mondoo.com/mql/types"
)

type mqlAzureSubscriptionAksServiceClusterInternal struct {
	cacheKmsKeyId                string
	cacheKubeletIdentityId       string
	cacheDiskEncryptionSetId     string
	cacheUserAssignedIdentityIds []string
	cacheProperties              *clusters.ManagedClusterProperties
	cacheSystemData              any
}

type mqlAzureSubscriptionAksServiceClusterIdentityBindingInternal struct {
	cacheManagedIdentityId string
}

type mqlAzureSubscriptionAksServiceClusterNodePoolInternal struct {
	subscriptionId           string
	resourceGroup            string
	clusterName              string
	poolName                 string
	cacheAppSecurityGroupIds []string
}

func (a *mqlAzureSubscriptionAksService) id() (string, error) {
	return "azure.subscription.aks/" + a.SubscriptionId.Data, nil
}

func initAzureSubscriptionAksService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func initAzureSubscriptionAksServiceCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil && ids.id != "" {
			args["id"] = llx.StringData(ids.id)
		}
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch azure aks cluster")
	}
	conn, ok := runtime.Connection.(*connection.AzureConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not an Azure connection")
	}
	res, err := NewResource(runtime, "azure.subscription.aksService", map[string]*llx.RawData{
		"subscriptionId": llx.StringData(conn.SubId()),
	})
	if err != nil {
		return nil, nil, err
	}
	aksSvc := res.(*mqlAzureSubscriptionAksService)
	clusterList := aksSvc.GetClusters()
	if clusterList.Error != nil {
		return nil, nil, clusterList.Error
	}
	id, ok := args["id"].Value.(string)
	if !ok {
		return nil, nil, errors.New("id must be a non-nil string value")
	}
	for _, entry := range clusterList.Data {
		cluster := entry.(*mqlAzureSubscriptionAksServiceCluster)
		if cluster.Id.Data == id {
			return args, cluster, nil
		}
	}

	return nil, nil, errors.New("azure aks cluster does not exist")
}

func (a *mqlAzureSubscriptionAksServiceCluster) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAksServiceClusterAadProfile) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAksServiceClusterAutoUpgradeProfile) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAksServiceClusterAdvancedNetworking) id() (string, error) {
	return a.Id.Data, nil
}

// aksSecurityFlags are the cluster security-profile toggles flattened out of
// the deeply nested ARM securityProfile block.
type aksSecurityFlags struct {
	defenderEnabled               bool
	defenderSecurityGatingEnabled bool
	imageCleanerEnabled           bool
	imageCleanerIntervalHours     *int32
	workloadIdentityEnabled       bool
	azureKeyVaultKmsEnabled       bool
	azureKeyVaultKmsNetworkAccess *string
	azureKeyVaultKmsKeyID         string
}

// aksSecurityProfileFlags flattens the cluster security profile.
//
// Azure omits each sub-block entirely when its feature is switched off, so an
// absent block means "disabled", not "unknown". These are reported as explicit
// false rather than null: MQL's three-valued logic makes `null && null` true,
// so a null here would let `clusters.all(defenderEnabled && workloadIdentityEnabled)`
// pass on precisely the clusters it is meant to fail.
func aksSecurityProfileFlags(sp *clusters.ManagedClusterSecurityProfile) aksSecurityFlags {
	var f aksSecurityFlags
	if sp == nil {
		return f
	}
	if sp.Defender != nil {
		if sp.Defender.SecurityMonitoring != nil {
			f.defenderEnabled = convert.ToValue(sp.Defender.SecurityMonitoring.Enabled)
		}
		if sp.Defender.SecurityGating != nil {
			f.defenderSecurityGatingEnabled = convert.ToValue(sp.Defender.SecurityGating.Enabled)
		}
	}
	if sp.ImageCleaner != nil {
		f.imageCleanerEnabled = convert.ToValue(sp.ImageCleaner.Enabled)
		f.imageCleanerIntervalHours = sp.ImageCleaner.IntervalHours
	}
	if sp.WorkloadIdentity != nil {
		f.workloadIdentityEnabled = convert.ToValue(sp.WorkloadIdentity.Enabled)
	}
	if sp.AzureKeyVaultKms != nil {
		f.azureKeyVaultKmsEnabled = convert.ToValue(sp.AzureKeyVaultKms.Enabled)
		f.azureKeyVaultKmsNetworkAccess = (*string)(sp.AzureKeyVaultKms.KeyVaultNetworkAccess)
		f.azureKeyVaultKmsKeyID = convert.ToValue(sp.AzureKeyVaultKms.KeyID)
	}
	return f
}

// aksKubernetesResourceObjectEncryption returns the infrastructure encryption
// setting for Kubernetes resource objects, or nil when the cluster does not
// configure it.
func aksKubernetesResourceObjectEncryption(sp *clusters.ManagedClusterSecurityProfile) *string {
	if sp == nil || sp.KubernetesResourceObjectEncryptionProfile == nil {
		return nil
	}
	return (*string)(sp.KubernetesResourceObjectEncryptionProfile.InfrastructureEncryption)
}

// advancedNetworkingFields flattens the nested Advanced Networking (Cilium)
// profile into the scalars the resource exposes. Absent sub-blocks mean the
// feature is off, so every value defaults to its disabled state rather than
// null: a null would let `{ securityEnabled && ... }` pass vacuously.
func advancedNetworkingFields(an *clusters.AdvancedNetworking) (enabled bool, transitEncryptionType string, accelerationMode string, securityEnabled bool) {
	transitEncryptionType = string(clusters.TransitEncryptionTypeNone)
	accelerationMode = string(clusters.AccelerationModeNone)
	if an == nil {
		return false, transitEncryptionType, accelerationMode, false
	}
	enabled = convert.ToValue(an.Enabled)
	if an.Performance != nil && an.Performance.AccelerationMode != nil {
		accelerationMode = string(*an.Performance.AccelerationMode)
	}
	if an.Security != nil {
		securityEnabled = convert.ToValue(an.Security.Enabled)
		if an.Security.TransitEncryption != nil && an.Security.TransitEncryption.Type != nil {
			transitEncryptionType = string(*an.Security.TransitEncryption.Type)
		}
	}
	return enabled, transitEncryptionType, accelerationMode, securityEnabled
}

// advancedNetworking exposes the cluster's Advanced Networking (Cilium)
// profile. Returns null when the cluster does not use Azure CNI powered by
// Cilium, in which case the profile is absent from the ARM response.
func (a *mqlAzureSubscriptionAksServiceCluster) advancedNetworking() (*mqlAzureSubscriptionAksServiceClusterAdvancedNetworking, error) {
	if a.cacheProperties == nil || a.cacheProperties.NetworkProfile == nil || a.cacheProperties.NetworkProfile.AdvancedNetworking == nil {
		a.AdvancedNetworking.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	enabled, transitEncryptionType, accelerationMode, securityEnabled := advancedNetworkingFields(a.cacheProperties.NetworkProfile.AdvancedNetworking)
	res, err := CreateResource(a.MqlRuntime, ResourceAzureSubscriptionAksServiceClusterAdvancedNetworking,
		map[string]*llx.RawData{
			"id":                    llx.StringData(a.Id.Data + "/advancedNetworking"),
			"enabled":               llx.BoolData(enabled),
			"transitEncryptionType": llx.StringData(transitEncryptionType),
			"accelerationMode":      llx.StringData(accelerationMode),
			"securityEnabled":       llx.BoolData(securityEnabled),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionAksServiceClusterAdvancedNetworking), nil
}

func (a *mqlAzureSubscriptionAksServiceClusterNodePool) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAksService) clusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()
	subId := a.SubscriptionId.Data
	client, err := clusters.NewManagedClustersClient(subId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}
	pager := client.NewListPager(&clusters.ManagedClustersClientListOptions{})
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			if isAzureNotConfigured(err) {
				log.Warn().Err(err).Msg("could not list azure clusters, returning partial results")
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}
			// Normalize a nil Properties to an empty struct so the many early
			// accesses below are nil-safe; the later blocks already guard it.
			if entry.Properties == nil {
				entry.Properties = &clusters.ManagedClusterProperties{}
			}
			storageProfile, err := convert.JsonToDict(entry.Properties.StorageProfile)
			if err != nil {
				return nil, err
			}
			diskCsiDriverEnabled := aksDiskCsiDriverEnabled(entry.Properties.StorageProfile)
			workloadAutoScalerProfile, err := convert.JsonToDict(entry.Properties.WorkloadAutoScalerProfile)
			if err != nil {
				return nil, err
			}
			securityProfile, err := convert.JsonToDict(entry.Properties.SecurityProfile)
			if err != nil {
				return nil, err
			}
			podIdentityProfile, err := convert.JsonToDict(entry.Properties.PodIdentityProfile)
			if err != nil {
				return nil, err
			}
			networkProfile, err := convert.JsonToDict(entry.Properties.NetworkProfile)
			if err != nil {
				return nil, err
			}
			httpProxyConfig, err := convert.JsonToDict(entry.Properties.HTTPProxyConfig)
			if err != nil {
				return nil, err
			}
			apiServerAccessProfile, err := convert.JsonToDict(entry.Properties.APIServerAccessProfile)
			if err != nil {
				return nil, err
			}
			addonProfiles := []any{}
			for k, a := range entry.Properties.AddonProfiles {
				dict, err := convert.JsonToDict(a)
				if err != nil {
					return nil, err
				}
				m := map[string]any{}
				m[k] = dict
				addonProfiles = append(addonProfiles, m)
			}
			if err != nil {
				return nil, err
			}
			var createdAt *time.Time
			if entry.SystemData != nil {
				createdAt = entry.SystemData.CreatedAt
			}

			var enablePrivateCluster *bool
			var enablePrivateClusterPublicFQDN *bool
			var disableRunCommand *bool
			var privateDnsZone *string
			apiServerAuthorizedIPRanges := []any{}
			if entry.Properties.APIServerAccessProfile != nil {
				asp := entry.Properties.APIServerAccessProfile
				enablePrivateCluster = asp.EnablePrivateCluster
				enablePrivateClusterPublicFQDN = asp.EnablePrivateClusterPublicFQDN
				disableRunCommand = asp.DisableRunCommand
				privateDnsZone = asp.PrivateDNSZone
				for _, r := range asp.AuthorizedIPRanges {
					if r != nil {
						apiServerAuthorizedIPRanges = append(apiServerAuthorizedIPRanges, *r)
					}
				}
			}

			linuxAdminUsername, linuxSshPublicKeys, windowsAdminUsername := aksNodeAdminAccess(entry.Properties)

			secFlags := aksSecurityProfileFlags(entry.Properties.SecurityProfile)
			azureKeyVaultKmsKeyId := secFlags.azureKeyVaultKmsKeyID

			var networkPlugin, networkPolicy *string
			if entry.Properties.NetworkProfile != nil {
				np := entry.Properties.NetworkProfile
				networkPlugin = (*string)(np.NetworkPlugin)
				networkPolicy = (*string)(np.NetworkPolicy)
			}

			var oidcIssuerEnabled *bool
			if entry.Properties.OidcIssuerProfile != nil {
				oidcIssuerEnabled = entry.Properties.OidcIssuerProfile.Enabled
			}

			var nodeResourceGroupRestrictionLevel *string
			if entry.Properties.NodeResourceGroupProfile != nil {
				nodeResourceGroupRestrictionLevel = (*string)(entry.Properties.NodeResourceGroupProfile.RestrictionLevel)
			}

			var serviceMeshMode *string
			if entry.Properties.ServiceMeshProfile != nil {
				serviceMeshMode = (*string)(entry.Properties.ServiceMeshProfile.Mode)
			}

			var skuTier string
			if entry.SKU != nil && entry.SKU.Tier != nil {
				skuTier = string(*entry.SKU.Tier)
			}

			var powerState *string
			if entry.Properties.PowerState != nil {
				powerState = (*string)(entry.Properties.PowerState.Code)
			}

			var controlPlaneMetricsEnabled *bool
			if amp := entry.Properties.AzureMonitorProfile; amp != nil && amp.Metrics != nil && amp.Metrics.ControlPlane != nil {
				controlPlaneMetricsEnabled = amp.Metrics.ControlPlane.Enabled
			}

			identityDict, err := convert.JsonToDict(entry.Identity)
			if err != nil {
				return nil, err
			}
			clusterIdentity := orZero(entry.Identity)
			userAssignedIdentityIds := sortedUserAssignedIdentityIDs(clusterIdentity.UserAssignedIdentities)

			diskEncryptionSetId := ""
			if entry.Properties != nil && entry.Properties.DiskEncryptionSetID != nil {
				diskEncryptionSetId = *entry.Properties.DiskEncryptionSetID
			}

			servicePrincipalClientId := ""
			kubeletIdentityId := ""
			if entry.Properties != nil {
				// Service-principal clusters report the SP client ID here;
				// managed-identity clusters report the sentinel "msi" instead,
				// which carries no provenance value.
				if spp := entry.Properties.ServicePrincipalProfile; spp != nil && spp.ClientID != nil && !strings.EqualFold(*spp.ClientID, "msi") {
					servicePrincipalClientId = *spp.ClientID
				}
				for k, v := range entry.Properties.IdentityProfile {
					if strings.EqualFold(k, "kubeletidentity") && v != nil {
						kubeletIdentityId = convert.ToValue(v.ResourceID)
					}
				}
			}

			resourceIdentity, err := resourceIdentityData(a.MqlRuntime, convert.ToValue(entry.ID), userAssignedIdentityIds,
				identityType(clusterIdentity.Type), identityPrincipalId(clusterIdentity.PrincipalID), identityTenantId(clusterIdentity.TenantID))
			if err != nil {
				return nil, err
			}

			mqlAksCluster, err := CreateResource(a.MqlRuntime, "azure.subscription.aksService.cluster",
				map[string]*llx.RawData{
					"id":                                llx.StringDataPtr(entry.ID),
					"name":                              llx.StringDataPtr(entry.Name),
					"location":                          llx.StringDataPtr(entry.Location),
					"kubernetesVersion":                 llx.StringDataPtr(entry.Properties.KubernetesVersion),
					"provisioningState":                 llx.StringDataPtr(entry.Properties.ProvisioningState),
					"createdAt":                         llx.TimeDataPtr(createdAt),
					"nodeResourceGroup":                 llx.StringDataPtr(entry.Properties.NodeResourceGroup),
					"powerState":                        llx.StringDataPtr(powerState),
					"tags":                              llx.MapData(convert.PtrMapStrToInterface(entry.Tags), types.String),
					"rbacEnabled":                       llx.BoolDataPtr(entry.Properties.EnableRBAC),
					"dnsPrefix":                         llx.StringDataPtr(entry.Properties.DNSPrefix),
					"fqdn":                              llx.StringDataPtr(entry.Properties.Fqdn),
					"fqdnSubdomain":                     llx.StringDataPtr(entry.Properties.FqdnSubdomain),
					"privateFqdn":                       llx.StringDataPtr(entry.Properties.PrivateFQDN),
					"addonProfiles":                     llx.ArrayData(addonProfiles, types.Dict),
					"httpProxyConfig":                   llx.DictData(httpProxyConfig),
					"networkProfile":                    llx.DictData(networkProfile),
					"podIdentityProfile":                llx.DictData(podIdentityProfile),
					"securityProfile":                   llx.DictData(securityProfile),
					"storageProfile":                    llx.DictData(storageProfile),
					"diskCsiDriverEnabled":              llx.BoolDataPtr(diskCsiDriverEnabled),
					"workloadAutoScalerProfile":         llx.DictData(workloadAutoScalerProfile),
					"apiServerAccessProfile":            llx.DictData(apiServerAccessProfile),
					"enablePrivateCluster":              llx.BoolData(convert.ToValue(enablePrivateCluster)),
					"enablePrivateClusterPublicFQDN":    llx.BoolData(convert.ToValue(enablePrivateClusterPublicFQDN)),
					"disableRunCommand":                 llx.BoolData(convert.ToValue(disableRunCommand)),
					"apiServerAuthorizedIPRanges":       llx.ArrayData(apiServerAuthorizedIPRanges, types.String),
					"privateDnsZone":                    llx.StringDataPtr(privateDnsZone),
					"defenderEnabled":                   llx.BoolData(secFlags.defenderEnabled),
					"defenderSecurityGatingEnabled":     llx.BoolData(secFlags.defenderSecurityGatingEnabled),
					"imageCleanerEnabled":               llx.BoolData(secFlags.imageCleanerEnabled),
					"imageCleanerIntervalHours":         llx.IntDataDefault(secFlags.imageCleanerIntervalHours, 0),
					"workloadIdentityEnabled":           llx.BoolData(secFlags.workloadIdentityEnabled),
					"azureKeyVaultKmsEnabled":           llx.BoolData(secFlags.azureKeyVaultKmsEnabled),
					"azureKeyVaultKmsNetworkAccess":     llx.StringDataPtr(secFlags.azureKeyVaultKmsNetworkAccess),
					"disableLocalAccounts":              llx.BoolData(convert.ToValue(entry.Properties.DisableLocalAccounts)),
					"publicNetworkAccess":               llx.StringDataPtr((*string)(entry.Properties.PublicNetworkAccess)),
					"skuTier":                           llx.StringData(skuTier),
					"networkPlugin":                     llx.StringDataPtr(networkPlugin),
					"networkPolicy":                     llx.StringDataPtr(networkPolicy),
					"oidcIssuerEnabled":                 llx.BoolData(convert.ToValue(oidcIssuerEnabled)),
					"nodeResourceGroupRestrictionLevel": llx.StringDataPtr(nodeResourceGroupRestrictionLevel),
					"serviceMeshMode":                   llx.StringDataPtr(serviceMeshMode),
					"supportPlan":                       llx.StringDataPtr((*string)(entry.Properties.SupportPlan)),
					"controlPlaneMetricsEnabled":        llx.BoolData(convert.ToValue(controlPlaneMetricsEnabled)),
					"identity":                          llx.DictData(identityDict),
					"resourceIdentity":                  resourceIdentity,
					"principalId":                       llx.StringDataPtr(clusterIdentity.PrincipalID),
					"servicePrincipalClientId":          llx.StringData(servicePrincipalClientId),
					"linuxAdminUsername":                llx.StringData(linuxAdminUsername),
					"linuxSshPublicKeys":                llx.ArrayData(linuxSshPublicKeys, types.String),
					"windowsAdminUsername":              llx.StringData(windowsAdminUsername),

					"kubernetesResourceObjectEncryption": llx.StringDataPtr(aksKubernetesResourceObjectEncryption(entry.Properties.SecurityProfile)),
					"enableFIPS":                         llx.BoolDataPtr(entry.Properties.EnableFIPS),
				})
			if err != nil {
				return nil, err
			}
			mqlCluster := mqlAksCluster.(*mqlAzureSubscriptionAksServiceCluster)
			mqlCluster.cacheKmsKeyId = azureKeyVaultKmsKeyId
			mqlCluster.cacheKubeletIdentityId = kubeletIdentityId
			mqlCluster.cacheDiskEncryptionSetId = diskEncryptionSetId
			mqlCluster.cacheUserAssignedIdentityIds = userAssignedIdentityIds
			mqlCluster.cacheProperties = entry.Properties
			sysData, err := convert.JsonToDict(entry.SystemData)
			if err != nil {
				return nil, err
			}
			mqlCluster.cacheSystemData = sysData
			res = append(res, mqlCluster)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAksServiceCluster) azureKeyVaultKmsKey() (*mqlAzureSubscriptionKeyVaultServiceKey, error) {
	if a.cacheKmsKeyId == "" {
		a.AzureKeyVaultKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return newKeyVaultKeyResource(a.MqlRuntime, a.cacheKmsKeyId)
}

func (a *mqlAzureSubscriptionAksServiceCluster) aadProfile() (*mqlAzureSubscriptionAksServiceClusterAadProfile, error) {
	if a.cacheProperties == nil || a.cacheProperties.AADProfile == nil {
		a.AadProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	aadP := a.cacheProperties.AADProfile
	adminGroupObjectIDs := []any{}
	for _, gid := range aadP.AdminGroupObjectIDs {
		if gid != nil {
			adminGroupObjectIDs = append(adminGroupObjectIDs, *gid)
		}
	}
	aadRes, err := CreateResource(a.MqlRuntime, "azure.subscription.aksService.cluster.aadProfile",
		map[string]*llx.RawData{
			"id":                  llx.StringData(a.Id.Data + "/aadProfile"),
			"managed":             llx.BoolDataPtr(aadP.Managed),
			"enableAzureRBAC":     llx.BoolDataPtr(aadP.EnableAzureRBAC),
			"adminGroupObjectIDs": llx.ArrayData(adminGroupObjectIDs, types.String),
		})
	if err != nil {
		return nil, err
	}
	return aadRes.(*mqlAzureSubscriptionAksServiceClusterAadProfile), nil
}

func (a *mqlAzureSubscriptionAksServiceCluster) autoUpgradeProfile() (*mqlAzureSubscriptionAksServiceClusterAutoUpgradeProfile, error) {
	if a.cacheProperties == nil || a.cacheProperties.AutoUpgradeProfile == nil {
		a.AutoUpgradeProfile.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	aup := a.cacheProperties.AutoUpgradeProfile
	autoUpgradeRes, err := CreateResource(a.MqlRuntime, "azure.subscription.aksService.cluster.autoUpgradeProfile",
		map[string]*llx.RawData{
			"id":                   llx.StringData(a.Id.Data + "/autoUpgradeProfile"),
			"upgradeChannel":       llx.StringDataPtr((*string)(aup.UpgradeChannel)),
			"nodeOSUpgradeChannel": llx.StringDataPtr((*string)(aup.NodeOSUpgradeChannel)),
		})
	if err != nil {
		return nil, err
	}
	return autoUpgradeRes.(*mqlAzureSubscriptionAksServiceClusterAutoUpgradeProfile), nil
}

func (a *mqlAzureSubscriptionAksServiceCluster) nodePools() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := clusters.NewAgentPoolsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListPager(resourceID.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil || entry.Properties == nil {
				continue
			}
			props := entry.Properties

			zones := []any{}
			for _, z := range props.AvailabilityZones {
				if z != nil {
					zones = append(zones, *z)
				}
			}

			taints := []any{}
			for _, t := range props.NodeTaints {
				if t != nil {
					taints = append(taints, *t)
				}
			}

			var spotMaxPrice float64
			if props.SpotMaxPrice != nil {
				spotMaxPrice = float64(*props.SpotMaxPrice)
			}

			var powerState *string
			if props.PowerState != nil {
				powerState = (*string)(props.PowerState.Code)
			}

			var enableSecureBoot, enableVTPM *bool
			var sshAccess *string
			if props.SecurityProfile != nil {
				enableSecureBoot = props.SecurityProfile.EnableSecureBoot
				enableVTPM = props.SecurityProfile.EnableVTPM
				sshAccess = (*string)(props.SecurityProfile.SSHAccess)
			}

			unsafeSysctls, allowedHostPorts, nodePublicIPTags, appSecurityGroupIds := aksNodePoolHostAccess(props)

			var upgradeMaxSurge, upgradeMaxUnavailable *string
			var upgradeDrainTimeout, upgradeNodeSoak *int32
			if props.UpgradeSettings != nil {
				upgradeMaxSurge = props.UpgradeSettings.MaxSurge
				upgradeMaxUnavailable = props.UpgradeSettings.MaxUnavailable
				upgradeDrainTimeout = props.UpgradeSettings.DrainTimeoutInMinutes
				upgradeNodeSoak = props.UpgradeSettings.NodeSoakDurationInMinutes
			}

			mqlPool, err := CreateResource(a.MqlRuntime, "azure.subscription.aksService.cluster.nodePool",
				map[string]*llx.RawData{
					"id":                               llx.StringDataPtr(entry.ID),
					"name":                             llx.StringDataPtr(entry.Name),
					"mode":                             llx.StringDataPtr((*string)(props.Mode)),
					"vmType":                           llx.StringDataPtr((*string)(props.Type)),
					"count":                            llx.IntDataDefault(props.Count, 0),
					"minCount":                         llx.IntDataDefault(props.MinCount, 0),
					"maxCount":                         llx.IntDataDefault(props.MaxCount, 0),
					"enableAutoScaling":                llx.BoolDataPtr(props.EnableAutoScaling),
					"maxPods":                          llx.IntDataDefault(props.MaxPods, 0),
					"vmSize":                           llx.StringDataPtr(props.VMSize),
					"osType":                           llx.StringDataPtr((*string)(props.OSType)),
					"osSku":                            llx.StringDataPtr((*string)(props.OSSKU)),
					"osDiskType":                       llx.StringDataPtr((*string)(props.OSDiskType)),
					"osDiskSizeGB":                     llx.IntDataDefault(props.OSDiskSizeGB, 0),
					"scaleSetPriority":                 llx.StringDataPtr((*string)(props.ScaleSetPriority)),
					"scaleSetEvictionPolicy":           llx.StringDataPtr((*string)(props.ScaleSetEvictionPolicy)),
					"spotMaxPrice":                     llx.FloatData(spotMaxPrice),
					"availabilityZones":                llx.ArrayData(zones, types.String),
					"enableNodePublicIP":               llx.BoolDataPtr(props.EnableNodePublicIP),
					"nodePublicIPPrefixId":             llx.StringDataPtr(props.NodePublicIPPrefixID),
					"enableEncryptionAtHost":           llx.BoolDataPtr(props.EnableEncryptionAtHost),
					"enableUltraSSD":                   llx.BoolDataPtr(props.EnableUltraSSD),
					"enableFIPS":                       llx.BoolDataPtr(props.EnableFIPS),
					"orchestratorVersion":              llx.StringDataPtr(props.OrchestratorVersion),
					"currentOrchestratorVersion":       llx.StringDataPtr(props.CurrentOrchestratorVersion),
					"nodeImageVersion":                 llx.StringDataPtr(props.NodeImageVersion),
					"vnetSubnetId":                     llx.StringDataPtr(props.VnetSubnetID),
					"podSubnetId":                      llx.StringDataPtr(props.PodSubnetID),
					"proximityPlacementGroupId":        llx.StringDataPtr(props.ProximityPlacementGroupID),
					"hostGroupId":                      llx.StringDataPtr(props.HostGroupID),
					"provisioningState":                llx.StringDataPtr(props.ProvisioningState),
					"powerState":                       llx.StringDataPtr(powerState),
					"workloadRuntime":                  llx.StringDataPtr((*string)(props.WorkloadRuntime)),
					"nodeLabels":                       llx.MapData(convert.PtrMapStrToInterface(props.NodeLabels), types.String),
					"nodeTaints":                       llx.ArrayData(taints, types.String),
					"tags":                             llx.MapData(convert.PtrMapStrToInterface(props.Tags), types.String),
					"upgradeMaxSurge":                  llx.StringDataPtr(upgradeMaxSurge),
					"upgradeMaxUnavailable":            llx.StringDataPtr(upgradeMaxUnavailable),
					"upgradeDrainTimeoutInMinutes":     llx.IntDataDefault(upgradeDrainTimeout, 0),
					"upgradeNodeSoakDurationInMinutes": llx.IntDataDefault(upgradeNodeSoak, 0),
					"sshAccess":                        llx.StringDataPtr(sshAccess),
					"enableVTPM":                       llx.BoolDataPtr(enableVTPM),
					"enableSecureBoot":                 llx.BoolDataPtr(enableSecureBoot),
					"kubeletAllowedUnsafeSysctls":      llx.ArrayData(unsafeSysctls, types.String),
					"allowedHostPorts":                 llx.ArrayData(allowedHostPorts, types.Dict),
					"nodePublicIPTags":                 llx.MapData(nodePublicIPTags, types.String),
				})
			if err != nil {
				return nil, err
			}
			pool := mqlPool.(*mqlAzureSubscriptionAksServiceClusterNodePool)
			pool.subscriptionId = resourceID.SubscriptionID
			pool.resourceGroup = resourceID.ResourceGroup
			pool.clusterName = a.Name.Data
			pool.poolName = convert.ToValue(entry.Name)
			pool.cacheAppSecurityGroupIds = appSecurityGroupIds
			res = append(res, pool)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAksServiceClusterIdentityBinding) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAzureSubscriptionAksServiceCluster) privateEndpointConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := clusters.NewPrivateEndpointConnectionsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	resp, err := client.List(ctx, resourceID.ResourceGroup, a.Name.Data, nil)
	if err != nil {
		// Private endpoint connections are absent on clusters without private
		// networking, and the endpoint returns 403 when the caller lacks
		// access. A cluster that is not a private-link private cluster -- the
		// default shape -- answers 400 ClusterIsNotAPrivateLinkCluster, which
		// is the same absence. None of them should fail the cluster list.
		if isAzureNotConfigured(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return azurePrivateEndpointConnectionsToMql(a.MqlRuntime, resp.Value)
}

func (a *mqlAzureSubscriptionAksServiceCluster) identityBindings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	resourceID, err := ParseResourceID(a.Id.Data)
	if err != nil {
		return nil, err
	}

	client, err := clusters.NewIdentityBindingsClient(resourceID.SubscriptionID, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	pager := client.NewListByManagedClusterPager(resourceID.ResourceGroup, a.Name.Data, nil)
	res := []any{}
	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			// Identity bindings are a preview capability: the endpoint
			// returns 404 on clusters/subscriptions where it is not
			// available, and 403 when the caller lacks access. Treat
			// both as "no bindings" rather than failing the query.
			var respErr *azcore.ResponseError
			if errors.As(err, &respErr) && (respErr.StatusCode == http.StatusNotFound || respErr.StatusCode == http.StatusForbidden) {
				return res, nil
			}
			return nil, err
		}
		for _, entry := range page.Value {
			if entry == nil {
				continue
			}

			var provisioningState, oidcIssuerUrl string
			var managedIdentityId, managedIdentityClientId, managedIdentityObjectId, managedIdentityTenantId string
			if props := entry.Properties; props != nil {
				provisioningState = convert.ToValue((*string)(props.ProvisioningState))
				if props.OidcIssuer != nil {
					oidcIssuerUrl = convert.ToValue(props.OidcIssuer.OidcIssuerURL)
				}
				if mi := props.ManagedIdentity; mi != nil {
					managedIdentityId = convert.ToValue(mi.ResourceID)
					managedIdentityClientId = convert.ToValue(mi.ClientID)
					managedIdentityObjectId = convert.ToValue(mi.ObjectID)
					managedIdentityTenantId = convert.ToValue(mi.TenantID)
				}
			}

			mqlBinding, err := CreateResource(a.MqlRuntime, "azure.subscription.aksService.cluster.identityBinding",
				map[string]*llx.RawData{
					"id":                      llx.StringDataPtr(entry.ID),
					"name":                    llx.StringDataPtr(entry.Name),
					"provisioningState":       llx.StringData(provisioningState),
					"managedIdentityClientId": llx.StringData(managedIdentityClientId),
					"managedIdentityObjectId": llx.StringData(managedIdentityObjectId),
					"managedIdentityTenantId": llx.StringData(managedIdentityTenantId),
					"oidcIssuerUrl":           llx.StringData(oidcIssuerUrl),
				})
			if err != nil {
				return nil, err
			}
			binding := mqlBinding.(*mqlAzureSubscriptionAksServiceClusterIdentityBinding)
			binding.cacheManagedIdentityId = managedIdentityId
			res = append(res, binding)
		}
	}
	return res, nil
}

func (a *mqlAzureSubscriptionAksServiceClusterIdentityBinding) managedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheManagedIdentityId == "" {
		a.ManagedIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheManagedIdentityId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionAksServiceCluster) kubeletIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	if a.cacheKubeletIdentityId == "" {
		a.KubeletIdentity.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.managedIdentity",
		map[string]*llx.RawData{"__id": llx.StringData(a.cacheKubeletIdentityId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionManagedIdentity), nil
}

func (a *mqlAzureSubscriptionAksServiceCluster) userAssignedIdentities() ([]any, error) {
	return resolveUserAssignedIdentities(a.MqlRuntime, a.cacheUserAssignedIdentityIds)
}

func (a *mqlAzureSubscriptionAksServiceCluster) systemAssignedIdentity() (*mqlAzureSubscriptionManagedIdentity, error) {
	return newSystemAssignedManagedIdentity(a.MqlRuntime, a.Id.Data, a.PrincipalId.Data, tenantIDFromIdentityDict(a.Identity), &a.SystemAssignedIdentity)
}

func (a *mqlAzureSubscriptionAksServiceCluster) diskEncryptionSet() (*mqlAzureSubscriptionComputeServiceDiskEncryptionSet, error) {
	if a.cacheDiskEncryptionSetId == "" {
		a.DiskEncryptionSet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "azure.subscription.computeService.diskEncryptionSet",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheDiskEncryptionSetId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAzureSubscriptionComputeServiceDiskEncryptionSet), nil
}

func (a *mqlAzureSubscriptionAksServiceClusterNodePool) recentlyUsedVersions() ([]any, error) {
	if a.poolName == "" || a.clusterName == "" {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AzureConnection)
	ctx := context.Background()
	token := conn.Token()

	client, err := clusters.NewAgentPoolsClient(a.subscriptionId, token, &arm.ClientOptions{
		ClientOptions: conn.ClientOptions(),
	})
	if err != nil {
		return nil, err
	}

	profile, err := client.GetUpgradeProfile(ctx, a.resourceGroup, a.clusterName, a.poolName, nil)
	if err != nil {
		return nil, err
	}
	if profile.Properties == nil {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(profile.Properties.RecentlyUsedVersions)
}

// aksDiskCsiDriverEnabled reports whether the Azure Disk CSI driver is enabled
// on an AKS cluster, returning nil (null in MQL) when the storage profile or
// driver block is absent.
func aksDiskCsiDriverEnabled(sp *clusters.ManagedClusterStorageProfile) *bool {
	if sp == nil || sp.DiskCSIDriver == nil {
		return nil
	}
	return sp.DiskCSIDriver.Enabled
}
