// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"

	container "cloud.google.com/go/container/apiv1"
	"cloud.google.com/go/container/apiv1/containerpb"
	"github.com/rs/zerolog/log"
	"google.golang.org/api/option"
)

// initGcpProjectGkeService fills in the project the service belongs to when the
// resource is reached by its own type name (gcp.project.gkeService.clusters)
// rather than through the gcp.project.gke() accessor. Without it the resource
// is built with an empty projectId, and the serviceEnabled gate then asks
// Service Usage about "projects/", which fails the whole query with an
// InvalidArgument rather than returning clusters. Every sibling service
// resource carries the same init.
func initGcpProjectGkeService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	args["projectId"] = llx.StringData(conn.ResourceID())

	return args, nil, nil
}

type mqlGcpProjectGkeServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProjectGkeService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.gkeService", projectId), nil
}

func (g *mqlGcpProject) gke() (*mqlGcpProjectGkeService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.gkeService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_gke)
	if err != nil {
		return nil, err
	}

	gkeService := res.(*mqlGcpProjectGkeService)
	gkeService.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_gke).Msg("gcp service is not enabled, skipping")
	}

	return gkeService, nil
}

func (g *mqlGcpProjectGkeServiceCluster) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return fmt.Sprintf("gcp.project.gkeService.cluster/%s", id), nil
}

func initGcpProjectGkeServiceCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["location"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: a missing projectId would nil-deref
	// (and blow the type assertion) rather than return an error.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.gkeService.cluster requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.gkeService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	gkeSvc := obj.(*mqlGcpProjectGkeService)
	clusters := gkeSvc.GetClusters()
	if clusters.Error != nil {
		return nil, nil, clusters.Error
	}

	// args["name"] on an absent key is a nil *llx.RawData; dereferencing it
	// panics the provider and kills the whole scan. `location` narrows the
	// match when supplied but is optional, so a two-arg lookup still resolves.
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.gkeService.cluster requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	locationVal := ""
	if args["location"] != nil {
		locationVal, _ = args["location"].Value.(string)
	}

	for _, c := range clusters.Data {
		cluster := c.(*mqlGcpProjectGkeServiceCluster)
		name := cluster.GetName()
		if name.Error != nil {
			return nil, nil, name.Error
		}
		projectId := cluster.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}
		location := cluster.GetLocation()
		if location.Error != nil {
			return nil, nil, location.Error
		}

		if name.Data == nameVal && projectId.Data == args["projectId"].Value &&
			(locationVal == "" || location.Data == locationVal) {
			return args, cluster, nil
		}
	}
	return nil, nil, errors.New("cluster not found")
}

type mqlGcpProjectGkeServiceClusterNodepoolInternal struct {
	cacheInstanceGroupUrls []string
	cacheProjectId         string
}

func (g *mqlGcpProjectGkeServiceClusterNodepool) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepool) instanceGroupManagers() ([]any, error) {
	if len(g.cacheInstanceGroupUrls) == 0 {
		return nil, nil
	}

	obj, err := NewResource(g.MqlRuntime, "gcp.project.computeService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.cacheProjectId),
	})
	if err != nil {
		return nil, err
	}
	computeSvc := obj.(*mqlGcpProjectComputeService)
	allManagers := computeSvc.GetInstanceGroupManagers()
	if allManagers.Error != nil {
		return nil, allManagers.Error
	}

	// Build a lookup by selfLink
	bySelfLink := make(map[string]*mqlGcpProjectComputeServiceInstanceGroupManager, len(allManagers.Data))
	for _, igm := range allManagers.Data {
		mqlIGM := igm.(*mqlGcpProjectComputeServiceInstanceGroupManager)
		bySelfLink[mqlIGM.SelfLink.Data] = mqlIGM
	}

	var res []any
	for _, url := range g.cacheInstanceGroupUrls {
		if igm, ok := bySelfLink[url]; ok {
			res = append(res, igm)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolNetworkConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolNetworkConfigPerformanceConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigAccelerator) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigAcceleratorGpuSharingConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigNodeTaint) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigSandboxConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigShieldedInstanceConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigLinuxNodeConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigKubeletConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigGcfsConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigAdvancedMachineFeatures) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigGvnicConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfigConfidentialNodes) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterAddonsConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterIpAllocationPolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNetworkConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

type mqlGcpProjectGkeServiceClusterInternal struct {
	cacheDatabaseEncryptionKeyName string
	cacheLoggingService            string
	cacheMonitoringService         string
	cacheNetworkPolicyConfig       any
}

func (g *mqlGcpProjectGkeServiceCluster) databaseEncryptionKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheDatabaseEncryptionKeyName == "" {
		g.DatabaseEncryptionKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheDatabaseEncryptionKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectGkeServiceCluster) managedBy() (string, error) {
	return managedByFromLabels(g.GetResourceLabels())
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfig) bootDiskKmsKeyRef() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	keyName := g.GetBootDiskKmsKey()
	if keyName.Error != nil {
		return nil, keyName.Error
	}
	return newKmsCryptoKeyRef(g.MqlRuntime, &g.BootDiskKmsKeyRef, keyName.Data)
}

// gkeNetworkPolicyCacheKey scopes a cluster's network policy to that cluster.
func gkeNetworkPolicyCacheKey(clusterId string) string {
	return clusterId + "/networkPolicy"
}

func (g *mqlGcpProjectGkeServiceCluster) networkPolicy() (*mqlGcpProjectGkeServiceClusterNetworkPolicy, error) {
	npConfig := g.cacheNetworkPolicyConfig
	if npConfig == nil {
		g.NetworkPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	npMap, ok := npConfig.(map[string]any)
	if !ok {
		g.NetworkPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	enabled, _ := npMap["enabled"].(bool)
	provider, _ := npMap["provider"].(string)

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	clusterId := g.Id.Data

	// The cache key has to be passed explicitly. This resource declares no
	// id() method, so without an "__id" argument every cluster's network
	// policy is stored under the same empty key, and CreateResource returns
	// the first resource stored under a key -- so a cluster with network
	// policy switched off reports the enabled neighbour's answer.
	key := gkeNetworkPolicyCacheKey(clusterId)
	res, err := CreateResource(g.MqlRuntime, "gcp.project.gkeService.cluster.networkPolicy", map[string]*llx.RawData{
		"__id":     llx.StringData(key),
		"id":       llx.StringData(key),
		"enabled":  llx.BoolData(enabled),
		"provider": llx.StringData(provider),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectGkeServiceClusterNetworkPolicy), nil
}

func (g *mqlGcpProjectGkeService) clusters() ([]any, error) {
	// when the service is not enabled, we return nil
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	creds, err := conn.Credentials(container.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	containerSvc, err := container.NewClusterManagerClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer containerSvc.Close()

	// List the clusters in the current projects for all locations
	resp, err := containerSvc.ListClusters(ctx, &containerpb.ListClustersRequest{Parent: fmt.Sprintf("projects/%s/locations/-", projectId)})
	if err != nil {
		log.Error().Err(err).Msg("failed to list clusters")
		return nil, err
	}
	res := []any{}

	for i := range resp.Clusters {
		c := resp.Clusters[i]

		nodePools := make([]any, 0, len(c.NodePools))
		for _, np := range c.NodePools {
			mqlNodePool, err := createMqlNodePool(g.MqlRuntime, np, c.Id, projectId)
			if err != nil {
				return nil, err
			}
			nodePools = append(nodePools, mqlNodePool)
		}

		autopilotEnabled := false
		autopilotAllowNetAdmin := false
		if c.Autopilot != nil {
			autopilotEnabled = c.Autopilot.Enabled
			if wpc := c.Autopilot.GetWorkloadPolicyConfig(); wpc != nil {
				autopilotAllowNetAdmin = wpc.GetAllowNetAdmin()
			}
		}

		var resourceUsageExportConfig map[string]any
		if ruec := c.GetResourceUsageExportConfig(); ruec != nil {
			resourceUsageExportConfig = map[string]any{
				"enableNetworkEgressMetering":       ruec.GetEnableNetworkEgressMetering(),
				"enableResourceConsumptionMetering": ruec.GetConsumptionMeteringConfig().GetEnabled(),
			}
			if bq := ruec.GetBigqueryDestination(); bq != nil {
				resourceUsageExportConfig["bigqueryDestinationDatasetId"] = bq.GetDatasetId()
			}
		}

		verticalPodAutoscalingEnabled := c.GetVerticalPodAutoscaling().GetEnabled()
		intraNodeVisibilityEnabled := c.GetNetworkConfig().GetEnableIntraNodeVisibility()
		defaultMaxPodsPerNode := c.GetDefaultMaxPodsConstraint().GetMaxPodsPerNode()

		var addonsConfig plugin.Resource
		if c.AddonsConfig != nil {
			addonsConfig, err = newMqlGkeAddonsConfig(g.MqlRuntime,
				fmt.Sprintf("gcp.project.gkeService.cluster/%s/addonsConfig", c.Id), c.AddonsConfig)
			if err != nil {
				return nil, err
			}
		}

		var workloadIdCfg map[string]any
		var workloadIdentityEnabled bool
		if c.WorkloadIdentityConfig != nil {
			workloadIdCfg = map[string]any{
				"workloadPool": c.WorkloadIdentityConfig.WorkloadPool,
			}
			workloadIdentityEnabled = c.WorkloadIdentityConfig.WorkloadPool != ""
		}

		var ipAllocPolicy plugin.Resource
		if c.IpAllocationPolicy != nil {
			ipAllocPolicy, err = CreateResource(g.MqlRuntime, "gcp.project.gkeService.cluster.ipAllocationPolicy", map[string]*llx.RawData{
				"id":                         llx.StringData(fmt.Sprintf("gcp.project.gkeService.cluster/%s/ipAllocationPolicy", c.Id)),
				"useIpAliases":               llx.BoolData(c.IpAllocationPolicy.UseIpAliases),
				"createSubnetwork":           llx.BoolData(c.IpAllocationPolicy.CreateSubnetwork),
				"subnetworkName":             llx.StringData(c.IpAllocationPolicy.SubnetworkName),
				"clusterSecondaryRangeName":  llx.StringData(c.IpAllocationPolicy.ClusterSecondaryRangeName),
				"servicesSecondaryRangeName": llx.StringData(c.IpAllocationPolicy.ServicesSecondaryRangeName),
				"clusterIpv4CidrBlock":       llx.StringData(c.IpAllocationPolicy.ClusterIpv4CidrBlock),
				"nodeIpv4CidrBlock":          llx.StringData(c.IpAllocationPolicy.NodeIpv4CidrBlock),
				"servicesIpv4CidrBlock":      llx.StringData(c.IpAllocationPolicy.ServicesIpv4CidrBlock),
				"tpuIpv4CidrBlock":           llx.StringData(c.IpAllocationPolicy.TpuIpv4CidrBlock),
				"useRoutes":                  llx.BoolData(c.IpAllocationPolicy.UseRoutes),
				"stackType":                  llx.StringData(c.IpAllocationPolicy.StackType.String()),
				"ipv6AccessType":             llx.StringData(c.IpAllocationPolicy.Ipv6AccessType.String()),
			})
			if err != nil {
				return nil, err
			}
		}
		var networkConfig plugin.Resource
		if c.NetworkConfig != nil {
			var defaultSnatStatus map[string]any
			if c.NetworkConfig.DefaultSnatStatus != nil {
				defaultSnatStatus = map[string]any{
					"disabled": c.NetworkConfig.DefaultSnatStatus.Disabled,
				}
			}

			var dnsConfig map[string]any
			if c.NetworkConfig.DnsConfig != nil {
				dnsConfig = map[string]any{
					"clusterDns":       c.NetworkConfig.DnsConfig.ClusterDns.String(),
					"clusterDnsScope":  c.NetworkConfig.DnsConfig.ClusterDnsScope.String(),
					"clusterDnsDomain": c.NetworkConfig.DnsConfig.ClusterDnsDomain,
				}
			}

			var serviceExternalIpsConfig map[string]any
			if c.NetworkConfig.ServiceExternalIpsConfig != nil {
				serviceExternalIpsConfig = map[string]any{
					"enabled": c.NetworkConfig.ServiceExternalIpsConfig.Enabled,
				}
			}
			networkConfig, err = CreateResource(g.MqlRuntime, "gcp.project.gkeService.cluster.networkConfig", map[string]*llx.RawData{
				"id":                                   llx.StringData(fmt.Sprintf("gcp.project.gkeService.cluster/%s/networkConfig", c.Id)),
				"networkPath":                          llx.StringData(c.NetworkConfig.Network),
				"subnetworkPath":                       llx.StringData(c.NetworkConfig.Subnetwork),
				"enableIntraNodeVisibility":            llx.BoolData(c.NetworkConfig.EnableIntraNodeVisibility),
				"defaultSnatStatus":                    llx.DictData(defaultSnatStatus),
				"enableL4IlbSubsetting":                llx.BoolData(c.NetworkConfig.EnableL4IlbSubsetting),
				"datapathProvider":                     llx.StringData(c.NetworkConfig.DatapathProvider.String()),
				"privateIpv6GoogleAccess":              llx.StringData(c.NetworkConfig.PrivateIpv6GoogleAccess.String()),
				"dnsConfig":                            llx.DictData(dnsConfig),
				"serviceExternalIpsConfig":             llx.DictData(serviceExternalIpsConfig),
				"enableMultiNetworking":                llx.BoolData(c.NetworkConfig.EnableMultiNetworking),
				"enableFqdnNetworkPolicy":              llx.BoolDataPtr(c.NetworkConfig.EnableFqdnNetworkPolicy),
				"enableCiliumClusterwideNetworkPolicy": llx.BoolDataPtr(c.NetworkConfig.EnableCiliumClusterwideNetworkPolicy),
			})
			if err != nil {
				return nil, err
			}
		}

		var binaryAuthorizationEvaluationMode string
		if c.BinaryAuthorization != nil {
			binaryAuthorizationEvaluationMode = c.BinaryAuthorization.EvaluationMode.String()
		}

		var legacyAbac map[string]any
		var legacyAbacEnabled bool
		if c.LegacyAbac != nil {
			legacyAbac = map[string]any{
				"enabled": c.LegacyAbac.Enabled,
			}
			legacyAbacEnabled = c.LegacyAbac.Enabled
		}

		var masterAuth map[string]any
		var clientCertificateEnabled, basicAuthEnabled bool
		if c.MasterAuth != nil {
			var clientCertCfg map[string]any
			if c.MasterAuth.ClientCertificateConfig != nil {
				clientCertCfg = map[string]any{
					"issueClientCertificate": c.MasterAuth.ClientCertificateConfig.IssueClientCertificate,
				}
			}
			// Client cert auth is on when the cluster issues one (config) or an
			// output client certificate is present.
			clientCertificateEnabled = c.MasterAuth.GetClientCertificateConfig().GetIssueClientCertificate() ||
				c.MasterAuth.ClientCertificate != ""
			// Username is the deprecated HTTP basic-auth field; a non-empty value
			// means basic auth is enabled (read solely for the audit signal).
			basicAuthEnabled = c.MasterAuth.Username != ""
			// Password and ClientKey are deliberately not published. They are
			// the control-plane basic-auth password and the client private
			// key; the audit signals they would serve are already carried by
			// basicAuthEnabled and clientCertificateEnabled above.
			masterAuth = map[string]any{
				"username":                c.MasterAuth.Username,
				"clientCertificateConfig": clientCertCfg,
				"clusterCaCertificate":    c.MasterAuth.ClusterCaCertificate,
				"clientCertificate":       c.MasterAuth.ClientCertificate,
			}
		}

		// Derived: the CIDR allowlist and enablement read from the modern
		// ControlPlaneEndpointsConfig when present, otherwise the legacy
		// MasterAuthorizedNetworksConfig.
		var masterAuthorizedNetworksCidrs []any
		var masterAuthorizedNetworksAllowed bool
		if c.MasterAuthorizedNetworksConfig != nil {
			masterAuthorizedNetworksAllowed = c.MasterAuthorizedNetworksConfig.Enabled
			for _, cidrBlock := range c.MasterAuthorizedNetworksConfig.CidrBlocks {
				masterAuthorizedNetworksCidrs = append(masterAuthorizedNetworksCidrs, cidrBlock.CidrBlock)
			}
		}

		// Modern control-plane endpoint config overrides the legacy access fields.
		// Default to true: a cluster with neither config block present (e.g. a
		// vanilla public cluster on an older API response) has a publicly
		// reachable control plane, so the safe default avoids audit false negatives.
		controlPlanePublicEndpointEnabled := true
		if ipc := c.GetControlPlaneEndpointsConfig().GetIpEndpointsConfig(); ipc != nil {
			controlPlanePublicEndpointEnabled = ipc.GetEnablePublicEndpoint()
			if anc := ipc.GetAuthorizedNetworksConfig(); anc != nil {
				masterAuthorizedNetworksAllowed = anc.GetEnabled()
				modernCidrs := make([]any, 0, len(anc.CidrBlocks))
				for _, cidrBlock := range anc.CidrBlocks {
					modernCidrs = append(modernCidrs, cidrBlock.CidrBlock)
				}
				masterAuthorizedNetworksCidrs = modernCidrs
			}
		} else if c.PrivateClusterConfig != nil {
			// Legacy: public endpoint is enabled when the private endpoint is not.
			controlPlanePublicEndpointEnabled = !c.PrivateClusterConfig.EnablePrivateEndpoint
		}

		controlPlaneLoggingComponents := make([]any, 0)
		if cc := c.GetLoggingConfig().GetComponentConfig(); cc != nil {
			for _, comp := range cc.EnableComponents {
				controlPlaneLoggingComponents = append(controlPlaneLoggingComponents, comp.String())
			}
		}

		controlPlaneMonitoringComponents := make([]any, 0)
		if cc := c.GetMonitoringConfig().GetComponentConfig(); cc != nil {
			for _, comp := range cc.EnableComponents {
				controlPlaneMonitoringComponents = append(controlPlaneMonitoringComponents, comp.String())
			}
		}

		var privateClusterCfg map[string]any
		if c.PrivateClusterConfig != nil {
			var masterGlobalAccessCfg map[string]any
			if c.PrivateClusterConfig.MasterGlobalAccessConfig != nil {
				masterGlobalAccessCfg = map[string]any{
					"enabled": c.PrivateClusterConfig.MasterGlobalAccessConfig.Enabled,
				}
			}

			privateClusterCfg = map[string]any{
				"enablePrivateNodes":       c.PrivateClusterConfig.EnablePrivateNodes,
				"enablePrivateEndpoint":    c.PrivateClusterConfig.EnablePrivateEndpoint,
				"masterIpv4CidrBlock":      c.PrivateClusterConfig.MasterIpv4CidrBlock,
				"privateEndpoint":          c.PrivateClusterConfig.PrivateEndpoint,
				"publicEndpoint":           c.PrivateClusterConfig.PublicEndpoint,
				"peeringName":              c.PrivateClusterConfig.PeeringName,
				"masterGlobalAccessConfig": masterGlobalAccessCfg,
			}
		}

		dbEnc := newGkeDatabaseEncryption(c.DatabaseEncryption)
		databaseEncryptionKeyName := dbEnc.keyName

		var shieldedNodesConfig map[string]any
		var shieldedNodesEnabled bool
		if c.ShieldedNodes != nil {
			shieldedNodesConfig = map[string]any{
				"enabled": c.ShieldedNodes.Enabled,
			}
			shieldedNodesEnabled = c.ShieldedNodes.Enabled
		}

		var costManagementConfig map[string]any
		if c.CostManagementConfig != nil {
			costManagementConfig = map[string]any{
				"enabled": c.CostManagementConfig.Enabled,
			}
		}

		var confidentialNodesConfig map[string]any
		var confidentialNodesEnabled bool
		if c.ConfidentialNodes != nil {
			confidentialNodesEnabled = c.ConfidentialNodes.Enabled
			confidentialNodesConfig = map[string]any{
				"enabled": c.ConfidentialNodes.Enabled,
			}
		}

		var identityServiceConfig map[string]any
		if c.IdentityServiceConfig != nil {
			identityServiceConfig = map[string]any{
				"enabled": c.IdentityServiceConfig.Enabled,
			}
		}

		var networkPolicyConfig map[string]any
		if c.NetworkPolicy != nil {
			networkPolicyConfig = map[string]any{
				"enabled":  c.NetworkPolicy.Enabled,
				"provider": c.NetworkPolicy.Provider.String(),
			}
		}

		secPostureConfig, err := CreateResource(g.MqlRuntime, "gcp.project.gkeService.cluster.securityPostureConfig", map[string]*llx.RawData{
			"id":                llx.StringData(c.Id + "/securityPostureConfig"),
			"mode":              llx.StringData(c.GetSecurityPostureConfig().GetMode().String()),
			"vulnerabilityMode": llx.StringData(c.GetSecurityPostureConfig().GetVulnerabilityMode().String()),
		})
		if err != nil {
			return nil, err
		}

		var dailyStartTime, dailyDuration, recurringRecurrence string
		var recurringStartTime, recurringEndTime *time.Time
		var maintenanceExclusions map[string]any
		resourceVersion := ""
		if c.MaintenancePolicy != nil {
			resourceVersion = c.MaintenancePolicy.ResourceVersion
			if w := c.MaintenancePolicy.Window; w != nil {
				if dmw := w.GetDailyMaintenanceWindow(); dmw != nil {
					dailyStartTime = dmw.StartTime
					dailyDuration = dmw.Duration
				}
				if rw := w.GetRecurringWindow(); rw != nil {
					recurringRecurrence = rw.Recurrence
					if rw.Window != nil {
						if rw.Window.StartTime != nil {
							t := rw.Window.StartTime.AsTime()
							recurringStartTime = &t
						}
						if rw.Window.EndTime != nil {
							t := rw.Window.EndTime.AsTime()
							recurringEndTime = &t
						}
					}
				}
				if len(w.MaintenanceExclusions) > 0 {
					maintenanceExclusions = make(map[string]any, len(w.MaintenanceExclusions))
					for k, v := range w.MaintenanceExclusions {
						excl, _ := convert.JsonToDict(v)
						maintenanceExclusions[k] = excl
					}
				}
			}
		}
		maintenancePolicy, err := CreateResource(g.MqlRuntime, "gcp.project.gkeService.cluster.maintenancePolicy", map[string]*llx.RawData{
			"id":                              llx.StringData(c.Id + "/maintenancePolicy"),
			"resourceVersion":                 llx.StringData(resourceVersion),
			"dailyMaintenanceWindowStartTime": llx.StringData(dailyStartTime),
			"dailyMaintenanceWindowDuration":  llx.StringData(dailyDuration),
			"recurringWindowRecurrence":       llx.StringData(recurringRecurrence),
			"recurringWindowStartTime":        llx.TimeDataPtr(recurringStartTime),
			"recurringWindowEndTime":          llx.TimeDataPtr(recurringEndTime),
			"maintenanceExclusions":           llx.DictData(maintenanceExclusions),
		})
		if err != nil {
			return nil, err
		}

		var enabledK8sBetaApis []any
		if c.EnableK8SBetaApis != nil {
			enabledK8sBetaApis = convert.SliceAnyToInterface(c.EnableK8SBetaApis.EnabledApis)
		}

		meshCertificates, err := protoToDict(c.MeshCertificates)
		if err != nil {
			return nil, err
		}

		controlPlaneEndpointsConfig, err := protoToDict(c.ControlPlaneEndpointsConfig)
		if err != nil {
			return nil, err
		}

		controlPlaneEndpoints, err := newMqlGkeControlPlaneEndpoints(g.MqlRuntime,
			fmt.Sprintf("gcp.project.gkeService.cluster/%s", c.Id), c.ControlPlaneEndpointsConfig)
		if err != nil {
			return nil, err
		}

		loggingConfig, err := protoToDict(c.LoggingConfig)
		if err != nil {
			return nil, err
		}

		monitoringConfig, err := protoToDict(c.MonitoringConfig)
		if err != nil {
			return nil, err
		}

		secretManagerConfig, err := protoToDict(c.SecretManagerConfig)
		if err != nil {
			return nil, err
		}

		userManagedKeysConfig, err := protoToDict(c.UserManagedKeysConfig)
		if err != nil {
			return nil, err
		}

		anonymousAuthenticationConfig, err := protoToDict(c.AnonymousAuthenticationConfig)
		if err != nil {
			return nil, err
		}

		fleet, err := protoToDict(c.Fleet)
		if err != nil {
			return nil, err
		}

		rbacBindingConfig, err := protoToDict(c.RbacBindingConfig)
		if err != nil {
			return nil, err
		}
		rbacInsecureSystemUnauthenticated, rbacInsecureSystemAuthenticated := gkeRbacInsecureBindings(c.RbacBindingConfig)

		conditions := make([]any, 0, len(c.Conditions))
		for _, cond := range c.Conditions {
			condDict, err := protoToDict(cond)
			if err != nil {
				return nil, err
			}
			if condDict != nil {
				conditions = append(conditions, condDict)
			}
		}

		// Key on the cluster's server-assigned unique Id, not its name: cluster
		// names are unique only within a project+location, so two clusters named
		// "prod" in different projects would share one notificationConfig cache
		// entry. Every other cluster sub-resource in this file uses c.Id.
		notificationConfig, err := buildGKENotificationConfig(g.MqlRuntime, c.Id, c.NotificationConfig)
		if err != nil {
			return nil, err
		}

		var authenticatorGroupsEnabled bool
		authenticatorGroupsSecurityGroup := ""
		if c.AuthenticatorGroupsConfig != nil {
			authenticatorGroupsEnabled = c.AuthenticatorGroupsConfig.Enabled
			authenticatorGroupsSecurityGroup = c.AuthenticatorGroupsConfig.SecurityGroup
		}

		compliancePostureMode := ""
		complianceStandards := []any{}
		if c.CompliancePostureConfig != nil {
			compliancePostureMode = c.CompliancePostureConfig.GetMode().String()
			for _, s := range c.CompliancePostureConfig.ComplianceStandards {
				if std := s.GetStandard(); std != "" {
					complianceStandards = append(complianceStandards, std)
				}
			}
		}

		nodePoolAutoConfig, err := protoToDict(c.GetNodePoolAutoConfig())
		if err != nil {
			return nil, err
		}

		// Only a cluster with a ClusterAutoscaling block has ever been
		// configured for node auto-provisioning. Leave the field null on the
		// rest, so a check on the auto-provisioned node defaults cannot match a
		// cluster that never creates such nodes.
		nodeAutoprovisioningData := llx.NilData
		if ca := c.GetAutoscaling(); ca != nil {
			mqlNap, err := newMqlNodeAutoprovisioning(g.MqlRuntime, projectId, c.Id, ca)
			if err != nil {
				return nil, err
			}
			nodeAutoprovisioningData = llx.ResourceData(mqlNap, "gcp.project.gkeService.cluster.nodeAutoprovisioningConfig")
		}

		clusterArgs := map[string]*llx.RawData{
			"projectId":                                llx.StringData(projectId),
			"id":                                       llx.StringData(c.Id),
			"name":                                     llx.StringData(c.Name),
			"description":                              llx.StringData(c.Description),
			"network":                                  llx.StringData(c.Network),
			"clusterIpv4Cidr":                          llx.StringData(c.ClusterIpv4Cidr),
			"subnetwork":                               llx.StringData(c.Subnetwork),
			"nodePools":                                llx.ArrayData(nodePools, types.Resource("gcp.project.gkeService.cluster.nodepool")),
			"locations":                                llx.ArrayData(convert.SliceAnyToInterface(c.Locations), types.String),
			"enableKubernetesAlpha":                    llx.BoolData(c.EnableKubernetesAlpha),
			"autopilotEnabled":                         llx.BoolData(autopilotEnabled),
			"autopilotWorkloadPolicyAllowNetAdmin":     llx.BoolData(autopilotAllowNetAdmin),
			"resourceUsageExportConfig":                llx.DictData(resourceUsageExportConfig),
			"verticalPodAutoscalingEnabled":            llx.BoolData(verticalPodAutoscalingEnabled),
			"intraNodeVisibilityEnabled":               llx.BoolData(intraNodeVisibilityEnabled),
			"defaultMaxPodsPerNode":                    llx.IntData(defaultMaxPodsPerNode),
			"location":                                 llx.StringData(c.Location),
			"endpoint":                                 llx.StringData(c.Endpoint),
			"initialClusterVersion":                    llx.StringData(c.InitialClusterVersion),
			"currentMasterVersion":                     llx.StringData(c.CurrentMasterVersion),
			"status":                                   llx.StringData(c.Status.String()),
			"resourceLabels":                           llx.MapData(convert.MapToInterfaceMap(c.ResourceLabels), types.String),
			"created":                                  llx.TimeDataPtr(parseTime(c.CreateTime)),
			"expirationTime":                           llx.TimeDataPtr(parseTime(c.ExpireTime)),
			"addonsConfig":                             llx.ResourceData(addonsConfig, "gcp.project.gkeService.cluster.addonsConfig"),
			"workloadIdentityConfig":                   llx.DictData(workloadIdCfg),
			"workloadIdentityEnabled":                  llx.BoolData(workloadIdentityEnabled),
			"ipAllocationPolicy":                       llx.ResourceData(ipAllocPolicy, "gcp.project.gkeService.cluster.ipAllocationPolicy"),
			"networkConfig":                            llx.ResourceData(networkConfig, "gcp.project.gkeService.cluster.networkConfig"),
			"binaryAuthorizationEvaluationMode":        llx.StringData(binaryAuthorizationEvaluationMode),
			"legacyAbac":                               llx.DictData(legacyAbac),
			"legacyAbacEnabled":                        llx.BoolData(legacyAbacEnabled),
			"masterAuth":                               llx.DictData(masterAuth),
			"clientCertificateEnabled":                 llx.BoolData(clientCertificateEnabled),
			"basicAuthEnabled":                         llx.BoolData(basicAuthEnabled),
			"privateClusterConfig":                     llx.DictData(privateClusterCfg),
			"databaseEncryption":                       llx.DictData(dbEnc.dict),
			"databaseEncryptionState":                  llx.StringData(dbEnc.state),
			"databaseEncryptionCurrentState":           llx.StringData(dbEnc.currentState),
			"shieldedNodesConfig":                      llx.DictData(shieldedNodesConfig),
			"shieldedNodesEnabled":                     llx.BoolData(shieldedNodesEnabled),
			"costManagementConfig":                     llx.DictData(costManagementConfig),
			"confidentialNodesConfig":                  llx.DictData(confidentialNodesConfig),
			"confidentialNodesEnabled":                 llx.BoolData(confidentialNodesEnabled),
			"identityServiceConfig":                    llx.DictData(identityServiceConfig),
			"releaseChannel":                           llx.StringData(strings.ToLower(c.ReleaseChannel.GetChannel().String())),
			"enableTpu":                                llx.BoolData(c.EnableTpu),
			"currentNodeCount":                         llx.IntData(int64(c.CurrentNodeCount)),
			"securityPostureConfig":                    llx.ResourceData(secPostureConfig, "gcp.project.gkeService.cluster.securityPostureConfig"),
			"authenticatorGroupsEnabled":               llx.BoolData(authenticatorGroupsEnabled),
			"authenticatorGroupsSecurityGroup":         llx.StringData(authenticatorGroupsSecurityGroup),
			"compliancePostureMode":                    llx.StringData(compliancePostureMode),
			"complianceStandards":                      llx.ArrayData(complianceStandards, types.String),
			"maintenancePolicy":                        llx.ResourceData(maintenancePolicy, "gcp.project.gkeService.cluster.maintenancePolicy"),
			"etag":                                     llx.StringData(c.Etag),
			"initialNodeCount":                         llx.IntData(int64(c.InitialNodeCount)),
			"servicesIpv4Cidr":                         llx.StringData(c.ServicesIpv4Cidr),
			"nodeIpv4CidrSize":                         llx.IntData(int64(c.NodeIpv4CidrSize)),
			"tpuIpv4CidrBlock":                         llx.StringData(c.TpuIpv4CidrBlock),
			"enabledK8sBetaApis":                       llx.ArrayData(enabledK8sBetaApis, types.String),
			"enterpriseClusterTier":                    llx.StringData(c.GetEnterpriseConfig().GetClusterTier().String()),
			"enterpriseDesiredTier":                    llx.StringData(c.GetEnterpriseConfig().GetDesiredTier().String()),
			"autoUpgradePatchMode":                     llx.StringData(c.GetGkeAutoUpgradeConfig().GetPatchMode().String()),
			"secretSyncEnabled":                        llx.BoolData(c.GetSecretSyncConfig().GetEnabled()),
			"secretSyncRotationEnabled":                llx.BoolData(c.GetSecretSyncConfig().GetRotationConfig().GetEnabled()),
			"secretSyncRotationIntervalSeconds":        llx.IntData(c.GetSecretSyncConfig().GetRotationConfig().GetRotationInterval().GetSeconds()),
			"podAutoscalingHpaProfile":                 llx.StringData(c.GetPodAutoscaling().GetHpaProfile().String()),
			"currentNodeVersion":                       llx.StringData(c.GetCurrentNodeVersion()),
			"statusMessage":                            llx.StringData(c.GetStatusMessage()),
			"nodePoolAutoConfig":                       llx.DictData(nodePoolAutoConfig),
			"nodeAutoprovisioning":                     nodeAutoprovisioningData,
			"meshCertificates":                         llx.DictData(meshCertificates),
			"controlPlaneEndpointsConfig":              llx.DictData(controlPlaneEndpointsConfig),
			"controlPlaneEndpoints":                    controlPlaneEndpoints,
			"controlPlanePublicEndpointEnabled":        llx.BoolData(controlPlanePublicEndpointEnabled),
			"masterAuthorizedNetworksCidrs":            llx.ArrayData(masterAuthorizedNetworksCidrs, types.String),
			"masterAuthorizedNetworksAllowed":          llx.BoolData(masterAuthorizedNetworksAllowed),
			"controlPlaneLoggingComponents":            llx.ArrayData(controlPlaneLoggingComponents, types.String),
			"controlPlaneMonitoringComponents":         llx.ArrayData(controlPlaneMonitoringComponents, types.String),
			"loggingConfig":                            llx.DictData(loggingConfig),
			"monitoringConfig":                         llx.DictData(monitoringConfig),
			"secretManagerConfig":                      llx.DictData(secretManagerConfig),
			"userManagedKeysConfig":                    llx.DictData(userManagedKeysConfig),
			"anonymousAuthenticationConfig":            llx.DictData(anonymousAuthenticationConfig),
			"fleet":                                    llx.DictData(fleet),
			"rbacBindingConfig":                        llx.DictData(rbacBindingConfig),
			"rbacBindingInsecureSystemUnauthenticated": llx.BoolData(rbacInsecureSystemUnauthenticated),
			"rbacBindingInsecureSystemAuthenticated":   llx.BoolData(rbacInsecureSystemAuthenticated),
			"conditions":                               llx.ArrayData(conditions, types.Dict),
			"satisfiesPzi":                             llx.BoolDataPtr(c.SatisfiesPzi),
			"satisfiesPzs":                             llx.BoolDataPtr(c.SatisfiesPzs),
		}
		if notificationConfig != nil {
			clusterArgs["notificationConfig"] = llx.ResourceData(notificationConfig, "gcp.project.gkeService.cluster.notificationConfig")
		}

		mqlCluster, err := CreateResource(g.MqlRuntime, "gcp.project.gkeService.cluster", clusterArgs)
		if err != nil {
			return nil, err
		}
		mqlC := mqlCluster.(*mqlGcpProjectGkeServiceCluster)
		mqlC.cacheDatabaseEncryptionKeyName = databaseEncryptionKeyName
		mqlC.cacheLoggingService = c.LoggingService
		mqlC.cacheMonitoringService = c.MonitoringService
		mqlC.cacheNetworkPolicyConfig = networkPolicyConfig
		if notificationConfig == nil {
			mqlC.NotificationConfig.State = plugin.StateIsNull | plugin.StateIsSet
		}
		res = append(res, mqlCluster)
	}

	return res, nil
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfig) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		// No SA on the node pool config means it falls back to the project
		// default; resolve to null rather than a husk keyed on an empty email.
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func createMqlNodePool(runtime *plugin.Runtime, np *containerpb.NodePool, clusterId, projectId string) (plugin.Resource, error) {
	nodePoolId := fmt.Sprintf("%s/%s", clusterId, np.Name)

	mqlPoolConfig, err := createMqlNodePoolConfig(runtime, np, nodePoolId, projectId)
	if err != nil {
		return nil, err
	}

	mqlPoolNetworkConfig, err := createMqlNodePoolNetworkConfig(runtime, np, nodePoolId)
	if err != nil {
		return nil, err
	}

	mqlPoolAutoscaling, err := createMqlNodePoolAutoscaling(runtime, np, nodePoolId)
	if err != nil {
		return nil, err
	}

	var management map[string]any
	var autoUpgrade, autoRepair bool
	if np.Management != nil {
		var upgradeOpts map[string]any
		if np.Management.UpgradeOptions != nil {
			upgradeOpts = map[string]any{
				"autoUpgradeStartTime": np.Management.UpgradeOptions.AutoUpgradeStartTime,
				"description":          np.Management.UpgradeOptions.Description,
			}
		}
		autoUpgrade = np.Management.AutoUpgrade
		autoRepair = np.Management.AutoRepair
		management = map[string]any{
			"autoRepair":     np.Management.AutoRepair,
			"autoUpgrade":    np.Management.AutoUpgrade,
			"upgradeOptions": upgradeOpts,
		}
	}

	var blueGreenSettings map[string]any
	upgradeStrategy := ""
	var maxSurge, maxUnavailable int32
	if np.UpgradeSettings != nil {
		maxSurge = np.UpgradeSettings.MaxSurge
		maxUnavailable = np.UpgradeSettings.MaxUnavailable
		if np.UpgradeSettings.Strategy != nil {
			upgradeStrategy = np.UpgradeSettings.GetStrategy().String()
		}
		blueGreenSettings, _ = convert.JsonToDict(np.UpgradeSettings.BlueGreenSettings)
	}

	mqlUpgradeSettings, err := CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.upgradeSettings", map[string]*llx.RawData{
		"id":                llx.StringData(nodePoolId + "/upgradeSettings"),
		"maxSurge":          llx.IntData(int64(maxSurge)),
		"maxUnavailable":    llx.IntData(int64(maxUnavailable)),
		"strategy":          llx.StringData(upgradeStrategy),
		"blueGreenSettings": llx.DictData(blueGreenSettings),
	})
	if err != nil {
		return nil, err
	}

	var nodeDrainConfig map[string]any
	if np.NodeDrainConfig != nil {
		nodeDrainConfig, _ = convert.JsonToDict(np.NodeDrainConfig)
	}

	res, err := CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool", map[string]*llx.RawData{
		"id":                llx.StringData(nodePoolId),
		"name":              llx.StringData(np.Name),
		"config":            llx.ResourceData(mqlPoolConfig, "gcp.project.gkeService.cluster.nodepool.config"),
		"initialNodeCount":  llx.IntData(int64(np.InitialNodeCount)),
		"locations":         llx.ArrayData(convert.SliceAnyToInterface(np.Locations), types.String),
		"networkConfig":     llx.ResourceData(mqlPoolNetworkConfig, "gcp.project.gkeService.cluster.nodepool.networkConfig"),
		"version":           llx.StringData(np.Version),
		"instanceGroupUrls": llx.ArrayData(convert.SliceAnyToInterface(np.InstanceGroupUrls), types.String),
		"status":            llx.StringData(np.Status.String()),
		"management":        llx.DictData(management),
		"autoUpgrade":       llx.BoolData(autoUpgrade),
		"autoRepair":        llx.BoolData(autoRepair),
		"autoscaling":       llx.ResourceData(mqlPoolAutoscaling, "gcp.project.gkeService.cluster.nodepool.autoscaling"),
		"statusMessage":     llx.StringData(np.StatusMessage),
		"podIpv4CidrSize":   llx.IntData(int64(np.PodIpv4CidrSize)),
		"upgradeSettings":   llx.ResourceData(mqlUpgradeSettings, "gcp.project.gkeService.cluster.nodepool.upgradeSettings"),
		"nodeDrainConfig":   llx.DictData(nodeDrainConfig),
		"etag":              llx.StringData(np.Etag),
	})
	if err != nil {
		return nil, err
	}
	mqlNodePool := res.(*mqlGcpProjectGkeServiceClusterNodepool)
	mqlNodePool.cacheInstanceGroupUrls = np.InstanceGroupUrls
	mqlNodePool.cacheProjectId = projectId
	return res, nil
}

// nodeTaintID returns a cache-stable identifier for a node-pool taint.
// Kubernetes taints are uniquely identified by (key, value, effect); a node
// pool can carry sibling taints sharing any one of those, so all three must
// participate in the id to avoid runtime-cache collisions.
func nodeTaintID(nodePoolId, key, value, effect string) string {
	return fmt.Sprintf("%s/taints/%s/%s/%s", nodePoolId, key, value, effect)
}

func createMqlNodePoolConfig(runtime *plugin.Runtime, np *containerpb.NodePool, nodePoolId, projectId string) (plugin.Resource, error) {
	cfg := np.Config
	if cfg == nil {
		cfg = &containerpb.NodeConfig{}
	}
	var err error
	mqlAccelerators := make([]any, 0, len(cfg.Accelerators))
	for i, acc := range cfg.Accelerators {
		mqlAcc, err := createMqlAccelerator(runtime, acc, nodePoolId, i)
		if err != nil {
			return nil, err
		}
		mqlAccelerators = append(mqlAccelerators, mqlAcc)
	}

	nodeTaints := make([]any, 0, len(cfg.Taints))
	for _, taint := range cfg.Taints {
		mqlNodeTaint, err := CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.nodeTaint", map[string]*llx.RawData{
			"id":     llx.StringData(nodeTaintID(nodePoolId, taint.Key, taint.Value, taint.Effect.String())),
			"key":    llx.StringData(taint.Key),
			"value":  llx.StringData(taint.Value),
			"effect": llx.StringData(taint.Effect.String()),
		})
		if err != nil {
			return nil, err
		}
		nodeTaints = append(nodeTaints, mqlNodeTaint)
	}

	var mqlSandboxCfg plugin.Resource
	var gvisorSandbox bool
	if cfg.SandboxConfig != nil {
		gvisorSandbox = cfg.SandboxConfig.Type == containerpb.SandboxConfig_GVISOR
		mqlSandboxCfg, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.sandboxConfig", map[string]*llx.RawData{
			"id":   llx.StringData(fmt.Sprintf("%s/sandbox", nodePoolId)),
			"type": llx.StringData(cfg.SandboxConfig.Type.String()),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlShieldedInstanceCfg plugin.Resource
	if cfg.ShieldedInstanceConfig != nil {
		mqlShieldedInstanceCfg, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.shieldedInstanceConfig", map[string]*llx.RawData{
			"id":                        llx.StringData(fmt.Sprintf("%s/shieldedInstanceConfig", nodePoolId)),
			"enableSecureBoot":          llx.BoolData(cfg.ShieldedInstanceConfig.EnableSecureBoot),
			"enableIntegrityMonitoring": llx.BoolData(cfg.ShieldedInstanceConfig.EnableIntegrityMonitoring),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlLinuxNodeCfg plugin.Resource
	if cfg.LinuxNodeConfig != nil {
		var swapConfig map[string]any
		if cfg.LinuxNodeConfig.SwapConfig != nil {
			swapConfig, _ = convert.JsonToDict(cfg.LinuxNodeConfig.SwapConfig)
		}
		mqlLinuxNodeCfg, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.linuxNodeConfig", map[string]*llx.RawData{
			"id":         llx.StringData(fmt.Sprintf("%s/linuxNodeConfig", nodePoolId)),
			"sysctls":    llx.MapData(convert.MapToInterfaceMap(cfg.LinuxNodeConfig.Sysctls), types.String),
			"swapConfig": llx.DictData(swapConfig),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlWindowsNodeCfg plugin.Resource
	if cfg.WindowsNodeConfig != nil {
		mqlWindowsNodeCfg, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.windowsNodeConfig", map[string]*llx.RawData{
			"__id":      llx.StringData(fmt.Sprintf("%s/windowsNodeConfig", nodePoolId)),
			"osVersion": llx.StringData(cfg.WindowsNodeConfig.OsVersion.String()),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlKubeletCfg plugin.Resource
	if cfg.KubeletConfig != nil {
		mqlKubeletCfg, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.kubeletConfig", map[string]*llx.RawData{
			"id":                llx.StringData(fmt.Sprintf("%s/kubeletConfig", nodePoolId)),
			"cpuManagerPolicy":  llx.StringData(cfg.KubeletConfig.CpuManagerPolicy),
			"cpuCfsQuotaPeriod": llx.StringData(cfg.KubeletConfig.CpuCfsQuotaPeriod),
			"podPidsLimit":      llx.IntData(cfg.KubeletConfig.PodPidsLimit),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlGcfsCfg plugin.Resource
	var gcfsEnabled bool
	if cfg.GcfsConfig != nil {
		gcfsEnabled = cfg.GcfsConfig.Enabled
		mqlGcfsCfg, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.gcfsConfig", map[string]*llx.RawData{
			"id":      llx.StringData(fmt.Sprintf("%s/gcfsConfig", nodePoolId)),
			"enabled": llx.BoolData(cfg.GcfsConfig.Enabled),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlAdvancedMachineFeatures plugin.Resource
	if cfg.AdvancedMachineFeatures != nil {
		mqlAdvancedMachineFeatures, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.advancedMachineFeatures", map[string]*llx.RawData{
			"id":             llx.StringData(fmt.Sprintf("%s/advancedMachineFeatures", nodePoolId)),
			"threadsPerCore": llx.IntDataPtr(cfg.AdvancedMachineFeatures.ThreadsPerCore),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlGvnicCfg plugin.Resource
	if cfg.Gvnic != nil {
		mqlGvnicCfg, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.gvnicConfig", map[string]*llx.RawData{
			"id":      llx.StringData(fmt.Sprintf("%s/gvnicConfig", nodePoolId)),
			"enabled": llx.BoolData(cfg.Gvnic.Enabled),
		})
		if err != nil {
			return nil, err
		}
	}

	var mqlConfidentialNodes plugin.Resource
	if cfg.ConfidentialNodes != nil {
		mqlConfidentialNodes, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.confidentialNodes", map[string]*llx.RawData{
			"id":      llx.StringData(fmt.Sprintf("%s/confidentialNodes", nodePoolId)),
			"enabled": llx.BoolData(cfg.ConfidentialNodes.Enabled),
		})
		if err != nil {
			return nil, err
		}
	}

	var gpuDirectConfig map[string]any
	if cfg.GpuDirectConfig != nil {
		gpuDirectConfig = map[string]any{
			"gpuDirectStrategy": cfg.GpuDirectConfig.GetGpuDirectStrategy().String(),
		}
	}

	var containerdConfig map[string]any
	if cfg.ContainerdConfig != nil {
		containerdConfig, _ = convert.JsonToDict(cfg.ContainerdConfig)
	}

	workloadMetadataMode := ""
	if cfg.WorkloadMetadataConfig != nil {
		workloadMetadataMode = cfg.WorkloadMetadataConfig.Mode.String()
	}

	return CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config", map[string]*llx.RawData{
		"id":                      llx.StringData(fmt.Sprintf("%s/config", nodePoolId)),
		"projectId":               llx.StringData(projectId),
		"machineType":             llx.StringData(cfg.MachineType),
		"diskSizeGb":              llx.IntData(int64(cfg.DiskSizeGb)),
		"oauthScopes":             llx.ArrayData(convert.SliceAnyToInterface(cfg.OauthScopes), types.String),
		"serviceAccountEmail":     llx.StringData(cfg.ServiceAccount),
		"metadata":                llx.MapData(convert.MapToInterfaceMap(cfg.Metadata), types.String),
		"imageType":               llx.StringData(cfg.ImageType),
		"labels":                  llx.MapData(convert.MapToInterfaceMap(cfg.Labels), types.String),
		"localSsdCount":           llx.IntData(int64(cfg.LocalSsdCount)),
		"tags":                    llx.ArrayData(convert.SliceAnyToInterface(cfg.Tags), types.String),
		"preemptible":             llx.BoolData(cfg.Preemptible),
		"accelerators":            llx.ArrayData(mqlAccelerators, types.Resource("gcp.project.gkeService.cluster.nodepool.config.accelerator")),
		"diskType":                llx.StringData(cfg.DiskType),
		"minCpuPlatform":          llx.StringData(cfg.MinCpuPlatform),
		"workloadMetadataMode":    llx.StringData(workloadMetadataMode),
		"taints":                  llx.ArrayData(nodeTaints, types.Resource("gcp.project.gkeService.cluster.nodepool.config.nodeTaint")),
		"sandboxConfig":           llx.ResourceData(mqlSandboxCfg, "gcp.project.gkeService.cluster.nodepool.config.sandboxConfig"),
		"gvisorSandbox":           llx.BoolData(gvisorSandbox),
		"shieldedInstanceConfig":  llx.ResourceData(mqlShieldedInstanceCfg, "gcp.project.gkeService.cluster.nodepool.config.shieldedInstanceConfig"),
		"linuxNodeConfig":         llx.ResourceData(mqlLinuxNodeCfg, "gcp.project.gkeService.cluster.nodepool.config.linuxNodeConfig"),
		"windowsNodeConfig":       llx.ResourceData(mqlWindowsNodeCfg, "gcp.project.gkeService.cluster.nodepool.config.windowsNodeConfig"),
		"kubeletConfig":           llx.ResourceData(mqlKubeletCfg, "gcp.project.gkeService.cluster.nodepool.config.kubeletConfig"),
		"bootDiskKmsKey":          llx.StringData(cfg.BootDiskKmsKey),
		"localSsdEncryptionMode":  llx.StringData(cfg.GetLocalSsdEncryptionMode().String()),
		"gcfsConfig":              llx.ResourceData(mqlGcfsCfg, "gcp.project.gkeService.cluster.nodepool.config.gcfsConfig"),
		"gcfsEnabled":             llx.BoolData(gcfsEnabled),
		"gvnicConfig":             llx.ResourceData(mqlGvnicCfg, "gcp.project.gkeService.cluster.nodepool.config.gvnicConfig"),
		"advancedMachineFeatures": llx.ResourceData(mqlAdvancedMachineFeatures, "gcp.project.gkeService.cluster.nodepool.config.advancedMachineFeatures"),
		"spot":                    llx.BoolData(cfg.Spot),
		"confidentialNodes":       llx.ResourceData(mqlConfidentialNodes, "gcp.project.gkeService.cluster.nodepool.config.confidentialNodes"),
		"gpuDirectConfig":         llx.DictData(gpuDirectConfig),
		"containerdConfig":        llx.DictData(containerdConfig),
	})
}

func createMqlNodePoolNetworkConfig(runtime *plugin.Runtime, np *containerpb.NodePool, nodePoolId string) (plugin.Resource, error) {
	netCfg := np.NetworkConfig
	if netCfg == nil {
		return nil, nil
	}

	netCfgId := fmt.Sprintf("%s/networkConfig", nodePoolId)

	var performanceConfig plugin.Resource
	var err error
	if netCfg.NetworkPerformanceConfig != nil {
		performanceConfig, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.networkConfig.performanceConfig", map[string]*llx.RawData{
			"id":                       llx.StringData(fmt.Sprintf("%s/performanceConfig", netCfgId)),
			"totalEgressBandwidthTier": llx.StringData(netCfg.NetworkPerformanceConfig.TotalEgressBandwidthTier.String()),
		})
		if err != nil {
			return nil, err
		}
	}

	return CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.networkConfig", map[string]*llx.RawData{
		"id":                llx.StringData(netCfgId),
		"podRange":          llx.StringData(netCfg.PodRange),
		"podIpv4CidrBlock":  llx.StringData(netCfg.PodIpv4CidrBlock),
		"performanceConfig": llx.ResourceData(performanceConfig, "gcp.project.gkeService.cluster.nodepool.networkConfig.performanceConfig"),
	})
}

func createMqlNodePoolAutoscaling(runtime *plugin.Runtime, nodepool *containerpb.NodePool, nodePoolId string) (plugin.Resource, error) {
	autoscalingCfg := nodepool.Autoscaling
	if autoscalingCfg == nil {
		return nil, nil
	}

	autoscalingId := fmt.Sprintf("gcp.project.gkeService.cluster.nodepool.autoscaling/%s", nodePoolId)

	return CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.autoscaling", map[string]*llx.RawData{
		"__id":              llx.StringData(autoscalingId),
		"minNodeCount":      llx.IntData(autoscalingCfg.MinNodeCount),
		"maxNodeCount":      llx.IntData(autoscalingCfg.MaxNodeCount),
		"autoprovisioned":   llx.BoolData(autoscalingCfg.Autoprovisioned),
		"enabled":           llx.BoolData(autoscalingCfg.Enabled),
		"totalMinNodeCount": llx.IntData(autoscalingCfg.TotalMinNodeCount),
		"totalMaxNodeCount": llx.IntData(autoscalingCfg.TotalMaxNodeCount),
	})
}

func createMqlAccelerator(runtime *plugin.Runtime, acc *containerpb.AcceleratorConfig, nodePoolId string, i int) (plugin.Resource, error) {
	accId := fmt.Sprintf("%s/accelerators/%d", nodePoolId, i)

	var gpuSharingConfig plugin.Resource
	var err error
	if acc.GpuSharingConfig != nil {
		gpuSharingConfig, err = CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.accelerator.gpuSharingConfig", map[string]*llx.RawData{
			"id":                     llx.StringData(fmt.Sprintf("%s/gpuSharingConfig", accId)),
			"maxSharedClientsPerGpu": llx.IntData(acc.GpuSharingConfig.MaxSharedClientsPerGpu),
			"strategy":               llx.StringData(acc.GpuSharingConfig.GpuSharingStrategy.String()),
		})
		if err != nil {
			return nil, err
		}
	}

	return CreateResource(runtime, "gcp.project.gkeService.cluster.nodepool.config.accelerator", map[string]*llx.RawData{
		"id":               llx.StringData(accId),
		"count":            llx.IntData(acc.AcceleratorCount),
		"type":             llx.StringData(acc.AcceleratorType),
		"gpuPartitionSize": llx.StringData(acc.GpuPartitionSize),
		"gpuSharingConfig": llx.ResourceData(gpuSharingConfig, "gcp.project.gkeService.cluster.nodepool.config.accelerator.gpuSharingConfig"),
	})
}

func (g *mqlGcpProjectGkeServiceClusterNetworkConfig) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	if g.NetworkPath.Error != nil {
		return nil, g.NetworkPath.Error
	}
	networkPath := g.NetworkPath.Data
	if networkPath == "" {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	// Format is projects/project-1/global/networks/net-1. getNetworkByUrl uses
	// NewResource so the network's init runs and every field is populated (a
	// plain CreateResource here would leave a husk with only name/projectId set),
	// and it length-guards the path instead of blindly indexing.
	net, err := getNetworkByUrl(networkPath, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if net == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return net, nil
}

func (g *mqlGcpProjectGkeServiceClusterNetworkConfig) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	if g.SubnetworkPath.Error != nil {
		return nil, g.SubnetworkPath.Error
	}
	subnetPath := g.SubnetworkPath.Data

	// NetworkConfig.Subnetwork is not a required field: it is empty for
	// routes-based clusters on a legacy (subnet-less) network. Blindly indexing
	// the split path panics there, and a panic in a provider accessor is
	// unrecoverable because the executor runs blocks in goroutines. Delegate to
	// getSubnetworkByUrl, which length-guards the path, and degrade to null.
	if subnetPath == "" {
		g.Subnetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	subnet, err := getSubnetworkByUrl(subnetPath, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if subnet == nil {
		g.Subnetwork.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return subnet, nil
}

func (g *mqlGcpProjectGkeServiceClusterMaintenancePolicy) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterSecurityPostureConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolUpgradeSettings) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func buildGKENotificationConfig(runtime *plugin.Runtime, parentName string, nc *containerpb.NotificationConfig) (*mqlGcpProjectGkeServiceClusterNotificationConfig, error) {
	if nc == nil || nc.Pubsub == nil {
		return nil, nil
	}

	var filterEventTypes []any
	if nc.Pubsub.Filter != nil {
		for _, et := range nc.Pubsub.Filter.EventType {
			filterEventTypes = append(filterEventTypes, et.String())
		}
	}

	res, err := CreateResource(runtime, "gcp.project.gkeService.cluster.notificationConfig", map[string]*llx.RawData{
		"id":               llx.StringData(parentName + "/notificationConfig"),
		"pubsubEnabled":    llx.BoolData(nc.Pubsub.Enabled),
		"pubsubTopic":      llx.StringData(nc.Pubsub.Topic),
		"filterEventTypes": llx.ArrayData(filterEventTypes, types.String),
	})
	if err != nil {
		return nil, err
	}
	r := res.(*mqlGcpProjectGkeServiceClusterNotificationConfig)
	r.cacheTopic = nc.Pubsub.Topic
	return r, nil
}

func (g *mqlGcpProjectGkeServiceClusterNotificationConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

type mqlGcpProjectGkeServiceClusterNotificationConfigInternal struct {
	cacheTopic string
}

func (g *mqlGcpProjectGkeServiceClusterNotificationConfig) topic() (*mqlGcpProjectPubsubServiceTopic, error) {
	ref, err := resolvePubsubTopicRef(g.MqlRuntime, g.cacheTopic, "")
	if err != nil {
		return nil, err
	}
	if ref == nil {
		g.Topic.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return ref, nil
}

func (g *mqlGcpProjectGkeServiceCluster) loggingEnabled() (bool, error) {
	v := strings.ToLower(g.cacheLoggingService)
	return v != "" && v != "none", nil
}

func (g *mqlGcpProjectGkeServiceCluster) monitoringEnabled() (bool, error) {
	v := strings.ToLower(g.cacheMonitoringService)
	return v != "" && v != "none", nil
}

func (g *mqlGcpProjectGkeServiceCluster) releaseChannelManaged() (bool, error) {
	if g.ReleaseChannel.Error != nil {
		return false, g.ReleaseChannel.Error
	}
	switch strings.ToLower(g.ReleaseChannel.Data) {
	case "rapid", "regular", "stable":
		return true, nil
	}
	return false, nil
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfig) usesDefaultServiceAccount() (bool, error) {
	if g.ServiceAccountEmail.Error != nil {
		return false, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" || email == "default" {
		return true, nil
	}
	return defaultComputeServiceAccountRe.MatchString(email), nil
}

func (g *mqlGcpProjectGkeServiceClusterNodepoolConfig) hasFullCloudPlatformScope() (bool, error) {
	scopes := g.GetOauthScopes()
	if scopes.Error != nil {
		return false, scopes.Error
	}
	for _, s := range scopes.Data {
		if str, ok := s.(string); ok && str == cloudPlatformOAuthScope {
			return true, nil
		}
	}
	return false, nil
}

// gkeRbacInsecureBindings reports whether a GKE cluster allows insecure RBAC
// bindings — to system:anonymous/system:unauthenticated subjects
// (systemUnauthenticated) and to system:authenticated subjects
// (systemAuthenticated). The protobuf getters are nil-safe, so an absent
// config reports both as false (the secure default).
func gkeRbacInsecureBindings(cfg *containerpb.RBACBindingConfig) (systemUnauthenticated, systemAuthenticated bool) {
	return cfg.GetEnableInsecureBindingSystemUnauthenticated(), cfg.GetEnableInsecureBindingSystemAuthenticated()
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectGkeService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_gke)
}

type mqlGcpProjectGkeServiceClusterNodeAutoprovisioningConfigInternal struct {
	cacheServiceAccount string
	cacheProjectId      string
}

// newMqlNodeAutoprovisioning maps a cluster's node auto-provisioning settings
// and the defaults applied to the nodes it creates.
//
// The defaults block is optional even when auto-provisioning is configured. A
// missing block leaves the shielded and kubelet booleans false, which is the
// safe reading: it must not report protections the API never claimed.
func newMqlNodeAutoprovisioning(runtime *plugin.Runtime, projectId, clusterId string, ca *containerpb.ClusterAutoscaling) (plugin.Resource, error) {
	resourceLimits := make([]any, 0, len(ca.GetResourceLimits()))
	for _, rl := range ca.GetResourceLimits() {
		if rl == nil {
			continue
		}
		resourceLimits = append(resourceLimits, map[string]any{
			"resourceType": rl.GetResourceType(),
			"minimum":      rl.GetMinimum(),
			"maximum":      rl.GetMaximum(),
		})
	}

	defaults := ca.GetAutoprovisioningNodePoolDefaults()
	args := map[string]*llx.RawData{
		"__id":                               llx.StringData(fmt.Sprintf("%s/%s/nodeAutoprovisioning", projectId, clusterId)),
		"enabled":                            llx.BoolData(ca.GetEnableNodeAutoprovisioning()),
		"autoscalingProfile":                 llx.StringData(ca.GetAutoscalingProfile().String()),
		"autoprovisioningLocations":          llx.ArrayData(convert.SliceAnyToInterface(ca.GetAutoprovisioningLocations()), types.String),
		"resourceLimits":                     llx.ArrayData(resourceLimits, types.Dict),
		"oauthScopes":                        llx.ArrayData(convert.SliceAnyToInterface(defaults.GetOauthScopes()), types.String),
		"shieldedSecureBootEnabled":          llx.BoolData(defaults.GetShieldedInstanceConfig().GetEnableSecureBoot()),
		"shieldedIntegrityMonitoringEnabled": llx.BoolData(defaults.GetShieldedInstanceConfig().GetEnableIntegrityMonitoring()),
		"bootDiskKmsKey":                     llx.StringData(defaults.GetBootDiskKmsKey()),
		"diskType":                           llx.StringData(defaults.GetDiskType()),
		"diskSizeGb":                         llx.IntData(int64(defaults.GetDiskSizeGb())),
		"imageType":                          llx.StringData(defaults.GetImageType()),
		"minCpuPlatform":                     llx.StringData(defaults.GetMinCpuPlatform()),
		"insecureKubeletReadonlyPortEnabled": llx.BoolData(defaults.GetInsecureKubeletReadonlyPortEnabled()),
	}

	res, err := CreateResource(runtime, "gcp.project.gkeService.cluster.nodeAutoprovisioningConfig", args)
	if err != nil {
		return nil, err
	}
	nap := res.(*mqlGcpProjectGkeServiceClusterNodeAutoprovisioningConfig)
	nap.cacheServiceAccount = defaults.GetServiceAccount()
	nap.cacheProjectId = projectId
	return res, nil
}

func (g *mqlGcpProjectGkeServiceClusterNodeAutoprovisioningConfig) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	// GKE reports a bare email here rather than a full resource path, so the
	// cluster's project is supplied as the fallback.
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheServiceAccount, g.cacheProjectId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

// gkeDatabaseEncryption is the etcd (application-layer Secrets) encryption
// configuration of a GKE cluster.
type gkeDatabaseEncryption struct {
	dict         map[string]any
	state        string
	currentState string
	keyName      string
}

// newGkeDatabaseEncryption reads the etcd encryption configuration of a
// cluster. `state` is the requested state, `currentState` the one GKE reports
// as in effect. All fields are empty when the cluster reports none.
func newGkeDatabaseEncryption(de *containerpb.DatabaseEncryption) gkeDatabaseEncryption {
	if de == nil {
		return gkeDatabaseEncryption{}
	}
	res := gkeDatabaseEncryption{
		state:   de.State.String(),
		keyName: de.KeyName,
	}
	if de.CurrentState != nil {
		res.currentState = de.GetCurrentState().String()
	}
	res.dict = map[string]any{
		"state":        res.state,
		"keyName":      res.keyName,
		"currentState": res.currentState,
	}
	return res
}
