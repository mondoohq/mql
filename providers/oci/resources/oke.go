// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/containerengine"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciOke) id() (string, error) {
	return "oci.oke", nil
}

// okePodNetworkTypes reads the CNI type out of the cluster's pod network
// options. The SDK models these as a polymorphic list whose concrete types
// carry nothing beyond the discriminator, so the type is the whole value.
//
// The entries arrive as concrete structs rather than pointers. Matching on the
// pointer types instead would compile and silently produce an empty list, which
// reads as "this cluster has no pod networking" rather than as a failure.
func okePodNetworkTypes(opts []containerengine.ClusterPodNetworkOptionDetails) []any {
	out := make([]any, 0, len(opts))
	for _, opt := range opts {
		switch opt.(type) {
		case containerengine.OciVcnIpNativeClusterPodNetworkOptionDetails:
			out = append(out, string(containerengine.ClusterPodNetworkOptionDetailsCniTypeOciVcnIpNative))
		case containerengine.FlannelOverlayClusterPodNetworkOptionDetails:
			out = append(out, string(containerengine.ClusterPodNetworkOptionDetailsCniTypeFlannelOverlay))
		}
	}
	return out
}

func (o *mqlOciOke) clusters() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	return ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			log.Debug().Msgf("calling oci oke with region %s", region)

			svc, err := conn.ContainerEngineClient(region)
			if err != nil {
				return nil, err
			}

			clusters, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]containerengine.ClusterSummary, *string, error) {
				response, err := svc.ListClusters(ctx, containerengine.ListClustersRequest{
					CompartmentId: new(compartmentID),
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			var res []any
			for i := range clusters {
				cluster := clusters[i]

				if conn.Filters.IsFilteredOutByTags(cluster.FreeformTags, cluster.DefinedTags) {
					continue
				}

				var created *time.Time
				if cluster.Metadata != nil && cluster.Metadata.TimeCreated != nil {
					created = &cluster.Metadata.TimeCreated.Time
				}

				// Extract endpoint config
				var isPublicEndpointEnabled bool
				var securityAttributes map[string]any
				if cluster.EndpointConfig != nil {
					isPublicEndpointEnabled = boolValue(cluster.EndpointConfig.IsPublicIpEnabled)
					securityAttributes = definedTagsToAny(cluster.EndpointConfig.SecurityAttributes)
				}

				// Extract endpoints
				var publicEndpoint, privateEndpoint string
				if cluster.Endpoints != nil {
					publicEndpoint = stringValue(cluster.Endpoints.PublicEndpoint)
					privateEndpoint = stringValue(cluster.Endpoints.PrivateEndpoint)
				}

				// endpointConfig.isPublicIpEnabled only exists for clusters using
				// native VCN networking; it is absent for older clusters that
				// still serve a reachable public API endpoint. Trust an actual
				// published public endpoint over the missing flag, otherwise a
				// publicly reachable control plane reports as private.
				if publicEndpoint != "" {
					isPublicEndpointEnabled = true
				}

				// Extract image policy
				var isImagePolicyEnabled bool
				if cluster.ImagePolicyConfig != nil {
					isImagePolicyEnabled = boolValue(cluster.ImagePolicyConfig.IsPolicyEnabled)
				}

				// Extract admission controller options
				var isPodSecurityPolicyEnabled bool
				if cluster.Options != nil && cluster.Options.AdmissionControllerOptions != nil {
					isPodSecurityPolicyEnabled = boolValue(cluster.Options.AdmissionControllerOptions.IsPodSecurityPolicyEnabled)
				}

				// Available upgrades
				upgrades := make([]any, 0, len(cluster.AvailableKubernetesUpgrades))
				for _, u := range cluster.AvailableKubernetesUpgrades {
					upgrades = append(upgrades, u)
				}

				var isDashboardEnabled, isTillerEnabled bool
				var podsCidr, servicesCidr string
				var ipFamilies, serviceLbSubnetIDs []string
				var isOidcEnabled bool
				var oidcIssuerUrl, oidcClientId, oidcUsernameClaim, oidcGroupsClaim string
				var oidcSigningAlgorithms []string
				if opts := cluster.Options; opts != nil {
					if opts.AddOns != nil {
						isDashboardEnabled = boolValue(opts.AddOns.IsKubernetesDashboardEnabled)
						isTillerEnabled = boolValue(opts.AddOns.IsTillerEnabled)
					}
					if opts.KubernetesNetworkConfig != nil {
						podsCidr = stringValue(opts.KubernetesNetworkConfig.PodsCidr)
						servicesCidr = stringValue(opts.KubernetesNetworkConfig.ServicesCidr)
					}
					for _, f := range opts.IpFamilies {
						ipFamilies = append(ipFamilies, string(f))
					}
					serviceLbSubnetIDs = opts.ServiceLbSubnetIds
					if oidc := opts.OpenIdConnectTokenAuthenticationConfig; oidc != nil {
						isOidcEnabled = boolValue(oidc.IsOpenIdConnectAuthEnabled)
						oidcIssuerUrl = stringValue(oidc.IssuerUrl)
						oidcClientId = stringValue(oidc.ClientId)
						oidcUsernameClaim = stringValue(oidc.UsernameClaim)
						oidcGroupsClaim = stringValue(oidc.GroupsClaim)
						oidcSigningAlgorithms = oidc.SigningAlgorithms
					}
				}

				podNetworkTypes := okePodNetworkTypes(cluster.ClusterPodNetworkOptions)

				var endpointSubnetID string
				var endpointNsgIDs []string
				if cluster.EndpointConfig != nil {
					endpointSubnetID = stringValue(cluster.EndpointConfig.SubnetId)
					endpointNsgIDs = cluster.EndpointConfig.NsgIds
				}

				var imagePolicyKeyIDs []string
				if cluster.ImagePolicyConfig != nil {
					for _, kd := range cluster.ImagePolicyConfig.KeyDetails {
						if kd.KmsKeyId != nil {
							imagePolicyKeyIDs = append(imagePolicyKeyIDs, *kd.KmsKeyId)
						}
					}
				}

				var createdByUserID string
				var timeUpdated, timeCredentialExpiration *time.Time
				if md := cluster.Metadata; md != nil {
					createdByUserID = stringValue(md.CreatedByUserId)
					if md.TimeUpdated != nil {
						timeUpdated = &md.TimeUpdated.Time
					}
					if md.TimeCredentialExpiration != nil {
						timeCredentialExpiration = &md.TimeCredentialExpiration.Time
					}
				}

				mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.oke.cluster", stringValue(cluster.CompartmentId), map[string]*llx.RawData{
					"id":                             llx.StringDataPtr(cluster.Id),
					"name":                           llx.StringDataPtr(cluster.Name),
					"kubernetesVersion":              llx.StringDataPtr(cluster.KubernetesVersion),
					"type":                           llx.StringData(string(cluster.Type)),
					"isPublicEndpointEnabled":        llx.BoolData(isPublicEndpointEnabled),
					"publicEndpoint":                 llx.StringData(publicEndpoint),
					"privateEndpoint":                llx.StringData(privateEndpoint),
					"isImagePolicyEnabled":           llx.BoolData(isImagePolicyEnabled),
					"availableKubernetesUpgrades":    llx.ArrayData(upgrades, types.String),
					"isPodSecurityPolicyEnabled":     llx.BoolData(isPodSecurityPolicyEnabled),
					"isKubernetesDashboardEnabled":   llx.BoolData(isDashboardEnabled),
					"isTillerEnabled":                llx.BoolData(isTillerEnabled),
					"podsCidr":                       llx.StringData(podsCidr),
					"servicesCidr":                   llx.StringData(servicesCidr),
					"ipFamilies":                     llx.ArrayData(stringsToAny(ipFamilies), types.String),
					"podNetworkTypes":                llx.ArrayData(podNetworkTypes, types.String),
					"isOpenIdConnectAuthEnabled":     llx.BoolData(isOidcEnabled),
					"openIdConnectIssuerUrl":         llx.StringData(oidcIssuerUrl),
					"openIdConnectClientId":          llx.StringData(oidcClientId),
					"openIdConnectUsernameClaim":     llx.StringData(oidcUsernameClaim),
					"openIdConnectGroupsClaim":       llx.StringData(oidcGroupsClaim),
					"openIdConnectSigningAlgorithms": llx.ArrayData(stringsToAny(oidcSigningAlgorithms), types.String),
					"state":                          llx.StringData(string(cluster.LifecycleState)),
					"lifecycleDetails":               llx.StringDataPtr(cluster.LifecycleDetails),
					"timeUpdated":                    llx.TimeDataPtr(timeUpdated),
					"timeCredentialExpiration":       llx.TimeDataPtr(timeCredentialExpiration),
					"created":                        llx.TimeDataPtr(created),
					"freeformTags":                   llx.MapData(strMapToAny(cluster.FreeformTags), types.String),
					"definedTags":                    llx.MapData(definedTagsToAny(cluster.DefinedTags), types.Any),
					"securityAttributes":             llx.MapData(securityAttributes, types.Dict),
					"systemTags":                     llx.MapData(definedTagsToAny(cluster.SystemTags), types.Dict),
				})
				if err != nil {
					return nil, err
				}
				mqlCluster := mqlInstance.(*mqlOciOkeCluster)
				mqlCluster.cacheVcnID = stringValue(cluster.VcnId)
				mqlCluster.cacheRegion = region
				mqlCluster.cacheServiceLbSubnetIDs = serviceLbSubnetIDs
				mqlCluster.cacheEndpointSubnetID = endpointSubnetID
				mqlCluster.cacheEndpointNsgIDs = endpointNsgIDs
				mqlCluster.cacheImagePolicyKeyIDs = imagePolicyKeyIDs
				mqlCluster.cacheCreatedByUserID = createdByUserID
				res = append(res, mqlCluster)
			}

			return res, nil
		})
}

type mqlOciOkeClusterInternal struct {
	ociCompartmentRef
	cluster                 ociRetryLazy[*containerengine.Cluster]
	addonOptions            ociRetryLazy[map[string]containerengine.AddonOptionSummary]
	cacheVcnID              string
	cacheRegion             string
	cacheServiceLbSubnetIDs []string
	cacheEndpointSubnetID   string
	cacheEndpointNsgIDs     []string
	cacheImagePolicyKeyIDs  []string
	cacheCreatedByUserID    string
}

func (o *mqlOciOkeCluster) serviceLbSubnets() ([]any, error) {
	return resolveOciSubnets(o.MqlRuntime, stringsToAny(o.cacheServiceLbSubnetIDs))
}

func (o *mqlOciOkeCluster) endpointSubnet() (*mqlOciNetworkSubnet, error) {
	if o.cacheEndpointSubnetID == "" {
		o.EndpointSubnet.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlSubnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheEndpointSubnetID),
	})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlOciNetworkSubnet), nil
}

func (o *mqlOciOkeCluster) endpointSecurityGroups() ([]any, error) {
	return resolveOciSecurityGroups(o.MqlRuntime, stringsToAny(o.cacheEndpointNsgIDs))
}

func (o *mqlOciOkeCluster) imagePolicyKmsKeys() ([]any, error) {
	return resolveOciKmsKeys(o.MqlRuntime, stringsToAny(o.cacheImagePolicyKeyIDs))
}

func (o *mqlOciOkeCluster) createdByUser() (*mqlOciIdentityUser, error) {
	if !strings.HasPrefix(o.cacheCreatedByUserID, "ocid1.user.") {
		o.CreatedByUser.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(o.MqlRuntime, "oci.identity.user", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheCreatedByUserID),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciIdentityUser), nil
}

// openIdConnectDiscoveryEndpoint is the one cluster field this resource needs
// that ListClusters does not return. It rides the same GetCluster fetch that
// kmsKey already performs, so it costs no call the scan was not making.
func (o *mqlOciOkeCluster) openIdConnectDiscoveryEndpoint() (string, error) {
	cluster, err := o.fetchCluster()
	if err != nil {
		return "", err
	}
	return stringValue(cluster.OpenIdConnectDiscoveryEndpoint), nil
}

func (o *mqlOciOkeCluster) id() (string, error) {
	return "oci.oke.cluster/" + o.Id.Data, nil
}

// initOciOkeCluster resolves a single OKE cluster from the scan asset's
// PlatformId when policies reference `oci.oke.cluster` on a discovered
// oci-oke-cluster asset. Explicit id takes precedence.
func initOciOkeCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	idVal := ociArgString(args, "id")
	if idVal == "" {
		conn := runtime.Connection.(*connection.OciConnection)
		if conn.Conf == nil || conn.Conf.PlatformId == "" {
			return args, nil, nil
		}
		parsed, ok := parseOciObjectPlatformID(conn.Conf.PlatformId)
		if !ok || parsed.service != "oke" || parsed.objectType != "cluster" {
			return args, nil, nil
		}
		idVal = parsed.id
	}

	obj, err := CreateResource(runtime, "oci.oke", nil)
	if err != nil {
		return nil, nil, err
	}
	oke := obj.(*mqlOciOke)

	clusters := oke.GetClusters()
	if clusters.Error != nil {
		return nil, nil, clusters.Error
	}

	for _, raw := range clusters.Data {
		c := raw.(*mqlOciOkeCluster)
		if c.Id.Data == idVal {
			return args, c, nil
		}
	}

	return nil, nil, errors.New("oci.oke.cluster not found: " + idVal)
}

func (o *mqlOciOkeCluster) vcn() (*mqlOciNetworkVcn, error) {
	if o.cacheVcnID == "" || !isOcid(o.cacheVcnID) {
		o.Vcn.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVcn, err := NewResource(o.MqlRuntime, "oci.network.vcn", map[string]*llx.RawData{
		"id": llx.StringData(o.cacheVcnID),
	})
	if err != nil {
		return nil, err
	}
	return mqlVcn.(*mqlOciNetworkVcn), nil
}

func (o *mqlOciOkeCluster) fetchCluster() (*containerengine.Cluster, error) {
	return o.cluster.get(func() (*containerengine.Cluster, error) {
		conn := o.MqlRuntime.Connection.(*connection.OciConnection)

		svc, err := conn.ContainerEngineClient(o.cacheRegion)
		if err != nil {
			return nil, err
		}

		resp, err := svc.GetCluster(context.Background(), containerengine.GetClusterRequest{
			ClusterId: new(o.Id.Data),
		})
		if err != nil {
			return nil, err
		}
		return &resp.Cluster, nil
	})
}

func (o *mqlOciOkeCluster) kmsKey() (*mqlOciKmsKey, error) {
	cluster, err := o.fetchCluster()
	if err != nil {
		return nil, err
	}

	kmsKeyId := stringValue(cluster.KmsKeyId)
	if kmsKeyId == "" {
		o.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(o.MqlRuntime, "oci.kms.key", map[string]*llx.RawData{
		"id": llx.StringData(kmsKeyId),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlOciKmsKey), nil
}

func (o *mqlOciOkeCluster) nodePools() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	svc, err := conn.ContainerEngineClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	clusterId := o.Id.Data
	pools, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]containerengine.NodePoolSummary, *string, error) {
		response, err := svc.ListNodePools(ctx, containerengine.ListNodePoolsRequest{
			CompartmentId: new(o.cacheCompartmentID),
			ClusterId:     new(clusterId),
			Page:          page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(pools))
	for i := range pools {
		np := pools[i]

		nodeShapeConfig, err := convert.JsonToDict(np.NodeShapeConfig)
		if err != nil {
			return nil, err
		}

		subnetIds := []string{}
		nsgIds := []string{}
		var nodeConfigSize *int
		var isPvEncryptionInTransitEnabled bool
		var nodeKmsKeyID string
		if np.NodeConfigDetails != nil {
			for _, placement := range np.NodeConfigDetails.PlacementConfigs {
				if placement.SubnetId != nil {
					subnetIds = append(subnetIds, *placement.SubnetId)
				}
			}
			nsgIds = append(nsgIds, np.NodeConfigDetails.NsgIds...)
			nodeConfigSize = np.NodeConfigDetails.Size
			isPvEncryptionInTransitEnabled = boolValue(np.NodeConfigDetails.IsPvEncryptionInTransitEnabled)
			nodeKmsKeyID = stringValue(np.NodeConfigDetails.KmsKeyId)
		}
		if len(subnetIds) == 0 {
			subnetIds = append(subnetIds, np.SubnetIds...)
		}

		initialNodeLabels := make(map[string]any, len(np.InitialNodeLabels))
		for _, kv := range np.InitialNodeLabels {
			if kv.Key != nil {
				initialNodeLabels[*kv.Key] = stringValue(kv.Value)
			}
		}

		var evictionGraceDuration string
		var isForceDeleteAfterGraceDuration bool
		if s := np.NodeEvictionNodePoolSettings; s != nil {
			evictionGraceDuration = stringValue(s.EvictionGraceDuration)
			isForceDeleteAfterGraceDuration = boolValue(s.IsForceDeleteAfterGraceDuration)
		}

		var isNodeCyclingEnabled bool
		var cyclingMaximumUnavailable, cyclingMaximumSurge string
		if c := np.NodePoolCyclingDetails; c != nil {
			isNodeCyclingEnabled = boolValue(c.IsNodeCyclingEnabled)
			cyclingMaximumUnavailable = stringValue(c.MaximumUnavailable)
			cyclingMaximumSurge = stringValue(c.MaximumSurge)
		}

		// nodeImageName and nodeImageId are both deprecated in the SDK in favour
		// of nodeSourceDetails, and OCI leaves them empty on node pools created
		// through the modern path - which is every Terraform-provisioned pool.
		// Read the image from nodeSourceDetails so "which image do the workers
		// run" has an answer on current node pools.
		var nodeImageId string
		var bootVolumeSizeInGBs *int64
		if src, ok := np.NodeSourceDetails.(containerengine.NodeSourceViaImageDetails); ok {
			nodeImageId = stringValue(src.ImageId)
			bootVolumeSizeInGBs = src.BootVolumeSizeInGBs
		}

		mqlInstance, err := createOciResourceInCompartment(o.MqlRuntime, "oci.oke.nodePool", stringValue(np.CompartmentId), map[string]*llx.RawData{
			"id":                  llx.StringDataPtr(np.Id),
			"name":                llx.StringDataPtr(np.Name),
			"kubernetesVersion":   llx.StringDataPtr(np.KubernetesVersion),
			"nodeShape":           llx.StringDataPtr(np.NodeShape),
			"nodeShapeConfig":     llx.DictData(nodeShapeConfig),
			"bootVolumeSizeInGBs": llx.IntDataPtr(bootVolumeSizeInGBs),
			"sshPublicKey":        llx.StringDataPtr(np.SshPublicKey),
			"state":               llx.StringData(string(np.LifecycleState)),
			"lifecycleDetails":    llx.StringDataPtr(np.LifecycleDetails),
			"freeformTags":        llx.MapData(strMapToAny(np.FreeformTags), types.String),
			"definedTags":         llx.MapData(definedTagsToAny(np.DefinedTags), types.Any),
			"systemTags":          llx.MapData(definedTagsToAny(np.SystemTags), types.Dict),

			"size":                            llx.IntDataPtr(nodeConfigSize),
			"isPvEncryptionInTransitEnabled":  llx.BoolData(isPvEncryptionInTransitEnabled),
			"initialNodeLabels":               llx.MapData(initialNodeLabels, types.String),
			"evictionGraceDuration":           llx.StringData(evictionGraceDuration),
			"isForceDeleteAfterGraceDuration": llx.BoolData(isForceDeleteAfterGraceDuration),
			"isNodeCyclingEnabled":            llx.BoolData(isNodeCyclingEnabled),
			"cyclingMaximumUnavailable":       llx.StringData(cyclingMaximumUnavailable),
			"cyclingMaximumSurge":             llx.StringData(cyclingMaximumSurge),
		})
		if err != nil {
			return nil, err
		}
		mqlPool := mqlInstance.(*mqlOciOkeNodePool)
		mqlPool.cacheSubnetIDs = subnetIds
		mqlPool.cacheNsgIDs = nsgIds
		mqlPool.cacheClusterID = stringValue(np.ClusterId)
		mqlPool.cacheNodeImageID = nodeImageId
		mqlPool.cacheNodeKmsKeyID = nodeKmsKeyID
		mqlPool.cacheNodeShapeConfig = np.NodeShapeConfig
		res = append(res, mqlPool)
	}

	return res, nil
}

type mqlOciOkeNodePoolInternal struct {
	ociCompartmentRef
	cacheSubnetIDs    []string
	cacheNsgIDs       []string
	cacheClusterID    string
	cacheNodeImageID  string
	cacheNodeKmsKeyID string

	cacheNodeShapeConfig *containerengine.NodeShapeConfig
}

// nodeSizing builds the compute and memory allocated to each node in the pool.
//
// Null on a pool running a fixed shape, which carries no shape configuration
// because the shape name alone fixes the sizing.
func (o *mqlOciOkeNodePool) nodeSizing() (*mqlOciOkeNodeSizing, error) {
	shape := o.cacheNodeShapeConfig
	if shape == nil {
		o.NodeSizing.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	res, err := CreateResource(o.MqlRuntime, "oci.oke.nodeSizing", map[string]*llx.RawData{
		"__id":        llx.StringData(o.Id.Data + "/nodeShapeConfig"),
		"ocpus":       llx.FloatDataPtr(shape.Ocpus),
		"memoryInGBs": llx.FloatDataPtr(shape.MemoryInGBs),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlOciOkeNodeSizing), nil
}

func (o *mqlOciOkeNodePool) nodeKmsKey() (*mqlOciKmsKey, error) {
	return resolveOciKmsKey(o.MqlRuntime, o.cacheNodeKmsKeyID, &o.NodeKmsKey)
}

func (o *mqlOciOkeNodePool) id() (string, error) {
	return "oci.oke.nodePool/" + o.Id.Data, nil
}

func (o *mqlOciOkeNodePool) nodeImage() (*mqlOciComputeImage, error) {
	return resolveOciImage(o.MqlRuntime, o.cacheNodeImageID, &o.NodeImage)
}

func (o *mqlOciOkeNodePool) subnets() ([]any, error) {
	res := make([]any, 0, len(o.cacheSubnetIDs))
	for _, id := range o.cacheSubnetIDs {
		mqlSubnet, err := NewResource(o.MqlRuntime, "oci.network.subnet", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// Skip an element we cannot resolve rather than failing the
			// whole list and losing the ones that did resolve.
			log.Debug().Err(err).Str("subnet", id).Msg("skipping unresolvable oci reference")
			continue
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (o *mqlOciOkeNodePool) networkSecurityGroups() ([]any, error) {
	res := make([]any, 0, len(o.cacheNsgIDs))
	for _, id := range o.cacheNsgIDs {
		mqlNsg, err := NewResource(o.MqlRuntime, "oci.network.networkSecurityGroup", map[string]*llx.RawData{
			"id": llx.StringData(id),
		})
		if err != nil {
			// Skip an element we cannot resolve rather than failing the
			// whole list and losing the ones that did resolve.
			log.Debug().Err(err).Str("nsg", id).Msg("skipping unresolvable oci reference")
			continue
		}
		res = append(res, mqlNsg)
	}
	return res, nil
}
