// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/compute/v1"
	dataproc "google.golang.org/api/dataproc/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

type mqlGcpProjectDataprocServiceClusterConfigGceClusterInternal struct {
	cacheNetworkUri    string
	cacheSubnetworkUri string
}

type mqlGkeNodePoolAccelerator struct {
	AcceleratorCount int64  `json:"acceleratorCount"`
	AcceleratorType  string `json:"acceleratorType"`
	GpuPartitionSize string `json:"gpuPartitionSize"`
}
type mqlGkeNodePoolAutoscalingConfig struct {
	MaxNodeCount int64 `json:"maxNodeCount"`
	MinNodeCount int64 `json:"minNodeCount"`
}
type mqlGkeNodeConfig struct {
	Accelerators   []mqlGkeNodePoolAccelerator `json:"accelerators"`
	BootDiskKmsKey string                      `json:"bootDiskKmsKey"`
	LocalSsdCount  int64                       `json:"localSsdCount"`
	MachineType    string                      `json:"machineType"`
	MinCpuPlatform string                      `json:"minCpuPlatform"`
	Preemptible    bool                        `json:"preemptible"`
	Spot           bool                        `json:"spot"`
}
type mqlGkeNodePoolConfig struct {
	Autoscaling mqlGkeNodePoolAutoscalingConfig `json:"autoscaling"`
	Config      mqlGkeNodeConfig                `json:"config"`
	Locations   []string                        `json:"locations"`
}
type mqlGkeNodePoolTarget struct {
	NodePool       string               `json:"nodePool"`
	NodePoolConfig mqlGkeNodePoolConfig `json:"nodePoolConfig"`
	Roles          []string             `json:"roles"`
}

func (g *mqlGcpProjectDataprocService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("%s/gcp.project.dataprocService", projectId), nil
}

func (g *mqlGcpProject) dataproc() (*mqlGcpProjectDataprocService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	serviceEnabled, err := g.isServiceEnabled(service_dataproc)
	if err != nil {
		return nil, err
	}
	if !serviceEnabled {
		log.Debug().Str("service", service_dataproc).Msg("gcp service is not enabled, skipping")
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.dataprocService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"enabled":   llx.BoolData(serviceEnabled),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDataprocService), nil
}

// Direct construction (e.g. `gcp.project.dataprocService.regions`) bypasses
// gcp.project.dataproc(), leaving projectId empty so regions() calls the
// compute API with an empty project ID. Delegate to the parent project
// accessor so projectId + enabled are both populated.
func initGcpProjectDataprocService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if _, ok := args["projectId"]; ok {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	proj, err := NewResource(runtime, "gcp.project", map[string]*llx.RawData{
		"id": llx.StringData(conn.ResourceID()),
	})
	if err != nil {
		return nil, nil, err
	}
	svc, err := proj.(*mqlGcpProject).dataproc()
	if err != nil {
		return nil, nil, err
	}
	return nil, svc, nil
}

func (g *mqlGcpProjectDataprocService) regions() ([]any, error) {
	// no check whether DataProc service is enabled here, this uses a different service
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	client, err := conn.Client(dataproc.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	computeSvc, err := compute.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	regions, err := computeSvc.Regions.List(projectId).Do()
	if err != nil {
		return nil, err
	}

	regionNames := make([]any, 0, len(regions.Items))
	for _, region := range regions.Items {
		regionNames = append(regionNames, region.Name)
	}
	return regionNames, nil
}

func (g *mqlGcpProjectDataprocService) clusters() ([]any, error) {
	if g.Enabled.Error != nil {
		return nil, g.Enabled.Error
	}
	enabled := g.Enabled.Data
	if !enabled {
		return []any{}, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	regions := g.GetRegions()
	if regions.Error != nil {
		return nil, regions.Error
	}

	client, err := conn.Client(dataproc.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()

	dataprocSvc, err := dataproc.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	var mqlClusters []any
	wg.Add(len(regions.Data))
	mux := &sync.Mutex{}
	for _, region := range regions.Data {
		go func(projectId, regionName string) {
			defer wg.Done()
			err := dataprocSvc.Projects.Regions.Clusters.List(projectId, regionName).Pages(ctx, func(clusters *dataproc.ListClustersResponse) error {
				// A `:=` variable is not in scope inside its own initializer, so
				// without this declaration every `err = ...` in the closure below
				// would write the function-scope `err` that all region goroutines
				// share -- a data race, and misattributed error logs.
				var err error
				for _, c := range clusters.Clusters {
					var mqlConfig plugin.Resource
					if c.Config != nil {
						var mqlAutoscalingCfg map[string]any
						if c.Config.AutoscalingConfig != nil {
							type mqlAutoscalingConfig struct {
								PolicyUri string `json:"policyUri"`
							}
							mqlAutoscalingCfg, err = convert.JsonToDict(mqlAutoscalingConfig{PolicyUri: c.Config.AutoscalingConfig.PolicyUri})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						var mqlMetricsCfg map[string]any
						if c.Config.DataprocMetricConfig != nil {
							type mqlMetricsConfigMetric struct {
								MetricOverrides []string `json:"metricOverrides"`
								MetricSource    string   `json:"metricSource"`
							}
							type mqlMetricsConfig struct {
								Metrics []mqlMetricsConfigMetric `json:"metrics"`
							}

							mqlMetricsConfigs := make([]mqlMetricsConfigMetric, 0, len(c.Config.DataprocMetricConfig.Metrics))
							for _, m := range c.Config.DataprocMetricConfig.Metrics {
								mqlMetricsConfigs = append(mqlMetricsConfigs, mqlMetricsConfigMetric{
									MetricOverrides: m.MetricOverrides,
									MetricSource:    m.MetricSource,
								})
							}

							mqlMetricsCfg, err = convert.JsonToDict(mqlMetricsConfig{Metrics: mqlMetricsConfigs})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						var mqlEncryptionCfg map[string]any
						if c.Config.EncryptionConfig != nil {
							type mqlEncryptionConfig struct {
								GcePdKmsKeyName string `json:"gcePdKmsKeyName"`
								KmsKey          string `json:"kmsKey"`
							}
							mqlEncryptionCfg, err = convert.JsonToDict(mqlEncryptionConfig{
								GcePdKmsKeyName: c.Config.EncryptionConfig.GcePdKmsKeyName,
								KmsKey:          c.Config.EncryptionConfig.KmsKey,
							})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						var mqlEndpointCfg map[string]any
						if c.Config.EndpointConfig != nil {
							type mqlEndpointConfig struct {
								HttpPorts            map[string]string `json:"httpPorts"`
								EnableHttpPortAccess bool              `json:"enableHttpPortAccess"`
							}
							mqlEndpointCfg, err = convert.JsonToDict(mqlEndpointConfig{
								HttpPorts:            c.Config.EndpointConfig.HttpPorts,
								EnableHttpPortAccess: c.Config.EndpointConfig.EnableHttpPortAccess,
							})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						var mqlGceClusterCfg plugin.Resource
						if c.Config.GceClusterConfig != nil {
							var mqlConfidentialInstanceCfg map[string]any
							if c.Config.GceClusterConfig.ConfidentialInstanceConfig != nil {
								type mqlConfidentialInstanceConfig struct {
									EnableConfidentialCompute bool `json:"enableConfidentialCompute"`
								}
								mqlConfidentialInstanceCfg, err = convert.JsonToDict(mqlConfidentialInstanceConfig{
									EnableConfidentialCompute: c.Config.GceClusterConfig.ConfidentialInstanceConfig.EnableConfidentialCompute,
								})
								if err != nil {
									log.Error().Err(err).Send()
								}
							}

							var mqlNodeGroupAffinityCfg map[string]any
							if c.Config.GceClusterConfig.NodeGroupAffinity != nil {
								type mqlNodeGroupAffinityConfig struct {
									Uri string `json:"uri"`
								}
								mqlNodeGroupAffinityCfg, err = convert.JsonToDict(mqlNodeGroupAffinityConfig{
									Uri: c.Config.GceClusterConfig.NodeGroupAffinity.NodeGroupUri,
								})
								if err != nil {
									log.Error().Err(err).Send()
								}
							}

							var mqlReservationAffinity plugin.Resource
							if c.Config.GceClusterConfig.ReservationAffinity != nil {
								mqlReservationAffinity, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.config.gceCluster.reservationAffinity", map[string]*llx.RawData{
									"id":                     llx.StringData(fmt.Sprintf("%s/dataproc/%s/config/gceCluster/reservationAffinity", projectId, c.ClusterName)),
									"consumeReservationType": llx.StringData(c.Config.GceClusterConfig.ReservationAffinity.ConsumeReservationType),
									"key":                    llx.StringData(c.Config.GceClusterConfig.ReservationAffinity.Key),
									"values":                 llx.ArrayData(convert.SliceAnyToInterface(c.Config.GceClusterConfig.ReservationAffinity.Values), types.String),
								})
								if err != nil {
									log.Error().Err(err).Send()
								}
							}

							var mqlShieldedCfg plugin.Resource
							if c.Config.GceClusterConfig.ShieldedInstanceConfig != nil {
								mqlShieldedCfg, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.config.gceCluster.shieldedInstanceConfig", map[string]*llx.RawData{
									"id":                        llx.StringData(fmt.Sprintf("%s/dataproc/%s/config/gceCluster/shieldedInstanceConfig", projectId, c.ClusterName)),
									"enableIntegrityMonitoring": llx.BoolData(c.Config.GceClusterConfig.ShieldedInstanceConfig.EnableIntegrityMonitoring),
									"enableSecureBoot":          llx.BoolData(c.Config.GceClusterConfig.ShieldedInstanceConfig.EnableSecureBoot),
									"enableVtpm":                llx.BoolData(c.Config.GceClusterConfig.ShieldedInstanceConfig.EnableVtpm),
								})
								if err != nil {
									log.Error().Err(err).Send()
								}
							}

							mqlGceClusterCfg, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.config.gceCluster", map[string]*llx.RawData{
								"id":                      llx.StringData(fmt.Sprintf("%s/dataproc/%s/config/gceCluster", projectId, c.ClusterName)),
								"projectId":               llx.StringData(projectId),
								"confidentialInstance":    llx.DictData(mqlConfidentialInstanceCfg),
								"internalIpOnly":          llx.BoolData(c.Config.GceClusterConfig.InternalIpOnly),
								"metadata":                llx.MapData(convert.MapToInterfaceMap(c.Config.GceClusterConfig.Metadata), types.String),
								"nodeGroupAffinity":       llx.DictData(mqlNodeGroupAffinityCfg),
								"privateIpv6GoogleAccess": llx.StringData(c.Config.GceClusterConfig.PrivateIpv6GoogleAccess),
								"reservationAffinity":     llx.ResourceData(mqlReservationAffinity, "gcp.project.dataprocService.cluster.config.gceCluster.reservationAffinity"),
								"serviceAccountEmail":     llx.StringData(c.Config.GceClusterConfig.ServiceAccount),
								"serviceAccountScopes":    llx.ArrayData(convert.SliceAnyToInterface(c.Config.GceClusterConfig.ServiceAccountScopes), types.String),
								"shieldedInstanceConfig":  llx.ResourceData(mqlShieldedCfg, "gcp.project.dataprocService.cluster.config.gceCluster.shieldedInstanceConfig"),
								"tags":                    llx.ArrayData(convert.SliceAnyToInterface(c.Config.GceClusterConfig.Tags), types.String),
								"zoneUri":                 llx.StringData(c.Config.GceClusterConfig.ZoneUri),
							})
							if err != nil {
								log.Error().Err(err).Send()
							}
							mqlRef := mqlGceClusterCfg.(*mqlGcpProjectDataprocServiceClusterConfigGceCluster)
							mqlRef.cacheNetworkUri = c.Config.GceClusterConfig.NetworkUri
							mqlRef.cacheSubnetworkUri = c.Config.GceClusterConfig.SubnetworkUri
						}

						var mqlGkeClusterCfg plugin.Resource
						if c.Config.GkeClusterConfig != nil {
							mqlNodePools := make([]mqlGkeNodePoolTarget, 0, len(c.Config.GkeClusterConfig.NodePoolTarget))
							for _, npt := range c.Config.GkeClusterConfig.NodePoolTarget {
								mqlNodePools = append(mqlNodePools, nodePoolTargetToMql(npt))
							}
							nodePoolsDict, err := convert.JsonToDictSlice(mqlNodePools)
							if err != nil {
								log.Error().Err(err).Send()
							}
							mqlGkeClusterCfg, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.config.gkeCluster", map[string]*llx.RawData{
								"id":               llx.StringData(fmt.Sprintf("%s/dataproc/%s/config/gkeCluster", projectId, c.ClusterName)),
								"gkeClusterTarget": llx.StringData(c.Config.GkeClusterConfig.GkeClusterTarget),
								"nodePoolTarget":   llx.ArrayData(nodePoolsDict, types.Dict),
							})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						type mqlNodeInitializationACtion struct {
							ExecutableFile   string `json:"executableFile"`
							ExecutionTimeout string `json:"executionTimeout"`
						}
						initActions := make([]mqlNodeInitializationACtion, 0, len(c.Config.InitializationActions))
						for _, ia := range c.Config.InitializationActions {
							initActions = append(initActions, mqlNodeInitializationACtion{
								ExecutableFile:   ia.ExecutableFile,
								ExecutionTimeout: ia.ExecutionTimeout,
							})
						}

						dictInitActions, err := convert.JsonToDictSlice(initActions)
						if err != nil {
							log.Error().Err(err).Send()
						}

						var mqlLifecycleCfg plugin.Resource
						if c.Config.LifecycleConfig != nil {
							mqlLifecycleCfg, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.config.lifecycle", map[string]*llx.RawData{
								"id":             llx.StringData(fmt.Sprintf("%s/dataproc/%s/config/lifecycle", projectId, c.ClusterName)),
								"autoDeleteTime": llx.StringData(c.Config.LifecycleConfig.AutoDeleteTime),
								"autoDeleteTtl":  llx.StringData(c.Config.LifecycleConfig.AutoDeleteTtl),
								"idleDeleteTtl":  llx.StringData(c.Config.LifecycleConfig.IdleDeleteTtl),
								"idleStartTime":  llx.StringData(c.Config.LifecycleConfig.IdleStartTime),
							})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						mqlMasterCfg, err := instanceGroupConfigToMql(
							g.MqlRuntime, c.Config.MasterConfig, fmt.Sprintf("%s/dataproc/%s/config/master", projectId, c.ClusterName))
						if err != nil {
							log.Error().Err(err).Send()
						}

						type mqlMetastoreConfig struct {
							DataprocMetastoreService string `json:"dataprocMetastoreService"`
						}
						var mqlMetastoreCfg map[string]any
						if c.Config.MetastoreConfig != nil {
							mqlMetastoreCfg, err = convert.JsonToDict(mqlMetastoreConfig{
								DataprocMetastoreService: c.Config.MetastoreConfig.DataprocMetastoreService,
							})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						mqlSecondaryWorkerCfg, err := instanceGroupConfigToMql(
							g.MqlRuntime, c.Config.SecondaryWorkerConfig, fmt.Sprintf("%s/dataproc/%s/config/secondaryWorker", projectId, c.ClusterName))
						if err != nil {
							log.Error().Err(err).Send()
						}

						type mqlSecurityIdentity struct {
							UserServiceAccountMapping map[string]string `json:"userServiceAccountMapping"`
						}
						type mqlSecurityKerberos struct {
							CrossRealmTrustAdminServer       string `json:"crossRealmTrustAdminServer"`
							CrossRealmTrustKdc               string `json:"crossRealmTrustKdc"`
							CrossRealmTrustRealm             string `json:"crossRealmTrustRealm"`
							CrossRealmTrustSharedPasswordUri string `json:"crossRealmTrustSharedPasswordUri"`
							EnableKerberos                   bool   `json:"enableKerberos"`
							KdcDbKeyUri                      string `json:"kdcDbKeyUri"`
							KeyPasswordUri                   string `json:"keyPasswordUri"`
							KeystorePasswordUri              string `json:"keystorePasswordUri"`
							KeystoreUri                      string `json:"keystoreUri"`
							KmsKeyUri                        string `json:"kmsKeyUri"`
							Realm                            string `json:"realm"`
							RootPrincipalPasswordUri         string `json:"rootPrincipalPasswordUri"`
							TgtLifetimeHours                 int64  `json:"tgtLifetimeHours"`
							TruststorePasswordUri            string `json:"truststorePasswordUri"`
							TruststoreUri                    string `json:"truststoreUri"`
						}
						type mqlSecurityConfig struct {
							IdentityConfig mqlSecurityIdentity `json:"identityConfig"`
							KerberosConfig mqlSecurityKerberos `json:"kerberosConfig"`
						}
						var mqlSecurityCfg map[string]any
						if c.Config.SecurityConfig != nil {
							cfg := mqlSecurityConfig{}
							if c.Config.SecurityConfig.IdentityConfig != nil {
								cfg.IdentityConfig = mqlSecurityIdentity{
									UserServiceAccountMapping: c.Config.SecurityConfig.IdentityConfig.UserServiceAccountMapping,
								}
							}
							if c.Config.SecurityConfig.KerberosConfig != nil {
								cfg.KerberosConfig = mqlSecurityKerberos{
									CrossRealmTrustAdminServer:       c.Config.SecurityConfig.KerberosConfig.CrossRealmTrustAdminServer,
									CrossRealmTrustKdc:               c.Config.SecurityConfig.KerberosConfig.CrossRealmTrustKdc,
									CrossRealmTrustRealm:             c.Config.SecurityConfig.KerberosConfig.CrossRealmTrustRealm,
									CrossRealmTrustSharedPasswordUri: c.Config.SecurityConfig.KerberosConfig.CrossRealmTrustSharedPasswordUri,
									EnableKerberos:                   c.Config.SecurityConfig.KerberosConfig.EnableKerberos,
									KdcDbKeyUri:                      c.Config.SecurityConfig.KerberosConfig.KdcDbKeyUri,
									KeyPasswordUri:                   c.Config.SecurityConfig.KerberosConfig.KeyPasswordUri,
									KeystorePasswordUri:              c.Config.SecurityConfig.KerberosConfig.KeystorePasswordUri,
									KeystoreUri:                      c.Config.SecurityConfig.KerberosConfig.KeystoreUri,
									KmsKeyUri:                        c.Config.SecurityConfig.KerberosConfig.KmsKeyUri,
									Realm:                            c.Config.SecurityConfig.KerberosConfig.Realm,
									RootPrincipalPasswordUri:         c.Config.SecurityConfig.KerberosConfig.RootPrincipalPasswordUri,
									TgtLifetimeHours:                 c.Config.SecurityConfig.KerberosConfig.TgtLifetimeHours,
									TruststorePasswordUri:            c.Config.SecurityConfig.KerberosConfig.TruststorePasswordUri,
									TruststoreUri:                    c.Config.SecurityConfig.KerberosConfig.TruststoreUri,
								}
							}
							// Serialize the whole security config, not just the Kerberos
							// branch: a cluster with only IdentityConfig set (workforce
							// identity federation without Kerberos) must still surface its
							// security config instead of a null.
							mqlSecurityCfg, err = convert.JsonToDict(cfg)
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						type mqlSoftwareConfig struct {
							ImageVersion       string   `json:"imageVersion"`
							OptionalComponents []string `json:"optionalComponents"`
						}
						var mqlSoftwareCfg map[string]any
						if c.Config.SoftwareConfig != nil {
							mqlSoftwareCfg, err = convert.JsonToDict(mqlSoftwareConfig{
								ImageVersion:       c.Config.SoftwareConfig.ImageVersion,
								OptionalComponents: c.Config.SoftwareConfig.OptionalComponents,
							})
							if err != nil {
								log.Error().Err(err).Send()
							}
						}

						mqlWorkerCfg, err := instanceGroupConfigToMql(
							g.MqlRuntime, c.Config.WorkerConfig, fmt.Sprintf("%s/dataproc/%s/config/worker", projectId, c.ClusterName))
						if err != nil {
							log.Error().Err(err).Send()
						}

						componentGatewayEnabled := c.Config.EndpointConfig != nil && c.Config.EndpointConfig.EnableHttpPortAccess
						kerberosEnabled := c.Config.SecurityConfig != nil && c.Config.SecurityConfig.KerberosConfig != nil && c.Config.SecurityConfig.KerberosConfig.EnableKerberos
						sshEnabled := c.Config.SecurityConfig != nil && c.Config.SecurityConfig.IdentityConfig != nil && c.Config.SecurityConfig.IdentityConfig.EnableSsh
						mqlConfig, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.config", map[string]*llx.RawData{
							"parentResourcePath":      llx.StringData(fmt.Sprintf("%s/dataproc/%s", projectId, c.ClusterName)),
							"componentGatewayEnabled": llx.BoolData(componentGatewayEnabled),
							"kerberosEnabled":         llx.BoolData(kerberosEnabled),
							"sshEnabled":              llx.BoolData(sshEnabled),
							"autoscaling":             llx.DictData(mqlAutoscalingCfg),
							"configBucket":            llx.StringData(c.Config.ConfigBucket),
							"metrics":                 llx.DictData(mqlMetricsCfg),
							"encryption":              llx.DictData(mqlEncryptionCfg),
							"endpoint":                llx.DictData(mqlEndpointCfg),
							"gceCluster":              llx.ResourceData(mqlGceClusterCfg, "gcp.project.dataprocService.cluster.config.gceCluster"),
							"gkeCluster":              llx.ResourceData(mqlGkeClusterCfg, "gcp.project.dataprocService.cluster.config.gkeCluster"),
							"initializationActions":   llx.ArrayData(dictInitActions, types.Dict),
							"lifecycle":               llx.ResourceData(mqlLifecycleCfg, "gcp.project.dataprocService.cluster.config.lifecycle"),
							"master":                  llx.ResourceData(mqlMasterCfg, "gcp.project.dataprocService.cluster.config.instance"),
							"metastore":               llx.DictData(mqlMetastoreCfg),
							"secondaryWorker":         llx.ResourceData(mqlSecondaryWorkerCfg, "gcp.project.dataprocService.cluster.config.instance"),
							"security":                llx.DictData(mqlSecurityCfg),
							"software":                llx.DictData(mqlSoftwareCfg),
							"tempBucket":              llx.StringData(c.Config.TempBucket),
							"worker":                  llx.ResourceData(mqlWorkerCfg, "gcp.project.dataprocService.cluster.config.instance"),
						})
						if err != nil {
							log.Error().Err(err).Send()
						}
						if mqlConfig != nil {
							kmsKeyName := ""
							if c.Config.EncryptionConfig != nil {
								kmsKeyName = c.Config.EncryptionConfig.GcePdKmsKeyName
							}
							autoscalingPolicyUri := ""
							if c.Config.AutoscalingConfig != nil {
								autoscalingPolicyUri = c.Config.AutoscalingConfig.PolicyUri
							}
							cfg := mqlConfig.(*mqlGcpProjectDataprocServiceClusterConfig)
							cfg.cacheKmsKeyName = kmsKeyName
							cfg.cacheProjectId = projectId
							cfg.cacheAutoscalingPolicyUri = autoscalingPolicyUri
						}
					}

					var mqlMetrics map[string]any
					if c.Metrics != nil {
						type mqlClusterMetrics struct {
							HdfsMetrics map[string]string `json:"hdfsMetrics"`
							YarnMetrics map[string]string `json:"yarnMetrics"`
						}
						mqlMetrics, err = convert.JsonToDict(mqlClusterMetrics{HdfsMetrics: c.Metrics.HdfsMetrics, YarnMetrics: c.Metrics.YarnMetrics})
						if err != nil {
							log.Error().Err(err).Send()
						}
					}

					var mqlStatus plugin.Resource
					if c.Status != nil {
						mqlStatus, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.status", map[string]*llx.RawData{
							"id":       llx.StringData(fmt.Sprintf("%s/dataproc/%s/status", projectId, c.ClusterName)),
							"detail":   llx.StringData(c.Status.Detail),
							"state":    llx.StringData(c.Status.State),
							"started":  llx.TimeDataPtr(parseTime(c.Status.StateStartTime)),
							"substate": llx.StringData(c.Status.Substate),
						})
						if err != nil {
							log.Error().Err(err).Send()
						}
					}

					mqlStatusHistory := make([]any, 0, len(c.StatusHistory))
					for _, s := range c.StatusHistory {
						mqlHistoryEntry, err := CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.status", map[string]*llx.RawData{
							"id":       llx.StringData(fmt.Sprintf("%s/dataproc/%s/status/%s", projectId, c.ClusterName, s.StateStartTime)),
							"detail":   llx.StringData(s.Detail),
							"state":    llx.StringData(s.State),
							"started":  llx.TimeDataPtr(parseTime(s.StateStartTime)),
							"substate": llx.StringData(s.Substate),
						})
						if err != nil {
							log.Error().Err(err).Send()
							continue
						}
						mqlStatusHistory = append(mqlStatusHistory, mqlHistoryEntry)
					}

					var mqlVirtualClusterCfg plugin.Resource
					if c.VirtualClusterConfig != nil {
						type mqlMetastoreConfig struct {
							DataprocMetastoreService string `json:"dataprocMetastoreService"`
						}
						type mqlSparkHistoryServerConfig struct {
							DataprocCluster string `json:"dataprocCluster"`
						}
						type mqlAuxiliaryServices struct {
							MetastoreConfig          mqlMetastoreConfig          `json:"metastoreConfig"`
							SparkHistoryServerConfig mqlSparkHistoryServerConfig `json:"sparkHistoryServerConfig"`
						}

						auxSvc := mqlAuxiliaryServices{}
						if c.VirtualClusterConfig.AuxiliaryServicesConfig != nil {
							if c.VirtualClusterConfig.AuxiliaryServicesConfig.MetastoreConfig != nil {
								auxSvc.MetastoreConfig = mqlMetastoreConfig{DataprocMetastoreService: c.VirtualClusterConfig.AuxiliaryServicesConfig.MetastoreConfig.DataprocMetastoreService}
							}
							if c.VirtualClusterConfig.AuxiliaryServicesConfig.SparkHistoryServerConfig != nil {
								auxSvc.SparkHistoryServerConfig = mqlSparkHistoryServerConfig{DataprocCluster: c.VirtualClusterConfig.AuxiliaryServicesConfig.SparkHistoryServerConfig.DataprocCluster}
							}
						}
						mqlAuxServices, err := convert.JsonToDict(auxSvc)
						if err != nil {
							log.Error().Err(err).Send()
						}

						type mqlNamespacedGkeDeploymentTarget struct {
							ClusterNamespace string `json:"clusterNamespace"`
							TargetGkeCluster string `json:"targetGkeCluster"`
						}

						type mqlGkeClusterConfig struct {
							TargetCluster                 string                           `json:"targetCluster"`
							NamespacedGkeDeploymentTarget mqlNamespacedGkeDeploymentTarget `json:"namespacedGkeDeploymentTarget"`
							NodePoolTarget                []mqlGkeNodePoolTarget           `json:"nodePoolTarget"`
						}
						type mqlKubernetesSoftwareConfig struct {
							ComponentVersion map[string]string `json:"componentVersion"`
							Properties       map[string]string `json:"properties"`
						}
						type mqlKubernetesClusterConfig struct {
							GkeClusterConfig    mqlGkeClusterConfig `json:"gkeClusterConfig"`
							KubernetesNamespace string              `json:"kubernetesNamespace"`
						}

						k8sCfg := mqlKubernetesClusterConfig{}
						if c.VirtualClusterConfig.KubernetesClusterConfig != nil {
							k8sCfg.KubernetesNamespace = c.VirtualClusterConfig.KubernetesClusterConfig.KubernetesNamespace
							if c.VirtualClusterConfig.KubernetesClusterConfig.GkeClusterConfig != nil {
								gkeCfg := c.VirtualClusterConfig.KubernetesClusterConfig.GkeClusterConfig
								k8sCfg.GkeClusterConfig.TargetCluster = gkeCfg.GkeClusterTarget
								if gkeCfg.NamespacedGkeDeploymentTarget != nil {
									k8sCfg.GkeClusterConfig.NamespacedGkeDeploymentTarget = mqlNamespacedGkeDeploymentTarget{
										ClusterNamespace: gkeCfg.NamespacedGkeDeploymentTarget.ClusterNamespace,
										TargetGkeCluster: gkeCfg.NamespacedGkeDeploymentTarget.TargetGkeCluster,
									}
								}
								npTargets := make([]mqlGkeNodePoolTarget, 0, len(gkeCfg.NodePoolTarget))
								for _, npt := range gkeCfg.NodePoolTarget {
									npTargets = append(npTargets, nodePoolTargetToMql(npt))
								}
								k8sCfg.GkeClusterConfig.NodePoolTarget = npTargets
							}
						}

						mqlK8sClusterCfg, err := convert.JsonToDict(k8sCfg)
						if err != nil {
							log.Error().Err(err).Send()
						}

						mqlVirtualClusterCfg, err = CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster.virtualClusterConfig", map[string]*llx.RawData{
							"parentResourcePath": llx.StringData(fmt.Sprintf("%s/dataproc/%s", projectId, c.ClusterName)),
							"auxiliaryServices":  llx.DictData(mqlAuxServices),
							"kubernetesCluster":  llx.DictData(mqlK8sClusterCfg),
							"stagingBucket":      llx.StringData(c.VirtualClusterConfig.StagingBucket),
						})
						if err != nil {
							log.Error().Err(err).Send()
						}
					}

					mqlCluster, err := CreateResource(g.MqlRuntime, "gcp.project.dataprocService.cluster", map[string]*llx.RawData{
						"projectId":            llx.StringData(projectId),
						"location":             llx.StringData(regionName),
						"name":                 llx.StringData(c.ClusterName),
						"uuid":                 llx.StringData(c.ClusterUuid),
						"config":               llx.ResourceData(mqlConfig, "gcp.project.dataprocService.cluster.config"),
						"labels":               llx.MapData(convert.MapToInterfaceMap(c.Labels), types.String),
						"metrics":              llx.DictData(mqlMetrics),
						"status":               llx.ResourceData(mqlStatus, "gcp.project.dataprocService.cluster.status"),
						"statusHistory":        llx.ArrayData(mqlStatusHistory, types.Resource("gcp.project.dataprocService.cluster.status")),
						"virtualClusterConfig": llx.ResourceData(mqlVirtualClusterCfg, "gcp.project.dataprocService.cluster.virtualClusterConfig"),
					})
					if err != nil {
						log.Error().Err(err).Send()
					}
					mux.Lock()
					mqlClusters = append(mqlClusters, mqlCluster)
					mux.Unlock()
				}
				return nil
			})
			if err != nil {
				log.Error().Str("region", regionName).Err(err).Send()
			}
		}(projectId, region.(string))
	}
	wg.Wait()
	return mqlClusters, nil
}

func (g *mqlGcpProjectDataprocServiceClusterConfigGceCluster) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cacheNetworkUri, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectDataprocServiceClusterConfigGceCluster) subnetwork() (*mqlGcpProjectComputeServiceSubnetwork, error) {
	s, err := getSubnetworkByUrl(g.cacheSubnetworkUri, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if s == nil {
		g.Subnetwork.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return s, nil
}

func (g *mqlGcpProjectDataprocServiceClusterConfigGceCluster) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.ServiceAccountEmail.Error != nil {
		return nil, g.ServiceAccountEmail.Error
	}
	email := g.ServiceAccountEmail.Data
	if email == "" {
		g.ServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	// NewResource, not CreateResource: the service account has an init that
	// resolves the real account. CreateResource skips it, leaving a husk whose
	// id() keys on the email while a listed account keys on uniqueId, so the
	// two never share a cache entry.
	res, err := NewResource(g.MqlRuntime, "gcp.project.iamService.serviceAccount", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"email":     llx.StringData(email),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIamServiceServiceAccount), nil
}

func (g *mqlGcpProjectDataprocServiceCluster) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	name := g.Name.Data
	return fmt.Sprintf("%s/dataproc/%s", projectId, name), nil
}

func (g *mqlGcpProjectDataprocServiceCluster) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectDataprocServiceCluster) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Location.Error != nil {
		return nil, g.Location.Error
	}
	location := g.Location.Data
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dataproc.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dataprocSvc, err := dataproc.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	resource := fmt.Sprintf("projects/%s/regions/%s/clusters/%s", projectId, location, name)
	// Request policy schema v3 so conditional bindings are returned; the
	// default v1 omits any binding carrying an IAM condition.
	policy, err := dataprocSvc.Projects.Regions.Clusters.GetIamPolicy(resource, &dataproc.GetIamPolicyRequest{
		Options: &dataproc.GetPolicyOptions{RequestedPolicyVersion: 3},
	}).Do()
	if err != nil {
		if gerr, ok := err.(*googleapi.Error); ok && gerr.Code == 403 {
			log.Warn().Str("cluster", resource).Msg("not authorized to retrieve dataproc cluster iam policy")
			return nil, nil
		}
		return nil, err
	}

	return dataprocBindingsToMql(g.MqlRuntime, resource, policy.Bindings)
}

// dataprocBindingsToMql converts the dataproc REST client's IAM policy bindings
// into gcp.resourcemanager.binding resources, preserving IAM conditions. It
// mirrors iampbBindingsToMql, but for the REST *dataproc.Binding type, whose
// condition lives in a different struct than the protobuf bindings used by the
// gRPC-based accessors elsewhere in this provider. Keep the two in sync — if a
// field is added to gcp.resourcemanager.binding, update both.
func dataprocBindingsToMql(runtime *plugin.Runtime, resource string, bindings []*dataproc.Binding) ([]any, error) {
	res := make([]any, 0, len(bindings))
	for i, b := range bindings {
		conditionTitle := ""
		conditionExpression := ""
		conditionDescription := ""
		if b.Condition != nil {
			conditionTitle = b.Condition.Title
			conditionExpression = b.Condition.Expression
			conditionDescription = b.Condition.Description
		}
		mqlBinding, err := CreateResource(runtime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(resource + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(conditionTitle),
			"conditionExpression":  llx.StringData(conditionExpression),
			"conditionDescription": llx.StringData(conditionDescription),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func initGcpProjectDataprocServiceCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 3 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["location"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.dataprocService.cluster requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.dataprocService", map[string]*llx.RawData{
		"projectId": args["projectId"],
		"enabled":   llx.BoolData(true),
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectDataprocService)
	clusters := svc.GetClusters()
	if clusters.Error != nil {
		return nil, nil, clusters.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.dataprocService.cluster requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	locationVal := ""
	if args["location"] != nil {
		locationVal, _ = args["location"].Value.(string)
	}
	for _, c := range clusters.Data {
		cluster := c.(*mqlGcpProjectDataprocServiceCluster)
		if cluster.Name.Data == nameVal && (locationVal == "" || cluster.Location.Data == locationVal) {
			return args, cluster, nil
		}
	}

	return nil, nil, fmt.Errorf("dataproc cluster %q not found", nameVal)
}

type mqlGcpProjectDataprocServiceClusterConfigInternal struct {
	cacheKmsKeyName           string
	cacheProjectId            string
	cacheAutoscalingPolicyUri string
}

func (g *mqlGcpProjectDataprocServiceClusterConfig) id() (string, error) {
	if g.ParentResourcePath.Error != nil {
		return "", g.ParentResourcePath.Error
	}
	parentResource := g.ParentResourcePath.Data
	return fmt.Sprintf("%s/config", parentResource), nil
}

func (a *mqlGcpProjectDataprocServiceClusterConfig) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	return newKmsCryptoKeyRef(a.MqlRuntime, &a.KmsKey, a.cacheKmsKeyName)
}

// dataprocResourceNameFromUri normalizes a GCP resource URI to its bare
// resource name (projects/.../...), stripping any API host prefix so it
// matches the name used as a resource's cache key.
func dataprocResourceNameFromUri(uri string) string {
	if i := strings.Index(uri, "projects/"); i >= 0 {
		return uri[i:]
	}
	return uri
}

func (a *mqlGcpProjectDataprocServiceClusterConfig) autoscalingPolicyRef() (*mqlGcpProjectDataprocServiceAutoscalingPolicy, error) {
	name := dataprocResourceNameFromUri(a.cacheAutoscalingPolicyUri)
	if name == "" || a.cacheProjectId == "" {
		a.AutoscalingPolicyRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// The autoscalingPolicy resource has no init, so a NewResource by-name would
	// leave a husk (workerConfig/secondaryWorkerConfig/basicAlgorithm unset).
	// Scan the parent service's autoscalingPolicies() list and return the real,
	// fully-populated resource.
	obj, err := CreateResource(a.MqlRuntime, "gcp.project.dataprocService", map[string]*llx.RawData{
		"projectId": llx.StringData(a.cacheProjectId),
	})
	if err != nil {
		return nil, err
	}
	svc := obj.(*mqlGcpProjectDataprocService)
	policies := svc.GetAutoscalingPolicies()
	if policies.Error != nil {
		return nil, policies.Error
	}
	for _, p := range policies.Data {
		policy, ok := p.(*mqlGcpProjectDataprocServiceAutoscalingPolicy)
		if ok && policy.Name.Data == name {
			return policy, nil
		}
	}
	a.AutoscalingPolicyRef.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func dataprocBucketRef(runtime *plugin.Runtime, field *plugin.TValue[*mqlGcpProjectStorageServiceBucket], nameField plugin.TValue[string]) (*mqlGcpProjectStorageServiceBucket, error) {
	if nameField.Error != nil {
		return nil, nameField.Error
	}
	name := nameField.Data
	if name == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(runtime, "gcp.project.storageService.bucket", map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectStorageServiceBucket), nil
}

func (a *mqlGcpProjectDataprocServiceClusterConfig) configBucketRef() (*mqlGcpProjectStorageServiceBucket, error) {
	return dataprocBucketRef(a.MqlRuntime, &a.ConfigBucketRef, a.ConfigBucket)
}

func (a *mqlGcpProjectDataprocServiceClusterConfig) tempBucketRef() (*mqlGcpProjectStorageServiceBucket, error) {
	return dataprocBucketRef(a.MqlRuntime, &a.TempBucketRef, a.TempBucket)
}

func (g *mqlGcpProjectDataprocServiceClusterStatus) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectDataprocServiceClusterVirtualClusterConfig) id() (string, error) {
	if g.ParentResourcePath.Error != nil {
		return "", g.ParentResourcePath.Error
	}
	parentResource := g.ParentResourcePath.Data
	return fmt.Sprintf("%s/virtualClusterConfig", parentResource), nil
}

func (g *mqlGcpProjectDataprocServiceClusterConfigGceCluster) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectDataprocServiceClusterConfigGceClusterReservationAffinity) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectDataprocServiceClusterConfigGceClusterShieldedInstanceConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectDataprocServiceClusterConfigGkeCluster) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectDataprocServiceClusterConfigLifecycle) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectDataprocServiceClusterConfigInstance) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectDataprocServiceClusterConfigInstanceDiskConfig) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func nodePoolTargetToMql(npt *dataproc.GkeNodePoolTarget) mqlGkeNodePoolTarget {
	result := mqlGkeNodePoolTarget{
		NodePool: npt.NodePool,
		Roles:    npt.Roles,
	}
	if npt.NodePoolConfig == nil {
		return result
	}
	result.NodePoolConfig.Locations = npt.NodePoolConfig.Locations
	if npt.NodePoolConfig.Config != nil {
		cfg := npt.NodePoolConfig.Config
		accs := make([]mqlGkeNodePoolAccelerator, 0, len(cfg.Accelerators))
		for _, acc := range cfg.Accelerators {
			accs = append(accs, mqlGkeNodePoolAccelerator{
				AcceleratorCount: acc.AcceleratorCount,
				AcceleratorType:  acc.AcceleratorType,
				GpuPartitionSize: acc.GpuPartitionSize,
			})
		}
		result.NodePoolConfig.Config = mqlGkeNodeConfig{
			Accelerators:   accs,
			BootDiskKmsKey: cfg.BootDiskKmsKey,
			LocalSsdCount:  cfg.LocalSsdCount,
			MachineType:    cfg.MachineType,
			MinCpuPlatform: cfg.MinCpuPlatform,
			Preemptible:    cfg.Preemptible,
			Spot:           cfg.Spot,
		}
	}
	if npt.NodePoolConfig.Autoscaling != nil {
		result.NodePoolConfig.Autoscaling = mqlGkeNodePoolAutoscalingConfig{
			MaxNodeCount: npt.NodePoolConfig.Autoscaling.MaxNodeCount,
			MinNodeCount: npt.NodePoolConfig.Autoscaling.MinNodeCount,
		}
	}
	return result
}

func instanceGroupConfigToMql(runtime *plugin.Runtime, igc *dataproc.InstanceGroupConfig, id string) (plugin.Resource, error) {
	if igc == nil {
		return nil, nil
	}
	type mqlAccelerator struct {
		AcceleratorCount   int64  `json:"acceleratorCount"`
		AcceleratorTypeUri string `json:"acceleratorTypeUri"`
	}
	accs := make([]mqlAccelerator, 0, len(igc.Accelerators))
	for _, acc := range igc.Accelerators {
		accs = append(accs, mqlAccelerator{
			AcceleratorCount:   acc.AcceleratorCount,
			AcceleratorTypeUri: acc.AcceleratorTypeUri,
		})
	}
	mqlAccs, err := convert.JsonToDictSlice(accs)
	if err != nil {
		return nil, err
	}

	var mqlDiskCfg plugin.Resource
	if igc.DiskConfig != nil {
		mqlDiskCfg, err = CreateResource(runtime, "gcp.project.dataprocService.cluster.config.instance.diskConfig", map[string]*llx.RawData{
			"id":                llx.StringData(fmt.Sprintf("%s/diskConfig", id)),
			"bootDiskSizeGb":    llx.IntData(igc.DiskConfig.BootDiskSizeGb),
			"bootDiskType":      llx.StringData(igc.DiskConfig.BootDiskType),
			"localSsdInterface": llx.StringData(igc.DiskConfig.LocalSsdInterface),
			"numLocalSsds":      llx.IntData(igc.DiskConfig.NumLocalSsds),
		})
		if err != nil {
			return nil, err
		}
	}

	type mqlInstanceReference struct {
		InstanceId     string `json:"instanceId"`
		InstanceName   string `json:"instanceName"`
		PublicEciesKey string `json:"publicEciesKey"`
		PublicKey      string `json:"publicKey"`
	}
	instanceReferences := make([]mqlInstanceReference, 0, len(igc.InstanceReferences))
	for _, ref := range igc.InstanceReferences {
		instanceReferences = append(instanceReferences, mqlInstanceReference{
			InstanceId:     ref.InstanceId,
			InstanceName:   ref.InstanceName,
			PublicEciesKey: ref.PublicEciesKey,
			PublicKey:      ref.PublicKey,
		})
	}
	mqlInstanceRefs, err := convert.JsonToDictSlice(instanceReferences)
	if err != nil {
		return nil, err
	}

	type mqlManagedGroupConfig struct {
		InstanceGroupManagerName string `json:"instanceGroupManagerName"`
		InstanceTemplateName     string `json:"instanceTemplateName"`
	}
	var mqlManagerGroupCfg map[string]any
	if igc.ManagedGroupConfig != nil {
		mqlManagerGroupCfg, err = convert.JsonToDict(mqlManagedGroupConfig{
			InstanceGroupManagerName: igc.ManagedGroupConfig.InstanceGroupManagerName,
			InstanceTemplateName:     igc.ManagedGroupConfig.InstanceTemplateName,
		})
		if err != nil {
			return nil, err
		}
	}

	return CreateResource(runtime, "gcp.project.dataprocService.cluster.config.instance", map[string]*llx.RawData{
		"id":                 llx.StringData(id),
		"accelerators":       llx.ArrayData(mqlAccs, types.Dict),
		"diskConfig":         llx.ResourceData(mqlDiskCfg, "gcp.project.dataprocService.cluster.config.instance.diskConfig"),
		"imageUri":           llx.StringData(igc.ImageUri),
		"instanceNames":      llx.ArrayData(convert.SliceAnyToInterface(igc.InstanceNames), types.String),
		"instanceReferences": llx.ArrayData(mqlInstanceRefs, types.Dict),
		"isPreemptible":      llx.BoolData(igc.IsPreemptible),
		"machineTypeUri":     llx.StringData(igc.MachineTypeUri),
		"managedGroupConfig": llx.DictData(mqlManagerGroupCfg),
		"minCpuPlatform":     llx.StringData(igc.MinCpuPlatform),
		"numInstances":       llx.IntData(igc.NumInstances),
		"preemptibility":     llx.StringData(igc.Preemptibility),
	})
}

func (g *mqlGcpProjectDataprocService) jobs() ([]any, error) {
	if g.Enabled.Error != nil {
		return nil, g.Enabled.Error
	}
	if !g.Enabled.Data {
		return []any{}, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	regions := g.GetRegions()
	if regions.Error != nil {
		return nil, regions.Error
	}

	client, err := conn.Client(dataproc.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dataprocSvc, err := dataproc.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	var mqlJobs []any
	wg.Add(len(regions.Data))
	mux := &sync.Mutex{}
	for _, region := range regions.Data {
		go func(projectId, regionName string) {
			defer wg.Done()
			err := dataprocSvc.Projects.Regions.Jobs.List(projectId, regionName).Pages(ctx, func(resp *dataproc.ListJobsResponse) error {
				for _, job := range resp.Jobs {
					jobId := ""
					if job.Reference != nil {
						jobId = job.Reference.JobId
					}

					status := ""
					statusDetail := ""
					if job.Status != nil {
						status = job.Status.State
						statusDetail = job.Status.Details
					}

					clusterName := ""
					clusterUuid := ""
					if job.Placement != nil {
						clusterName = job.Placement.ClusterName
						clusterUuid = job.Placement.ClusterUuid
					}

					var stateStartTime *time.Time
					if job.Status != nil {
						stateStartTime = parseTime(job.Status.StateStartTime)
					}

					statusHistory := make([]any, 0, len(job.StatusHistory))
					for _, s := range job.StatusHistory {
						entry, err := convert.JsonToDict(struct {
							State          string `json:"state"`
							Details        string `json:"details"`
							Substate       string `json:"substate"`
							StateStartTime string `json:"stateStartTime"`
						}{
							State:          s.State,
							Details:        s.Details,
							Substate:       s.Substate,
							StateStartTime: s.StateStartTime,
						})
						if err != nil {
							log.Error().Err(err).Send()
							continue
						}
						statusHistory = append(statusHistory, entry)
					}

					jobType := determineDataprocJobType(job)

					mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.dataprocService.job", map[string]*llx.RawData{
						"projectId":               llx.StringData(projectId),
						"name":                    llx.StringData(fmt.Sprintf("projects/%s/regions/%s/jobs/%s", projectId, regionName, jobId)),
						"jobUuid":                 llx.StringData(job.JobUuid),
						"status":                  llx.StringData(status),
						"statusDetail":            llx.StringData(statusDetail),
						"jobType":                 llx.StringData(jobType),
						"clusterName":             llx.StringData(clusterName),
						"clusterUuid":             llx.StringData(clusterUuid),
						"labels":                  llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
						"done":                    llx.BoolData(job.Done),
						"driverOutputResourceUri": llx.StringData(job.DriverOutputResourceUri),
						"stateStartTime":          llx.TimeDataPtr(stateStartTime),
						"statusHistory":           llx.ArrayData(statusHistory, types.Dict),
					})
					if err != nil {
						log.Error().Err(err).Send()
						continue
					}
					mux.Lock()
					mqlJobs = append(mqlJobs, mqlJob)
					mux.Unlock()
				}
				return nil
			})
			if err != nil {
				log.Error().Str("region", regionName).Err(err).Send()
			}
		}(projectId, region.(string))
	}
	wg.Wait()
	return mqlJobs, nil
}

func (g *mqlGcpProjectDataprocServiceJob) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.JobUuid.Error != nil {
		return "", g.JobUuid.Error
	}
	return fmt.Sprintf("gcp.project/%s/dataprocService.job/%s", g.ProjectId.Data, g.JobUuid.Data), nil
}

func (g *mqlGcpProjectDataprocServiceJob) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

func (g *mqlGcpProjectDataprocServiceJob) cluster() (*mqlGcpProjectDataprocServiceCluster, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.ClusterName.Error != nil {
		return nil, g.ClusterName.Error
	}
	name := g.ClusterName.Data
	if name == "" {
		g.Cluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.dataprocService.cluster", map[string]*llx.RawData{
		"projectId": llx.StringData(g.ProjectId.Data),
		"name":      llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDataprocServiceCluster), nil
}

func determineDataprocJobType(job *dataproc.Job) string {
	switch {
	case job.HadoopJob != nil:
		return "hadoop"
	case job.SparkJob != nil:
		return "spark"
	case job.PysparkJob != nil:
		return "pyspark"
	case job.HiveJob != nil:
		return "hive"
	case job.PigJob != nil:
		return "pig"
	case job.SparkRJob != nil:
		return "sparkR"
	case job.SparkSqlJob != nil:
		return "sparkSql"
	case job.PrestoJob != nil:
		return "presto"
	case job.FlinkJob != nil:
		return "flink"
	case job.TrinoJob != nil:
		return "trino"
	default:
		return "unknown"
	}
}

func (g *mqlGcpProjectDataprocService) autoscalingPolicies() ([]any, error) {
	if g.Enabled.Error != nil {
		return nil, g.Enabled.Error
	}
	if !g.Enabled.Data {
		return []any{}, nil
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	regions := g.GetRegions()
	if regions.Error != nil {
		return nil, regions.Error
	}

	client, err := conn.Client(dataproc.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dataprocSvc, err := dataproc.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	var mqlPolicies []any
	wg.Add(len(regions.Data))
	mux := &sync.Mutex{}
	for _, region := range regions.Data {
		go func(projectId, regionName string) {
			defer wg.Done()
			parent := fmt.Sprintf("projects/%s/regions/%s", projectId, regionName)
			err := dataprocSvc.Projects.Regions.AutoscalingPolicies.List(parent).Pages(ctx, func(resp *dataproc.ListAutoscalingPoliciesResponse) error {
				for _, policy := range resp.Policies {
					workerConfig, err := convert.JsonToDict(policy.WorkerConfig)
					if err != nil {
						log.Error().Err(err).Send()
						continue
					}

					secondaryWorkerConfig, err := convert.JsonToDict(policy.SecondaryWorkerConfig)
					if err != nil {
						log.Error().Err(err).Send()
						continue
					}

					basicAlgorithm, err := convert.JsonToDict(policy.BasicAlgorithm)
					if err != nil {
						log.Error().Err(err).Send()
						continue
					}

					mqlPolicy, err := CreateResource(g.MqlRuntime, "gcp.project.dataprocService.autoscalingPolicy", map[string]*llx.RawData{
						"projectId":             llx.StringData(projectId),
						"name":                  llx.StringData(policy.Name),
						"workerConfig":          llx.DictData(workerConfig),
						"secondaryWorkerConfig": llx.DictData(secondaryWorkerConfig),
						"basicAlgorithm":        llx.DictData(basicAlgorithm),
						"labels":                llx.MapData(convert.MapToInterfaceMap(policy.Labels), types.String),
					})
					if err != nil {
						log.Error().Err(err).Send()
						continue
					}
					mux.Lock()
					mqlPolicies = append(mqlPolicies, mqlPolicy)
					mux.Unlock()
				}
				return nil
			})
			if err != nil {
				log.Error().Str("region", regionName).Err(err).Send()
			}
		}(projectId, region.(string))
	}
	wg.Wait()
	return mqlPolicies, nil
}

func (g *mqlGcpProjectDataprocServiceAutoscalingPolicy) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/dataprocService.autoscalingPolicy/%s", g.ProjectId.Data, g.Name.Data), nil
}
