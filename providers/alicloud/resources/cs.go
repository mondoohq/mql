// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	csclient "github.com/alibabacloud-go/cs-20151215/v8/client"
	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/rs/zerolog/log"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/alicloud/connection"
	"go.mondoo.com/mql/types"
)

// csMasterURL is the shape of the JSON-encoded MasterUrl field on an ACK
// cluster. A non-empty api_server_endpoint means the API server has a public
// (internet) endpoint.
type csMasterURL struct {
	APIServerEndpoint         string `json:"api_server_endpoint"`
	IntranetAPIServerEndpoint string `json:"intranet_api_server_endpoint"`
}

// parseCsMasterURL extracts the public and intranet API server endpoints from
// the cluster's MasterUrl JSON string, returning empties when it is absent or
// unparseable (for example on an initializing cluster).
func parseCsMasterURL(s *string) (public, intranet string) {
	if s == nil || *s == "" {
		return "", ""
	}
	var m csMasterURL
	if err := json.Unmarshal([]byte(*s), &m); err != nil {
		return "", ""
	}
	return m.APIServerEndpoint, m.IntranetAPIServerEndpoint
}

func (r *mqlAlicloudCs) id() (string, error) {
	return "alicloud.cs", nil
}

func (r *mqlAlicloudCs) clusters() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	regions, err := conn.GetRegions()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for _, region := range regions {
		client, err := conn.CsClient(region)
		if err != nil {
			return nil, err
		}

		pageNumber := int64(1)
		pageSize := int64(50)
		for {
			resp, err := client.DescribeClustersV1(&csclient.DescribeClustersV1Request{
				RegionId:   tea.String(region),
				PageNumber: tea.Int64(pageNumber),
				PageSize:   tea.Int64(pageSize),
			})
			if err != nil {
				// A region may not have ACK enabled or the credential may lack
				// access there; skip it rather than failing the whole scan. Log
				// so a transient failure leaves a trace instead of silently
				// omitting a region's clusters.
				log.Warn().Err(err).Str("region", region).Msg("alicloud: failed to list ACK clusters")
				break
			}
			if resp == nil || resp.Body == nil {
				break
			}

			items := resp.Body.Clusters
			for _, c := range items {
				if c == nil || c.ClusterId == nil {
					continue
				}
				mqlCluster, err := newCsCluster(r.MqlRuntime, region, c)
				if err != nil {
					return nil, err
				}
				if filteredOutByTags(conn, mqlCluster.Tags.Data) {
					continue
				}
				res = append(res, mqlCluster)
			}

			if len(items) < int(pageSize) {
				break
			}
			pageNumber++
		}
	}
	return res, nil
}

// mqlAlicloudCsClusterInternal caches the identifiers for the typed
// cross-references and memoizes the two per-cluster detail calls.
type mqlAlicloudCsClusterInternal struct {
	region               string
	clusterId            string
	cacheVpcId           string
	cacheVswitchIds      []string
	cacheSecurityGroupId string
	cacheWorkerRamRole   string

	detailLock    sync.Mutex
	detailFetched atomic.Bool
	detail        *csclient.DescribeClusterDetailResponseBody

	logLock    sync.Mutex
	logFetched atomic.Bool
	logBody    *csclient.CheckControlPlaneLogEnableResponseBody

	auditLock    sync.Mutex
	auditFetched atomic.Bool
	auditBody    *csclient.GetClusterAuditProjectResponseBody
}

// newCsCluster builds a fully populated alicloud.cs.cluster from a
// DescribeClustersV1 item. It is shared by the clusters list accessor and the
// by-id init so both produce identical resources.
func newCsCluster(runtime *plugin.Runtime, region string, c *csclient.DescribeClustersV1ResponseBodyClusters) (*mqlAlicloudCsCluster, error) {
	if v := tea.StringValue(c.RegionId); v != "" {
		region = v
	}
	clusterID := tea.StringValue(c.ClusterId)

	public, intranet := parseCsMasterURL(c.MasterUrl)

	vswitchIds := strPtrsToStrings(c.VswitchIds)
	if len(vswitchIds) == 0 && tea.StringValue(c.VswitchId) != "" {
		for _, v := range strings.Split(*c.VswitchId, ",") {
			if v = strings.TrimSpace(v); v != "" {
				vswitchIds = append(vswitchIds, v)
			}
		}
	}

	tags := map[string]any{}
	for _, t := range c.Tags {
		if t == nil || t.Key == nil {
			continue
		}
		tags[*t.Key] = tea.StringValue(t.Value)
	}

	var maintenanceWindow any
	if c.MaintenanceWindow != nil {
		maintenanceWindow = map[string]any{
			"enable":          tea.BoolValue(c.MaintenanceWindow.Enable),
			"duration":        tea.StringValue(c.MaintenanceWindow.Duration),
			"maintenanceTime": tea.StringValue(c.MaintenanceWindow.MaintenanceTime),
			"recurrence":      tea.StringValue(c.MaintenanceWindow.Recurrence),
			"weeklyPeriod":    tea.StringValue(c.MaintenanceWindow.WeeklyPeriod),
		}
	}

	resource, err := CreateResource(runtime, "alicloud.cs.cluster", map[string]*llx.RawData{
		"__id":                      llx.StringData(region + "/" + clusterID),
		"regionId":                  llx.StringData(region),
		"clusterId":                 llx.StringData(clusterID),
		"name":                      llx.StringDataPtr(c.Name),
		"clusterType":               llx.StringDataPtr(c.ClusterType),
		"profile":                   llx.StringDataPtr(c.Profile),
		"clusterSpec":               llx.StringDataPtr(c.ClusterSpec),
		"state":                     llx.StringDataPtr(c.State),
		"currentVersion":            llx.StringDataPtr(c.CurrentVersion),
		"initVersion":               llx.StringDataPtr(c.InitVersion),
		"nextVersion":               llx.StringDataPtr(c.NextVersion),
		"containerCidr":             llx.StringDataPtr(c.ContainerCidr),
		"serviceCidr":               llx.StringDataPtr(c.ServiceCidr),
		"subnetCidr":                llx.StringDataPtr(c.SubnetCidr),
		"ipStack":                   llx.StringDataPtr(c.IpStack),
		"proxyMode":                 llx.StringDataPtr(c.ProxyMode),
		"networkMode":               llx.StringDataPtr(c.NetworkMode),
		"clusterDomain":             llx.StringDataPtr(c.ClusterDomain),
		"privateZone":               llx.BoolDataPtr(c.PrivateZone),
		"deletionProtection":        llx.BoolDataPtr(c.DeletionProtection),
		"size":                      llx.IntData(tea.Int64Value(c.Size)),
		"resourceGroupId":           llx.StringDataPtr(c.ResourceGroupId),
		"zoneId":                    llx.StringDataPtr(c.ZoneId),
		"timezone":                  llx.StringDataPtr(c.Timezone),
		"apiServerPublicEndpoint":   llx.StringData(public),
		"apiServerIntranetEndpoint": llx.StringData(intranet),
		"apiServerInternetExposed":  llx.BoolData(public != ""),
		"created":                   llx.TimeDataPtr(alicloudParseTime(c.Created)),
		"updated":                   llx.TimeDataPtr(alicloudParseTime(c.Updated)),
		"tags":                      llx.MapData(tags, types.String),
		"maintenanceWindow":         llx.DictData(maintenanceWindow),
	})
	if err != nil {
		return nil, err
	}
	mqlCluster := resource.(*mqlAlicloudCsCluster)
	mqlCluster.region = region
	mqlCluster.clusterId = clusterID
	mqlCluster.cacheVpcId = tea.StringValue(c.VpcId)
	mqlCluster.cacheVswitchIds = vswitchIds
	mqlCluster.cacheSecurityGroupId = tea.StringValue(c.SecurityGroupId)
	mqlCluster.cacheWorkerRamRole = tea.StringValue(c.WorkerRamRoleName)
	return mqlCluster, nil
}

// initAlicloudCsCluster resolves an ACK cluster by its id within a region,
// reusing an already-listed cluster from the resource cache and otherwise
// fetching it via DescribeClustersV1 filtered by cluster id.
func initAlicloudCsCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	args = scopedInitArgs(runtime, args, connection.OptionClusterID, "clusterId")

	clusterID, err := requiredStringArg(args, "clusterId", "alicloud.cs.cluster")
	if err != nil {
		return nil, nil, err
	}
	region, err := requiredStringArg(args, "regionId", "alicloud.cs.cluster")
	if err != nil {
		return nil, nil, err
	}

	if x, ok := runtime.Resources.Get("alicloud.cs.cluster\x00" + region + "/" + clusterID); ok {
		return nil, x, nil
	}

	conn := runtime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CsClient(region)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.DescribeClustersV1(&csclient.DescribeClustersV1Request{
		RegionId:  tea.String(region),
		ClusterId: tea.String(clusterID),
	})
	if err != nil {
		return nil, nil, err
	}
	if resp != nil && resp.Body != nil {
		for _, c := range resp.Body.Clusters {
			if c == nil || c.ClusterId == nil || *c.ClusterId != clusterID {
				continue
			}
			res, err := newCsCluster(runtime, region, c)
			if err != nil {
				return nil, nil, err
			}
			return nil, res, nil
		}
	}
	return nil, nil, fmt.Errorf("alicloud.cs.cluster %q not found in region %q", clusterID, region)
}

func (r *mqlAlicloudCsCluster) id() (string, error) {
	// Read the public fields (populated by SetAllData on every path) rather
	// than the Internal cache fields, which are unset when the resource is
	// built from args on the init fast-path — leaving __id "/" and colliding.
	return r.RegionId.Data + "/" + r.ClusterId.Data, nil
}

// clusterDetail lazily fetches and caches DescribeClusterDetail, which carries
// the RRSA workload-identity config. A transient error is not cached and is
// returned so dependent fields surface the failure.
func (r *mqlAlicloudCsCluster) clusterDetail() (*csclient.DescribeClusterDetailResponseBody, error) {
	if r.detailFetched.Load() {
		return r.detail, nil
	}
	r.detailLock.Lock()
	defer r.detailLock.Unlock()
	if r.detailFetched.Load() {
		return r.detail, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeClusterDetail(tea.String(r.clusterId))
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.detail = resp.Body
	}
	r.detailFetched.Store(true)
	return r.detail, nil
}

// controlPlaneLog lazily fetches and caches CheckControlPlaneLogEnable, the
// audit-logging signal. A transient error is not cached and is returned.
func (r *mqlAlicloudCsCluster) controlPlaneLog() (*csclient.CheckControlPlaneLogEnableResponseBody, error) {
	if r.logFetched.Load() {
		return r.logBody, nil
	}
	r.logLock.Lock()
	defer r.logLock.Unlock()
	if r.logFetched.Load() {
		return r.logBody, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.CheckControlPlaneLogEnable(tea.String(r.clusterId))
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.logBody = resp.Body
	}
	r.logFetched.Store(true)
	return r.logBody, nil
}

func (r *mqlAlicloudCsCluster) rrsaEnabled() (bool, error) {
	d, err := r.clusterDetail()
	if err != nil || d == nil || d.RrsaConfig == nil {
		return false, err
	}
	return tea.BoolValue(d.RrsaConfig.Enabled), nil
}

func (r *mqlAlicloudCsCluster) oidcIssuerUrl() (string, error) {
	d, err := r.clusterDetail()
	if err != nil || d == nil || d.RrsaConfig == nil {
		return "", err
	}
	return tea.StringValue(d.RrsaConfig.Issuer), nil
}

// clusterAuditProject lazily fetches and caches GetClusterAuditProject, the
// cluster auditing configuration that carries the API server audit setting. A
// transient error is not cached and is returned.
func (r *mqlAlicloudCsCluster) clusterAuditProject() (*csclient.GetClusterAuditProjectResponseBody, error) {
	if r.auditFetched.Load() {
		return r.auditBody, nil
	}
	r.auditLock.Lock()
	defer r.auditLock.Unlock()
	if r.auditFetched.Load() {
		return r.auditBody, nil
	}

	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetClusterAuditProject(tea.String(r.clusterId))
	if err != nil {
		return nil, err
	}
	if resp != nil {
		r.auditBody = resp.Body
	}
	r.auditFetched.Store(true)
	return r.auditBody, nil
}

// csControlPlaneLogComponentEnabled reports whether the control plane log
// configuration collects the named component. CheckControlPlaneLogEnable lists
// only the components it collects, so an absent response and an empty list both
// mean the component is not collected.
func csControlPlaneLogComponentEnabled(body *csclient.CheckControlPlaneLogEnableResponseBody, component string) bool {
	if body == nil {
		return false
	}
	for _, c := range body.Components {
		if strings.EqualFold(strings.TrimSpace(tea.StringValue(c)), component) {
			return true
		}
	}
	return false
}

// csClusterAuditEnabled reads the API server audit setting out of the cluster
// auditing configuration. The second return value is false when the
// configuration does not carry the setting, which is a null field rather than a
// measured false.
func csClusterAuditEnabled(body *csclient.GetClusterAuditProjectResponseBody) (bool, bool) {
	if body == nil || body.AuditEnabled == nil {
		return false, false
	}
	return *body.AuditEnabled, true
}

// csClusterAuditProjectName reads the Log Service project holding the API
// server audit logs, empty when cluster auditing is not configured.
func csClusterAuditProjectName(body *csclient.GetClusterAuditProjectResponseBody) string {
	if body == nil {
		return ""
	}
	return strings.TrimSpace(tea.StringValue(body.SlsProjectName))
}

func (r *mqlAlicloudCsCluster) auditLogEnabled() (bool, error) {
	lb, err := r.controlPlaneLog()
	if err != nil {
		return false, err
	}
	return csControlPlaneLogComponentEnabled(lb, "audit"), nil
}

// apiServerAuditEnabled reports the cluster auditing setting. A configuration
// that does not carry the setting resolves to null: not knowing whether audit
// logs are collected is not the same as knowing they are not.
func (r *mqlAlicloudCsCluster) apiServerAuditEnabled() (bool, error) {
	ab, err := r.clusterAuditProject()
	if err != nil {
		return false, err
	}
	enabled, known := csClusterAuditEnabled(ab)
	if !known {
		r.ApiServerAuditEnabled.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return enabled, nil
}

func (r *mqlAlicloudCsCluster) apiServerAuditLogProject() (*mqlAlicloudLogProject, error) {
	ab, err := r.clusterAuditProject()
	if err != nil {
		return nil, err
	}
	project := csClusterAuditProjectName(ab)
	if project == "" {
		r.ApiServerAuditLogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveLogProject(r.MqlRuntime, r.region, project)
}

func (r *mqlAlicloudCsCluster) controlPlaneLogComponents() ([]any, error) {
	lb, err := r.controlPlaneLog()
	if err != nil || lb == nil {
		return []any{}, err
	}
	return strPtrsToAny(lb.Components), nil
}

func (r *mqlAlicloudCsCluster) controlPlaneLogTtl() (int64, error) {
	lb, err := r.controlPlaneLog()
	if err != nil || lb == nil {
		return 0, err
	}
	ttl, convErr := strconv.Atoi(strings.TrimSpace(tea.StringValue(lb.LogTtl)))
	if convErr != nil {
		return 0, nil
	}
	return int64(ttl), nil
}

func (r *mqlAlicloudCsCluster) controlPlaneLogProject() (*mqlAlicloudLogProject, error) {
	lb, err := r.controlPlaneLog()
	if err != nil {
		return nil, err
	}
	project := ""
	if lb != nil {
		project = tea.StringValue(lb.LogProject)
	}
	if project == "" {
		r.ControlPlaneLogProject.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveLogProject(r.MqlRuntime, r.region, project)
}

func (r *mqlAlicloudCsCluster) vpc() (*mqlAlicloudVpcNetwork, error) {
	if r.cacheVpcId == "" {
		r.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveVpcNetwork(r.MqlRuntime, r.region, r.cacheVpcId)
}

func (r *mqlAlicloudCsCluster) vswitches() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheVswitchIds {
		vsw, err := resolveVpcVswitch(r.MqlRuntime, r.region, id)
		if err != nil {
			return nil, err
		}
		if vsw != nil {
			res = append(res, vsw)
		}
	}
	return res, nil
}

func (r *mqlAlicloudCsCluster) securityGroup() (*mqlAlicloudEcsSecuritygroup, error) {
	if r.cacheSecurityGroupId == "" {
		r.SecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveEcsSecuritygroup(r.MqlRuntime, r.region, r.cacheSecurityGroupId)
}

func (r *mqlAlicloudCsCluster) workerRamRole() (*mqlAlicloudRamRole, error) {
	if r.cacheWorkerRamRole == "" {
		r.WorkerRamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRamRole(r.MqlRuntime, r.cacheWorkerRamRole)
}

func (r *mqlAlicloudCsCluster) addons() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.ListClusterAddonInstances(tea.String(r.clusterId))
	if err != nil || resp == nil || resp.Body == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, a := range resp.Body.Addons {
		if a == nil || a.Name == nil {
			continue
		}
		res = append(res, map[string]any{
			"name":    tea.StringValue(a.Name),
			"version": tea.StringValue(a.Version),
			"state":   tea.StringValue(a.State),
		})
	}
	return res, nil
}

func (r *mqlAlicloudCsCluster) nodePools() ([]any, error) {
	conn := r.MqlRuntime.Connection.(*connection.AlicloudConnection)
	client, err := conn.CsClient(r.region)
	if err != nil {
		return nil, err
	}
	resp, err := client.DescribeClusterNodePools(tea.String(r.clusterId), &csclient.DescribeClusterNodePoolsRequest{})
	if err != nil || resp == nil || resp.Body == nil {
		return []any{}, nil
	}

	res := []any{}
	for _, np := range resp.Body.Nodepools {
		if np == nil || np.NodepoolInfo == nil || np.NodepoolInfo.NodepoolId == nil {
			continue
		}
		mqlNp, err := newCsNodePool(r.MqlRuntime, r.region, r.clusterId, np)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNp)
	}
	return res, nil
}

// mqlAlicloudCsNodePoolInternal caches the identifiers for the node pool's typed
// cross-references.
type mqlAlicloudCsNodePoolInternal struct {
	region                  string
	cacheSystemDiskKmsKeyId string
	cacheSecurityGroupIds   []string
	cacheVswitchIds         []string
	cacheRamRoleName        string
}

// newCsNodePool builds a fully populated alicloud.cs.nodePool from a
// DescribeClusterNodePools item, flattening the nested config groups.
func newCsNodePool(runtime *plugin.Runtime, region, clusterID string, np *csclient.DescribeClusterNodePoolsResponseBodyNodepools) (*mqlAlicloudCsNodePool, error) {
	info := np.NodepoolInfo
	nodePoolID := tea.StringValue(info.NodepoolId)

	// scaling group (nil-safe accessors)
	sg := np.ScalingGroup
	instanceTypes := []any{}
	systemDiskCategory, systemDiskEncryptAlgorithm, keyPair := "", "", ""
	imageID, imageType, instanceChargeType, multiAzPolicy, spotStrategy := "", "", "", "", ""
	var systemDiskSize, desiredSize, internetMaxBandwidthOut int64
	systemDiskEncrypted, securityHardeningOs, socEnabled, cisEnabled := false, false, false, false
	securityGroupIds := []string{}
	vswitchIds := []string{}
	ramRoleName, systemDiskKmsKeyId := "", ""
	dataDisks := []any{}
	npTags := map[string]any{}
	if sg != nil {
		instanceTypes = strPtrsToAny(sg.InstanceTypes)
		systemDiskCategory = tea.StringValue(sg.SystemDiskCategory)
		systemDiskSize = tea.Int64Value(sg.SystemDiskSize)
		systemDiskEncrypted = tea.BoolValue(sg.SystemDiskEncrypted)
		systemDiskEncryptAlgorithm = tea.StringValue(sg.SystemDiskEncryptAlgorithm)
		systemDiskKmsKeyId = tea.StringValue(sg.SystemDiskKmsKeyId)
		keyPair = tea.StringValue(sg.KeyPair)
		ramRoleName = tea.StringValue(sg.RamRoleName)
		imageID = tea.StringValue(sg.ImageId)
		imageType = tea.StringValue(sg.ImageType)
		instanceChargeType = tea.StringValue(sg.InstanceChargeType)
		desiredSize = tea.Int64Value(sg.DesiredSize)
		multiAzPolicy = tea.StringValue(sg.MultiAzPolicy)
		spotStrategy = tea.StringValue(sg.SpotStrategy)
		securityHardeningOs = tea.BoolValue(sg.SecurityHardeningOs)
		socEnabled = tea.BoolValue(sg.SocEnabled)
		cisEnabled = tea.BoolValue(sg.CisEnabled)
		internetMaxBandwidthOut = tea.Int64Value(sg.InternetMaxBandwidthOut)
		securityGroupIds = strPtrsToStrings(sg.SecurityGroupIds)
		if len(securityGroupIds) == 0 && tea.StringValue(sg.SecurityGroupId) != "" {
			securityGroupIds = append(securityGroupIds, *sg.SecurityGroupId)
		}
		vswitchIds = strPtrsToStrings(sg.VswitchIds)
		for _, d := range sg.DataDisks {
			if d == nil {
				continue
			}
			dataDisks = append(dataDisks, map[string]any{
				"category":             tea.StringValue(d.Category),
				"size":                 tea.Int64Value(d.Size),
				"encrypted":            strings.EqualFold(tea.StringValue(d.Encrypted), "true"),
				"kmsKeyId":             tea.StringValue(d.KmsKeyId),
				"performanceLevel":     tea.StringValue(d.PerformanceLevel),
				"autoSnapshotPolicyId": tea.StringValue(d.AutoSnapshotPolicyId),
			})
		}
		for _, t := range sg.Tags {
			if t == nil || t.Key == nil {
				continue
			}
			npTags[*t.Key] = tea.StringValue(t.Value)
		}
	}

	// kubernetes config
	kc := np.KubernetesConfig
	runtime_, runtimeVersion, cpuPolicy := "", "", ""
	cmsEnabled, unschedulable := false, false
	labels := map[string]any{}
	taints := []any{}
	if kc != nil {
		runtime_ = tea.StringValue(kc.Runtime)
		runtimeVersion = tea.StringValue(kc.RuntimeVersion)
		cpuPolicy = tea.StringValue(kc.CpuPolicy)
		cmsEnabled = tea.BoolValue(kc.CmsEnabled)
		unschedulable = tea.BoolValue(kc.Unschedulable)
		for _, l := range kc.Labels {
			if l == nil || l.Key == nil {
				continue
			}
			labels[*l.Key] = tea.StringValue(l.Value)
		}
		for _, t := range kc.Taints {
			if t == nil {
				continue
			}
			taints = append(taints, map[string]any{
				"key":    tea.StringValue(t.Key),
				"value":  tea.StringValue(t.Value),
				"effect": tea.StringValue(t.Effect),
			})
		}
	}

	// autoscaling
	as := np.AutoScaling
	autoScalingEnabled := false
	autoScalingType := ""
	var minInstances, maxInstances int64
	if as != nil {
		autoScalingEnabled = tea.BoolValue(as.Enable)
		autoScalingType = tea.StringValue(as.Type)
		minInstances = tea.Int64Value(as.MinInstances)
		maxInstances = tea.Int64Value(as.MaxInstances)
	}

	// management
	mg := np.Management
	managed, autoRepair, autoUpgrade, autoVulFix := false, false, false, false
	if mg != nil {
		managed = tea.BoolValue(mg.Enable)
		autoRepair = tea.BoolValue(mg.AutoRepair)
		autoUpgrade = tea.BoolValue(mg.AutoUpgrade)
		autoVulFix = tea.BoolValue(mg.AutoVulFix)
	}

	teeEnabled := false
	if np.TeeConfig != nil {
		teeEnabled = tea.BoolValue(np.TeeConfig.TeeEnable)
	}

	// status
	st := np.Status
	var totalNodes, servingNodes, healthyNodes, failedNodes int64
	nodePoolState := ""
	if st != nil {
		totalNodes = tea.Int64Value(st.TotalNodes)
		servingNodes = tea.Int64Value(st.ServingNodes)
		healthyNodes = tea.Int64Value(st.HealthyNodes)
		failedNodes = tea.Int64Value(st.FailedNodes)
		nodePoolState = tea.StringValue(st.State)
	}

	resource, err := CreateResource(runtime, "alicloud.cs.nodePool", map[string]*llx.RawData{
		"__id":                       llx.StringData(clusterID + "/" + nodePoolID),
		"regionId":                   llx.StringData(region),
		"clusterId":                  llx.StringData(clusterID),
		"nodePoolId":                 llx.StringData(nodePoolID),
		"name":                       llx.StringDataPtr(info.Name),
		"type":                       llx.StringDataPtr(info.Type),
		"resourceGroupId":            llx.StringDataPtr(info.ResourceGroupId),
		"isDefault":                  llx.BoolDataPtr(info.IsDefault),
		"created":                    llx.TimeDataPtr(alicloudParseTime(info.Created)),
		"updated":                    llx.TimeDataPtr(alicloudParseTime(info.Updated)),
		"instanceTypes":              llx.ArrayData(instanceTypes, types.String),
		"systemDiskCategory":         llx.StringData(systemDiskCategory),
		"systemDiskSize":             llx.IntData(systemDiskSize),
		"systemDiskEncrypted":        llx.BoolData(systemDiskEncrypted),
		"systemDiskEncryptAlgorithm": llx.StringData(systemDiskEncryptAlgorithm),
		"keyPair":                    llx.StringData(keyPair),
		"imageType":                  llx.StringData(imageType),
		"imageId":                    llx.StringData(imageID),
		"instanceChargeType":         llx.StringData(instanceChargeType),
		"desiredSize":                llx.IntData(desiredSize),
		"multiAzPolicy":              llx.StringData(multiAzPolicy),
		"spotStrategy":               llx.StringData(spotStrategy),
		"securityHardeningOs":        llx.BoolData(securityHardeningOs),
		"socEnabled":                 llx.BoolData(socEnabled),
		"cisEnabled":                 llx.BoolData(cisEnabled),
		"internetMaxBandwidthOut":    llx.IntData(internetMaxBandwidthOut),
		"dataDisks":                  llx.ArrayData(dataDisks, types.Dict),
		"runtime":                    llx.StringData(runtime_),
		"runtimeVersion":             llx.StringData(runtimeVersion),
		"cmsEnabled":                 llx.BoolData(cmsEnabled),
		"cpuPolicy":                  llx.StringData(cpuPolicy),
		"unschedulable":              llx.BoolData(unschedulable),
		"labels":                     llx.MapData(labels, types.String),
		"taints":                     llx.ArrayData(taints, types.Dict),
		"autoScalingEnabled":         llx.BoolData(autoScalingEnabled),
		"autoScalingType":            llx.StringData(autoScalingType),
		"minInstances":               llx.IntData(minInstances),
		"maxInstances":               llx.IntData(maxInstances),
		"managed":                    llx.BoolData(managed),
		"autoRepair":                 llx.BoolData(autoRepair),
		"autoUpgrade":                llx.BoolData(autoUpgrade),
		"autoVulFix":                 llx.BoolData(autoVulFix),
		"teeEnabled":                 llx.BoolData(teeEnabled),
		"totalNodes":                 llx.IntData(totalNodes),
		"servingNodes":               llx.IntData(servingNodes),
		"healthyNodes":               llx.IntData(healthyNodes),
		"failedNodes":                llx.IntData(failedNodes),
		"nodePoolState":              llx.StringData(nodePoolState),
	})
	if err != nil {
		return nil, err
	}
	mqlNp := resource.(*mqlAlicloudCsNodePool)
	mqlNp.region = region
	mqlNp.cacheSystemDiskKmsKeyId = systemDiskKmsKeyId
	mqlNp.cacheSecurityGroupIds = securityGroupIds
	mqlNp.cacheVswitchIds = vswitchIds
	mqlNp.cacheRamRoleName = ramRoleName
	return mqlNp, nil
}

func (r *mqlAlicloudCsNodePool) id() (string, error) {
	return r.ClusterId.Data + "/" + r.NodePoolId.Data, nil
}

// cluster resolves the ACK cluster the node pool belongs to. A node pool cannot
// outlive its cluster, so a failure to read it is a real error. The cluster is
// already in the resource cache whenever the node pool was reached through it,
// which the cluster init consults before calling the API.
func (r *mqlAlicloudCsNodePool) cluster() (*mqlAlicloudCsCluster, error) {
	if r.ClusterId.Data == "" {
		r.Cluster.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(r.MqlRuntime, "alicloud.cs.cluster", map[string]*llx.RawData{
		"clusterId": llx.StringData(r.ClusterId.Data),
		"regionId":  llx.StringData(r.RegionId.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAlicloudCsCluster), nil
}

// image resolves the image the node pool launches nodes from.
//
// A node pool can name an image the account can no longer read, for example a
// retired public image or one shared from another account, so an image that
// does not resolve yields null rather than failing the node pool.
func (r *mqlAlicloudCsNodePool) image() (*mqlAlicloudEcsImage, error) {
	imageID := r.ImageId.Data
	if imageID == "" {
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	image, err := resolveEcsImage(r.MqlRuntime, r.region, imageID)
	if err != nil || image == nil {
		log.Debug().Err(err).Str("image", imageID).Str("region", r.region).
			Msg("alicloud> could not resolve node pool image")
		r.Image.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return image, nil
}

func (r *mqlAlicloudCsNodePool) systemDiskKmsKey() (*mqlAlicloudKmsKey, error) {
	if r.cacheSystemDiskKmsKeyId == "" {
		r.SystemDiskKmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveKmsKey(r.MqlRuntime, r.region, r.cacheSystemDiskKmsKeyId)
}

func (r *mqlAlicloudCsNodePool) securityGroups() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheSecurityGroupIds {
		sg, err := resolveEcsSecuritygroup(r.MqlRuntime, r.region, id)
		if err != nil {
			return nil, err
		}
		if sg != nil {
			res = append(res, sg)
		}
	}
	return res, nil
}

func (r *mqlAlicloudCsNodePool) vswitches() ([]any, error) {
	res := []any{}
	for _, id := range r.cacheVswitchIds {
		vsw, err := resolveVpcVswitch(r.MqlRuntime, r.region, id)
		if err != nil {
			return nil, err
		}
		if vsw != nil {
			res = append(res, vsw)
		}
	}
	return res, nil
}

func (r *mqlAlicloudCsNodePool) ramRole() (*mqlAlicloudRamRole, error) {
	if r.cacheRamRoleName == "" {
		r.RamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return resolveRamRole(r.MqlRuntime, r.cacheRamRoleName)
}
