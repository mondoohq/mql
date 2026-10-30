// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	redis "cloud.google.com/go/redis/apiv1"
	"cloud.google.com/go/redis/apiv1/redispb"
	rediscluster "cloud.google.com/go/redis/cluster/apiv1"
	"cloud.google.com/go/redis/cluster/apiv1/clusterpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

// initGcpProjectRedisService fills in the project the service belongs to when the
// resource is reached by its own type name rather than through the
// gcp.project accessor. Without it the resource is built with an empty
// projectId, and the serviceEnabled gate then asks Service Usage about
// "projects/", which fails the whole query with an InvalidArgument.
func initGcpProjectRedisService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

type mqlGcpProjectRedisServiceInternal struct {
	serviceGate
}

type mqlGcpProjectRedisServiceInstanceInternal struct {
	cacheKmsKey            string
	cacheAuthorizedNetwork string
}

func (g *mqlGcpProjectRedisServiceInstance) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKey == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKey)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

type mqlGcpProjectRedisServiceClusterInternal struct {
	cacheKmsKey string
}

func (g *mqlGcpProjectRedisServiceCluster) cryptoKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKey == "" {
		g.CryptoKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKey)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProject) redis() (*mqlGcpProjectRedisService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.redisService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_redis)
	if err != nil {
		return nil, err
	}

	redisSvc := res.(*mqlGcpProjectRedisService)
	redisSvc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_redis).Msg("gcp service is not enabled, skipping")
	}

	return redisSvc, nil
}

func initGcpProjectRedisServiceInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.redisService.instance requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.redisService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	redisSvc := obj.(*mqlGcpProjectRedisService)
	instances := redisSvc.GetInstances()
	if instances.Error != nil {
		return nil, nil, instances.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.redisService.instance requires a \"name\" argument")
	}
	wantName, _ := nameRaw.Value.(string)
	for _, inst := range instances.Data {
		instance := inst.(*mqlGcpProjectRedisServiceInstance)
		// Redis instance name is a full resource path:
		// projects/{project}/locations/{location}/instances/{instance_id}
		nameParts := strings.Split(instance.Name.Data, "/")
		instanceName := nameParts[len(nameParts)-1]

		if instanceName == wantName {
			return args, instance, nil
		}
	}

	return nil, nil, errors.New("Redis instance not found")
}

func (g *mqlGcpProjectRedisService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/redisService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectRedisServiceInstance) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cacheAuthorizedNetwork, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectRedisServiceInstance) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectRedisServiceInstance) persistenceServiceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	if g.PersistenceIamIdentity.Error != nil {
		return nil, g.PersistenceIamIdentity.Error
	}
	// The persistence IAM identity is carried as "serviceAccount:{email}".
	raw := strings.TrimPrefix(g.PersistenceIamIdentity.Data, "serviceAccount:")
	projectId := ""
	if g.ProjectId.Error == nil {
		projectId = g.ProjectId.Data
	}
	sa, err := resolveServiceAccountRef(g.MqlRuntime, raw, projectId)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.PersistenceServiceAccount.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return sa, nil
}

func (g *mqlGcpProjectRedisServiceInstance) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf(
		"gcp.project/%s/redisService.instance/%s", g.ProjectId.Data, g.Name.Data,
	), nil
}

// Requires the following OAuth scope:
//
// https://www.googleapis.com/auth/cloud-platform
//
// Docs https://docs.cloud.google.com/memorystore/docs/redis/reference/rest/v1/projects.locations/list#authorization-scopes
func (g *mqlGcpProjectRedisService) instances() ([]any, error) {
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

	creds, err := conn.Credentials(redis.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	redisSvc, err := redis.NewCloudRedisClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer redisSvc.Close()

	it := redisSvc.ListInstances(ctx, &redispb.ListInstancesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})
	res := []any{}
	for {
		instance, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		persistenceConfig, err := redisConvertPersistenceConfig(instance.PersistenceConfig)
		if err != nil {
			return nil, err
		}
		maintenancePolicy, err := redisConvertMaintenancePolicy(instance.MaintenancePolicy)
		if err != nil {
			return nil, err
		}
		maintenanceSchedule, err := redisConvertMaintenanceSchedule(instance.MaintenanceSchedule)
		if err != nil {
			return nil, err
		}

		mqlRedisInstance, err := CreateResource(g.MqlRuntime, "gcp.project.redisService.instance", map[string]*llx.RawData{
			"projectId":              llx.StringData(projectId),
			"name":                   llx.StringData(instance.Name),
			"state":                  llx.StringData(instance.State.String()),
			"displayName":            llx.StringData(instance.DisplayName),
			"locationId":             llx.StringData(instance.LocationId),
			"redisVersion":           llx.StringData(instance.RedisVersion),
			"reservedIpRange":        llx.StringData(instance.ReservedIpRange),
			"secondaryIpRange":       llx.StringData(instance.SecondaryIpRange),
			"persistenceIamIdentity": llx.StringData(instance.PersistenceIamIdentity),
			"connectMode":            llx.StringData(instance.ConnectMode.String()),
			"readEndpoint":           llx.StringData(instance.ReadEndpoint),
			"maintenanceVersion":     llx.StringData(instance.MaintenanceVersion),
			"host":                   llx.StringData(instance.Host),
			"currentLocationId":      llx.StringData(instance.CurrentLocationId),
			"statusMessage":          llx.StringData(instance.StatusMessage),
			"tier":                   llx.StringData(instance.Tier.String()),
			"transitEncryptionMode":  llx.StringData(instance.TransitEncryptionMode.String()),
			"readReplicasMode":       llx.StringData(instance.ReadReplicasMode.String()),
			"alternativeLocationId":  llx.StringData(instance.AlternativeLocationId),
			"port":                   llx.IntData(instance.Port),
			"memorySizeGb":           llx.IntData(instance.MemorySizeGb),
			"replicaCount":           llx.IntData(instance.ReplicaCount),
			"readEndpointPort":       llx.IntData(instance.ReadEndpointPort),
			"authEnabled":            llx.BoolData(instance.AuthEnabled),
			"createTime":             llx.TimeDataPtr(timestampAsTimePtr(instance.CreateTime)),
			"labels":                 llx.MapData(convert.MapToInterfaceMap(instance.Labels), types.String),
			"redisConfigs":           llx.MapData(convert.MapToInterfaceMap(instance.RedisConfigs), types.String),
			"persistenceConfig":      llx.DictData(persistenceConfig),
			"maintenancePolicy":      llx.DictData(maintenancePolicy),
			"maintenanceSchedule":    llx.DictData(maintenanceSchedule),
			"suspensionReasons":      llx.ArrayData(redisConvertSuspensionReasons(instance.SuspensionReasons), types.String),
			"availableMaintenanceVersions": llx.ArrayData(
				convert.SliceAnyToInterface(instance.AvailableMaintenanceVersions), types.String,
			),
			"nodes": llx.ArrayData(
				redisInstanceNodesToArrayInterface(g.MqlRuntime, projectId, instance.Name, instance.Nodes),
				types.Resource("gcp.project.redisService.instance.nodeInfo"),
			),
			"serverCaCerts": llx.ArrayData(
				redisConvertServerCaCerts(g.MqlRuntime, projectId, instance.Name, instance.ServerCaCerts),
				types.Resource("gcp.project.redisService.instance.serverCaCert"),
			),
		})
		if err != nil {
			return nil, err
		}
		mqlRef := mqlRedisInstance.(*mqlGcpProjectRedisServiceInstance)
		mqlRef.cacheAuthorizedNetwork = instance.AuthorizedNetwork
		mqlRedisInstance.(*mqlGcpProjectRedisServiceInstance).cacheKmsKey = instance.CustomerManagedKey
		res = append(res, mqlRedisInstance)
	}

	return res, nil
}

func (n *mqlGcpProjectRedisServiceInstanceNodeInfo) id() (string, error) {
	if n.ProjectId.Error != nil {
		return "", n.ProjectId.Error
	}
	return fmt.Sprintf(
		"gcp.project.redisService.instance.nodeInfo/%s/%s", n.ProjectId.Data, n.Id.Data,
	), nil
}

// redisInstanceNodesToArrayInterface keys each node on its parent instance:
// NodeInfo.Id is only "node-0", "node-1", ... which is unique within one
// instance, so a project-scoped key aliased every instance's nodes onto the
// first instance's.
func redisInstanceNodesToArrayInterface(runtime *plugin.Runtime, projectId, instanceName string, nodes []*redispb.NodeInfo) (list []any) {
	for _, node := range nodes {
		if node == nil {
			continue
		}

		r, err := CreateResource(runtime, "gcp.project.redisService.instance.nodeInfo", map[string]*llx.RawData{
			"__id":      llx.StringData(instanceName + "/nodes/" + node.Id),
			"projectId": llx.StringData(projectId),
			"id":        llx.StringData(node.Id),
			"zone":      llx.StringData(node.Zone),
		})
		if err != nil {
			continue
		}
		list = append(list, r)
	}

	return
}

func (c *mqlGcpProjectRedisServiceInstanceServerCaCert) id() (string, error) {
	if c.ProjectId.Error != nil {
		return "", c.ProjectId.Error
	}
	return fmt.Sprintf(
		"gcp.project.redisService.instance.serverCaCert/%s/%s", c.ProjectId.Data, c.SerialNumber.Data,
	), nil
}

// redisConvertServerCaCerts keys each certificate on its parent instance:
// Memorystore issues a per-instance server CA whose serial numbers start at
// "1", so a project-scoped key made instance B render instance A's PEM and
// expiry -- silently evaluating a CA-expiry audit against the wrong cert.
func redisConvertServerCaCerts(runtime *plugin.Runtime, projectId, instanceName string, certs []*redispb.TlsCertificate) (list []any) {
	for _, cert := range certs {
		if cert == nil {
			continue
		}

		var createTime, expireTime time.Time
		if cert.CreateTime != nil {
			createTime = cert.CreateTime.AsTime()
		}
		if cert.ExpireTime != nil {
			expireTime = cert.ExpireTime.AsTime()
		}

		r, err := CreateResource(runtime, "gcp.project.redisService.instance.serverCaCert", map[string]*llx.RawData{
			"__id":            llx.StringData(instanceName + "/serverCaCerts/" + cert.SerialNumber),
			"projectId":       llx.StringData(projectId),
			"serialNumber":    llx.StringData(cert.SerialNumber),
			"cert":            llx.StringData(cert.Cert),
			"createTime":      llx.TimeData(createTime),
			"expireTime":      llx.TimeData(expireTime),
			"sha1Fingerprint": llx.StringData(cert.Sha1Fingerprint),
		})
		if err != nil {
			continue
		}
		list = append(list, r)
	}

	return
}

func redisConvertSuspensionReasons(reasons []redispb.Instance_SuspensionReason) []any {
	res := make([]any, 0, len(reasons))
	for _, r := range reasons {
		res = append(res, r.String())
	}
	return res
}

type mqlRedisPersistenceConfig struct {
	PersistenceMode      string  `json:"persistenceMode"`
	RdbSnapshotPeriod    string  `json:"rdbSnapshotPeriod"`
	RdbNextSnapshotTime  *string `json:"rdbNextSnapshotTime"`
	RdbSnapshotStartTime *string `json:"rdbSnapshotStartTime"`
}

func redisConvertPersistenceConfig(pc *redispb.PersistenceConfig) (map[string]any, error) {
	if pc == nil {
		return nil, nil
	}

	cfg := mqlRedisPersistenceConfig{
		PersistenceMode:   pc.PersistenceMode.String(),
		RdbSnapshotPeriod: pc.RdbSnapshotPeriod.String(),
	}
	if pc.RdbNextSnapshotTime != nil {
		s := pc.RdbNextSnapshotTime.AsTime().Format(time.RFC3339)
		cfg.RdbNextSnapshotTime = &s
	}
	if pc.RdbSnapshotStartTime != nil {
		s := pc.RdbSnapshotStartTime.AsTime().Format(time.RFC3339)
		cfg.RdbSnapshotStartTime = &s
	}

	return convert.JsonToDict(cfg)
}

type mqlRedisMaintenanceWindow struct {
	Day       string `json:"day"`
	StartTime string `json:"startTime"`
	Duration  string `json:"duration"`
}

type mqlRedisMaintenancePolicy struct {
	CreateTime              *string                     `json:"createTime"`
	UpdateTime              *string                     `json:"updateTime"`
	Description             string                      `json:"description"`
	WeeklyMaintenanceWindow []mqlRedisMaintenanceWindow `json:"weeklyMaintenanceWindow"`
}

func redisConvertMaintenancePolicy(mp *redispb.MaintenancePolicy) (map[string]any, error) {
	if mp == nil {
		return nil, nil
	}

	policy := mqlRedisMaintenancePolicy{
		Description: mp.Description,
	}
	if mp.CreateTime != nil {
		s := mp.CreateTime.AsTime().Format(time.RFC3339)
		policy.CreateTime = &s
	}
	if mp.UpdateTime != nil {
		s := mp.UpdateTime.AsTime().Format(time.RFC3339)
		policy.UpdateTime = &s
	}

	for _, w := range mp.WeeklyMaintenanceWindow {
		if w == nil {
			continue
		}
		window := mqlRedisMaintenanceWindow{
			Day: w.Day.String(),
		}
		if w.StartTime != nil {
			window.StartTime = fmt.Sprintf("%02d:%02d:%02d", w.StartTime.Hours, w.StartTime.Minutes, w.StartTime.Seconds)
		}
		if w.Duration != nil {
			window.Duration = w.Duration.AsDuration().String()
		}
		policy.WeeklyMaintenanceWindow = append(policy.WeeklyMaintenanceWindow, window)
	}

	return convert.JsonToDict(policy)
}

type mqlRedisMaintenanceSchedule struct {
	StartTime            *string `json:"startTime"`
	EndTime              *string `json:"endTime"`
	ScheduleDeadlineTime *string `json:"scheduleDeadlineTime"`
}

func redisConvertMaintenanceSchedule(ms *redispb.MaintenanceSchedule) (map[string]any, error) {
	if ms == nil {
		return nil, nil
	}

	schedule := mqlRedisMaintenanceSchedule{}
	if ms.StartTime != nil {
		s := ms.StartTime.AsTime().Format(time.RFC3339)
		schedule.StartTime = &s
	}
	if ms.EndTime != nil {
		s := ms.EndTime.AsTime().Format(time.RFC3339)
		schedule.EndTime = &s
	}
	if ms.ScheduleDeadlineTime != nil {
		s := ms.ScheduleDeadlineTime.AsTime().Format(time.RFC3339)
		schedule.ScheduleDeadlineTime = &s
	}

	return convert.JsonToDict(schedule)
}

// ===== Redis Cluster resources =====

func (g *mqlGcpProjectRedisServiceCluster) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf(
		"gcp.project/%s/redisService.cluster/%s", g.ProjectId.Data, g.Name.Data,
	), nil
}

func initGcpProjectRedisServiceCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if args == nil {
			args = make(map[string]*llx.RawData)
		}
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	// Guard before building the parent: CreateResource hands args["projectId"]
	// to the generated setter, which dereferences it, so nil panics the provider.
	if args["projectId"] == nil {
		return nil, nil, errors.New("gcp.project.redisService.cluster requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.redisService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	redisSvc := obj.(*mqlGcpProjectRedisService)
	clusters := redisSvc.GetClusters()
	if clusters.Error != nil {
		return nil, nil, clusters.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.redisService.cluster requires a \"name\" argument")
	}
	wantName, _ := nameRaw.Value.(string)
	for _, c := range clusters.Data {
		cluster := c.(*mqlGcpProjectRedisServiceCluster)
		nameParts := strings.Split(cluster.Name.Data, "/")
		clusterName := nameParts[len(nameParts)-1]

		if clusterName == wantName {
			return args, cluster, nil
		}
	}

	return nil, nil, errors.New("Redis cluster not found")
}

func (g *mqlGcpProjectRedisService) clusters() ([]any, error) {
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

	creds, err := conn.Credentials(rediscluster.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	clusterSvc, err := rediscluster.NewCloudRedisClusterClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer clusterSvc.Close()

	it := clusterSvc.ListClusters(ctx, &clusterpb.ListClustersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})
	res := []any{}
	for {
		cluster, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		persistenceConfig, err := clusterConvertPersistenceConfig(cluster.PersistenceConfig)
		if err != nil {
			return nil, err
		}
		zoneDistConfig, err := clusterConvertZoneDistributionConfig(cluster.ZoneDistributionConfig)
		if err != nil {
			return nil, err
		}
		maintenancePolicy, err := clusterConvertMaintenancePolicy(cluster.MaintenancePolicy)
		if err != nil {
			return nil, err
		}
		maintenanceSchedule, err := clusterConvertMaintenanceSchedule(cluster.MaintenanceSchedule)
		if err != nil {
			return nil, err
		}
		encryptionInfo, err := clusterConvertEncryptionInfo(cluster.EncryptionInfo)
		if err != nil {
			return nil, err
		}
		automatedBackupConfig, err := clusterConvertAutomatedBackupConfig(cluster.AutomatedBackupConfig)
		if err != nil {
			return nil, err
		}
		crossClusterConfig, err := clusterConvertCrossClusterReplicationConfig(cluster.CrossClusterReplicationConfig)
		if err != nil {
			return nil, err
		}
		stateInfo, err := protoToDict(cluster.StateInfo)
		if err != nil {
			return nil, err
		}

		var replicaCount int64
		if cluster.ReplicaCount != nil {
			replicaCount = int64(*cluster.ReplicaCount)
		}
		var shardCount int64
		if cluster.ShardCount != nil {
			shardCount = int64(*cluster.ShardCount)
		}
		var sizeGb int64
		if cluster.SizeGb != nil {
			sizeGb = int64(*cluster.SizeGb)
		}
		var preciseSizeGb float64
		if cluster.PreciseSizeGb != nil {
			preciseSizeGb = *cluster.PreciseSizeGb
		}
		var deletionProtection bool
		if cluster.DeletionProtectionEnabled != nil {
			deletionProtection = *cluster.DeletionProtectionEnabled
		}
		var kmsKey string
		if cluster.KmsKey != nil {
			kmsKey = *cluster.KmsKey
		}
		var backupCollection string
		if cluster.BackupCollection != nil {
			backupCollection = *cluster.BackupCollection
		}
		var serverCaMode string
		if cluster.ServerCaMode != nil {
			serverCaMode = cluster.ServerCaMode.String()
		}
		var serverCaPool string
		if cluster.ServerCaPool != nil {
			serverCaPool = *cluster.ServerCaPool
		}

		pscServiceAttachments := make([]any, 0, len(cluster.PscServiceAttachments))
		for _, psa := range cluster.PscServiceAttachments {
			if psa == nil {
				continue
			}
			pscServiceAttachments = append(pscServiceAttachments, map[string]any{
				"serviceAttachment": psa.ServiceAttachment,
				"connectionType":    psa.ConnectionType.String(),
			})
		}

		mqlCluster, err := CreateResource(g.MqlRuntime, "gcp.project.redisService.cluster", map[string]*llx.RawData{
			"projectId":                     llx.StringData(projectId),
			"name":                          llx.StringData(cluster.Name),
			"uid":                           llx.StringData(cluster.Uid),
			"state":                         llx.StringData(cluster.State.String()),
			"stateInfo":                     llx.DictData(stateInfo),
			"createTime":                    llx.TimeDataPtr(timestampAsTimePtr(cluster.CreateTime)),
			"authorizationMode":             llx.StringData(cluster.AuthorizationMode.String()),
			"transitEncryptionMode":         llx.StringData(cluster.TransitEncryptionMode.String()),
			"nodeType":                      llx.StringData(cluster.NodeType.String()),
			"shardCount":                    llx.IntData(shardCount),
			"replicaCount":                  llx.IntData(replicaCount),
			"sizeGb":                        llx.IntData(sizeGb),
			"preciseSizeGb":                 llx.FloatData(preciseSizeGb),
			"deletionProtectionEnabled":     llx.BoolData(deletionProtection),
			"backupCollection":              llx.StringData(backupCollection),
			"redisConfigs":                  llx.MapData(convert.MapToInterfaceMap(cluster.RedisConfigs), types.String),
			"persistenceConfig":             llx.DictData(persistenceConfig),
			"zoneDistributionConfig":        llx.DictData(zoneDistConfig),
			"maintenancePolicy":             llx.DictData(maintenancePolicy),
			"maintenanceSchedule":           llx.DictData(maintenanceSchedule),
			"encryptionInfo":                llx.DictData(encryptionInfo),
			"automatedBackupConfig":         llx.DictData(automatedBackupConfig),
			"crossClusterReplicationConfig": llx.DictData(crossClusterConfig),
			"pscConfigs": llx.ArrayData(
				clusterConvertPscConfigs(g.MqlRuntime, projectId, cluster.Name, cluster.PscConfigs),
				types.Resource("gcp.project.redisService.cluster.pscConfig"),
			),
			"discoveryEndpoints": llx.ArrayData(
				clusterConvertDiscoveryEndpoints(g.MqlRuntime, projectId, cluster.Name, cluster.DiscoveryEndpoints),
				types.Resource("gcp.project.redisService.cluster.discoveryEndpoint"),
			),
			"pscConnections": llx.ArrayData(
				clusterConvertPscConnections(g.MqlRuntime, projectId, cluster.Name, cluster.PscConnections),
				types.Resource("gcp.project.redisService.cluster.pscConnection"),
			),
			"clusterEndpoints": llx.ArrayData(
				clusterConvertClusterEndpoints(g.MqlRuntime, projectId, cluster.Name, cluster.ClusterEndpoints),
				types.Resource("gcp.project.redisService.cluster.clusterEndpoint"),
			),
			"serverCaMode":                         llx.StringData(serverCaMode),
			"serverCaPool":                         llx.StringData(serverCaPool),
			"pscServiceAttachments":                llx.ArrayData(pscServiceAttachments, types.Dict),
			"asyncClusterEndpointsDeletionEnabled": llx.BoolDataPtr(cluster.AsyncClusterEndpointsDeletionEnabled),
		})
		if err != nil {
			return nil, err
		}
		mqlCluster.(*mqlGcpProjectRedisServiceCluster).cacheKmsKey = kmsKey
		res = append(res, mqlCluster)
	}

	return res, nil
}

// ===== Cluster sub-resource id() methods =====

func (c *mqlGcpProjectRedisServiceClusterPscConfig) id() (string, error) {
	return fmt.Sprintf(
		"gcp.project.redisService.cluster.pscConfig/%s/%s/%s", c.ProjectId.Data, c.ClusterName.Data, c.Network.Data,
	), nil
}

func (c *mqlGcpProjectRedisServiceClusterPscConfig) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	if c.Network.Error != nil {
		return nil, c.Network.Error
	}
	n, err := getNetworkByUrl(c.Network.Data, c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		c.NetworkRef.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return n, nil
}

func (c *mqlGcpProjectRedisServiceClusterDiscoveryEndpoint) id() (string, error) {
	return fmt.Sprintf(
		"gcp.project.redisService.cluster.discoveryEndpoint/%s/%s/%s", c.ProjectId.Data, c.ClusterName.Data, c.Address.Data,
	), nil
}

func (c *mqlGcpProjectRedisServiceClusterPscConnection) id() (string, error) {
	return fmt.Sprintf(
		"gcp.project.redisService.cluster.pscConnection/%s/%s/%s", c.ProjectId.Data, c.ClusterName.Data, c.PscConnectionId.Data,
	), nil
}

func (c *mqlGcpProjectRedisServiceClusterPscConnection) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	if c.Network.Error != nil {
		return nil, c.Network.Error
	}
	n, err := getNetworkByUrl(c.Network.Data, c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		c.NetworkRef.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return n, nil
}

func (c *mqlGcpProjectRedisServiceClusterBackup) id() (string, error) {
	return fmt.Sprintf(
		"gcp.project.redisService.cluster.backup/%s/%s", c.ProjectId.Data, c.Name.Data,
	), nil
}

func (c *mqlGcpProjectRedisServiceClusterClusterEndpoint) id() (string, error) {
	// __id is set explicitly during resource creation since ClusterEndpoint
	// has no natural unique key
	return c.__id, nil
}

func (c *mqlGcpProjectRedisServiceClusterConnectionDetail) id() (string, error) {
	return fmt.Sprintf(
		"gcp.project.redisService.cluster.connectionDetail/%s/%s/%s", c.ProjectId.Data, c.ClusterName.Data, c.PscConnectionId.Data,
	), nil
}

func (c *mqlGcpProjectRedisServiceClusterConnectionDetail) networkRef() (*mqlGcpProjectComputeServiceNetwork, error) {
	if c.Network.Error != nil {
		return nil, c.Network.Error
	}
	n, err := getNetworkByUrl(c.Network.Data, c.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		c.NetworkRef.State = plugin.StateIsNull | plugin.StateIsSet
	}
	return n, nil
}

// ===== Cluster sub-resource converters =====

func clusterConvertPscConfigs(runtime *plugin.Runtime, projectId, clusterName string, configs []*clusterpb.PscConfig) (list []any) {
	for _, cfg := range configs {
		if cfg == nil {
			continue
		}
		r, err := CreateResource(runtime, "gcp.project.redisService.cluster.pscConfig", map[string]*llx.RawData{
			"projectId":   llx.StringData(projectId),
			"clusterName": llx.StringData(clusterName),
			"network":     llx.StringData(cfg.Network),
		})
		if err != nil {
			continue
		}
		list = append(list, r)
	}
	return
}

func clusterConvertDiscoveryEndpoints(runtime *plugin.Runtime, projectId, clusterName string, endpoints []*clusterpb.DiscoveryEndpoint) (list []any) {
	for _, ep := range endpoints {
		if ep == nil {
			continue
		}
		var network string
		if ep.PscConfig != nil {
			network = ep.PscConfig.Network
		}
		r, err := CreateResource(runtime, "gcp.project.redisService.cluster.discoveryEndpoint", map[string]*llx.RawData{
			"projectId":   llx.StringData(projectId),
			"clusterName": llx.StringData(clusterName),
			"address":     llx.StringData(ep.Address),
			"port":        llx.IntData(int64(ep.Port)),
			"network":     llx.StringData(network),
		})
		if err != nil {
			continue
		}
		list = append(list, r)
	}
	return
}

func clusterConvertPscConnections(runtime *plugin.Runtime, projectId, clusterName string, connections []*clusterpb.PscConnection) (list []any) {
	for _, conn := range connections {
		if conn == nil {
			continue
		}
		r, err := CreateResource(runtime, "gcp.project.redisService.cluster.pscConnection", map[string]*llx.RawData{
			"projectId":           llx.StringData(projectId),
			"clusterName":         llx.StringData(clusterName),
			"pscConnectionId":     llx.StringData(conn.PscConnectionId),
			"address":             llx.StringData(conn.Address),
			"forwardingRule":      llx.StringData(conn.ForwardingRule),
			"connectionProjectId": llx.StringData(conn.ProjectId),
			"network":             llx.StringData(conn.Network),
			"serviceAttachment":   llx.StringData(conn.ServiceAttachment),
			"pscConnectionStatus": llx.StringData(conn.PscConnectionStatus.String()),
			"connectionType":      llx.StringData(conn.ConnectionType.String()),
		})
		if err != nil {
			continue
		}
		list = append(list, r)
	}
	return
}

// ===== Cluster dict converters =====

type mqlClusterPersistenceConfig struct {
	Mode      string `json:"mode"`
	RdbConfig *struct {
		RdbSnapshotPeriod    string  `json:"rdbSnapshotPeriod"`
		RdbSnapshotStartTime *string `json:"rdbSnapshotStartTime"`
	} `json:"rdbConfig"`
	AofConfig *struct {
		AppendFsync string `json:"appendFsync"`
	} `json:"aofConfig"`
}

func clusterConvertPersistenceConfig(pc *clusterpb.ClusterPersistenceConfig) (map[string]any, error) {
	if pc == nil {
		return nil, nil
	}
	cfg := mqlClusterPersistenceConfig{
		Mode: pc.Mode.String(),
	}
	if pc.RdbConfig != nil {
		rdb := &struct {
			RdbSnapshotPeriod    string  `json:"rdbSnapshotPeriod"`
			RdbSnapshotStartTime *string `json:"rdbSnapshotStartTime"`
		}{
			RdbSnapshotPeriod: pc.RdbConfig.RdbSnapshotPeriod.String(),
		}
		if pc.RdbConfig.RdbSnapshotStartTime != nil {
			s := pc.RdbConfig.RdbSnapshotStartTime.AsTime().Format(time.RFC3339)
			rdb.RdbSnapshotStartTime = &s
		}
		cfg.RdbConfig = rdb
	}
	if pc.AofConfig != nil {
		cfg.AofConfig = &struct {
			AppendFsync string `json:"appendFsync"`
		}{
			AppendFsync: pc.AofConfig.AppendFsync.String(),
		}
	}
	return convert.JsonToDict(cfg)
}

type mqlClusterZoneDistConfig struct {
	Mode string `json:"mode"`
	Zone string `json:"zone"`
}

func clusterConvertZoneDistributionConfig(zdc *clusterpb.ZoneDistributionConfig) (map[string]any, error) {
	if zdc == nil {
		return nil, nil
	}
	return convert.JsonToDict(mqlClusterZoneDistConfig{
		Mode: zdc.Mode.String(),
		Zone: zdc.Zone,
	})
}

type mqlClusterMaintenanceWindow struct {
	Day       string `json:"day"`
	StartTime string `json:"startTime"`
}

type mqlClusterMaintenancePolicy struct {
	CreateTime              *string                       `json:"createTime"`
	UpdateTime              *string                       `json:"updateTime"`
	WeeklyMaintenanceWindow []mqlClusterMaintenanceWindow `json:"weeklyMaintenanceWindow"`
}

func clusterConvertMaintenancePolicy(mp *clusterpb.ClusterMaintenancePolicy) (map[string]any, error) {
	if mp == nil {
		return nil, nil
	}
	policy := mqlClusterMaintenancePolicy{}
	if mp.CreateTime != nil {
		s := mp.CreateTime.AsTime().Format(time.RFC3339)
		policy.CreateTime = &s
	}
	if mp.UpdateTime != nil {
		s := mp.UpdateTime.AsTime().Format(time.RFC3339)
		policy.UpdateTime = &s
	}
	for _, w := range mp.WeeklyMaintenanceWindow {
		if w == nil {
			continue
		}
		window := mqlClusterMaintenanceWindow{
			Day: w.Day.String(),
		}
		if w.StartTime != nil {
			window.StartTime = fmt.Sprintf("%02d:%02d:%02d", w.StartTime.Hours, w.StartTime.Minutes, w.StartTime.Seconds)
		}
		policy.WeeklyMaintenanceWindow = append(policy.WeeklyMaintenanceWindow, window)
	}
	return convert.JsonToDict(policy)
}

type mqlClusterMaintenanceSchedule struct {
	StartTime *string `json:"startTime"`
	EndTime   *string `json:"endTime"`
}

func clusterConvertMaintenanceSchedule(ms *clusterpb.ClusterMaintenanceSchedule) (map[string]any, error) {
	if ms == nil {
		return nil, nil
	}
	schedule := mqlClusterMaintenanceSchedule{}
	if ms.StartTime != nil {
		s := ms.StartTime.AsTime().Format(time.RFC3339)
		schedule.StartTime = &s
	}
	if ms.EndTime != nil {
		s := ms.EndTime.AsTime().Format(time.RFC3339)
		schedule.EndTime = &s
	}
	return convert.JsonToDict(schedule)
}

type mqlClusterEncryptionInfo struct {
	EncryptionType     string   `json:"encryptionType"`
	KmsKeyVersions     []string `json:"kmsKeyVersions"`
	KmsKeyPrimaryState string   `json:"kmsKeyPrimaryState"`
	LastUpdateTime     *string  `json:"lastUpdateTime"`
}

func clusterConvertEncryptionInfo(ei *clusterpb.EncryptionInfo) (map[string]any, error) {
	if ei == nil {
		return nil, nil
	}
	info := mqlClusterEncryptionInfo{
		EncryptionType:     ei.EncryptionType.String(),
		KmsKeyVersions:     ei.KmsKeyVersions,
		KmsKeyPrimaryState: ei.KmsKeyPrimaryState.String(),
	}
	if ei.LastUpdateTime != nil {
		s := ei.LastUpdateTime.AsTime().Format(time.RFC3339)
		info.LastUpdateTime = &s
	}
	return convert.JsonToDict(info)
}

type mqlClusterAutomatedBackupConfig struct {
	AutomatedBackupMode    string  `json:"automatedBackupMode"`
	Retention              *string `json:"retention"`
	FixedFrequencySchedule *struct {
		StartTime string `json:"startTime"`
	} `json:"fixedFrequencySchedule"`
}

func clusterConvertAutomatedBackupConfig(abc *clusterpb.AutomatedBackupConfig) (map[string]any, error) {
	if abc == nil {
		return nil, nil
	}
	cfg := mqlClusterAutomatedBackupConfig{
		AutomatedBackupMode: abc.AutomatedBackupMode.String(),
	}
	if abc.Retention != nil {
		s := abc.Retention.AsDuration().String()
		cfg.Retention = &s
	}
	if ffs := abc.GetFixedFrequencySchedule(); ffs != nil {
		sched := &struct {
			StartTime string `json:"startTime"`
		}{}
		if ffs.StartTime != nil {
			sched.StartTime = fmt.Sprintf("%02d:%02d:%02d", ffs.StartTime.Hours, ffs.StartTime.Minutes, ffs.StartTime.Seconds)
		}
		cfg.FixedFrequencySchedule = sched
	}
	return convert.JsonToDict(cfg)
}

type mqlClusterRemoteCluster struct {
	Cluster string `json:"cluster"`
	Uid     string `json:"uid"`
}

type mqlClusterCrossClusterReplicationConfig struct {
	ClusterRole       string                    `json:"clusterRole"`
	PrimaryCluster    *mqlClusterRemoteCluster  `json:"primaryCluster"`
	SecondaryClusters []mqlClusterRemoteCluster `json:"secondaryClusters"`
	UpdateTime        *string                   `json:"updateTime"`
}

func clusterConvertCrossClusterReplicationConfig(ccrc *clusterpb.CrossClusterReplicationConfig) (map[string]any, error) {
	if ccrc == nil {
		return nil, nil
	}
	cfg := mqlClusterCrossClusterReplicationConfig{
		ClusterRole: ccrc.ClusterRole.String(),
	}
	if ccrc.PrimaryCluster != nil {
		cfg.PrimaryCluster = &mqlClusterRemoteCluster{
			Cluster: ccrc.PrimaryCluster.Cluster,
			Uid:     ccrc.PrimaryCluster.Uid,
		}
	}
	for _, sc := range ccrc.SecondaryClusters {
		if sc == nil {
			continue
		}
		cfg.SecondaryClusters = append(cfg.SecondaryClusters, mqlClusterRemoteCluster{
			Cluster: sc.Cluster,
			Uid:     sc.Uid,
		})
	}
	if ccrc.UpdateTime != nil {
		s := ccrc.UpdateTime.AsTime().Format(time.RFC3339)
		cfg.UpdateTime = &s
	}
	return convert.JsonToDict(cfg)
}

// ===== Cluster backups =====

func (g *mqlGcpProjectRedisServiceCluster) backups() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	backupCollection := g.BackupCollection.Data
	if backupCollection == "" {
		return []any{}, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(rediscluster.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	clusterSvc, err := rediscluster.NewCloudRedisClusterClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer clusterSvc.Close()

	it := clusterSvc.ListBackups(ctx, &clusterpb.ListBackupsRequest{
		Parent: backupCollection,
	})
	res := []any{}
	for {
		backup, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		encryptionInfo, err := clusterConvertEncryptionInfo(backup.EncryptionInfo)
		if err != nil {
			return nil, err
		}

		backupFiles, err := clusterConvertBackupFiles(g.MqlRuntime, projectId, backup.Name, backup.BackupFiles)
		if err != nil {
			return nil, err
		}

		var expireTime *time.Time
		if backup.ExpireTime != nil {
			t := backup.ExpireTime.AsTime()
			expireTime = &t
		}
		var createTime *time.Time
		if backup.CreateTime != nil {
			t := backup.CreateTime.AsTime()
			createTime = &t
		}

		mqlBackup, err := CreateResource(g.MqlRuntime, "gcp.project.redisService.cluster.backup", map[string]*llx.RawData{
			"projectId":      llx.StringData(projectId),
			"name":           llx.StringData(backup.Name),
			"uid":            llx.StringData(backup.Uid),
			"createTime":     llx.TimeDataPtr(createTime),
			"expireTime":     llx.TimeDataPtr(expireTime),
			"cluster":        llx.StringData(backup.Cluster),
			"clusterUid":     llx.StringData(backup.ClusterUid),
			"totalSizeBytes": llx.IntData(backup.TotalSizeBytes),
			"engineVersion":  llx.StringData(backup.EngineVersion),
			"nodeType":       llx.StringData(backup.NodeType.String()),
			"replicaCount":   llx.IntData(int64(backup.ReplicaCount)),
			"shardCount":     llx.IntData(int64(backup.ShardCount)),
			"backupType":     llx.StringData(backup.BackupType.String()),
			"state":          llx.StringData(backup.State.String()),
			"encryptionInfo": llx.DictData(encryptionInfo),
			"backupFiles":    llx.ArrayData(backupFiles, types.Resource("gcp.project.redisService.cluster.backup.backupFile")),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBackup)
	}

	return res, nil
}

func clusterConvertBackupFiles(runtime *plugin.Runtime, projectId, backupName string, files []*clusterpb.BackupFile) ([]any, error) {
	res := make([]any, 0, len(files))
	for _, f := range files {
		if f == nil {
			continue
		}
		var createTime *llx.RawData
		if f.CreateTime != nil {
			createTime = llx.TimeData(f.CreateTime.AsTime())
		} else {
			createTime = llx.NilData
		}
		mqlFile, err := CreateResource(runtime, "gcp.project.redisService.cluster.backup.backupFile", map[string]*llx.RawData{
			"projectId":  llx.StringData(projectId),
			"backupName": llx.StringData(backupName),
			"fileName":   llx.StringData(f.FileName),
			"sizeBytes":  llx.IntData(f.SizeBytes),
			"createTime": createTime,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFile)
	}
	return res, nil
}

func (c *mqlGcpProjectRedisServiceClusterBackupBackupFile) id() (string, error) {
	if c.BackupName.Error != nil {
		return "", c.BackupName.Error
	}
	if c.FileName.Error != nil {
		return "", c.FileName.Error
	}
	return fmt.Sprintf("%s/backupFiles/%s", c.BackupName.Data, c.FileName.Data), nil
}

// ===== Cluster endpoint converters =====

func clusterConvertClusterEndpoints(runtime *plugin.Runtime, projectId, clusterName string, endpoints []*clusterpb.ClusterEndpoint) (list []any) {
	for i, ep := range endpoints {
		if ep == nil {
			continue
		}
		connections := clusterConvertConnectionDetails(runtime, projectId, clusterName, ep.Connections)
		id := fmt.Sprintf("gcp.project.redisService.cluster.clusterEndpoint/%s/%s/%d", projectId, clusterName, i)
		r, err := CreateResource(runtime, "gcp.project.redisService.cluster.clusterEndpoint", map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"projectId":   llx.StringData(projectId),
			"clusterName": llx.StringData(clusterName),
			"connections": llx.ArrayData(
				connections,
				types.Resource("gcp.project.redisService.cluster.connectionDetail"),
			),
		})
		if err != nil {
			continue
		}
		list = append(list, r)
	}
	return
}

func clusterConvertConnectionDetails(runtime *plugin.Runtime, projectId, clusterName string, details []*clusterpb.ConnectionDetail) (list []any) {
	for _, d := range details {
		if d == nil {
			continue
		}

		var pscConnectionId, address, forwardingRule, connectionProjectId string
		var network, serviceAttachment, pscConnectionStatus, connectionType string
		var connectionOrigin string

		if auto := d.GetPscAutoConnection(); auto != nil {
			connectionOrigin = "AUTO"
			pscConnectionId = auto.PscConnectionId
			address = auto.Address
			forwardingRule = auto.ForwardingRule
			connectionProjectId = auto.ProjectId
			network = auto.Network
			serviceAttachment = auto.ServiceAttachment
			pscConnectionStatus = auto.PscConnectionStatus.String()
			connectionType = auto.ConnectionType.String()
		} else if psc := d.GetPscConnection(); psc != nil {
			connectionOrigin = "USER"
			pscConnectionId = psc.PscConnectionId
			address = psc.Address
			forwardingRule = psc.ForwardingRule
			connectionProjectId = psc.ProjectId
			network = psc.Network
			serviceAttachment = psc.ServiceAttachment
			pscConnectionStatus = psc.PscConnectionStatus.String()
			connectionType = psc.ConnectionType.String()
		}

		r, err := CreateResource(runtime, "gcp.project.redisService.cluster.connectionDetail", map[string]*llx.RawData{
			"projectId":           llx.StringData(projectId),
			"clusterName":         llx.StringData(clusterName),
			"pscConnectionId":     llx.StringData(pscConnectionId),
			"address":             llx.StringData(address),
			"forwardingRule":      llx.StringData(forwardingRule),
			"connectionProjectId": llx.StringData(connectionProjectId),
			"network":             llx.StringData(network),
			"serviceAttachment":   llx.StringData(serviceAttachment),
			"pscConnectionStatus": llx.StringData(pscConnectionStatus),
			"connectionType":      llx.StringData(connectionType),
			"connectionOrigin":    llx.StringData(connectionOrigin),
		})
		if err != nil {
			continue
		}
		list = append(list, r)
	}
	return
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectRedisService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_redis)
}
