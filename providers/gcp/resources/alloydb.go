// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	alloydb "cloud.google.com/go/alloydb/apiv1"
	"cloud.google.com/go/alloydb/apiv1/alloydbpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) alloydb() (*mqlGcpProjectAlloydbService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.alloydbService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectAlloydbService), nil
}

func initGcpProjectAlloydbService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectAlloydbService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/alloydbService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectAlloydbService) clusters() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(alloydb.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := alloydb.NewAlloyDBAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListClusters(ctx, &alloydbpb.ListClustersRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		cluster, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list AlloyDB clusters")
				break
			}
			return nil, err
		}

		networkConfig, err := protoToDict(cluster.NetworkConfig)
		if err != nil {
			return nil, err
		}
		encryptionConfig, err := protoToDict(cluster.EncryptionConfig)
		if err != nil {
			return nil, err
		}
		encryptionInfo, err := protoToDict(cluster.EncryptionInfo)
		if err != nil {
			return nil, err
		}
		automatedBackupPolicy, err := protoToDict(cluster.AutomatedBackupPolicy)
		if err != nil {
			return nil, err
		}
		continuousBackupConfig, err := protoToDict(cluster.ContinuousBackupConfig)
		if err != nil {
			return nil, err
		}
		continuousBackupInfo, err := protoToDict(cluster.ContinuousBackupInfo)
		if err != nil {
			return nil, err
		}
		sslConfig, err := protoToDict(cluster.SslConfig)
		if err != nil {
			return nil, err
		}
		primaryConfig, err := protoToDict(cluster.PrimaryConfig)
		if err != nil {
			return nil, err
		}
		secondaryConfig, err := protoToDict(cluster.SecondaryConfig)
		if err != nil {
			return nil, err
		}
		maintenanceUpdatePolicy, err := protoToDict(cluster.MaintenanceUpdatePolicy)
		if err != nil {
			return nil, err
		}
		maintenanceSchedule, err := protoToDict(cluster.MaintenanceSchedule)
		if err != nil {
			return nil, err
		}

		var createdAt *llx.RawData
		if cluster.CreateTime != nil {
			createdAt = llx.TimeData(cluster.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}

		var updatedAt *llx.RawData
		if cluster.UpdateTime != nil {
			updatedAt = llx.TimeData(cluster.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		// Extract location from the cluster name: projects/{project}/locations/{location}/clusters/{cluster}
		location := ""
		if parts := parseAlloyDBClusterName(cluster.Name); parts != nil {
			location = parts.location
		}

		mqlCluster, err := CreateResource(g.MqlRuntime, "gcp.project.alloydbService.cluster", map[string]*llx.RawData{
			"projectId":               llx.StringData(projectId),
			"name":                    llx.StringData(cluster.Name),
			"displayName":             llx.StringData(cluster.DisplayName),
			"uid":                     llx.StringData(cluster.Uid),
			"state":                   llx.StringData(cluster.State.String()),
			"clusterType":             llx.StringData(cluster.ClusterType.String()),
			"databaseVersion":         llx.StringData(cluster.DatabaseVersion.String()),
			"networkConfig":           llx.DictData(networkConfig),
			"pscEnabled":              llx.BoolData(cluster.GetPscConfig().GetPscEnabled()),
			"encryptionConfig":        llx.DictData(encryptionConfig),
			"encryptionInfo":          llx.DictData(encryptionInfo),
			"automatedBackupPolicy":   llx.DictData(automatedBackupPolicy),
			"continuousBackupConfig":  llx.DictData(continuousBackupConfig),
			"continuousBackupInfo":    llx.DictData(continuousBackupInfo),
			"sslConfig":               llx.DictData(sslConfig),
			"labels":                  llx.MapData(convert.MapToInterfaceMap(cluster.Labels), types.String),
			"annotations":             llx.MapData(convert.MapToInterfaceMap(cluster.Annotations), types.String),
			"primaryConfig":           llx.DictData(primaryConfig),
			"secondaryConfig":         llx.DictData(secondaryConfig),
			"maintenanceUpdatePolicy": llx.DictData(maintenanceUpdatePolicy),
			"maintenanceSchedule":     llx.DictData(maintenanceSchedule),
			"location":                llx.StringData(location),
			"reconciling":             llx.BoolData(cluster.Reconciling),
			"etag":                    llx.StringData(cluster.Etag),
			"createdAt":               createdAt,
			"updatedAt":               updatedAt,
		})
		if err != nil {
			return nil, err
		}
		mqlAlloyCluster := mqlCluster.(*mqlGcpProjectAlloydbServiceCluster)
		if cluster.EncryptionConfig != nil {
			mqlAlloyCluster.cacheKmsKeyName = cluster.EncryptionConfig.KmsKeyName
		}
		if cluster.NetworkConfig != nil {
			mqlAlloyCluster.cacheNetworkName = cluster.NetworkConfig.Network
		}
		if cluster.SecondaryConfig != nil {
			mqlAlloyCluster.cachePrimaryClusterName = cluster.SecondaryConfig.PrimaryClusterName
		}
		if cluster.PrimaryConfig != nil {
			mqlAlloyCluster.cacheSecondaryClusterNames = cluster.PrimaryConfig.SecondaryClusterNames
		}
		res = append(res, mqlCluster)
	}

	return res, nil
}

type mqlGcpProjectAlloydbServiceClusterInternal struct {
	cacheKmsKeyName            string
	cacheNetworkName           string
	cachePrimaryClusterName    string
	cacheSecondaryClusterNames []string
}

type mqlGcpProjectAlloydbServiceBackupInternal struct {
	cacheKmsKeyName string
}

// getAlloyDBClusterByName resolves an AlloyDB cluster by its full resource name
// (projects/{project}/locations/{location}/clusters/{cluster}). It lists the
// referenced project's clusters (served from the runtime cache when the parent
// traversal already listed them) and matches by full name. Returns nil when the
// name is empty, malformed, or no matching cluster exists (for example a source
// cluster that has since been deleted).
func getAlloyDBClusterByName(runtime *plugin.Runtime, resourceName string) (*mqlGcpProjectAlloydbServiceCluster, error) {
	if resourceName == "" {
		return nil, nil
	}
	parts := parseAlloyDBClusterName(resourceName)
	if parts == nil {
		return nil, nil
	}
	obj, err := CreateResource(runtime, "gcp.project.alloydbService", map[string]*llx.RawData{
		"projectId": llx.StringData(parts.project),
	})
	if err != nil {
		return nil, err
	}
	svc := obj.(*mqlGcpProjectAlloydbService)
	clusters := svc.GetClusters()
	if clusters.Error != nil {
		return nil, clusters.Error
	}
	for _, c := range clusters.Data {
		cluster := c.(*mqlGcpProjectAlloydbServiceCluster)
		if cluster.Name.Error != nil {
			return nil, cluster.Name.Error
		}
		if cluster.Name.Data == resourceName {
			return cluster, nil
		}
	}
	return nil, nil
}

func (g *mqlGcpProjectAlloydbServiceCluster) network() (*mqlGcpProjectComputeServiceNetwork, error) {
	n, err := getNetworkByUrl(g.cacheNetworkName, g.MqlRuntime)
	if err != nil {
		return nil, err
	}
	if n == nil {
		g.Network.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return n, nil
}

func (g *mqlGcpProjectAlloydbServiceCluster) primaryCluster() (*mqlGcpProjectAlloydbServiceCluster, error) {
	c, err := getAlloyDBClusterByName(g.MqlRuntime, g.cachePrimaryClusterName)
	if err != nil {
		return nil, err
	}
	if c == nil {
		g.PrimaryCluster.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return c, nil
}

func (g *mqlGcpProjectAlloydbServiceCluster) secondaryClusters() ([]any, error) {
	res := []any{}
	for _, name := range g.cacheSecondaryClusterNames {
		c, err := getAlloyDBClusterByName(g.MqlRuntime, name)
		if err != nil {
			return nil, err
		}
		if c != nil {
			res = append(res, c)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectAlloydbServiceCluster) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels(), g.GetAnnotations())
}

func (g *mqlGcpProjectAlloydbServiceCluster) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}

func (g *mqlGcpProjectAlloydbServiceCluster) users() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	clusterName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(alloydb.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := alloydb.NewAlloyDBAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	res := []any{}
	it := client.ListUsers(ctx, &alloydbpb.ListUsersRequest{Parent: clusterName})
	for {
		user, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list AlloyDB users")
				break
			}
			return nil, err
		}
		mqlUser, err := CreateResource(g.MqlRuntime, "gcp.project.alloydbService.cluster.user", map[string]*llx.RawData{
			"projectId":     llx.StringData(projectId),
			"clusterName":   llx.StringData(clusterName),
			"name":          llx.StringData(user.Name),
			"userType":      llx.StringData(user.UserType.String()),
			"databaseRoles": llx.ArrayData(convert.SliceAnyToInterface(user.DatabaseRoles), types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}
	return res, nil
}

func (g *mqlGcpProjectAlloydbServiceClusterUser) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

type alloyDBClusterParts struct {
	project  string
	location string
	cluster  string
}

func parseAlloyDBClusterName(name string) *alloyDBClusterParts {
	// Format: projects/{project}/locations/{location}/clusters/{cluster}
	parts := strings.Split(name, "/")
	if len(parts) < 6 {
		return nil
	}
	return &alloyDBClusterParts{
		project:  parts[1],
		location: parts[3],
		cluster:  parts[5],
	}
}

func initGcpProjectAlloydbServiceCluster(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
		return nil, nil, errors.New("gcp.project.alloydbService.cluster requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.alloydbService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	alloydbSvc := obj.(*mqlGcpProjectAlloydbService)
	clusters := alloydbSvc.GetClusters()
	if clusters.Error != nil {
		return nil, nil, clusters.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.alloydbService.cluster requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	locationVal := ""
	if args["location"] != nil {
		locationVal, _ = args["location"].Value.(string)
	}
	for _, c := range clusters.Data {
		cluster := c.(*mqlGcpProjectAlloydbServiceCluster)
		nameParts := strings.Split(cluster.Name.Data, "/")
		clusterName := nameParts[len(nameParts)-1]

		if clusterName == nameVal && (locationVal == "" || cluster.Location.Data == locationVal) {
			return args, cluster, nil
		}
	}

	return nil, nil, fmt.Errorf("AlloyDB cluster %q not found", nameVal)
}

func (g *mqlGcpProjectAlloydbServiceCluster) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/alloydbService/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectAlloydbServiceCluster) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	clusterName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(alloydb.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := alloydb.NewAlloyDBAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInstances(ctx, &alloydbpb.ListInstancesRequest{
		Parent: clusterName,
	})

	var res []any
	for {
		inst, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list AlloyDB instances")
				break
			}
			return nil, err
		}

		machineConfig, err := protoToDict(inst.MachineConfig)
		if err != nil {
			return nil, err
		}
		queryInsightsConfig, err := protoToDict(inst.QueryInsightsConfig)
		if err != nil {
			return nil, err
		}
		readPoolConfig, err := protoToDict(inst.ReadPoolConfig)
		if err != nil {
			return nil, err
		}
		clientConnectionConfig, err := protoToDict(inst.ClientConnectionConfig)
		if err != nil {
			return nil, err
		}
		pscInstanceConfig, err := protoToDict(inst.PscInstanceConfig)
		if err != nil {
			return nil, err
		}
		networkConfig, err := protoToDict(inst.NetworkConfig)
		if err != nil {
			return nil, err
		}
		var enablePublicIp bool
		if inst.NetworkConfig != nil {
			enablePublicIp = inst.NetworkConfig.EnablePublicIp
		}
		connectionPoolConfig, err := protoToDict(inst.ConnectionPoolConfig)
		if err != nil {
			return nil, err
		}
		writableNode, err := protoToDict(inst.WritableNode)
		if err != nil {
			return nil, err
		}

		nodes := make([]any, 0, len(inst.Nodes))
		for _, node := range inst.Nodes {
			nodeDict, err := protoToDict(node)
			if err != nil {
				return nil, err
			}
			nodes = append(nodes, nodeDict)
		}

		var createdAt *llx.RawData
		if inst.CreateTime != nil {
			createdAt = llx.TimeData(inst.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}

		var updatedAt *llx.RawData
		if inst.UpdateTime != nil {
			updatedAt = llx.TimeData(inst.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		mqlInst, err := CreateResource(g.MqlRuntime, "gcp.project.alloydbService.instance", map[string]*llx.RawData{
			"projectId":                 llx.StringData(projectId),
			"clusterName":               llx.StringData(clusterName),
			"name":                      llx.StringData(inst.Name),
			"displayName":               llx.StringData(inst.DisplayName),
			"uid":                       llx.StringData(inst.Uid),
			"state":                     llx.StringData(inst.State.String()),
			"instanceType":              llx.StringData(inst.InstanceType.String()),
			"machineConfig":             llx.DictData(machineConfig),
			"availabilityType":          llx.StringData(inst.AvailabilityType.String()),
			"gceZone":                   llx.StringData(inst.GceZone),
			"ipAddress":                 llx.StringData(inst.IpAddress),
			"publicIpAddress":           llx.StringData(inst.PublicIpAddress),
			"networkConfig":             llx.DictData(networkConfig),
			"enablePublicIp":            llx.BoolData(enablePublicIp),
			"outboundPublicIpAddresses": llx.ArrayData(convert.SliceAnyToInterface(inst.OutboundPublicIpAddresses), types.String),
			"databaseFlags":             llx.MapData(convert.MapToInterfaceMap(inst.DatabaseFlags), types.String),
			"labels":                    llx.MapData(convert.MapToInterfaceMap(inst.Labels), types.String),
			"queryInsightsConfig":       llx.DictData(queryInsightsConfig),
			"readPoolConfig":            llx.DictData(readPoolConfig),
			"clientConnectionConfig":    llx.DictData(clientConnectionConfig),
			"pscInstanceConfig":         llx.DictData(pscInstanceConfig),
			"activationPolicy":          llx.StringData(inst.ActivationPolicy.String()),
			"connectionPoolConfig":      llx.DictData(connectionPoolConfig),
			"nodes":                     llx.ArrayData(nodes, types.Dict),
			"writableNode":              llx.DictData(writableNode),
			"reconciling":               llx.BoolData(inst.Reconciling),
			"etag":                      llx.StringData(inst.Etag),
			"createdAt":                 createdAt,
			"updatedAt":                 updatedAt,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInst)
	}

	return res, nil
}

func (g *mqlGcpProjectAlloydbServiceInstance) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/alloydbService/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectAlloydbServiceCluster) backups() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	clusterName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(alloydb.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := alloydb.NewAlloyDBAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// Extract location from cluster name for the backup list parent
	location := ""
	if parts := parseAlloyDBClusterName(clusterName); parts != nil {
		location = parts.location
	}
	if location == "" {
		location = "-"
	}

	it := client.ListBackups(ctx, &alloydbpb.ListBackupsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/%s", projectId, location),
		Filter: fmt.Sprintf("cluster_name=%q", clusterName),
	})

	var res []any
	for {
		backup, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list AlloyDB backups")
				break
			}
			return nil, err
		}

		encryptionConfig, err := protoToDict(backup.EncryptionConfig)
		if err != nil {
			return nil, err
		}
		encryptionInfo, err := protoToDict(backup.EncryptionInfo)
		if err != nil {
			return nil, err
		}
		expiryQuantity, err := protoToDict(backup.ExpiryQuantity)
		if err != nil {
			return nil, err
		}

		var createdAt *llx.RawData
		if backup.CreateTime != nil {
			createdAt = llx.TimeData(backup.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}

		var updatedAt *llx.RawData
		if backup.UpdateTime != nil {
			updatedAt = llx.TimeData(backup.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		var expiryTime *llx.RawData
		if backup.ExpiryTime != nil {
			expiryTime = llx.TimeData(backup.ExpiryTime.AsTime())
		} else {
			expiryTime = llx.NilData
		}

		mqlBackup, err := CreateResource(g.MqlRuntime, "gcp.project.alloydbService.backup", map[string]*llx.RawData{
			"projectId":        llx.StringData(projectId),
			"name":             llx.StringData(backup.Name),
			"displayName":      llx.StringData(backup.DisplayName),
			"uid":              llx.StringData(backup.Uid),
			"state":            llx.StringData(backup.State.String()),
			"type":             llx.StringData(backup.Type.String()),
			"description":      llx.StringData(backup.Description),
			"clusterName":      llx.StringData(backup.ClusterName),
			"databaseVersion":  llx.StringData(backup.DatabaseVersion.String()),
			"encryptionConfig": llx.DictData(encryptionConfig),
			"encryptionInfo":   llx.DictData(encryptionInfo),
			"sizeBytes":        llx.IntData(backup.SizeBytes),
			"expiryTime":       expiryTime,
			"expiryQuantity":   llx.DictData(expiryQuantity),
			"labels":           llx.MapData(convert.MapToInterfaceMap(backup.Labels), types.String),
			"etag":             llx.StringData(backup.Etag),
			"reconciling":      llx.BoolData(backup.Reconciling),
			"createdAt":        createdAt,
			"updatedAt":        updatedAt,
		})
		if err != nil {
			return nil, err
		}
		mqlAlloyBackup := mqlBackup.(*mqlGcpProjectAlloydbServiceBackup)
		if backup.EncryptionConfig != nil {
			mqlAlloyBackup.cacheKmsKeyName = backup.EncryptionConfig.KmsKeyName
		}
		res = append(res, mqlBackup)
	}

	return res, nil
}

func (g *mqlGcpProjectAlloydbServiceBackup) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/alloydbService/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectAlloydbServiceBackup) sourceCluster() (*mqlGcpProjectAlloydbServiceCluster, error) {
	if g.ClusterName.Error != nil {
		return nil, g.ClusterName.Error
	}
	c, err := getAlloyDBClusterByName(g.MqlRuntime, g.ClusterName.Data)
	if err != nil {
		return nil, err
	}
	if c == nil {
		g.SourceCluster.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return c, nil
}

func (g *mqlGcpProjectAlloydbServiceBackup) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
	if g.cacheKmsKeyName == "" {
		g.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
		map[string]*llx.RawData{"resourcePath": llx.StringData(g.cacheKmsKeyName)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectKmsServiceKeyringCryptokey), nil
}
