// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	memorystore "cloud.google.com/go/memorystore/apiv1"
	"cloud.google.com/go/memorystore/apiv1/memorystorepb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) memorystore() (*mqlGcpProjectMemorystoreService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.memorystoreService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectMemorystoreService), nil
}

func initGcpProjectMemorystoreService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

func (g *mqlGcpProjectMemorystoreService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/memorystoreService", g.ProjectId.Data), nil
}

// =====================
// Instance
// =====================

func (g *mqlGcpProjectMemorystoreServiceInstance) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

type mqlGcpProjectMemorystoreServiceInstanceInternal struct {
	cacheKmsKey           string
	cacheBackupCollection string
}

func (g *mqlGcpProjectMemorystoreServiceInstance) managedBy() (string, error) {
	return managedByFromLabels(&g.Labels)
}

func (g *mqlGcpProjectMemorystoreServiceInstance) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
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

func (g *mqlGcpProjectMemorystoreServiceInstance) backupCollection() (*mqlGcpProjectMemorystoreServiceBackupCollection, error) {
	if g.cacheBackupCollection == "" {
		g.BackupCollection.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.memorystoreService.backupCollection",
		map[string]*llx.RawData{"name": llx.StringData(g.cacheBackupCollection)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectMemorystoreServiceBackupCollection), nil
}

func (g *mqlGcpProjectMemorystoreService) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(memorystore.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := memorystore.NewRESTClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInstances(ctx, &memorystorepb.ListInstancesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		inst, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlInst, err := mqlMemorystoreInstanceFromProto(g.MqlRuntime, projectId, inst)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInst)
	}

	return res, nil
}

func mqlMemorystoreInstanceFromProto(runtime *plugin.Runtime, projectId string, inst *memorystorepb.Instance) (*mqlGcpProjectMemorystoreServiceInstance, error) {
	stateInfo, err := protoToDict(inst.StateInfo)
	if err != nil {
		return nil, err
	}
	persistenceConfig, err := protoToDict(inst.PersistenceConfig)
	if err != nil {
		return nil, err
	}
	maintenancePolicy, err := protoToDict(inst.MaintenancePolicy)
	if err != nil {
		return nil, err
	}
	maintenanceSchedule, err := protoToDict(inst.MaintenanceSchedule)
	if err != nil {
		return nil, err
	}
	encryptionInfo, err := protoToDict(inst.EncryptionInfo)
	if err != nil {
		return nil, err
	}
	zoneDistConfig, err := protoToDict(inst.ZoneDistributionConfig)
	if err != nil {
		return nil, err
	}
	crossRepl, err := protoToDict(inst.CrossInstanceReplicationConfig)
	if err != nil {
		return nil, err
	}
	autoBackup, err := protoToDict(inst.AutomatedBackupConfig)
	if err != nil {
		return nil, err
	}
	endpoints := make([]any, 0, len(inst.Endpoints))
	for _, ep := range inst.Endpoints {
		d, err := protoToDict(ep)
		if err != nil {
			return nil, err
		}
		endpoints = append(endpoints, d)
	}

	var nodeSizeGb int64
	if inst.NodeConfig != nil {
		nodeSizeGb = int64(inst.NodeConfig.SizeGb)
	}

	var replicaCount int64
	if inst.ReplicaCount != nil {
		replicaCount = int64(*inst.ReplicaCount)
	}
	var deletionProtection bool
	if inst.DeletionProtectionEnabled != nil {
		deletionProtection = *inst.DeletionProtectionEnabled
	}

	kmsKey := ""
	if inst.KmsKey != nil {
		kmsKey = *inst.KmsKey
	}
	backupCollection := ""
	if inst.BackupCollection != nil {
		backupCollection = *inst.BackupCollection
	}
	serverCaPool := ""
	if inst.ServerCaPool != nil {
		serverCaPool = *inst.ServerCaPool
	}
	serverCaMode := ""
	if inst.ServerCaMode != nil {
		serverCaMode = inst.ServerCaMode.String()
	}

	pscAttach, err := buildMemorystorePscAttachmentDetails(runtime, projectId, inst.Name, inst.PscAttachmentDetails)
	if err != nil {
		return nil, err
	}

	var createTime, updateTime *llx.RawData
	if inst.CreateTime != nil {
		createTime = llx.TimeData(inst.CreateTime.AsTime())
	} else {
		createTime = llx.NilData
	}
	if inst.UpdateTime != nil {
		updateTime = llx.TimeData(inst.UpdateTime.AsTime())
	} else {
		updateTime = llx.NilData
	}

	res, err := CreateResource(runtime, "gcp.project.memorystoreService.instance", map[string]*llx.RawData{
		"projectId":                      llx.StringData(projectId),
		"name":                           llx.StringData(inst.Name),
		"uid":                            llx.StringData(inst.Uid),
		"labels":                         llx.MapData(convert.MapToInterfaceMap(inst.Labels), types.String),
		"state":                          llx.StringData(inst.State.String()),
		"stateInfo":                      llx.DictData(stateInfo),
		"mode":                           llx.StringData(inst.Mode.String()),
		"nodeType":                       llx.StringData(inst.NodeType.String()),
		"replicaCount":                   llx.IntData(replicaCount),
		"shardCount":                     llx.IntData(int64(inst.ShardCount)),
		"nodeSizeGb":                     llx.IntData(nodeSizeGb),
		"engineVersion":                  llx.StringData(inst.EngineVersion),
		"engineConfigs":                  llx.MapData(convert.MapToInterfaceMap(inst.EngineConfigs), types.String),
		"authorizationMode":              llx.StringData(inst.AuthorizationMode.String()),
		"serverCaMode":                   llx.StringData(serverCaMode),
		"serverCaPool":                   llx.StringData(serverCaPool),
		"transitEncryptionMode":          llx.StringData(inst.TransitEncryptionMode.String()),
		"encryptionInfo":                 llx.DictData(encryptionInfo),
		"persistenceConfig":              llx.DictData(persistenceConfig),
		"maintenancePolicy":              llx.DictData(maintenancePolicy),
		"maintenanceSchedule":            llx.DictData(maintenanceSchedule),
		"maintenanceVersion":             llx.StringDataPtr(inst.MaintenanceVersion),
		"effectiveMaintenanceVersion":    llx.StringDataPtr(inst.EffectiveMaintenanceVersion),
		"availableMaintenanceVersions":   llx.ArrayData(convert.SliceAnyToInterface(inst.AvailableMaintenanceVersions), types.String),
		"deletionProtectionEnabled":      llx.BoolData(deletionProtection),
		"zoneDistributionConfig":         llx.DictData(zoneDistConfig),
		"crossInstanceReplicationConfig": llx.DictData(crossRepl),
		"automatedBackupConfig":          llx.DictData(autoBackup),
		"satisfiesPzi":                   llx.BoolDataPtr(inst.SatisfiesPzi),
		"satisfiesPzs":                   llx.BoolDataPtr(inst.SatisfiesPzs),
		"pscAttachmentDetails":           llx.ArrayData(pscAttach, types.Resource("gcp.project.memorystoreService.instance.pscAttachmentDetail")),
		"endpoints":                      llx.ArrayData(endpoints, types.Dict),
		"createTime":                     createTime,
		"updateTime":                     updateTime,
	})
	if err != nil {
		return nil, err
	}
	mqlInst := res.(*mqlGcpProjectMemorystoreServiceInstance)
	mqlInst.cacheKmsKey = kmsKey
	mqlInst.cacheBackupCollection = backupCollection
	return mqlInst, nil
}

func initGcpProjectMemorystoreServiceInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		args = make(map[string]*llx.RawData)
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["name"] = llx.StringData(ids.name)
			args["projectId"] = llx.StringData(ids.project)
			args["location"] = llx.StringData(ids.region)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.memorystoreService.instance requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.memorystoreService.instance requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	creds, err := conn.Credentials(memorystore.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := memorystore.NewRESTClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	// Accept either the full resource path or a short name + location from
	// the asset-identifier-driven discovery path.
	var fullName, projectId string
	if strings.HasPrefix(name, "projects/") {
		fullName = name
		projectId = parseProjectFromPath(name)
	} else {
		locRaw := args["location"]
		projRaw := args["projectId"]
		if locRaw == nil || projRaw == nil {
			return nil, nil, errors.New("memorystore instance init: projectId and location required when name is not a full resource path")
		}
		projectId, _ = projRaw.Value.(string)
		location, _ := locRaw.Value.(string)
		fullName = fmt.Sprintf("projects/%s/locations/%s/instances/%s", projectId, location, name)
	}

	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. Placed here rather than earlier because projectId is only
	// known once the name has been resolved. Memoized per project.
	if enabled, err := serviceEnabledForInit(runtime, projectId, service_memorystore); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Memorystore API is not enabled on project " + projectId)
	}

	inst, err := client.GetInstance(ctx, &memorystorepb.GetInstanceRequest{Name: fullName})
	if err != nil {
		return nil, nil, err
	}

	res, err := mqlMemorystoreInstanceFromProto(runtime, projectId, inst)
	if err != nil {
		return nil, nil, err
	}
	delete(args, "location")
	return args, res, nil
}

// =====================
// PscAttachmentDetail
// =====================

func (g *mqlGcpProjectMemorystoreServiceInstancePscAttachmentDetail) id() (string, error) {
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.ServiceAttachment.Error != nil {
		return "", g.ServiceAttachment.Error
	}
	return fmt.Sprintf("%s/pscAttachmentDetails/%s", g.InstanceName.Data, g.ServiceAttachment.Data), nil
}

func buildMemorystorePscAttachmentDetails(runtime *plugin.Runtime, projectId, instanceName string, details []*memorystorepb.PscAttachmentDetail) ([]any, error) {
	res := make([]any, 0, len(details))
	for _, d := range details {
		if d == nil {
			continue
		}
		mqlDetail, err := CreateResource(runtime, "gcp.project.memorystoreService.instance.pscAttachmentDetail", map[string]*llx.RawData{
			"projectId":         llx.StringData(projectId),
			"instanceName":      llx.StringData(instanceName),
			"serviceAttachment": llx.StringData(d.ServiceAttachment),
			"connectionType":    llx.StringData(d.ConnectionType.String()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDetail)
	}
	return res, nil
}

// =====================
// TokenAuthUser
// =====================

func (g *mqlGcpProjectMemorystoreServiceInstanceTokenAuthUser) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func (g *mqlGcpProjectMemorystoreServiceInstance) tokenAuthUsers() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	creds, err := conn.Credentials(memorystore.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := memorystore.NewRESTClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListTokenAuthUsers(ctx, &memorystorepb.ListTokenAuthUsersRequest{Parent: instanceName})

	res := []any{}
	for {
		user, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				log.Debug().Err(err).Str("instance", instanceName).Msg("gcp> skipping memorystore token auth users")
				return res, nil
			}
			return nil, err
		}
		mqlUser, err := CreateResource(g.MqlRuntime, "gcp.project.memorystoreService.instance.tokenAuthUser", map[string]*llx.RawData{
			"projectId": llx.StringData(projectId),
			"name":      llx.StringData(user.Name),
			"state":     llx.StringData(user.State.String()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlUser)
	}

	return res, nil
}

// =====================
// AuthToken
// =====================

func (g *mqlGcpProjectMemorystoreServiceInstanceTokenAuthUserAuthToken) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func (g *mqlGcpProjectMemorystoreServiceInstanceTokenAuthUser) authTokens() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	userName := g.Name.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	creds, err := conn.Credentials(memorystore.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := memorystore.NewRESTClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListAuthTokens(ctx, &memorystorepb.ListAuthTokensRequest{Parent: userName})

	res := []any{}
	for {
		token, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isInapplicable(err) {
				log.Debug().Err(err).Str("tokenAuthUser", userName).Msg("gcp> skipping memorystore auth tokens")
				return res, nil
			}
			return nil, err
		}
		// The secret token value (token.Token) is deliberately not modeled.
		mqlToken, err := CreateResource(g.MqlRuntime, "gcp.project.memorystoreService.instance.tokenAuthUser.authToken", map[string]*llx.RawData{
			"projectId":  llx.StringData(projectId),
			"name":       llx.StringData(token.Name),
			"state":      llx.StringData(token.State.String()),
			"createTime": llx.TimeDataPtr(timestampAsTimePtr(token.CreateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlToken)
	}

	return res, nil
}

// =====================
// BackupCollection
// =====================

func (g *mqlGcpProjectMemorystoreServiceBackupCollection) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

type mqlGcpProjectMemorystoreServiceBackupCollectionInternal struct {
	cacheInstance string
	cacheKmsKey   string
}

func (g *mqlGcpProjectMemorystoreServiceBackupCollection) instance() (*mqlGcpProjectMemorystoreServiceInstance, error) {
	if g.cacheInstance == "" {
		g.Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.memorystoreService.instance",
		map[string]*llx.RawData{"name": llx.StringData(g.cacheInstance)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectMemorystoreServiceInstance), nil
}

func (g *mqlGcpProjectMemorystoreServiceBackupCollection) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
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

func (g *mqlGcpProjectMemorystoreService) backupCollections() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(memorystore.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := memorystore.NewRESTClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackupCollections(ctx, &memorystorepb.ListBackupCollectionsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		bc, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlBc, err := mqlMemorystoreBackupCollectionFromProto(g.MqlRuntime, projectId, bc)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBc)
	}

	return res, nil
}

func mqlMemorystoreBackupCollectionFromProto(runtime *plugin.Runtime, projectId string, bc *memorystorepb.BackupCollection) (*mqlGcpProjectMemorystoreServiceBackupCollection, error) {
	var createTime, lastBackupTime *llx.RawData
	if bc.CreateTime != nil {
		createTime = llx.TimeData(bc.CreateTime.AsTime())
	} else {
		createTime = llx.NilData
	}
	if bc.LastBackupTime != nil {
		lastBackupTime = llx.TimeData(bc.LastBackupTime.AsTime())
	} else {
		lastBackupTime = llx.NilData
	}

	res, err := CreateResource(runtime, "gcp.project.memorystoreService.backupCollection", map[string]*llx.RawData{
		"projectId":            llx.StringData(projectId),
		"name":                 llx.StringData(bc.Name),
		"uid":                  llx.StringData(bc.Uid),
		"instanceUid":          llx.StringData(bc.InstanceUid),
		"totalBackupCount":     llx.IntData(bc.TotalBackupCount),
		"totalBackupSizeBytes": llx.IntData(bc.TotalBackupSizeBytes),
		"lastBackupTime":       lastBackupTime,
		"createTime":           createTime,
	})
	if err != nil {
		return nil, err
	}
	mqlBc := res.(*mqlGcpProjectMemorystoreServiceBackupCollection)
	mqlBc.cacheInstance = bc.Instance
	mqlBc.cacheKmsKey = bc.KmsKey
	return mqlBc, nil
}

func initGcpProjectMemorystoreServiceBackupCollection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.memorystoreService.backupCollection requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.memorystoreService.backupCollection requires a non-empty "name" argument`)
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	// Ask whether the API is on before paying for a Get that cannot succeed
	// without it. Memoized per project, so this is free after the first caller.
	if enabled, err := serviceEnabledForInit(runtime, conn.ResourceID(), service_memorystore); err != nil {
		return nil, nil, err
	} else if !enabled {
		return nil, nil, errors.New("Memorystore API is not enabled on project " + conn.ResourceID())
	}

	creds, err := conn.Credentials(memorystore.DefaultAuthScopes()...)
	if err != nil {
		return nil, nil, err
	}
	ctx := context.Background()
	client, err := memorystore.NewRESTClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, nil, err
	}
	defer client.Close()

	bc, err := client.GetBackupCollection(ctx, &memorystorepb.GetBackupCollectionRequest{Name: name})
	if err != nil {
		return nil, nil, err
	}

	res, err := mqlMemorystoreBackupCollectionFromProto(runtime, conn.ResourceID(), bc)
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// =====================
// Backup
// =====================

func (g *mqlGcpProjectMemorystoreServiceBackup) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

type mqlGcpProjectMemorystoreServiceBackupInternal struct {
	cacheInstance string
}

func (g *mqlGcpProjectMemorystoreServiceBackup) instance() (*mqlGcpProjectMemorystoreServiceInstance, error) {
	if g.cacheInstance == "" {
		g.Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(g.MqlRuntime, "gcp.project.memorystoreService.instance",
		map[string]*llx.RawData{"name": llx.StringData(g.cacheInstance)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectMemorystoreServiceInstance), nil
}

func (g *mqlGcpProjectMemorystoreServiceBackupCollection) backups() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	parent := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(memorystore.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := memorystore.NewRESTClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackups(ctx, &memorystorepb.ListBackupsRequest{
		Parent: parent,
	})

	var res []any
	for {
		backup, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		encryptionInfo, err := protoToDict(backup.EncryptionInfo)
		if err != nil {
			return nil, err
		}
		backupFiles, err := buildMemorystoreBackupFiles(g.MqlRuntime, projectId, backup.Name, backup.BackupFiles)
		if err != nil {
			return nil, err
		}

		var createTime, expireTime *llx.RawData
		if backup.CreateTime != nil {
			createTime = llx.TimeData(backup.CreateTime.AsTime())
		} else {
			createTime = llx.NilData
		}
		if backup.ExpireTime != nil {
			expireTime = llx.TimeData(backup.ExpireTime.AsTime())
		} else {
			expireTime = llx.NilData
		}

		mqlBackup, err := CreateResource(g.MqlRuntime, "gcp.project.memorystoreService.backup", map[string]*llx.RawData{
			"projectId":      llx.StringData(projectId),
			"name":           llx.StringData(backup.Name),
			"uid":            llx.StringData(backup.Uid),
			"instanceUid":    llx.StringData(backup.InstanceUid),
			"engineVersion":  llx.StringData(backup.EngineVersion),
			"nodeType":       llx.StringData(backup.NodeType.String()),
			"replicaCount":   llx.IntData(int64(backup.ReplicaCount)),
			"shardCount":     llx.IntData(int64(backup.ShardCount)),
			"totalSizeBytes": llx.IntData(backup.TotalSizeBytes),
			"backupType":     llx.StringData(backup.BackupType.String()),
			"state":          llx.StringData(backup.State.String()),
			"encryptionInfo": llx.DictData(encryptionInfo),
			"backupFiles":    llx.ArrayData(backupFiles, types.Resource("gcp.project.memorystoreService.backup.backupFile")),
			"createTime":     createTime,
			"expireTime":     expireTime,
		})
		if err != nil {
			return nil, err
		}
		obj := mqlBackup.(*mqlGcpProjectMemorystoreServiceBackup)
		obj.cacheInstance = backup.Instance
		res = append(res, obj)
	}

	return res, nil
}

// =====================
// BackupFile
// =====================

func (g *mqlGcpProjectMemorystoreServiceBackupBackupFile) id() (string, error) {
	if g.BackupName.Error != nil {
		return "", g.BackupName.Error
	}
	if g.FileName.Error != nil {
		return "", g.FileName.Error
	}
	return fmt.Sprintf("%s/backupFiles/%s", g.BackupName.Data, g.FileName.Data), nil
}

func buildMemorystoreBackupFiles(runtime *plugin.Runtime, projectId, backupName string, files []*memorystorepb.BackupFile) ([]any, error) {
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
		mqlFile, err := CreateResource(runtime, "gcp.project.memorystoreService.backup.backupFile", map[string]*llx.RawData{
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
