// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	spannerdatabase "cloud.google.com/go/spanner/admin/database/apiv1"
	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	spannerinstance "cloud.google.com/go/spanner/admin/instance/apiv1"
	"cloud.google.com/go/spanner/admin/instance/apiv1/instancepb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
)

func (g *mqlGcpProject) spanner() (*mqlGcpProjectSpannerService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectSpannerService), nil
}

func initGcpProjectSpannerService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

// initGcpProjectSpannerServiceInstance lets policies query a single Spanner
// instance directly (e.g. when cnspec scans a gcp-spanner-instance asset).
// It resolves the target instance from the asset identifier attached to the
// connection and locates it within the project's instance list.
func initGcpProjectSpannerServiceInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
		return nil, nil, errors.New("gcp.project.spannerService.instance requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.spannerService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	spannerSvc := obj.(*mqlGcpProjectSpannerService)
	instances := spannerSvc.GetInstances()
	if instances.Error != nil {
		return nil, nil, instances.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.spannerService.instance requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	for _, i := range instances.Data {
		instance := i.(*mqlGcpProjectSpannerServiceInstance)
		// Spanner instance name is a full resource path:
		// projects/{project}/instances/{instance}
		nameParts := strings.Split(instance.Name.Data, "/")
		instanceName := nameParts[len(nameParts)-1]
		if instanceName == nameVal {
			return args, instance, nil
		}
	}

	return nil, nil, fmt.Errorf("Spanner instance %q not found", nameVal)
}

func (g *mqlGcpProjectSpannerService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectSpannerService) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerinstance.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerinstance.NewInstanceAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInstances(ctx, &instancepb.ListInstancesRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		inst, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Spanner instances")
				break
			}
			return nil, err
		}

		autoscalingConfig, err := protoToDict(inst.AutoscalingConfig)
		if err != nil {
			return nil, err
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

		freeInstanceMetadata, err := protoToDict(inst.FreeInstanceMetadata)
		if err != nil {
			return nil, err
		}

		replicaComputeCapacity := make([]any, 0, len(inst.ReplicaComputeCapacity))
		for _, rcc := range inst.ReplicaComputeCapacity {
			rccDict, err := protoToDict(rcc)
			if err != nil {
				return nil, err
			}
			replicaComputeCapacity = append(replicaComputeCapacity, rccDict)
		}

		mqlInst, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService.instance", map[string]*llx.RawData{
			"projectId":                 llx.StringData(projectId),
			"name":                      llx.StringData(inst.Name),
			"displayName":               llx.StringData(inst.DisplayName),
			"config":                    llx.StringData(inst.Config),
			"nodeCount":                 llx.IntData(int64(inst.NodeCount)),
			"processingUnits":           llx.IntData(int64(inst.ProcessingUnits)),
			"state":                     llx.StringData(inst.State.String()),
			"instanceType":              llx.StringData(inst.InstanceType.String()),
			"labels":                    llx.MapData(convert.MapToInterfaceMap(inst.Labels), types.String),
			"edition":                   llx.StringData(inst.Edition.String()),
			"autoscalingConfig":         llx.DictData(autoscalingConfig),
			"defaultBackupScheduleType": llx.StringData(inst.DefaultBackupScheduleType.String()),
			"createdAt":                 createdAt,
			"updatedAt":                 updatedAt,
			"endpointUris":              llx.ArrayData(convert.SliceAnyToInterface(inst.EndpointUris), types.String),
			"freeInstanceMetadata":      llx.DictData(freeInstanceMetadata),
			"replicaComputeCapacity":    llx.ArrayData(replicaComputeCapacity, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInst)
	}

	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstance) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectSpannerServiceInstance) databases() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerdatabase.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerdatabase.NewDatabaseAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDatabases(ctx, &databasepb.ListDatabasesRequest{
		Parent: instanceName,
	})

	var res []any
	for {
		db, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Spanner databases")
				break
			}
			return nil, err
		}

		encryptionConfig, err := protoToDict(db.EncryptionConfig)
		if err != nil {
			return nil, err
		}

		encryptionInfo := make([]any, 0, len(db.EncryptionInfo))
		for _, ei := range db.EncryptionInfo {
			eiDict, err := protoToDict(ei)
			if err != nil {
				return nil, err
			}
			encryptionInfo = append(encryptionInfo, eiDict)
		}

		var earliestVersionTime *llx.RawData
		if db.EarliestVersionTime != nil {
			earliestVersionTime = llx.TimeData(db.EarliestVersionTime.AsTime())
		} else {
			earliestVersionTime = llx.NilData
		}

		var createdAt *llx.RawData
		if db.CreateTime != nil {
			createdAt = llx.TimeData(db.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}

		restoreInfo, err := protoToDict(db.RestoreInfo)
		if err != nil {
			return nil, err
		}

		mqlDb, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService.instance.database", map[string]*llx.RawData{
			"projectId":              llx.StringData(projectId),
			"instanceName":           llx.StringData(instanceName),
			"name":                   llx.StringData(db.Name),
			"state":                  llx.StringData(db.State.String()),
			"databaseDialect":        llx.StringData(db.DatabaseDialect.String()),
			"versionRetentionPeriod": llx.StringData(db.VersionRetentionPeriod),
			"earliestVersionTime":    earliestVersionTime,
			"encryptionConfig":       llx.DictData(encryptionConfig),
			"encryptionInfo":         llx.ArrayData(encryptionInfo, types.Dict),
			"defaultLeader":          llx.StringData(db.DefaultLeader),
			"enableDropProtection":   llx.BoolData(db.EnableDropProtection),
			"reconciling":            llx.BoolData(db.Reconciling),
			"createdAt":              createdAt,
			"restoreInfo":            llx.DictData(restoreInfo),
		})
		if err != nil {
			return nil, err
		}
		mqlSpannerDb := mqlDb.(*mqlGcpProjectSpannerServiceInstanceDatabase)
		if db.EncryptionConfig != nil {
			mqlSpannerDb.cacheKmsKeyNames = collectSpannerKmsKeyNames(db.EncryptionConfig)
		}
		mqlSpannerDb.cacheSourceBackupName = db.RestoreInfo.GetBackupInfo().GetBackup()
		res = append(res, mqlDb)
	}

	return res, nil
}

func collectSpannerKmsKeyNames(cfg *databasepb.EncryptionConfig) []string {
	if cfg == nil {
		return nil
	}
	seen := make(map[string]struct{}, len(cfg.KmsKeyNames)+1)
	out := make([]string, 0, len(cfg.KmsKeyNames)+1)
	add := func(name string) {
		if name == "" {
			return
		}
		if _, ok := seen[name]; ok {
			return
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	add(cfg.KmsKeyName)
	for _, n := range cfg.KmsKeyNames {
		add(n)
	}
	return out
}

type mqlGcpProjectSpannerServiceInstanceDatabaseInternal struct {
	cacheKmsKeyNames      []string
	cacheSourceBackupName string
}

func (g *mqlGcpProjectSpannerServiceInstance) managedBy() (string, error) {
	return managedByFromLabels(g.GetLabels())
}

// getSpannerInstanceForList creates a Spanner instance resource keyed only by
// project and full instance name so its databases()/backups() lists can be
// walked to resolve lineage. When the parent traversal already listed the
// instance, the fully populated resource is returned from the runtime cache.
func getSpannerInstanceForList(runtime *plugin.Runtime, projectId, instanceName string) (*mqlGcpProjectSpannerServiceInstance, error) {
	obj, err := CreateResource(runtime, "gcp.project.spannerService.instance", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"name":      llx.StringData(instanceName),
	})
	if err != nil {
		return nil, err
	}
	return obj.(*mqlGcpProjectSpannerServiceInstance), nil
}

// getSpannerBackupByName resolves a Spanner backup by its full resource name
// (projects/{project}/instances/{instance}/backups/{backup}). Returns nil when
// the name is empty, malformed, or no matching backup exists.
func getSpannerBackupByName(runtime *plugin.Runtime, backupName string) (*mqlGcpProjectSpannerServiceInstanceBackup, error) {
	if backupName == "" {
		return nil, nil
	}
	parts := strings.Split(backupName, "/")
	if len(parts) < 6 || parts[0] != "projects" || parts[2] != "instances" || parts[4] != "backups" {
		return nil, nil
	}
	instanceName := fmt.Sprintf("projects/%s/instances/%s", parts[1], parts[3])
	inst, err := getSpannerInstanceForList(runtime, parts[1], instanceName)
	if err != nil {
		return nil, err
	}
	backups := inst.GetBackups()
	if backups.Error != nil {
		return nil, backups.Error
	}
	for _, b := range backups.Data {
		backup := b.(*mqlGcpProjectSpannerServiceInstanceBackup)
		if backup.Name.Error != nil {
			return nil, backup.Name.Error
		}
		if backup.Name.Data == backupName {
			return backup, nil
		}
	}
	return nil, nil
}

// getSpannerDatabaseByName resolves a Spanner database by its full resource name
// (projects/{project}/instances/{instance}/databases/{database}). Returns nil
// when the name is empty, malformed, or no matching database exists.
func getSpannerDatabaseByName(runtime *plugin.Runtime, dbName string) (*mqlGcpProjectSpannerServiceInstanceDatabase, error) {
	if dbName == "" {
		return nil, nil
	}
	parts := strings.Split(dbName, "/")
	if len(parts) < 6 || parts[0] != "projects" || parts[2] != "instances" || parts[4] != "databases" {
		return nil, nil
	}
	instanceName := fmt.Sprintf("projects/%s/instances/%s", parts[1], parts[3])
	inst, err := getSpannerInstanceForList(runtime, parts[1], instanceName)
	if err != nil {
		return nil, err
	}
	dbs := inst.GetDatabases()
	if dbs.Error != nil {
		return nil, dbs.Error
	}
	for _, d := range dbs.Data {
		db := d.(*mqlGcpProjectSpannerServiceInstanceDatabase)
		if db.Name.Error != nil {
			return nil, db.Name.Error
		}
		if db.Name.Data == dbName {
			return db, nil
		}
	}
	return nil, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceDatabase) sourceBackup() (*mqlGcpProjectSpannerServiceInstanceBackup, error) {
	b, err := getSpannerBackupByName(g.MqlRuntime, g.cacheSourceBackupName)
	if err != nil {
		return nil, err
	}
	if b == nil {
		g.SourceBackup.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return b, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceBackup) sourceDatabase() (*mqlGcpProjectSpannerServiceInstanceDatabase, error) {
	if g.Database.Error != nil {
		return nil, g.Database.Error
	}
	d, err := getSpannerDatabaseByName(g.MqlRuntime, g.Database.Data)
	if err != nil {
		return nil, err
	}
	if d == nil {
		g.SourceDatabase.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return d, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceDatabase) kmsKeys() ([]any, error) {
	if len(g.cacheKmsKeyNames) == 0 {
		return []any{}, nil
	}
	res := make([]any, 0, len(g.cacheKmsKeyNames))
	for _, name := range g.cacheKmsKeyNames {
		key, err := NewResource(g.MqlRuntime, "gcp.project.kmsService.keyring.cryptokey",
			map[string]*llx.RawData{"resourcePath": llx.StringData(name)})
		if err != nil {
			return nil, err
		}
		res = append(res, key)
	}
	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceDatabase) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService/%s/database/%s", g.ProjectId.Data, g.InstanceName.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectSpannerServiceInstanceDatabase) ddl() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	dbName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerdatabase.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerdatabase.NewDatabaseAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	resp, err := client.GetDatabaseDdl(ctx, &databasepb.GetDatabaseDdlRequest{
		Database: dbName,
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not read Spanner database DDL")
			return nil, nil
		}
		return nil, err
	}

	return convert.SliceAnyToInterface(resp.Statements), nil
}

func (g *mqlGcpProjectSpannerServiceInstance) backups() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerdatabase.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerdatabase.NewDatabaseAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListBackups(ctx, &databasepb.ListBackupsRequest{
		Parent: instanceName,
	})

	var res []any
	for {
		backup, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Spanner backups")
				break
			}
			return nil, err
		}

		encryptionInfo, err := protoToDict(backup.EncryptionInfo)
		if err != nil {
			return nil, err
		}

		var expireTime *llx.RawData
		if backup.ExpireTime != nil {
			expireTime = llx.TimeData(backup.ExpireTime.AsTime())
		} else {
			expireTime = llx.NilData
		}

		var versionTime *llx.RawData
		if backup.VersionTime != nil {
			versionTime = llx.TimeData(backup.VersionTime.AsTime())
		} else {
			versionTime = llx.NilData
		}

		var createdAt *llx.RawData
		if backup.CreateTime != nil {
			createdAt = llx.TimeData(backup.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}

		var maxExpireTime *llx.RawData
		if backup.MaxExpireTime != nil {
			maxExpireTime = llx.TimeData(backup.MaxExpireTime.AsTime())
		} else {
			maxExpireTime = llx.NilData
		}

		var oldestVersionTime *llx.RawData
		if backup.OldestVersionTime != nil {
			oldestVersionTime = llx.TimeData(backup.OldestVersionTime.AsTime())
		} else {
			oldestVersionTime = llx.NilData
		}

		mqlBackup, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService.instance.backup", map[string]*llx.RawData{
			"projectId":                llx.StringData(projectId),
			"instanceName":             llx.StringData(instanceName),
			"name":                     llx.StringData(backup.Name),
			"database":                 llx.StringData(backup.Database),
			"state":                    llx.StringData(backup.State.String()),
			"expireTime":               expireTime,
			"versionTime":              versionTime,
			"createdAt":                createdAt,
			"sizeBytes":                llx.IntData(backup.SizeBytes),
			"encryptionInfo":           llx.DictData(encryptionInfo),
			"databaseDialect":          llx.StringData(backup.DatabaseDialect.String()),
			"maxExpireTime":            maxExpireTime,
			"freeableSizeBytes":        llx.IntData(backup.FreeableSizeBytes),
			"exclusiveSizeBytes":       llx.IntData(backup.ExclusiveSizeBytes),
			"referencingDatabases":     llx.ArrayData(convert.SliceAnyToInterface(backup.ReferencingDatabases), types.String),
			"referencingBackups":       llx.ArrayData(convert.SliceAnyToInterface(backup.ReferencingBackups), types.String),
			"backupSchedules":          llx.ArrayData(convert.SliceAnyToInterface(backup.BackupSchedules), types.String),
			"incrementalBackupChainId": llx.StringData(backup.IncrementalBackupChainId),
			"oldestVersionTime":        oldestVersionTime,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBackup)
	}

	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceBackup) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return "", g.InstanceName.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService/%s/backup/%s", g.ProjectId.Data, g.InstanceName.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectSpannerService) instanceConfigs() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerinstance.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerinstance.NewInstanceAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInstanceConfigs(ctx, &instancepb.ListInstanceConfigsRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})

	var res []any
	for {
		cfg, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Spanner instance configs")
				break
			}
			return nil, err
		}

		replicas := make([]any, 0, len(cfg.Replicas))
		for _, r := range cfg.Replicas {
			replicaDict, err := protoToDict(r)
			if err != nil {
				return nil, err
			}
			replicas = append(replicas, replicaDict)
		}

		optionalReplicas := make([]any, 0, len(cfg.OptionalReplicas))
		for _, r := range cfg.OptionalReplicas {
			replicaDict, err := protoToDict(r)
			if err != nil {
				return nil, err
			}
			optionalReplicas = append(optionalReplicas, replicaDict)
		}

		mqlCfg, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService.instanceConfig", map[string]*llx.RawData{
			"projectId":                     llx.StringData(projectId),
			"name":                          llx.StringData(cfg.Name),
			"displayName":                   llx.StringData(cfg.DisplayName),
			"replicas":                      llx.ArrayData(replicas, types.Dict),
			"leaderOptions":                 llx.ArrayData(convert.SliceAnyToInterface(cfg.LeaderOptions), types.String),
			"baseConfig":                    llx.StringData(cfg.BaseConfig),
			"configType":                    llx.StringData(cfg.ConfigType.String()),
			"freeInstanceAvailability":      llx.StringData(cfg.FreeInstanceAvailability.String()),
			"labels":                        llx.MapData(convert.MapToInterfaceMap(cfg.Labels), types.String),
			"optionalReplicas":              llx.ArrayData(optionalReplicas, types.Dict),
			"storageLimitPerProcessingUnit": llx.IntData(cfg.StorageLimitPerProcessingUnit),
			"state":                         llx.StringData(cfg.State.String()),
			"reconciling":                   llx.BoolData(cfg.Reconciling),
			"etag":                          llx.StringData(cfg.Etag),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCfg)
	}

	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceConfig) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService/instanceConfig/%s", g.ProjectId.Data, g.Name.Data), nil
}

func initGcpProjectSpannerServiceInstanceConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	nameRaw, ok := args["name"]
	if !ok || nameRaw == nil {
		return nil, nil, errors.New(`gcp.project.spannerService.instanceConfig requires a "name" argument`)
	}
	name, ok := nameRaw.Value.(string)
	if !ok || name == "" {
		return nil, nil, errors.New(`gcp.project.spannerService.instanceConfig requires a non-empty "name" argument`)
	}

	projectIdRaw, ok := args["projectId"]
	if !ok || projectIdRaw == nil {
		return nil, nil, errors.New(`gcp.project.spannerService.instanceConfig requires a "projectId" argument`)
	}
	projectId, ok := projectIdRaw.Value.(string)
	if !ok || projectId == "" {
		return nil, nil, errors.New(`gcp.project.spannerService.instanceConfig requires a non-empty "projectId" argument`)
	}

	obj, err := CreateResource(runtime, "gcp.project.spannerService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, nil, err
	}
	svc := obj.(*mqlGcpProjectSpannerService)
	configs := svc.GetInstanceConfigs()
	if configs.Error != nil {
		return nil, nil, configs.Error
	}

	for _, c := range configs.Data {
		cfg := c.(*mqlGcpProjectSpannerServiceInstanceConfig)
		if cfg.Name.Data == name {
			return args, cfg, nil
		}
	}

	return nil, nil, fmt.Errorf("spanner instance config %q not found in project %q", name, projectId)
}

func (g *mqlGcpProjectSpannerServiceInstance) instanceConfig() (*mqlGcpProjectSpannerServiceInstanceConfig, error) {
	if g.Config.Error != nil {
		return nil, g.Config.Error
	}
	configName := g.Config.Data
	if configName == "" {
		g.InstanceConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	res, err := NewResource(g.MqlRuntime, "gcp.project.spannerService.instanceConfig", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
		"name":      llx.StringData(configName),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectSpannerServiceInstanceConfig), nil
}

func spannerIamPolicyBindings(runtime *plugin.Runtime, resource string, policy *iampb.Policy) ([]any, error) {
	res := make([]any, 0, len(policy.Bindings))
	for i, b := range policy.Bindings {
		mqlBinding, err := CreateResource(runtime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(resource + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(b.GetCondition().GetTitle()),
			"conditionExpression":  llx.StringData(b.GetCondition().GetExpression()),
			"conditionDescription": llx.StringData(b.GetCondition().GetDescription()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstance) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerinstance.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerinstance.NewInstanceAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: instanceName, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not read Spanner instance IAM policy")
			return nil, nil
		}
		return nil, err
	}
	return spannerIamPolicyBindings(g.MqlRuntime, instanceName, policy)
}

func (g *mqlGcpProjectSpannerServiceInstanceDatabase) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	dbName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerdatabase.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerdatabase.NewDatabaseAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: dbName, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not read Spanner database IAM policy")
			return nil, nil
		}
		return nil, err
	}
	return spannerIamPolicyBindings(g.MqlRuntime, dbName, policy)
}

func (g *mqlGcpProjectSpannerServiceInstanceDatabase) databaseRoles() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.InstanceName.Error != nil {
		return nil, g.InstanceName.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.InstanceName.Data
	dbName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerdatabase.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerdatabase.NewDatabaseAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDatabaseRoles(ctx, &databasepb.ListDatabaseRolesRequest{
		Parent: dbName,
	})

	var res []any
	for {
		role, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Spanner database roles")
				break
			}
			return nil, err
		}
		mqlRole, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService.instance.database.role", map[string]*llx.RawData{
			"projectId":    llx.StringData(projectId),
			"instanceName": llx.StringData(instanceName),
			"databaseName": llx.StringData(dbName),
			"name":         llx.StringData(role.Name),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRole)
	}
	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceDatabaseRole) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService/databaseRole/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectSpannerServiceInstance) backupSchedules() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	databases := g.GetDatabases()
	if databases.Error != nil {
		return nil, databases.Error
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerdatabase.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	dbClient, err := spannerdatabase.NewDatabaseAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer dbClient.Close()

	var res []any
	for _, d := range databases.Data {
		mqlDb := d.(*mqlGcpProjectSpannerServiceInstanceDatabase)
		if mqlDb.Name.Error != nil {
			return nil, mqlDb.Name.Error
		}
		dbName := mqlDb.Name.Data

		schedIt := dbClient.ListBackupSchedules(ctx, &databasepb.ListBackupSchedulesRequest{Parent: dbName})
		for {
			sched, err := schedIt.Next()
			if err == iterator.Done {
				break
			}
			if err != nil {
				if isSkippable(err) {
					log.Warn().Err(err).Str("database", dbName).Msg("could not list Spanner backup schedules")
					break
				}
				return nil, err
			}

			specDict, err := protoToDict(sched.Spec)
			if err != nil {
				return nil, err
			}
			encConfigDict, err := protoToDict(sched.EncryptionConfig)
			if err != nil {
				return nil, err
			}

			var retention string
			if sched.RetentionDuration != nil {
				retention = sched.RetentionDuration.AsDuration().String()
			}

			var updatedAt *llx.RawData
			if sched.UpdateTime != nil {
				updatedAt = llx.TimeData(sched.UpdateTime.AsTime())
			} else {
				updatedAt = llx.NilData
			}

			backupType := ""
			switch sched.BackupTypeSpec.(type) {
			case *databasepb.BackupSchedule_FullBackupSpec:
				backupType = "FULL"
			case *databasepb.BackupSchedule_IncrementalBackupSpec:
				backupType = "INCREMENTAL"
			}

			mqlSched, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService.instance.backupSchedule", map[string]*llx.RawData{
				"projectId":         llx.StringData(projectId),
				"instanceName":      llx.StringData(instanceName),
				"databaseName":      llx.StringData(dbName),
				"name":              llx.StringData(sched.Name),
				"spec":              llx.DictData(specDict),
				"retentionDuration": llx.StringData(retention),
				"encryptionConfig":  llx.DictData(encConfigDict),
				"backupType":        llx.StringData(backupType),
				"updatedAt":         updatedAt,
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlSched)
		}
	}
	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceBackupSchedule) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService/backupSchedule/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectSpannerServiceInstance) instancePartitions() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	projectId := g.ProjectId.Data
	instanceName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(spannerinstance.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := spannerinstance.NewInstanceAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListInstancePartitions(ctx, &instancepb.ListInstancePartitionsRequest{Parent: instanceName})
	var res []any
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Spanner instance partitions")
				break
			}
			return nil, err
		}

		autoscalingConfig, err := protoToDict(p.AutoscalingConfig)
		if err != nil {
			return nil, err
		}

		var createdAt *llx.RawData
		if p.CreateTime != nil {
			createdAt = llx.TimeData(p.CreateTime.AsTime())
		} else {
			createdAt = llx.NilData
		}
		var updatedAt *llx.RawData
		if p.UpdateTime != nil {
			updatedAt = llx.TimeData(p.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		mqlPart, err := CreateResource(g.MqlRuntime, "gcp.project.spannerService.instance.instancePartition", map[string]*llx.RawData{
			"projectId":            llx.StringData(projectId),
			"instanceName":         llx.StringData(instanceName),
			"name":                 llx.StringData(p.Name),
			"config":               llx.StringData(p.Config),
			"displayName":          llx.StringData(p.DisplayName),
			"nodeCount":            llx.IntData(int64(p.GetNodeCount())),
			"processingUnits":      llx.IntData(int64(p.GetProcessingUnits())),
			"autoscalingConfig":    llx.DictData(autoscalingConfig),
			"state":                llx.StringData(p.State.String()),
			"referencingDatabases": llx.ArrayData(convert.SliceAnyToInterface(p.ReferencingDatabases), types.String),
			"etag":                 llx.StringData(p.Etag),
			"createdAt":            createdAt,
			"updatedAt":            updatedAt,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPart)
	}
	return res, nil
}

func (g *mqlGcpProjectSpannerServiceInstanceInstancePartition) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/spannerService/instancePartition/%s", g.ProjectId.Data, g.Name.Data), nil
}
