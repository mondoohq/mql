// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	firestoreadmin "cloud.google.com/go/firestore/apiv1/admin"
	"cloud.google.com/go/firestore/apiv1/admin/adminpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) firestore() (*mqlGcpProjectFirestoreService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.firestoreService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectFirestoreService), nil
}

func initGcpProjectFirestoreService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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

// initGcpProjectFirestoreServiceDatabase lets policies query a single Firestore
// database directly (e.g. when cnspec scans a gcp-firestore-database asset).
func initGcpProjectFirestoreServiceDatabase(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
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
		return nil, nil, errors.New("gcp.project.firestoreService.database requires a \"projectId\" argument")
	}

	obj, err := CreateResource(runtime, "gcp.project.firestoreService", map[string]*llx.RawData{
		"projectId": args["projectId"],
	})
	if err != nil {
		return nil, nil, err
	}
	firestoreSvc := obj.(*mqlGcpProjectFirestoreService)
	databases := firestoreSvc.GetDatabases()
	if databases.Error != nil {
		return nil, nil, databases.Error
	}

	nameRaw := args["name"]
	if nameRaw == nil {
		return nil, nil, errors.New("gcp.project.firestoreService.database requires a \"name\" argument")
	}
	nameVal, _ := nameRaw.Value.(string)
	for _, d := range databases.Data {
		database := d.(*mqlGcpProjectFirestoreServiceDatabase)
		// Firestore database name is a full resource path:
		// projects/{project}/databases/{database}
		nameParts := strings.Split(database.Name.Data, "/")
		dbName := nameParts[len(nameParts)-1]
		if dbName == nameVal {
			return args, database, nil
		}
	}

	return nil, nil, fmt.Errorf("Firestore database %q not found", nameVal)
}

func (g *mqlGcpProjectFirestoreService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/firestoreService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectFirestoreService) databases() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(firestoreadmin.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := firestoreadmin.NewFirestoreAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	resp, err := client.ListDatabases(ctx, &adminpb.ListDatabasesRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list Firestore databases")
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(resp.Databases))
	for _, db := range resp.Databases {
		cmekConfig, err := protoToDict(db.CmekConfig)
		if err != nil {
			return nil, err
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

		var updatedAt *llx.RawData
		if db.UpdateTime != nil {
			updatedAt = llx.TimeData(db.UpdateTime.AsTime())
		} else {
			updatedAt = llx.NilData
		}

		// durationToString, not (*durationpb.Duration).String(): the latter is
		// the generated proto stringer and renders protobuf TEXT
		// ("seconds:604800"), not a duration.
		versionRetentionPeriod := durationToString(db.VersionRetentionPeriod)

		mqlDb, err := CreateResource(g.MqlRuntime, "gcp.project.firestoreService.database", map[string]*llx.RawData{
			"projectId":                     llx.StringData(projectId),
			"name":                          llx.StringData(db.Name),
			"uid":                           llx.StringData(db.Uid),
			"locationId":                    llx.StringData(db.LocationId),
			"type":                          llx.StringData(db.Type.String()),
			"concurrencyMode":               llx.StringData(db.ConcurrencyMode.String()),
			"appEngineIntegrationMode":      llx.StringData(db.AppEngineIntegrationMode.String()),
			"pointInTimeRecoveryEnablement": llx.StringData(db.PointInTimeRecoveryEnablement.String()),
			"deleteProtectionState":         llx.StringData(db.DeleteProtectionState.String()),
			"tags":                          llx.MapData(convert.MapToInterfaceMap(db.Tags), types.String),
			"cmekConfig":                    llx.DictData(cmekConfig),
			"versionRetentionPeriod":        llx.StringData(versionRetentionPeriod),
			"earliestVersionTime":           earliestVersionTime,
			"etag":                          llx.StringData(db.Etag),
			"createdAt":                     createdAt,
			"updatedAt":                     updatedAt,
		})
		if err != nil {
			return nil, err
		}
		mqlFirestoreDb := mqlDb.(*mqlGcpProjectFirestoreServiceDatabase)
		mqlFirestoreDb.cacheKmsKeyName = db.GetCmekConfig().GetKmsKeyName()
		res = append(res, mqlDb)
	}

	return res, nil
}

type mqlGcpProjectFirestoreServiceDatabaseInternal struct {
	cacheKmsKeyName string
}

func (g *mqlGcpProjectFirestoreServiceDatabase) kmsKey() (*mqlGcpProjectKmsServiceKeyringCryptokey, error) {
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

func (g *mqlGcpProjectFirestoreServiceDatabase) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/firestoreService/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectFirestoreServiceDatabaseIndex) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func (g *mqlGcpProjectFirestoreServiceDatabaseBackupSchedule) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func (g *mqlGcpProjectFirestoreServiceDatabase) indexes() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	databaseName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(firestoreadmin.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := firestoreadmin.NewFirestoreAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListIndexes(ctx, &adminpb.ListIndexesRequest{
		Parent: databaseName + "/collectionGroups/-",
	})

	var res []any
	for {
		idx, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Firestore indexes")
				break
			}
			return nil, err
		}

		fields := make([]any, 0, len(idx.Fields))
		for _, f := range idx.Fields {
			fd, err := protoToDict(f)
			if err != nil {
				return nil, err
			}
			fields = append(fields, fd)
		}

		mqlIdx, err := CreateResource(g.MqlRuntime, "gcp.project.firestoreService.database.index", map[string]*llx.RawData{
			"name":       llx.StringData(idx.Name),
			"queryScope": llx.StringData(idx.QueryScope.String()),
			"apiScope":   llx.StringData(idx.ApiScope.String()),
			"fields":     llx.ArrayData(fields, types.Dict),
			"state":      llx.StringData(idx.State.String()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIdx)
	}

	return res, nil
}

func (g *mqlGcpProjectFirestoreServiceDatabase) backupSchedules() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	databaseName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(firestoreadmin.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := firestoreadmin.NewFirestoreAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	resp, err := client.ListBackupSchedules(ctx, &adminpb.ListBackupSchedulesRequest{
		Parent: databaseName,
	})
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list Firestore backup schedules")
			return nil, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(resp.BackupSchedules))
	for _, bs := range resp.BackupSchedules {
		retention := durationToString(bs.Retention)

		dailyRecurrence, err := protoToDict(bs.GetDailyRecurrence())
		if err != nil {
			return nil, err
		}

		weeklyRecurrence, err := protoToDict(bs.GetWeeklyRecurrence())
		if err != nil {
			return nil, err
		}

		var created *llx.RawData
		if bs.CreateTime != nil {
			created = llx.TimeData(bs.CreateTime.AsTime())
		} else {
			created = llx.NilData
		}

		var updated *llx.RawData
		if bs.UpdateTime != nil {
			updated = llx.TimeData(bs.UpdateTime.AsTime())
		} else {
			updated = llx.NilData
		}

		mqlBs, err := CreateResource(g.MqlRuntime, "gcp.project.firestoreService.database.backupSchedule", map[string]*llx.RawData{
			"name":             llx.StringData(bs.Name),
			"retention":        llx.StringData(retention),
			"dailyRecurrence":  llx.DictData(dailyRecurrence),
			"weeklyRecurrence": llx.DictData(weeklyRecurrence),
			"created":          created,
			"updated":          updated,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBs)
	}

	return res, nil
}
