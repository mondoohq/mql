// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"

	"cloud.google.com/go/bigquery"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func initGcpProjectBigqueryService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

type mqlGcpProjectBigqueryServiceInternal struct {
	serviceEnabled bool
}

func (g *mqlGcpProjectBigqueryService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	return fmt.Sprintf("gcp.project.bigqueryService/%s", projectId), nil
}

func (g *mqlGcpProject) bigquery() (*mqlGcpProjectBigqueryService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_bigquery)
	if err != nil {
		return nil, err
	}
	bqService := res.(*mqlGcpProjectBigqueryService)
	bqService.serviceEnabled = serviceEnabled

	return bqService, nil
}

func (g *mqlGcpProjectBigqueryService) datasets() ([]any, error) {
	// when the service is not enabled, we return nil
	if !g.serviceEnabled {
		return nil, nil
	}

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	client, err := conn.Client("https://www.googleapis.com/auth/bigquery")
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	bigquerySvc, err := bigquery.NewClient(ctx, projectId, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	it := bigquerySvc.Datasets(ctx)
	res := []any{}
	for {
		dataset, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := dataset.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		tags := map[string]string{}
		for i := range metadata.Tags {
			tag := metadata.Tags[i]
			tags[tag.TagKey] = tag.TagValue
		}

		var kmsName string
		if metadata.DefaultEncryptionConfig != nil {
			kmsName = metadata.DefaultEncryptionConfig.KMSKeyName
		}

		access := make([]any, 0, len(metadata.Access))
		for i, a := range metadata.Access {
			var viewRef any
			if a.View != nil {
				viewRef = map[string]any{
					"projectId": a.View.ProjectID,
					"datasetId": a.View.DatasetID,
					"tableId":   a.View.TableID,
				}
			}
			var routineRef any
			if a.Routine != nil {
				routineRef = map[string]any{
					"projectId": a.Routine.ProjectID,
					"datasetId": a.Routine.DatasetID,
					"tableId":   a.Routine.RoutineID,
				}
			}
			var datasetRef any
			if a.Dataset != nil {
				datasetRef = map[string]any{
					"projectId":   a.Dataset.Dataset.ProjectID,
					"datasetId":   a.Dataset.Dataset.DatasetID,
					"targetTypes": a.Dataset.TargetTypes,
				}
			}
			mqlA, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.dataset.accessEntry", map[string]*llx.RawData{
				"id":         llx.StringData(fmt.Sprintf("gcp.project.bigqueryService.dataset/%s/%s/accessEntry/%d", projectId, dataset.DatasetID, i)),
				"datasetId":  llx.StringData(dataset.DatasetID),
				"role":       llx.StringData(string(a.Role)),
				"entityType": llx.StringData(entityTypeToString(a.EntityType)),
				"entity":     llx.StringData(a.Entity),
				"viewRef":    llx.DictData(viewRef),
				"routineRef": llx.DictData(routineRef),
				"datasetRef": llx.DictData(datasetRef),
			})
			if err != nil {
				return nil, err
			}
			access = append(access, mqlA)
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.dataset", map[string]*llx.RawData{
			"id":                           llx.StringData(dataset.DatasetID),
			"projectId":                    llx.StringData(dataset.ProjectID),
			"name":                         llx.StringData(metadata.Name),
			"description":                  llx.StringData(metadata.Description),
			"location":                     llx.StringData(metadata.Location),
			"labels":                       llx.MapData(convert.MapToInterfaceMap(metadata.Labels), types.String),
			"created":                      llx.TimeData(metadata.CreationTime),
			"modified":                     llx.TimeData(metadata.LastModifiedTime),
			"tags":                         llx.MapData(convert.MapToInterfaceMap(tags), types.String),
			"kmsName":                      llx.StringData(kmsName),
			"access":                       llx.ArrayData(access, types.Resource("gcp.project.bigqueryService.dataset.accessEntry")),
			"defaultTableExpirationMs":     llx.IntData(metadata.DefaultTableExpiration.Milliseconds()),
			"maxTimeTravelHours":           llx.IntData(int64(metadata.MaxTimeTravel / time.Hour)),
			"storageBillingModel":          llx.StringData(metadata.StorageBillingModel),
			"defaultCollation":             llx.StringData(metadata.DefaultCollation),
			"defaultPartitionExpirationMs": llx.IntData(metadata.DefaultPartitionExpiration.Milliseconds()),
			"defaultRoundingMode":          llx.StringData(""),
			"isCaseInsensitive":            llx.BoolData(metadata.IsCaseInsensitive),
			"satisfiesPzi":                 llx.BoolData(false),
			"satisfiesPzs":                 llx.BoolData(false),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)
	}

	return res, nil
}

type mqlGcpProjectBigqueryServiceDatasetInternal struct {
	clientOnce sync.Once
	client     *bigquery.Client
	clientErr  error
}

func (g *mqlGcpProjectBigqueryServiceDataset) getClient() (*bigquery.Client, error) {
	g.clientOnce.Do(func() {
		conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
		httpClient, err := conn.Client("https://www.googleapis.com/auth/bigquery")
		if err != nil {
			g.clientErr = err
			return
		}
		ctx := context.Background()
		projectID := conn.ResourceID()
		g.client, g.clientErr = bigquery.NewClient(ctx, projectID, option.WithHTTPClient(httpClient))
	})
	return g.client, g.clientErr
}

func (g *mqlGcpProjectBigqueryServiceDataset) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	name := g.Id.Data
	return "gcp.project.bigqueryService.dataset/" + projectId + "/" + name, nil
}

func initGcpProjectBigqueryServiceDataset(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// If no args are set, try reading them from the platform ID
	if len(args) == 0 {
		if ids := getAssetIdentifier(runtime); ids != nil {
			args["id"] = llx.StringData(ids.name)
			args["location"] = llx.StringData(ids.region)
			args["projectId"] = llx.StringData(ids.project)
		} else {
			return nil, nil, errors.New("no asset identifier found")
		}
	}

	obj, err := CreateResource(runtime, "gcp.project.bigqueryService", map[string]*llx.RawData{
		"projectId": llx.StringData(args["projectId"].Value.(string)),
	})
	if err != nil {
		return nil, nil, err
	}
	bigquerySvc := obj.(*mqlGcpProjectBigqueryService)
	datasets := bigquerySvc.GetDatasets()
	if datasets.Error != nil {
		return nil, nil, datasets.Error
	}

	for _, d := range datasets.Data {
		dataset := d.(*mqlGcpProjectBigqueryServiceDataset)
		id := dataset.GetId()
		if id.Error != nil {
			return nil, nil, id.Error
		}
		location := dataset.GetLocation()
		if location.Error != nil {
			return nil, nil, location.Error
		}
		projectId := dataset.GetProjectId()
		if projectId.Error != nil {
			return nil, nil, projectId.Error
		}

		if id.Data == args["id"].Value && projectId.Data == args["projectId"].Value && location.Data == args["location"].Value {
			return args, dataset, nil
		}
	}
	return nil, nil, errors.New("dataset not found")
}

func (g *mqlGcpProjectBigqueryServiceDatasetAccessEntry) id() (string, error) {
	return g.Id.Data, g.Id.Error
}

func (g *mqlGcpProjectBigqueryServiceDataset) tables() ([]any, error) {
	bigquerySvc, err := g.getClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	datasetID := g.Id.Data

	dataset := bigquerySvc.Dataset(datasetID)
	if dataset == nil {
		return nil, errors.New("could not find dataset:" + datasetID)
	}

	it := dataset.Tables(ctx)
	res := []any{}
	for {
		table, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := table.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		var kmsName string
		if metadata.EncryptionConfig != nil {
			kmsName = metadata.EncryptionConfig.KMSKeyName
		}

		var clusteringFields []any
		if metadata.Clustering != nil {
			clusteringFields = convert.SliceAnyToInterface(metadata.Clustering.Fields)
		}

		externalDataConfig, err := convert.JsonToDict(metadata.ExternalDataConfig)
		if err != nil {
			return nil, err
		}

		materializedView, err := convert.JsonToDict(metadata.MaterializedView)
		if err != nil {
			return nil, err
		}

		rangePartitioning, err := convert.JsonToDict(metadata.RangePartitioning)
		if err != nil {
			return nil, err
		}

		schema, err := convert.JsonToDictSlice(metadata.Schema)
		if err != nil {
			return nil, err
		}

		timePartitioning, err := convert.JsonToDict(metadata.TimePartitioning)
		if err != nil {
			return nil, err
		}

		var snapshotTime *time.Time
		if metadata.SnapshotDefinition != nil {
			snapshotTime = &metadata.SnapshotDefinition.SnapshotTime
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.table", map[string]*llx.RawData{
			"id":                     llx.StringData(table.TableID),
			"projectId":              llx.StringData(table.ProjectID),
			"datasetId":              llx.StringData(table.DatasetID),
			"name":                   llx.StringData(metadata.Name),
			"location":               llx.StringData(metadata.Location),
			"description":            llx.StringData(metadata.Description),
			"labels":                 llx.MapData(convert.MapToInterfaceMap(metadata.Labels), types.String),
			"useLegacySQL":           llx.BoolData(metadata.UseLegacySQL),
			"requirePartitionFilter": llx.BoolData(metadata.RequirePartitionFilter),
			"created":                llx.TimeData(metadata.CreationTime),
			"modified":               llx.TimeData(metadata.LastModifiedTime),
			"numBytes":               llx.IntData(metadata.NumBytes),
			"numLongTermBytes":       llx.IntData(metadata.NumLongTermBytes),
			"numRows":                llx.IntData(int64(metadata.NumRows)),
			"type":                   llx.StringData(string(metadata.Type)),
			"expirationTime":         llx.TimeData(metadata.ExpirationTime),
			"kmsName":                llx.StringData(kmsName),
			"snapshotTime":           llx.TimeDataPtr(snapshotTime),
			"viewQuery":              llx.StringData(metadata.ViewQuery),
			"clusteringFields":       llx.DictData(clusteringFields),
			"externalDataConfig":     llx.DictData(externalDataConfig),
			"materializedView":       llx.DictData(materializedView),
			"rangePartitioning":      llx.DictData(rangePartitioning),
			"timePartitioning":       llx.DictData(timePartitioning),
			"schema":                 llx.ArrayData(schema, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)

	}
	return res, nil
}

func (g *mqlGcpProjectBigqueryServiceTable) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.DatasetId.Error != nil {
		return "", g.DatasetId.Error
	}
	datasetId := g.DatasetId.Data

	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data
	return fmt.Sprintf("gcp.project.bigqueryService.table/%s/%s/%s", projectId, datasetId, id), nil
}

func (g *mqlGcpProjectBigqueryServiceDataset) models() ([]any, error) {
	bigquerySvc, err := g.getClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	datasetID := g.Id.Data

	dataset := bigquerySvc.Dataset(datasetID)
	if dataset == nil {
		return nil, errors.New("could not find dataset:" + datasetID)
	}

	it := dataset.Models(ctx)
	res := []any{}
	for {
		model, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := model.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		var kmsName string
		if metadata.EncryptionConfig != nil {
			kmsName = metadata.EncryptionConfig.KMSKeyName
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.model", map[string]*llx.RawData{
			"id":             llx.StringData(model.ModelID),
			"datasetId":      llx.StringData(model.DatasetID),
			"projectId":      llx.StringData(model.ProjectID),
			"name":           llx.StringData(metadata.Name),
			"description":    llx.StringData(metadata.Description),
			"location":       llx.StringData(metadata.Location),
			"labels":         llx.MapData(convert.MapToInterfaceMap(metadata.Labels), types.String),
			"created":        llx.TimeData(metadata.CreationTime),
			"modified":       llx.TimeData(metadata.LastModifiedTime),
			"type":           llx.StringData(string(metadata.Type)),
			"expirationTime": llx.TimeData(metadata.ExpirationTime),
			"kmsName":        llx.StringData(kmsName),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)

	}
	return res, nil
}

func (g *mqlGcpProjectBigqueryServiceModel) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	projectId := g.ProjectId.Data
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	id := g.Id.Data

	if g.DatasetId.Error != nil {
		return "", g.DatasetId.Error
	}
	datasetId := g.DatasetId.Data
	return fmt.Sprintf("gcp.project.bigqueryService.model/%s/%s/%s", projectId, datasetId, id), nil
}

func (g *mqlGcpProjectBigqueryServiceDataset) routines() ([]any, error) {
	bigquerySvc, err := g.getClient()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	datasetID := g.Id.Data

	dataset := bigquerySvc.Dataset(datasetID)
	if dataset == nil {
		return nil, errors.New("could not find dataset:" + datasetID)
	}

	it := dataset.Routines(ctx)
	res := []any{}
	for {
		routine, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		metadata, err := routine.Metadata(ctx)
		if err != nil {
			return nil, err
		}

		mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.bigqueryService.routine", map[string]*llx.RawData{
			"id":          llx.StringData(routine.RoutineID),
			"datasetId":   llx.StringData(routine.DatasetID),
			"projectId":   llx.StringData(routine.ProjectID),
			"language":    llx.StringData(metadata.Language),
			"description": llx.StringData(metadata.Description),
			"created":     llx.TimeData(metadata.CreationTime),
			"modified":    llx.TimeData(metadata.LastModifiedTime),
			"type":        llx.StringData(string(metadata.Type)),
			"body":        llx.StringData(metadata.Body),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInstance)

	}
	return res, nil
}

func (g *mqlGcpProjectBigqueryServiceRoutine) id() (string, error) {
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	name := g.Id.Data
	return "gcp.project.bigqueryService.routine/" + name, nil
}

func entityTypeToString(entityType bigquery.EntityType) string {
	switch entityType {
	case bigquery.DomainEntity:
		return "DOMAIN"
	case bigquery.GroupEmailEntity:
		return "GROUP_EMAIL"
	case bigquery.UserEmailEntity:
		return "USER_EMAIL"
	case bigquery.SpecialGroupEntity:
		return "SPECIAL_GROUP"
	case bigquery.ViewEntity:
		return "VIEW"
	case bigquery.IAMMemberEntity:
		return "IAM_MEMBER"
	case bigquery.RoutineEntity:
		return "ROUTINE"
	case bigquery.DatasetEntity:
		return "DATASET"
	default:
		return "UNKNOWN"
	}
}
