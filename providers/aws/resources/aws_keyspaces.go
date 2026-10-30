// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/keyspaces"
	keyspaces_types "github.com/aws/aws-sdk-go-v2/service/keyspaces/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// keyspacesSystemKeyspaces is the closed set of Amazon Keyspaces system
// keyspaces. It is an exact-match set rather than a "system" prefix test: a
// prefix test also swallows user keyspaces such as systems_of_record or
// system_test, which then never appear in aws.keyspaces.keyspaces and whose
// tables are never audited -- with only a debug log to show for it.
var keyspacesSystemKeyspaces = map[string]struct{}{
	"system":                  {},
	"system_schema":           {},
	"system_schema_mcs":       {},
	"system_multiregion_info": {},
}

// isSystemKeyspace returns true for Cassandra system keyspaces that are
// present in every account/region and not relevant for security auditing.
func isSystemKeyspace(name string) bool {
	_, ok := keyspacesSystemKeyspaces[name]
	return ok
}

func (a *mqlAwsKeyspaces) id() (string, error) {
	return "aws.keyspaces", nil
}

func (a *mqlAwsKeyspaces) keyspaces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getKeyspaces(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsKeyspaces) getKeyspaces(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("keyspaces>getKeyspaces>calling aws with region %s", region)

			svc := conn.Keyspaces(region)
			ctx := context.Background()
			res := []any{}

			paginator := keyspaces.NewListKeyspacesPaginator(svc, &keyspaces.ListKeyspacesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("keyspaces service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, ks := range page.Keyspaces {
					// Skip system keyspaces — not user-created, not relevant for auditing
					if ks.KeyspaceName != nil && isSystemKeyspace(*ks.KeyspaceName) {
						continue
					}
					mqlKeyspace, err := newMqlAwsKeyspacesKeyspace(a.MqlRuntime, region, ks)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlKeyspace)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsKeyspacesKeyspace(runtime *plugin.Runtime, region string, ks keyspaces_types.KeyspaceSummary) (*mqlAwsKeyspacesKeyspace, error) {
	replicationRegions := ks.ReplicationRegions
	if replicationRegions == nil {
		replicationRegions = []string{}
	}
	resource, err := CreateResource(runtime, "aws.keyspaces.keyspace",
		map[string]*llx.RawData{
			"__id":                llx.StringDataPtr(ks.ResourceArn),
			"arn":                 llx.StringDataPtr(ks.ResourceArn),
			"name":                llx.StringDataPtr(ks.KeyspaceName),
			"region":              llx.StringData(region),
			"replicationStrategy": llx.StringData(string(ks.ReplicationStrategy)),
			"replicationRegions":  llx.ArrayData(convert.SliceAnyToInterface(replicationRegions), types.String),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsKeyspacesKeyspace), nil
}

func (a *mqlAwsKeyspacesKeyspace) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsKeyspacesKeyspace) tables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	keyspaceName := a.Name.Data
	svc := conn.Keyspaces(region)
	ctx := context.Background()
	res := []any{}

	paginator := keyspaces.NewListTablesPaginator(svc, &keyspaces.ListTablesInput{
		KeyspaceName: &keyspaceName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, table := range page.Tables {
			mqlTable, err := newMqlAwsKeyspacesTable(a.MqlRuntime, region, keyspaceName, table)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTable)
		}
	}
	return res, nil
}

func newMqlAwsKeyspacesTable(runtime *plugin.Runtime, region string, keyspaceName string, table keyspaces_types.TableSummary) (*mqlAwsKeyspacesTable, error) {
	resource, err := CreateResource(runtime, "aws.keyspaces.table",
		map[string]*llx.RawData{
			"__id":         llx.StringDataPtr(table.ResourceArn),
			"arn":          llx.StringDataPtr(table.ResourceArn),
			"keyspaceName": llx.StringData(keyspaceName),
			"name":         llx.StringDataPtr(table.TableName),
			"region":       llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsKeyspacesTable), nil
}

func (a *mqlAwsKeyspacesKeyspace) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Keyspaces(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data

	tags := make(map[string]any)
	paginator := keyspaces.NewListTagsForResourcePaginator(svc, &keyspaces.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}
	}
	return tags, nil
}

func (a *mqlAwsKeyspacesKeyspace) replicationGroupStatuses() ([]any, error) {
	// Only multi-region keyspaces have meaningful per-region replication status.
	if a.ReplicationStrategy.Data != string(keyspaces_types.RsMultiRegion) {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Keyspaces(a.Region.Data)
	ctx := context.Background()
	keyspaceName := a.Name.Data
	resp, err := svc.GetKeyspace(ctx, &keyspaces.GetKeyspaceInput{
		KeyspaceName: &keyspaceName,
	})
	if err != nil {
		return nil, err
	}
	res := make([]any, 0, len(resp.ReplicationGroupStatuses))
	for _, status := range resp.ReplicationGroupStatuses {
		row := map[string]any{
			"keyspaceStatus": string(status.KeyspaceStatus),
		}
		if status.Region != nil {
			row["region"] = *status.Region
		}
		if status.TablesReplicationProgress != nil {
			row["tablesReplicationProgress"] = *status.TablesReplicationProgress
		}
		res = append(res, row)
	}
	return res, nil
}

// mqlAwsKeyspacesTableInternal caches data from GetTable for lazy-loaded fields.
type mqlAwsKeyspacesTableInternal struct {
	fetched  bool
	fetchErr error
	lock     sync.Mutex

	// Cached GetTable response fields
	cachedStatus                    string
	cachedCreatedAt                 *time.Time
	cachedSchemaDefinition          *keyspaces_types.SchemaDefinition
	cachedThroughputMode            string
	cachedReadCapacityUnits         int64
	cachedWriteCapacityUnits        int64
	cachedLastUpdateToPayPerRequest *time.Time
	cachedWarmThroughputStatus      string
	cachedWarmReadUnitsPerSecond    int64
	cachedWarmWriteUnitsPerSecond   int64
	cachedEncryptionType            string
	cachedKmsKeyIdentifier          *string
	cachedPitrEnabled               bool
	cachedEarliestRestorableTime    *time.Time
	cachedTtlEnabled                bool
	cachedDefaultTimeToLive         int64
	cachedClientSideTimestamps      bool
	cachedCdcStatus                 string
	cachedCdcViewType               string
	cachedLatestStreamArn           string
	cachedComment                   string
	cachedReplicaSpecifications     []any
}

func (a *mqlAwsKeyspacesTable) fetchTable() error {
	if a.fetched {
		return a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Keyspaces(a.Region.Data)
	ctx := context.Background()

	keyspaceName := a.KeyspaceName.Data
	tableName := a.Name.Data
	resp, err := svc.GetTable(ctx, &keyspaces.GetTableInput{
		KeyspaceName: &keyspaceName,
		TableName:    &tableName,
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return err
	}

	a.cachedStatus = string(resp.Status)
	a.cachedCreatedAt = resp.CreationTimestamp
	a.cachedSchemaDefinition = resp.SchemaDefinition

	if resp.CapacitySpecification != nil {
		a.cachedThroughputMode = string(resp.CapacitySpecification.ThroughputMode)
		if resp.CapacitySpecification.ReadCapacityUnits != nil {
			a.cachedReadCapacityUnits = *resp.CapacitySpecification.ReadCapacityUnits
		}
		if resp.CapacitySpecification.WriteCapacityUnits != nil {
			a.cachedWriteCapacityUnits = *resp.CapacitySpecification.WriteCapacityUnits
		}
		a.cachedLastUpdateToPayPerRequest = resp.CapacitySpecification.LastUpdateToPayPerRequestTimestamp
	}

	if resp.WarmThroughputSpecification != nil {
		a.cachedWarmThroughputStatus = string(resp.WarmThroughputSpecification.Status)
		if resp.WarmThroughputSpecification.ReadUnitsPerSecond != nil {
			a.cachedWarmReadUnitsPerSecond = *resp.WarmThroughputSpecification.ReadUnitsPerSecond
		}
		if resp.WarmThroughputSpecification.WriteUnitsPerSecond != nil {
			a.cachedWarmWriteUnitsPerSecond = *resp.WarmThroughputSpecification.WriteUnitsPerSecond
		}
	}

	if resp.EncryptionSpecification != nil {
		a.cachedEncryptionType = string(resp.EncryptionSpecification.Type)
		a.cachedKmsKeyIdentifier = resp.EncryptionSpecification.KmsKeyIdentifier
	}

	if resp.PointInTimeRecovery != nil {
		a.cachedPitrEnabled = resp.PointInTimeRecovery.Status == keyspaces_types.PointInTimeRecoveryStatusEnabled
		a.cachedEarliestRestorableTime = resp.PointInTimeRecovery.EarliestRestorableTimestamp
	}

	if resp.Ttl != nil {
		a.cachedTtlEnabled = resp.Ttl.Status == keyspaces_types.TimeToLiveStatusEnabled
	}

	if resp.DefaultTimeToLive != nil {
		a.cachedDefaultTimeToLive = int64(*resp.DefaultTimeToLive)
	}

	if resp.ClientSideTimestamps != nil {
		a.cachedClientSideTimestamps = resp.ClientSideTimestamps.Status == keyspaces_types.ClientSideTimestampsStatusEnabled
	}

	if resp.CdcSpecification != nil {
		a.cachedCdcStatus = string(resp.CdcSpecification.Status)
		a.cachedCdcViewType = string(resp.CdcSpecification.ViewType)
	}

	if resp.LatestStreamArn != nil {
		a.cachedLatestStreamArn = *resp.LatestStreamArn
	}

	if resp.Comment != nil && resp.Comment.Message != nil {
		a.cachedComment = *resp.Comment.Message
	}

	if len(resp.ReplicaSpecifications) > 0 {
		replicas := make([]any, 0, len(resp.ReplicaSpecifications))
		for _, replica := range resp.ReplicaSpecifications {
			row := map[string]any{
				"status": string(replica.Status),
			}
			if replica.Region != nil {
				row["region"] = *replica.Region
			}
			if replica.CapacitySpecification != nil {
				row["throughputMode"] = string(replica.CapacitySpecification.ThroughputMode)
				if replica.CapacitySpecification.ReadCapacityUnits != nil {
					row["readCapacityUnits"] = *replica.CapacitySpecification.ReadCapacityUnits
				}
				if replica.CapacitySpecification.WriteCapacityUnits != nil {
					row["writeCapacityUnits"] = *replica.CapacitySpecification.WriteCapacityUnits
				}
			}
			if replica.WarmThroughputSpecification != nil {
				row["warmThroughputStatus"] = string(replica.WarmThroughputSpecification.Status)
				if replica.WarmThroughputSpecification.ReadUnitsPerSecond != nil {
					row["warmReadUnitsPerSecond"] = *replica.WarmThroughputSpecification.ReadUnitsPerSecond
				}
				if replica.WarmThroughputSpecification.WriteUnitsPerSecond != nil {
					row["warmWriteUnitsPerSecond"] = *replica.WarmThroughputSpecification.WriteUnitsPerSecond
				}
			}
			replicas = append(replicas, row)
		}
		a.cachedReplicaSpecifications = replicas
	}

	a.fetched = true
	return nil
}

func (a *mqlAwsKeyspacesTable) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsKeyspacesTable) status() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedStatus, nil
}

func (a *mqlAwsKeyspacesTable) createdAt() (*time.Time, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	return a.cachedCreatedAt, nil
}

func (a *mqlAwsKeyspacesTable) columns() ([]any, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	if a.cachedSchemaDefinition == nil {
		return []any{}, nil
	}
	res := make([]any, 0, len(a.cachedSchemaDefinition.AllColumns))
	for _, col := range a.cachedSchemaDefinition.AllColumns {
		id := fmt.Sprintf("%s/%s/%s", a.KeyspaceName.Data, a.Name.Data, *col.Name)
		mqlCol, err := CreateResource(a.MqlRuntime, "aws.keyspaces.table.column",
			map[string]*llx.RawData{
				"__id": llx.StringData(id),
				"id":   llx.StringData(id),
				"name": llx.StringDataPtr(col.Name),
				"type": llx.StringDataPtr(col.Type),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCol)
	}
	return res, nil
}

func (a *mqlAwsKeyspacesTable) partitionKeys() ([]any, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	if a.cachedSchemaDefinition == nil {
		return []any{}, nil
	}
	res := make([]any, 0, len(a.cachedSchemaDefinition.PartitionKeys))
	for _, pk := range a.cachedSchemaDefinition.PartitionKeys {
		colType := a.findColumnType(*pk.Name)
		id := fmt.Sprintf("%s/%s/pk/%s", a.KeyspaceName.Data, a.Name.Data, *pk.Name)
		mqlCol, err := CreateResource(a.MqlRuntime, "aws.keyspaces.table.column",
			map[string]*llx.RawData{
				"__id": llx.StringData(id),
				"id":   llx.StringData(id),
				"name": llx.StringDataPtr(pk.Name),
				"type": llx.StringData(colType),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCol)
	}
	return res, nil
}

func (a *mqlAwsKeyspacesTable) clusteringKeys() ([]any, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	if a.cachedSchemaDefinition == nil {
		return []any{}, nil
	}
	res := make([]any, 0, len(a.cachedSchemaDefinition.ClusteringKeys))
	for _, ck := range a.cachedSchemaDefinition.ClusteringKeys {
		id := fmt.Sprintf("%s/%s/ck/%s", a.KeyspaceName.Data, a.Name.Data, *ck.Name)
		mqlCk, err := CreateResource(a.MqlRuntime, "aws.keyspaces.table.clusteringKey",
			map[string]*llx.RawData{
				"__id":    llx.StringData(id),
				"id":      llx.StringData(id),
				"name":    llx.StringDataPtr(ck.Name),
				"orderBy": llx.StringData(string(ck.OrderBy)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCk)
	}
	return res, nil
}

func (a *mqlAwsKeyspacesTable) staticColumns() ([]any, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	if a.cachedSchemaDefinition == nil {
		return []any{}, nil
	}
	res := make([]any, 0, len(a.cachedSchemaDefinition.StaticColumns))
	for _, sc := range a.cachedSchemaDefinition.StaticColumns {
		colType := a.findColumnType(*sc.Name)
		id := fmt.Sprintf("%s/%s/static/%s", a.KeyspaceName.Data, a.Name.Data, *sc.Name)
		mqlCol, err := CreateResource(a.MqlRuntime, "aws.keyspaces.table.column",
			map[string]*llx.RawData{
				"__id": llx.StringData(id),
				"id":   llx.StringData(id),
				"name": llx.StringDataPtr(sc.Name),
				"type": llx.StringData(colType),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCol)
	}
	return res, nil
}

func (a *mqlAwsKeyspacesTable) findColumnType(name string) string {
	if a.cachedSchemaDefinition == nil {
		return ""
	}
	for _, col := range a.cachedSchemaDefinition.AllColumns {
		if col.Name != nil && *col.Name == name {
			if col.Type != nil {
				return *col.Type
			}
			return ""
		}
	}
	return ""
}

func (a *mqlAwsKeyspacesTable) throughputMode() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedThroughputMode, nil
}

func (a *mqlAwsKeyspacesTable) readCapacityUnits() (int64, error) {
	if err := a.fetchTable(); err != nil {
		return 0, err
	}
	return a.cachedReadCapacityUnits, nil
}

func (a *mqlAwsKeyspacesTable) writeCapacityUnits() (int64, error) {
	if err := a.fetchTable(); err != nil {
		return 0, err
	}
	return a.cachedWriteCapacityUnits, nil
}

func (a *mqlAwsKeyspacesTable) encryptionType() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedEncryptionType, nil
}

func (a *mqlAwsKeyspacesTable) kmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	if a.cachedKmsKeyIdentifier == nil || *a.cachedKmsKeyIdentifier == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cachedKmsKeyIdentifier),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsKeyspacesTable) pointInTimeRecoveryEnabled() (bool, error) {
	if err := a.fetchTable(); err != nil {
		return false, err
	}
	return a.cachedPitrEnabled, nil
}

func (a *mqlAwsKeyspacesTable) earliestRestorableTimestamp() (*time.Time, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	return a.cachedEarliestRestorableTime, nil
}

func (a *mqlAwsKeyspacesTable) ttlEnabled() (bool, error) {
	if err := a.fetchTable(); err != nil {
		return false, err
	}
	return a.cachedTtlEnabled, nil
}

func (a *mqlAwsKeyspacesTable) defaultTimeToLive() (int64, error) {
	if err := a.fetchTable(); err != nil {
		return 0, err
	}
	return a.cachedDefaultTimeToLive, nil
}

func (a *mqlAwsKeyspacesTable) clientSideTimestampsEnabled() (bool, error) {
	if err := a.fetchTable(); err != nil {
		return false, err
	}
	return a.cachedClientSideTimestamps, nil
}

func (a *mqlAwsKeyspacesTable) lastUpdateToPayPerRequestTimestamp() (*time.Time, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	return a.cachedLastUpdateToPayPerRequest, nil
}

func (a *mqlAwsKeyspacesTable) warmThroughputStatus() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedWarmThroughputStatus, nil
}

func (a *mqlAwsKeyspacesTable) warmReadUnitsPerSecond() (int64, error) {
	if err := a.fetchTable(); err != nil {
		return 0, err
	}
	return a.cachedWarmReadUnitsPerSecond, nil
}

func (a *mqlAwsKeyspacesTable) warmWriteUnitsPerSecond() (int64, error) {
	if err := a.fetchTable(); err != nil {
		return 0, err
	}
	return a.cachedWarmWriteUnitsPerSecond, nil
}

func (a *mqlAwsKeyspacesTable) cdcStatus() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedCdcStatus, nil
}

func (a *mqlAwsKeyspacesTable) cdcViewType() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedCdcViewType, nil
}

func (a *mqlAwsKeyspacesTable) latestStreamArn() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedLatestStreamArn, nil
}

func (a *mqlAwsKeyspacesTable) comment() (string, error) {
	if err := a.fetchTable(); err != nil {
		return "", err
	}
	return a.cachedComment, nil
}

func (a *mqlAwsKeyspacesTable) replicaSpecifications() ([]any, error) {
	if err := a.fetchTable(); err != nil {
		return nil, err
	}
	if a.cachedReplicaSpecifications == nil {
		return []any{}, nil
	}
	return a.cachedReplicaSpecifications, nil
}

func (a *mqlAwsKeyspacesTable) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Keyspaces(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data

	tags := make(map[string]any)
	paginator := keyspaces.NewListTagsForResourcePaginator(svc, &keyspaces.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, t := range page.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}
	}
	return tags, nil
}

func (a *mqlAwsKeyspacesTableColumn) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsKeyspacesTableClusteringKey) id() (string, error) {
	return a.Id.Data, nil
}
