// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aatypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
)

func (a *mqlAwsDynamodb) id() (string, error) {
	return "aws.dynamodb", nil
}

func (a *mqlAwsDynamodb) exports() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getExports(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}

	// get all the results
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsDynamodbExport) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsDynamodbExportInternal struct {
	exportCache *ddtypes.ExportDescription
	fetched     bool
	region      string
	arn         string
	lock        sync.Mutex
}

func (a *mqlAwsDynamodbExport) fetchExport() (*ddtypes.ExportDescription, error) {
	if a.fetched {
		return a.exportCache, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.exportCache, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Dynamodb(a.region)
	desc, err := svc.DescribeExport(ctx, &dynamodb.DescribeExportInput{ExportArn: aws.String(a.arn)})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.fetched = true
			return nil, nil
		}
		return nil, err
	}
	a.exportCache = desc.ExportDescription
	a.fetched = true
	return desc.ExportDescription, nil
}

func (a *mqlAwsDynamodb) getExports(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dynamodb>getExports>calling aws with region %s", region)

			svc := conn.Dynamodb(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				listExportsResp, err := svc.ListExports(ctx, &dynamodb.ListExportsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather aws dynamodb exports")
				}
				for _, exp := range listExportsResp.ExportSummaries {
					mqlExport, err := CreateResource(a.MqlRuntime, "aws.dynamodb.export",
						map[string]*llx.RawData{
							"arn":    llx.StringDataPtr(exp.ExportArn),
							"type":   llx.StringData(string(exp.ExportType)),
							"status": llx.StringData(string(exp.ExportStatus)),
						})
					if err != nil {
						return nil, err
					}
					mqlExport.(*mqlAwsDynamodbExport).arn = convert.ToValue(exp.ExportArn)
					mqlExport.(*mqlAwsDynamodbExport).region = region
					res = append(res, mqlExport)
				}
				if listExportsResp.NextToken == nil {
					break
				}
				nextToken = listExportsResp.NextToken
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDynamodbExport) s3Prefix() (string, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return "", err
	}
	if exp != nil && exp.S3Prefix != nil {
		return *exp.S3Prefix, nil
	}
	return "", nil
}

func (a *mqlAwsDynamodbExport) itemCount() (int64, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return 0, err
	}
	if exp != nil && exp.ItemCount != nil {
		return *exp.ItemCount, nil
	}
	return 0, nil
}

func (a *mqlAwsDynamodbExport) format() (string, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return "", err
	}
	if exp == nil {
		return "", nil
	}
	return string(exp.ExportFormat), nil
}

func (a *mqlAwsDynamodbExport) startTime() (*time.Time, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return nil, err
	}
	if exp == nil {
		return nil, nil
	}
	return exp.StartTime, nil
}

func (a *mqlAwsDynamodbExport) endTime() (*time.Time, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return nil, err
	}
	if exp == nil {
		return nil, nil
	}
	return exp.EndTime, nil
}

func (a *mqlAwsDynamodbExport) s3SseAlgorithm() (string, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return "", err
	}
	if exp == nil {
		return "", nil
	}
	return string(exp.S3SseAlgorithm), nil
}

func (a *mqlAwsDynamodbExport) s3Bucket() (*mqlAwsS3Bucket, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return nil, err
	}
	if exp == nil || exp.S3Bucket == nil || *exp.S3Bucket == "" {
		a.S3Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlS3Bucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{
			"name": llx.StringDataPtr(exp.S3Bucket),
		})
	if err != nil {
		return nil, err
	}
	return mqlS3Bucket.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsDynamodbExport) kmsKey() (*mqlAwsKmsKey, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return nil, err
	}
	if exp == nil || exp.S3SseKmsKeyId == nil {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		kmsKeyRefArgs(a.region, conn.AccountId(), convert.ToValue(exp.S3SseKmsKeyId)))
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsDynamodbExport) table() (*mqlAwsDynamodbTable, error) {
	exp, err := a.fetchExport()
	if err != nil {
		return nil, err
	}
	if exp == nil {
		a.Table.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	if exp.TableArn == nil || *exp.TableArn == "" {
		a.Table.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqltable, err := NewResource(a.MqlRuntime, "aws.dynamodb.table",
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(exp.TableArn),
		})
	if err != nil {
		return nil, err
	}
	return mqltable.(*mqlAwsDynamodbTable), nil
}

func (a *mqlAwsDynamodb) backups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getBackups(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsDynamodb) getBackups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dynamodb>getBackups>calling aws with region %s", region)

			svc := conn.Dynamodb(region)
			ctx := context.Background()
			res := []any{}

			var allBackups []ddtypes.BackupSummary
			var exclusiveStartBackupArn *string
			for {
				listBackupsResp, err := svc.ListBackups(ctx, &dynamodb.ListBackupsInput{
					ExclusiveStartBackupArn: exclusiveStartBackupArn,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather aws dynamodb backups")
				}
				allBackups = append(allBackups, listBackupsResp.BackupSummaries...)
				if listBackupsResp.LastEvaluatedBackupArn == nil {
					break
				}
				exclusiveStartBackupArn = listBackupsResp.LastEvaluatedBackupArn
			}
			backupSummary, err := convert.JsonToDictSlice(allBackups)
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult(backupSummary), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsDynamodbTable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformDynamodbTable); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch dynamodb table")
	}

	arnVal := args["arn"].Value.(string)

	// No API call is required: the DynamoDB table ARN
	// (arn:aws:dynamodb:<region>:<acct>:table/<name>) carries both the region
	// and the table name, and the list path only constructs a shell (arn / name
	// / region / id) - the heavy fields lazy-load via fetchDetail->DescribeTable.
	// So derive region + name from the ARN and build the shell directly instead
	// of fanning ListTables across every region and scanning in memory.
	var region, tableName string
	if parsed, err := arn.Parse(arnVal); err == nil && strings.HasPrefix(parsed.Resource, "table/") {
		region = parsed.Region
		tableName = strings.TrimPrefix(parsed.Resource, "table/")
	}
	if args["region"] != nil {
		if r, ok := args["region"].Value.(string); ok && r != "" {
			region = r
		}
	}
	if args["name"] != nil {
		if n, ok := args["name"].Value.(string); ok && n != "" {
			tableName = n
		}
	}

	if region != "" && tableName != "" {
		table, err := CreateResource(runtime, "aws.dynamodb.table",
			map[string]*llx.RawData{
				"arn":    llx.StringData(arnVal),
				"name":   llx.StringData(tableName),
				"region": llx.StringData(region),
				"id":     llx.StringData(""),
			})
		if err != nil {
			return nil, nil, err
		}
		return args, table, nil
	}

	// Fallback: scan the cached list (e.g. when the ARN can't be parsed and
	// there's no region hint).
	obj, err := CreateResource(runtime, "aws.dynamodb", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	dynamodb := obj.(*mqlAwsDynamodb)

	rawResources := dynamodb.GetTables()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	for _, rawResource := range rawResources.Data {
		dbInstance := rawResource.(*mqlAwsDynamodbTable)
		if dbInstance.Arn.Data == arnVal {
			return args, dbInstance, nil
		}
	}
	return nil, nil, errors.New("dynamo db table does not exist")
}

func (a *mqlAwsDynamodbTable) backups() ([]any, error) {
	tableName := a.Name.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Dynamodb(region)
	ctx := context.Background()

	var allBackups []ddtypes.BackupSummary
	var exclusiveStartBackupArn *string
	for {
		listBackupsResp, err := svc.ListBackups(ctx, &dynamodb.ListBackupsInput{
			TableName:               &tableName,
			ExclusiveStartBackupArn: exclusiveStartBackupArn,
		})
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws dynamodb backups")
		}
		allBackups = append(allBackups, listBackupsResp.BackupSummaries...)
		if listBackupsResp.LastEvaluatedBackupArn == nil {
			break
		}
		exclusiveStartBackupArn = listBackupsResp.LastEvaluatedBackupArn
	}
	return convert.JsonToDictSlice(allBackups)
}

type mqlAwsDynamodbTableInternal struct {
	cacheSseKmsKeyArn   *string
	cacheSourceTableArn *string
	fetched             bool
	fetchErr            error
	lock                sync.Mutex

	cbFetched bool
	cbErr     error
	cb        *ddtypes.ContinuousBackupsDescription
	cbLock    sync.Mutex
}

func (a *mqlAwsDynamodbTable) sseKmsKey() (*mqlAwsKmsKey, error) {
	// cacheSseKmsKeyArn is assigned by fetchDetail, so reading it without
	// fetching first reports null for every table - including one encrypted
	// with a customer-managed key, which is the case this field exists to
	// answer. sourceTable, the sibling built on the same cache, already
	// fetches first.
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	if a.cacheSseKmsKeyArn == nil || *a.cacheSseKmsKeyArn == "" {
		a.SseKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheSseKmsKeyArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsDynamodbTable) tags() (map[string]any, error) {
	tableArn := a.Arn.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Dynamodb(region)
	ctx := context.Background()
	tags, err := svc.ListTagsOfResource(ctx, &dynamodb.ListTagsOfResourceInput{ResourceArn: &tableArn})
	if err != nil {
		return nil, err
	}

	return dynamoDBTagsToMap(tags.Tags), nil
}

func (a *mqlAwsDynamodb) limits() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLimits(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.(any))
	}
	return res, nil
}

func (a *mqlAwsDynamodb) getLimits(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dynamodb>getLimits>calling aws with region %s", region)

			svc := conn.Dynamodb(region)
			ctx := context.Background()
			res := []any{}

			// no pagination required
			limitsResp, err := svc.DescribeLimits(ctx, &dynamodb.DescribeLimitsInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, errors.Wrap(err, "could not gather aws dynamodb backups")
			}

			mqlLimits, err := CreateResource(a.MqlRuntime, "aws.dynamodb.limit",
				map[string]*llx.RawData{
					"arn":             llx.StringData(fmt.Sprintf(limitsArn, region, conn.AccountId())),
					"region":          llx.StringData(region),
					"accountMaxRead":  llx.IntDataPtr(limitsResp.AccountMaxReadCapacityUnits),
					"accountMaxWrite": llx.IntDataPtr(limitsResp.AccountMaxWriteCapacityUnits),
					"tableMaxRead":    llx.IntDataPtr(limitsResp.TableMaxReadCapacityUnits),
					"tableMaxWrite":   llx.IntDataPtr(limitsResp.TableMaxWriteCapacityUnits),
				})
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult(mqlLimits), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDynamodb) globalTables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Dynamodb("")
	ctx := context.Background()

	res := []any{}
	var exclusiveStartGlobalTableName *string
	for {
		listGlobalTablesResp, err := svc.ListGlobalTables(ctx, &dynamodb.ListGlobalTablesInput{ExclusiveStartGlobalTableName: exclusiveStartGlobalTableName})
		if err != nil {
			return nil, errors.Wrap(err, "could not gather aws dynamodb global tables")
		}
		for _, table := range listGlobalTablesResp.GlobalTables {
			mqlTable, err := CreateResource(a.MqlRuntime, "aws.dynamodb.globaltable",
				map[string]*llx.RawData{
					"arn":  llx.StringData(fmt.Sprintf(dynamoGlobalTableArnPattern, conn.AccountId(), convert.ToValue(table.GlobalTableName))),
					"name": llx.StringDataPtr(table.GlobalTableName),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTable)
		}
		if listGlobalTablesResp.LastEvaluatedGlobalTableName == nil {
			break
		}
		exclusiveStartGlobalTableName = listGlobalTablesResp.LastEvaluatedGlobalTableName
	}
	return res, nil
}

func (a *mqlAwsDynamodb) tables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTables(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsDynamodb) getTables(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("dynamodb>getTables>calling aws with region %s", region)

			svc := conn.Dynamodb(region)
			ctx := context.Background()
			res := []any{}

			var exclusiveStartTableName *string
			for {
				listTablesResp, err := svc.ListTables(ctx, &dynamodb.ListTablesInput{ExclusiveStartTableName: exclusiveStartTableName})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather aws dynamodb tables")
				}
				for _, tableName := range listTablesResp.TableNames {
					mqlTable, err := CreateResource(a.MqlRuntime, "aws.dynamodb.table",
						map[string]*llx.RawData{
							"arn":    llx.StringData(fmt.Sprintf(dynamoTableArnPattern, region, conn.AccountId(), tableName)),
							"name":   llx.StringData(tableName),
							"region": llx.StringData(region),
							"id":     llx.StringData(""),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTable)
				}
				if listTablesResp.LastEvaluatedTableName == nil {
					break
				}
				exclusiveStartTableName = listTablesResp.LastEvaluatedTableName
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDynamodbTable) fetchDetail() error {
	if a.fetched {
		return a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	tableName := a.Name.Data
	svc := conn.Dynamodb(region)
	ctx := context.Background()

	table, err := svc.DescribeTable(ctx, &dynamodb.DescribeTableInput{TableName: &tableName})
	if err != nil {
		a.fetchErr = errors.Wrap(err, "could not get aws dynamodb table")
		a.fetched = true
		return a.fetchErr
	}

	sseDict, err := convert.JsonToDict(table.Table.SSEDescription)
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return a.fetchErr
	}
	throughputDict, err := convert.JsonToDict(table.Table.ProvisionedThroughput)
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return a.fetchErr
	}

	var sseType string
	if table.Table.SSEDescription != nil {
		sseType = string(table.Table.SSEDescription.SSEType)
		a.cacheSseKmsKeyArn = table.Table.SSEDescription.KMSMasterKeyArn
	}

	a.SseDescription = plugin.TValue[any]{Data: sseDict, State: plugin.StateIsSet}
	a.SseType = plugin.TValue[string]{Data: sseType, State: plugin.StateIsSet}
	a.KmsMasterKeyId = plugin.TValue[string]{Data: convert.ToValue(a.cacheSseKmsKeyArn), State: plugin.StateIsSet}
	a.ProvisionedThroughput = plugin.TValue[any]{Data: throughputDict, State: plugin.StateIsSet}
	a.CreatedAt = plugin.TValue[*time.Time]{Data: table.Table.CreationDateTime, State: plugin.StateIsSet}
	a.DeletionProtectionEnabled = plugin.TValue[bool]{Data: convert.ToValue(table.Table.DeletionProtectionEnabled), State: plugin.StateIsSet}
	a.GlobalTableVersion = plugin.TValue[string]{Data: convert.ToValue(table.Table.GlobalTableVersion), State: plugin.StateIsSet}
	a.Id = plugin.TValue[string]{Data: convert.ToValue(table.Table.TableId), State: plugin.StateIsSet}
	a.SizeBytes = plugin.TValue[int64]{Data: convert.ToValue(table.Table.TableSizeBytes), State: plugin.StateIsSet}
	a.Status = plugin.TValue[string]{Data: string(table.Table.TableStatus), State: plugin.StateIsSet}
	a.Items = plugin.TValue[int64]{Data: convert.ToValue(table.Table.ItemCount), State: plugin.StateIsSet}
	a.LatestStreamArn = plugin.TValue[string]{Data: convert.ToValue(table.Table.LatestStreamArn), State: plugin.StateIsSet}
	a.LatestStreamLabel = plugin.TValue[string]{Data: convert.ToValue(table.Table.LatestStreamLabel), State: plugin.StateIsSet}
	a.TableClass = plugin.TValue[string]{Data: tableClassFromSummary(table.Table.TableClassSummary), State: plugin.StateIsSet}
	a.StreamEnabled = plugin.TValue[bool]{Data: streamEnabledFromSpec(table.Table.StreamSpecification), State: plugin.StateIsSet}
	a.StreamViewType = plugin.TValue[string]{Data: streamViewTypeFromSpec(table.Table.StreamSpecification), State: plugin.StateIsSet}
	a.BillingMode = plugin.TValue[string]{Data: billingModeFromSummary(table.Table.BillingModeSummary), State: plugin.StateIsSet}
	a.ReplicaRegions = plugin.TValue[[]any]{Data: replicaRegionsFromDescriptions(table.Table.Replicas), State: plugin.StateIsSet}

	// RestoreSummary is only present when the table was created by restoring from
	// a backup or point-in-time recovery; its absence means "not restored".
	rs := table.Table.RestoreSummary
	a.RestoredFromBackup = plugin.TValue[bool]{Data: rs != nil, State: plugin.StateIsSet}
	if rs != nil {
		a.RestoreInProgress = plugin.TValue[bool]{Data: convert.ToValue(rs.RestoreInProgress), State: plugin.StateIsSet}
		a.RestoreDateTime = plugin.TValue[*time.Time]{Data: rs.RestoreDateTime, State: plugin.StateIsSet}
		a.cacheSourceTableArn = rs.SourceTableArn
	} else {
		a.RestoreInProgress = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
		a.RestoreDateTime = plugin.TValue[*time.Time]{Data: nil, State: plugin.StateIsSet | plugin.StateIsNull}
	}

	gsiList := []any{}
	for _, gsi := range table.Table.GlobalSecondaryIndexes {
		d, _ := convert.JsonToDict(gsi)
		gsiList = append(gsiList, d)
	}
	a.GlobalSecondaryIndexes = plugin.TValue[[]any]{Data: gsiList, State: plugin.StateIsSet}

	a.fetched = true
	return nil
}

func (a *mqlAwsDynamodbTable) sseDescription() (any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) sseType() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) kmsMasterKeyId() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) provisionedThroughput() (any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) createdAt() (*time.Time, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) deletionProtectionEnabled() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) globalTableVersion() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) items() (int64, error) {
	return 0, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) sizeBytes() (int64, error) {
	return 0, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) status() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) latestStreamArn() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) latestStreamLabel() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) tableClass() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) streamEnabled() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) streamViewType() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) billingMode() (string, error) {
	return "", a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) replicaRegions() ([]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) restoredFromBackup() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) restoreInProgress() (bool, error) {
	return false, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) restoreDateTime() (*time.Time, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) sourceTable() (*mqlAwsDynamodbTable, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	if a.cacheSourceTableArn == nil || *a.cacheSourceTableArn == "" {
		a.SourceTable.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.dynamodb.table",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheSourceTableArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsDynamodbTable), nil
}

func (a *mqlAwsDynamodbTable) autoScalingEnabled() (bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	tableName := a.Name.Data
	svc := conn.ApplicationAutoscaling(region)
	ctx := context.Background()

	// A table "scales with demand" when both its read and write capacity have
	// Application Auto Scaling scalable targets. On-demand (PAY_PER_REQUEST)
	// tables have none and are evaluated by their billing mode instead.
	resp, err := svc.DescribeScalableTargets(ctx, &applicationautoscaling.DescribeScalableTargetsInput{
		ServiceNamespace: aatypes.ServiceNamespaceDynamodb,
		ResourceIds:      []string{"table/" + tableName},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return false, nil
		}
		return false, err
	}

	var hasRead, hasWrite bool
	for i := range resp.ScalableTargets {
		switch resp.ScalableTargets[i].ScalableDimension {
		case aatypes.ScalableDimensionDynamoDBTableReadCapacityUnits:
			hasRead = true
		case aatypes.ScalableDimensionDynamoDBTableWriteCapacityUnits:
			hasWrite = true
		}
	}
	return hasRead && hasWrite, nil
}

func (a *mqlAwsDynamodbTable) globalSecondaryIndexes() ([]any, error) {
	return nil, a.fetchDetail()
}

func (a *mqlAwsDynamodbTable) ttlDescription() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	tableName := a.Name.Data
	svc := conn.Dynamodb(region)
	ctx := context.Background()

	resp, err := svc.DescribeTimeToLive(ctx, &dynamodb.DescribeTimeToLiveInput{TableName: &tableName})
	if err != nil {
		return nil, err
	}
	if resp.TimeToLiveDescription == nil {
		return nil, nil
	}
	return convert.JsonToDict(resp.TimeToLiveDescription)
}

func tableClassFromSummary(s *ddtypes.TableClassSummary) string {
	if s == nil {
		return string(ddtypes.TableClassStandard)
	}
	return string(s.TableClass)
}

func streamEnabledFromSpec(s *ddtypes.StreamSpecification) bool {
	if s == nil || s.StreamEnabled == nil {
		return false
	}
	return *s.StreamEnabled
}

func streamViewTypeFromSpec(s *ddtypes.StreamSpecification) string {
	if s == nil {
		return ""
	}
	return string(s.StreamViewType)
}

func billingModeFromSummary(s *ddtypes.BillingModeSummary) string {
	if s == nil {
		return string(ddtypes.BillingModeProvisioned)
	}
	return string(s.BillingMode)
}

func replicaRegionsFromDescriptions(replicas []ddtypes.ReplicaDescription) []any {
	res := make([]any, 0, len(replicas))
	for _, r := range replicas {
		if r.RegionName != nil {
			res = append(res, *r.RegionName)
		}
	}
	return res
}

func dynamoDBTagsToMap(tags []ddtypes.Tag) map[string]any {
	return tagsToMap(tags, func(t ddtypes.Tag) *string { return t.Key }, func(t ddtypes.Tag) *string { return t.Value })
}

func (a *mqlAwsDynamodbGlobaltable) replicaSettings() ([]any, error) {
	tableName := a.Name.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Dynamodb("")
	ctx := context.Background()

	// no pagination required
	tableSettingsResp, err := svc.DescribeGlobalTableSettings(ctx, &dynamodb.DescribeGlobalTableSettingsInput{GlobalTableName: &tableName})
	if err != nil {
		return nil, errors.Wrap(err, "could not gather aws dynamodb table settings")
	}
	return convert.JsonToDictSlice(tableSettingsResp.ReplicaSettings)
}

func initAwsDynamodbGlobaltable(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformDynamodbGlobaltable); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch dynamodb table")
	}

	obj, err := CreateResource(runtime, "aws.dynamodb", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	dynamodb := obj.(*mqlAwsDynamodb)

	rawResources := dynamodb.GetGlobalTables()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		dbInstance := rawResource.(*mqlAwsDynamodbGlobaltable)
		if dbInstance.Arn.Data == arnVal {
			return args, dbInstance, nil
		}
	}
	return nil, nil, errors.New("dynamo db table does not exist")
}

// fetchContinuousBackups loads the table's continuous-backups description once
// and shares it across the raw continuousBackups dict and the typed PITR
// scalars, so the whole group costs a single DescribeContinuousBackups call.
func (a *mqlAwsDynamodbTable) fetchContinuousBackups() (*ddtypes.ContinuousBackupsDescription, error) {
	if a.cbFetched {
		return a.cb, a.cbErr
	}
	a.cbLock.Lock()
	defer a.cbLock.Unlock()
	if a.cbFetched {
		return a.cb, a.cbErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Dynamodb(a.Region.Data)
	ctx := context.Background()

	// no pagination required
	resp, err := svc.DescribeContinuousBackups(ctx, &dynamodb.DescribeContinuousBackupsInput{TableName: &a.Name.Data})
	a.cbFetched = true
	if err != nil {
		a.cbErr = errors.Wrap(err, "could not gather aws dynamodb continuous backups")
		return nil, a.cbErr
	}
	a.cb = resp.ContinuousBackupsDescription
	return a.cb, nil
}

func (a *mqlAwsDynamodbTable) continuousBackups() (any, error) {
	cb, err := a.fetchContinuousBackups()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(cb)
}

func (a *mqlAwsDynamodbTable) continuousBackupsEnabled() (bool, error) {
	cb, err := a.fetchContinuousBackups()
	if err != nil || cb == nil {
		return false, err
	}
	return cb.ContinuousBackupsStatus == ddtypes.ContinuousBackupsStatusEnabled, nil
}

func (a *mqlAwsDynamodbTable) pointInTimeRecoveryEnabled() (bool, error) {
	cb, err := a.fetchContinuousBackups()
	if err != nil || cb == nil || cb.PointInTimeRecoveryDescription == nil {
		return false, err
	}
	return cb.PointInTimeRecoveryDescription.PointInTimeRecoveryStatus == ddtypes.PointInTimeRecoveryStatusEnabled, nil
}

func (a *mqlAwsDynamodbTable) earliestRestorableDateTime() (*time.Time, error) {
	cb, err := a.fetchContinuousBackups()
	if err != nil || cb == nil || cb.PointInTimeRecoveryDescription == nil {
		return nil, err
	}
	return cb.PointInTimeRecoveryDescription.EarliestRestorableDateTime, nil
}

func (a *mqlAwsDynamodbTable) latestRestorableDateTime() (*time.Time, error) {
	cb, err := a.fetchContinuousBackups()
	if err != nil || cb == nil || cb.PointInTimeRecoveryDescription == nil {
		return nil, err
	}
	return cb.PointInTimeRecoveryDescription.LatestRestorableDateTime, nil
}

func (a *mqlAwsDynamodbTable) pitrRecoveryPeriodInDays() (int64, error) {
	cb, err := a.fetchContinuousBackups()
	if err != nil || cb == nil || cb.PointInTimeRecoveryDescription == nil {
		return 0, err
	}
	period := cb.PointInTimeRecoveryDescription.RecoveryPeriodInDays
	if period == nil {
		// 0 is not a valid PITR window (AWS uses 1-35 days), so it unambiguously
		// signals "no configured recovery period" (PITR disabled or default retention).
		return 0, nil
	}
	return int64(*period), nil
}

func (a *mqlAwsDynamodbGlobaltable) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDynamodbTable) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDynamodbLimit) id() (string, error) {
	return a.Arn.Data, nil
}
