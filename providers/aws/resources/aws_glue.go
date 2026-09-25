// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/glue"
	glue_types "github.com/aws/aws-sdk-go-v2/service/glue/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsGlue) id() (string, error) {
	return "aws.glue", nil
}

func (a *mqlAwsGlue) crawlers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCrawlers(conn), 5)
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

func (a *mqlAwsGlue) getCrawlers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getCrawlers>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewGetCrawlersPaginator(svc, &glue.GetCrawlersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, crawler := range page.Crawlers {
					mqlCrawler, err := newMqlAwsGlueCrawler(a.MqlRuntime, region, conn.AccountId(), crawler)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCrawler)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsGlueCrawlerInternal struct {
	cacheRoleArn                   *string
	cacheSecurityConfigurationName *string
}

func newMqlAwsGlueCrawler(runtime *plugin.Runtime, region string, accountID string, crawler glue_types.Crawler) (*mqlAwsGlueCrawler, error) {
	arn := fmt.Sprintf("arn:aws:glue:%s:%s:crawler/%s", region, accountID, convert.ToValue(crawler.Name))

	targets, err := convert.JsonToDict(crawler.Targets)
	if err != nil {
		return nil, err
	}

	schemaChangePolicy, err := convert.JsonToDict(crawler.SchemaChangePolicy)
	if err != nil {
		return nil, err
	}

	recrawlPolicy, err := convert.JsonToDict(crawler.RecrawlPolicy)
	if err != nil {
		return nil, err
	}

	lineageConfiguration, err := convert.JsonToDict(crawler.LineageConfiguration)
	if err != nil {
		return nil, err
	}

	lakeFormationConfiguration, err := convert.JsonToDict(crawler.LakeFormationConfiguration)
	if err != nil {
		return nil, err
	}

	lastCrawl, err := convert.JsonToDict(crawler.LastCrawl)
	if err != nil {
		return nil, err
	}

	var schedule string
	if crawler.Schedule != nil {
		schedule = convert.ToValue(crawler.Schedule.ScheduleExpression)
	}

	resource, err := CreateResource(runtime, "aws.glue.crawler",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(arn),
			"arn":                        llx.StringData(arn),
			"name":                       llx.StringDataPtr(crawler.Name),
			"role":                       llx.StringDataPtr(crawler.Role),
			"databaseName":               llx.StringDataPtr(crawler.DatabaseName),
			"description":                llx.StringDataPtr(crawler.Description),
			"targets":                    llx.DictData(targets),
			"schedule":                   llx.StringData(schedule),
			"classifiers":                llx.ArrayData(convert.SliceAnyToInterface(crawler.Classifiers), types.String),
			"schemaChangePolicy":         llx.DictData(schemaChangePolicy),
			"recrawlPolicy":              llx.DictData(recrawlPolicy),
			"lineageConfiguration":       llx.DictData(lineageConfiguration),
			"lakeFormationConfiguration": llx.DictData(lakeFormationConfiguration),
			"state":                      llx.StringData(string(crawler.State)),
			"configuration":              llx.StringDataPtr(crawler.Configuration),
			"tablePrefix":                llx.StringDataPtr(crawler.TablePrefix),
			"securityConfiguration":      llx.StringDataPtr(crawler.CrawlerSecurityConfiguration),
			"crawlElapsedTime":           llx.IntData(crawler.CrawlElapsedTime),
			"lastCrawl":                  llx.DictData(lastCrawl),
			"version":                    llx.IntData(crawler.Version),
			"createdAt":                  llx.TimeDataPtr(crawler.CreationTime),
			"updatedAt":                  llx.TimeDataPtr(crawler.LastUpdated),
			"region":                     llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlCrawler := resource.(*mqlAwsGlueCrawler)
	mqlCrawler.cacheRoleArn = crawler.Role
	mqlCrawler.cacheSecurityConfigurationName = crawler.CrawlerSecurityConfiguration
	return mqlCrawler, nil
}

func (a *mqlAwsGlueCrawler) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	args := glueRoleLookupArgs(*a.cacheRoleArn)
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role", args)
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsGlueCrawler) glueSecurityConfiguration() (*mqlAwsGlueSecurityConfiguration, error) {
	if a.cacheSecurityConfigurationName == nil || *a.cacheSecurityConfigurationName == "" {
		a.GlueSecurityConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := findGlueSecurityConfiguration(a.MqlRuntime, a.Region.Data, *a.cacheSecurityConfigurationName)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.GlueSecurityConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

// glueRoleLookupArgs returns args for NewResource("aws.iam.role", ...) given a
// crawler/job Role field that may be either an IAM role ARN or just the role
// name (Glue accepts both).
func glueRoleLookupArgs(role string) map[string]*llx.RawData {
	if strings.HasPrefix(role, "arn:") {
		return map[string]*llx.RawData{"arn": llx.StringData(role)}
	}
	return map[string]*llx.RawData{"name": llx.StringData(role)}
}

// findGlueSecurityConfiguration looks up a Glue security configuration in a
// region by name via the singular GetSecurityConfiguration API.
//
// Returns (nil, nil) when the security configuration is missing: on
// EntityNotFoundException (deleted or stale name referenced by a crawler/job)
// and on a nil API response. Callers must set StateIsNull|StateIsSet on the surrounding
// field when this returns nil.
func findGlueSecurityConfiguration(runtime *plugin.Runtime, region, name string) (*mqlAwsGlueSecurityConfiguration, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Glue(region)
	resp, err := svc.GetSecurityConfiguration(context.Background(),
		&glue.GetSecurityConfigurationInput{Name: &name})
	if err != nil {
		var notFoundErr *glue_types.EntityNotFoundException
		if errors.As(err, &notFoundErr) {
			return nil, nil
		}
		return nil, classifyAwsError(err, "glue:GetSecurityConfiguration")
	}
	if resp == nil || resp.SecurityConfiguration == nil {
		return nil, nil
	}
	return newMqlAwsGlueSecurityConfiguration(runtime, region, conn.AccountId(), *resp.SecurityConfiguration)
}

func (a *mqlAwsGlueCrawler) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Glue(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.GetTags(ctx, &glue.GetTagsInput{
		ResourceArn: &arn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "glue:GetTags")
	}
	return toInterfaceMap(resp.Tags), nil
}

func (a *mqlAwsGlue) jobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getJobs(conn), 5)
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

func (a *mqlAwsGlue) getJobs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getJobs>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewGetJobsPaginator(svc, &glue.GetJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, job := range page.Jobs {
					mqlJob, err := newMqlAwsGlueJob(a.MqlRuntime, region, conn.AccountId(), job)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlJob)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsGlueJobInternal struct {
	cacheRoleArn                   *string
	cacheSecurityConfigurationName *string
}

func newMqlAwsGlueJob(runtime *plugin.Runtime, region string, accountID string, job glue_types.Job) (*mqlAwsGlueJob, error) {
	arn := fmt.Sprintf("arn:aws:glue:%s:%s:job/%s", region, accountID, convert.ToValue(job.Name))

	command, err := convert.JsonToDict(job.Command)
	if err != nil {
		return nil, err
	}

	executionProperty, err := convert.JsonToDict(job.ExecutionProperty)
	if err != nil {
		return nil, err
	}

	notificationProperty, err := convert.JsonToDict(job.NotificationProperty)
	if err != nil {
		return nil, err
	}

	var connections []any
	if job.Connections != nil {
		connections = convert.SliceAnyToInterface(job.Connections.Connections)
	}

	var maxCapacity float64
	if job.MaxCapacity != nil {
		maxCapacity = *job.MaxCapacity
	}

	resource, err := CreateResource(runtime, "aws.glue.job",
		map[string]*llx.RawData{
			"__id":                  llx.StringData(arn),
			"arn":                   llx.StringData(arn),
			"name":                  llx.StringDataPtr(job.Name),
			"description":           llx.StringDataPtr(job.Description),
			"role":                  llx.StringDataPtr(job.Role),
			"command":               llx.DictData(command),
			"maxRetries":            llx.IntData(int64(job.MaxRetries)),
			"timeout":               llx.IntDataDefault(job.Timeout, 0),
			"glueVersion":           llx.StringDataPtr(job.GlueVersion),
			"numberOfWorkers":       llx.IntDataDefault(job.NumberOfWorkers, 0),
			"workerType":            llx.StringData(string(job.WorkerType)),
			"maxCapacity":           llx.FloatData(maxCapacity),
			"executionProperty":     llx.DictData(executionProperty),
			"notificationProperty":  llx.DictData(notificationProperty),
			"connections":           llx.ArrayData(connections, types.String),
			"defaultArguments":      llx.MapData(toInterfaceMap(job.DefaultArguments), types.String),
			"securityConfiguration": llx.StringDataPtr(job.SecurityConfiguration),
			"executionClass":        llx.StringData(string(job.ExecutionClass)),
			"createdAt":             llx.TimeDataPtr(job.CreatedOn),
			"updatedAt":             llx.TimeDataPtr(job.LastModifiedOn),
			"region":                llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlJob := resource.(*mqlAwsGlueJob)
	mqlJob.cacheRoleArn = job.Role
	mqlJob.cacheSecurityConfigurationName = job.SecurityConfiguration
	return mqlJob, nil
}

func (a *mqlAwsGlueJob) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	args := glueRoleLookupArgs(*a.cacheRoleArn)
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role", args)
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsGlueJob) glueSecurityConfiguration() (*mqlAwsGlueSecurityConfiguration, error) {
	if a.cacheSecurityConfigurationName == nil || *a.cacheSecurityConfigurationName == "" {
		a.GlueSecurityConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := findGlueSecurityConfiguration(a.MqlRuntime, a.Region.Data, *a.cacheSecurityConfigurationName)
	if err != nil {
		return nil, err
	}
	if res == nil {
		a.GlueSecurityConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return res, nil
}

func (a *mqlAwsGlueJob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Glue(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.GetTags(ctx, &glue.GetTagsInput{
		ResourceArn: &arn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "glue:GetTags")
	}
	return toInterfaceMap(resp.Tags), nil
}

func (a *mqlAwsGlue) securityConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSecurityConfigurations(conn), 5)
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

func (a *mqlAwsGlue) getSecurityConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getSecurityConfigurations>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewGetSecurityConfigurationsPaginator(svc, &glue.GetSecurityConfigurationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, secConf := range page.SecurityConfigurations {
					mqlSecConf, err := newMqlAwsGlueSecurityConfiguration(a.MqlRuntime, region, conn.AccountId(), secConf)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSecConf)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsGlueSecurityConfigurationEncryptionInternal struct {
	cacheKmsKeyArn *string
	region         string
}

func (a *mqlAwsGlueSecurityConfigurationEncryption) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheKmsKeyArn, a.region, &a.KmsKey.State)
}

// newMqlGlueEncryption builds one destination's encryption setting. Glue
// reports each destination through its own SDK struct carrying the same mode
// plus key pair, so an absent struct means the security configuration says
// nothing about that destination and the reference reads null.
func newMqlGlueEncryption(runtime *plugin.Runtime, secConfArn, destination, region, mode string, kmsKeyArn *string, present bool) (*llx.RawData, error) {
	if !present {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.glue.securityConfiguration.encryption", map[string]*llx.RawData{
		"__id": llx.StringData(secConfArn + "/" + destination),
		"mode": llx.StringData(mode),
	})
	if err != nil {
		return nil, err
	}
	mqlEnc := res.(*mqlAwsGlueSecurityConfigurationEncryption)
	mqlEnc.cacheKmsKeyArn = kmsKeyArn
	mqlEnc.region = region
	return llx.ResourceData(mqlEnc, "aws.glue.securityConfiguration.encryption"), nil
}

// glueS3Encryption picks the S3 encryption entry a security configuration
// applies. The SDK types this as a list, but Glue rejects a configuration with
// more than one entry, so an entry beyond the first cannot exist; returning
// only the first is the whole list.
func glueS3Encryption(enc *glue_types.EncryptionConfiguration) *glue_types.S3Encryption {
	if enc == nil || len(enc.S3Encryption) == 0 {
		return nil
	}
	return &enc.S3Encryption[0]
}

func newMqlAwsGlueSecurityConfiguration(runtime *plugin.Runtime, region string, accountID string, secConf glue_types.SecurityConfiguration) (*mqlAwsGlueSecurityConfiguration, error) {
	id := fmt.Sprintf("arn:aws:glue:%s:%s:security-configuration/%s", region, accountID, convert.ToValue(secConf.Name))

	var s3Enc, cwEnc, jbEnc any
	mqlS3Enc, mqlCwEnc, mqlJbEnc, mqlDqEnc := llx.NilData, llx.NilData, llx.NilData, llx.NilData
	if secConf.EncryptionConfiguration != nil {
		var err error
		if s3 := glueS3Encryption(secConf.EncryptionConfiguration); s3 != nil {
			s3Enc, err = convert.JsonToDict(*s3)
			if err != nil {
				return nil, err
			}
			mqlS3Enc, err = newMqlGlueEncryption(runtime, id, "s3Encryption", region, string(s3.S3EncryptionMode), s3.KmsKeyArn, true)
			if err != nil {
				return nil, err
			}
		}
		cwEnc, err = convert.JsonToDict(secConf.EncryptionConfiguration.CloudWatchEncryption)
		if err != nil {
			return nil, err
		}
		if cw := secConf.EncryptionConfiguration.CloudWatchEncryption; cw != nil {
			mqlCwEnc, err = newMqlGlueEncryption(runtime, id, "cloudWatchEncryption", region, string(cw.CloudWatchEncryptionMode), cw.KmsKeyArn, true)
			if err != nil {
				return nil, err
			}
		}
		jbEnc, err = convert.JsonToDict(secConf.EncryptionConfiguration.JobBookmarksEncryption)
		if err != nil {
			return nil, err
		}
		if jb := secConf.EncryptionConfiguration.JobBookmarksEncryption; jb != nil {
			mqlJbEnc, err = newMqlGlueEncryption(runtime, id, "jobBookmarksEncryption", region, string(jb.JobBookmarksEncryptionMode), jb.KmsKeyArn, true)
			if err != nil {
				return nil, err
			}
		}
		if dq := secConf.EncryptionConfiguration.DataQualityEncryption; dq != nil {
			mqlDqEnc, err = newMqlGlueEncryption(runtime, id, "dataQualityEncryption", region, string(dq.DataQualityEncryptionMode), dq.KmsKeyArn, true)
			if err != nil {
				return nil, err
			}
		}
	}

	resource, err := CreateResource(runtime, "aws.glue.securityConfiguration",
		map[string]*llx.RawData{
			"__id":                     llx.StringData(id),
			"name":                     llx.StringDataPtr(secConf.Name),
			"createdAt":                llx.TimeDataPtr(secConf.CreatedTimeStamp),
			"s3Encryption":             llx.DictData(s3Enc),
			"cloudWatchEncryption":     llx.DictData(cwEnc),
			"jobBookmarksEncryption":   llx.DictData(jbEnc),
			"s3DataEncryption":         mqlS3Enc,
			"cloudWatchLogsEncryption": mqlCwEnc,
			"bookmarkStateEncryption":  mqlJbEnc,
			"dataQualityEncryption":    mqlDqEnc,
			"region":                   llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueSecurityConfiguration), nil
}

func (a *mqlAwsGlue) databases() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDatabases(conn), 5)
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

func (a *mqlAwsGlue) getDatabases(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getDatabases>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewGetDatabasesPaginator(svc, &glue.GetDatabasesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, db := range page.DatabaseList {
					mqlDb, err := newMqlAwsGlueDatabase(a.MqlRuntime, region, db)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDb)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsGlueDatabase(runtime *plugin.Runtime, region string, db glue_types.Database) (*mqlAwsGlueDatabase, error) {
	id := fmt.Sprintf("glue/database/%s/%s/%s", region, convert.ToValue(db.CatalogId), convert.ToValue(db.Name))

	var params map[string]any
	if db.Parameters != nil {
		params = toInterfaceMap(db.Parameters)
	}

	createTableDefaultPermissions, err := convert.JsonToDictSlice(db.CreateTableDefaultPermissions)
	if err != nil {
		return nil, err
	}

	targetDatabase, err := convert.JsonToDict(db.TargetDatabase)
	if err != nil {
		return nil, err
	}

	federatedDatabase, err := convert.JsonToDict(db.FederatedDatabase)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "aws.glue.database",
		map[string]*llx.RawData{
			"__id":                          llx.StringData(id),
			"name":                          llx.StringDataPtr(db.Name),
			"catalogId":                     llx.StringDataPtr(db.CatalogId),
			"description":                   llx.StringDataPtr(db.Description),
			"locationUri":                   llx.StringDataPtr(db.LocationUri),
			"parameters":                    llx.MapData(params, types.String),
			"createTableDefaultPermissions": llx.ArrayData(createTableDefaultPermissions, types.Dict),
			"targetDatabase":                llx.DictData(targetDatabase),
			"federatedDatabase":             llx.DictData(federatedDatabase),
			"createdAt":                     llx.TimeDataPtr(db.CreateTime),
			"region":                        llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueDatabase), nil
}

const (
	glueDatabaseArnPattern   = "arn:aws:glue:%s:%s:database/%s"
	glueConnectionArnPattern = "arn:aws:glue:%s:%s:connection/%s"
	glueWorkflowArnPattern   = "arn:aws:glue:%s:%s:workflow/%s"
)

func (a *mqlAwsGlueDatabase) arn() (string, error) {
	account := a.CatalogId.Data
	if account == "" {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		account = conn.AccountId()
	}
	return fmt.Sprintf(glueDatabaseArnPattern, a.Region.Data, account, a.Name.Data), nil
}

func (a *mqlAwsGlueConnection) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(glueConnectionArnPattern, a.Region.Data, conn.AccountId(), a.Name.Data), nil
}

func (a *mqlAwsGlueDatabase) tables() ([]any, error) {
	dbName := a.Name.Data
	region := a.Region.Data
	catalogId := a.CatalogId.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Glue(region)
	ctx := context.Background()
	res := []any{}

	paginator := glue.NewGetTablesPaginator(svc, &glue.GetTablesInput{
		DatabaseName: &dbName,
		CatalogId:    &catalogId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, table := range page.TableList {
			mqlTable, err := newMqlAwsGlueDatabaseTable(a.MqlRuntime, region, table)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTable)
		}
	}
	return res, nil
}

func newMqlAwsGlueDatabaseTable(runtime *plugin.Runtime, region string, table glue_types.Table) (*mqlAwsGlueDatabaseTable, error) {
	id := fmt.Sprintf("glue/table/%s/%s/%s/%s", region, convert.ToValue(table.CatalogId), convert.ToValue(table.DatabaseName), convert.ToValue(table.Name))

	storageDescriptor, err := convert.JsonToDict(table.StorageDescriptor)
	if err != nil {
		return nil, err
	}

	partitionKeys, err := convert.JsonToDictSlice(table.PartitionKeys)
	if err != nil {
		return nil, err
	}

	federatedTable, err := convert.JsonToDict(table.FederatedTable)
	if err != nil {
		return nil, err
	}

	var params map[string]any
	if table.Parameters != nil {
		params = toInterfaceMap(table.Parameters)
	}

	resource, err := CreateResource(runtime, "aws.glue.database.table",
		map[string]*llx.RawData{
			"__id":                          llx.StringData(id),
			"name":                          llx.StringDataPtr(table.Name),
			"databaseName":                  llx.StringDataPtr(table.DatabaseName),
			"catalogId":                     llx.StringDataPtr(table.CatalogId),
			"description":                   llx.StringDataPtr(table.Description),
			"owner":                         llx.StringDataPtr(table.Owner),
			"createdAt":                     llx.TimeDataPtr(table.CreateTime),
			"updatedAt":                     llx.TimeDataPtr(table.UpdateTime),
			"lastAccessedAt":                llx.TimeDataPtr(table.LastAccessTime),
			"retention":                     llx.IntData(int64(table.Retention)),
			"storageDescriptor":             llx.DictData(storageDescriptor),
			"tableType":                     llx.StringDataPtr(table.TableType),
			"partitionKeys":                 llx.ArrayData(partitionKeys, types.Dict),
			"viewExpandedText":              llx.StringDataPtr(table.ViewExpandedText),
			"isRegisteredWithLakeFormation": llx.BoolData(table.IsRegisteredWithLakeFormation),
			"isMaterializedView":            llx.BoolDataPtr(table.IsMaterializedView),
			"federatedTable":                llx.DictData(federatedTable),
			"parameters":                    llx.MapData(params, types.String),
			"createdBy":                     llx.StringDataPtr(table.CreatedBy),
			"region":                        llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueDatabaseTable), nil
}

func (a *mqlAwsGlue) catalogEncryptionSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCatalogEncryptionSettings(conn), 5)
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

func (a *mqlAwsGlue) catalogExportEncryptionSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCatalogExportEncryptionSettings(conn), 5)
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

func (a *mqlAwsGlue) getCatalogExportEncryptionSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getCatalogExportEncryptionSettings>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()

			resp, err := svc.GetDataCatalogExportConfiguration(ctx, &glue.GetDataCatalogExportConfigurationInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return jobpool.JobResult([]any{}), nil
				}
				return nil, err
			}
			// A region with no export configuration returns no entry rather than
			// one reporting empty encryption, so absence is not read as "no key".
			if resp.EncryptionConfiguration == nil {
				return jobpool.JobResult([]any{}), nil
			}

			mqlSettings, err := CreateResource(a.MqlRuntime, "aws.glue.catalogExportEncryption",
				map[string]*llx.RawData{
					"__id":         llx.StringData("aws.glue.catalogExportEncryption/" + region),
					"region":       llx.StringData(region),
					"sseAlgorithm": llx.StringDataPtr(resp.EncryptionConfiguration.SseAlgorithm),
				})
			if err != nil {
				return nil, err
			}
			mqlSettings.(*mqlAwsGlueCatalogExportEncryption).cacheKmsKeyArn = resp.EncryptionConfiguration.KmsKeyArn

			return jobpool.JobResult([]any{mqlSettings}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsGlueCatalogExportEncryptionInternal struct {
	cacheKmsKeyArn *string
}

func (a *mqlAwsGlueCatalogExportEncryption) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == nil || *a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsGlue) getCatalogEncryptionSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getCatalogEncryptionSettings>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()

			resp, err := svc.GetDataCatalogEncryptionSettings(ctx, &glue.GetDataCatalogEncryptionSettingsInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return []any{}, nil
				}
				return nil, err
			}

			if resp.DataCatalogEncryptionSettings == nil {
				return jobpool.JobResult([]any{}), nil
			}
			settingsDict, err := convert.JsonToDict(resp.DataCatalogEncryptionSettings)
			if err != nil {
				return nil, err
			}
			if settingsDict == nil {
				settingsDict = map[string]any{}
			}

			// Include region in the settings dict for identification
			settingsDict["region"] = region

			return jobpool.JobResult([]any{settingsDict}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsGlue) workflows() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getWorkflows(conn), 5)
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

func (a *mqlAwsGlue) getWorkflows(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getWorkflows>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			// ListWorkflows returns only names, so we need to batch-get the details
			paginator := glue.NewListWorkflowsPaginator(svc, &glue.ListWorkflowsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				if len(page.Workflows) == 0 {
					continue
				}

				// BatchGetWorkflows to get full details
				batchResp, err := svc.BatchGetWorkflows(ctx, &glue.BatchGetWorkflowsInput{
					Names: page.Workflows,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, wf := range batchResp.Workflows {
					mqlWf, err := newMqlAwsGlueWorkflow(a.MqlRuntime, region, conn.AccountId(), wf)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlWf)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsGlueWorkflow(runtime *plugin.Runtime, region string, accountID string, wf glue_types.Workflow) (*mqlAwsGlueWorkflow, error) {
	id := fmt.Sprintf("arn:aws:glue:%s:%s:workflow/%s", region, accountID, convert.ToValue(wf.Name))

	var maxConcurrentRuns int64
	if wf.MaxConcurrentRuns != nil {
		maxConcurrentRuns = int64(*wf.MaxConcurrentRuns)
	}

	resource, err := CreateResource(runtime, "aws.glue.workflow",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(id),
			"name":                 llx.StringDataPtr(wf.Name),
			"region":               llx.StringData(region),
			"description":          llx.StringDataPtr(wf.Description),
			"defaultRunProperties": llx.MapData(toInterfaceMap(wf.DefaultRunProperties), types.String),
			"maxConcurrentRuns":    llx.IntData(maxConcurrentRuns),
			"createdAt":            llx.TimeDataPtr(wf.CreatedOn),
			"updatedAt":            llx.TimeDataPtr(wf.LastModifiedOn),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueWorkflow), nil
}

func (a *mqlAwsGlueWorkflow) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(glueWorkflowArnPattern, a.Region.Data, conn.AccountId(), a.Name.Data), nil
}

func (a *mqlAwsGlueWorkflow) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Glue(a.Region.Data)
	ctx := context.Background()

	arn := fmt.Sprintf("arn:aws:glue:%s:%s:workflow/%s", a.Region.Data, conn.AccountId(), a.Name.Data)
	resp, err := svc.GetTags(ctx, &glue.GetTagsInput{
		ResourceArn: &arn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "glue:GetTags")
	}
	return toInterfaceMap(resp.Tags), nil
}

func (a *mqlAwsGlue) connections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConnections(conn), 5)
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

func (a *mqlAwsGlue) getConnections(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getConnections>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewGetConnectionsPaginator(svc, &glue.GetConnectionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, c := range page.ConnectionList {
					connArn := fmt.Sprintf("arn:aws:glue:%s:%s:connection/%s", region, conn.AccountId(), convert.ToValue(c.Name))

					physical, err := convert.JsonToDict(c.PhysicalConnectionRequirements)
					if err != nil {
						return nil, err
					}

					mqlConn, err := CreateResource(a.MqlRuntime, "aws.glue.connection",
						map[string]*llx.RawData{
							"__id":                           llx.StringData(connArn),
							"name":                           llx.StringDataPtr(c.Name),
							"region":                         llx.StringData(region),
							"description":                    llx.StringDataPtr(c.Description),
							"connectionType":                 llx.StringData(string(c.ConnectionType)),
							"connectionProperties":           llx.MapData(redactedGlueConnectionProperties(c.ConnectionProperties), types.String),
							"matchCriteria":                  llx.ArrayData(convert.SliceAnyToInterface(c.MatchCriteria), types.String),
							"physicalConnectionRequirements": llx.DictData(physical),
							"createdAt":                      llx.TimeDataPtr(c.CreationTime),
							"updatedAt":                      llx.TimeDataPtr(c.LastUpdatedTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlConn)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// sensitiveGlueConnectionPropertyKeys lists Glue ConnectionProperty names whose
// values the API returns in plaintext. The keys are preserved (so audits can
// still flag misconfigurations like inline PASSWORD vs SECRET_ID), but the
// values are replaced with a sentinel so the secret never reaches MQL output.
var sensitiveGlueConnectionPropertyKeys = map[string]struct{}{
	"PASSWORD":                       {},
	"ENCRYPTED_PASSWORD":             {},
	"KAFKA_CLIENT_KEYSTORE_PASSWORD": {},
	"KAFKA_CLIENT_KEY_PASSWORD":      {},
	"KAFKA_TRUSTSTORE_PASSWORD":      {},
	"KAFKA_SASL_SCRAM_PASSWORD":      {},
	"KAFKA_CLIENT_KEYSTORE":          {},
	"KAFKA_SASL_GSSAPI_KEYTAB":       {},
	"KAFKA_SASL_GSSAPI_KRB5_CONF":    {},
}

func redactedGlueConnectionProperties[K ~string](m map[K]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		key := string(k)
		if _, sensitive := sensitiveGlueConnectionPropertyKeys[key]; sensitive && v != "" {
			out[key] = "<redacted>"
			continue
		}
		out[key] = v
	}
	return out
}

// --- Triggers -----------------------------------------------------------------

func (a *mqlAwsGlue) triggers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTriggers(conn), 5)
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

func (a *mqlAwsGlue) getTriggers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getTriggers>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewGetTriggersPaginator(svc, &glue.GetTriggersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, trigger := range page.Triggers {
					mqlTrigger, err := newMqlAwsGlueTrigger(a.MqlRuntime, region, conn.AccountId(), trigger)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTrigger)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsGlueTrigger(runtime *plugin.Runtime, region, accountID string, trigger glue_types.Trigger) (*mqlAwsGlueTrigger, error) {
	arn := fmt.Sprintf("arn:aws:glue:%s:%s:trigger/%s", region, accountID, convert.ToValue(trigger.Name))

	actions, err := convert.JsonToDictSlice(trigger.Actions)
	if err != nil {
		return nil, err
	}

	predicate, err := convert.JsonToDict(trigger.Predicate)
	if err != nil {
		return nil, err
	}

	eventBatchingCondition, err := convert.JsonToDict(trigger.EventBatchingCondition)
	if err != nil {
		return nil, err
	}

	resource, err := CreateResource(runtime, "aws.glue.trigger",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(arn),
			"arn":                    llx.StringData(arn),
			"name":                   llx.StringDataPtr(trigger.Name),
			"region":                 llx.StringData(region),
			"description":            llx.StringDataPtr(trigger.Description),
			"type":                   llx.StringData(string(trigger.Type)),
			"state":                  llx.StringData(string(trigger.State)),
			"schedule":               llx.StringDataPtr(trigger.Schedule),
			"workflowName":           llx.StringDataPtr(trigger.WorkflowName),
			"actions":                llx.ArrayData(actions, types.Dict),
			"predicate":              llx.DictData(predicate),
			"eventBatchingCondition": llx.DictData(eventBatchingCondition),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueTrigger), nil
}

func (a *mqlAwsGlueTrigger) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Glue(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.GetTags(ctx, &glue.GetTagsInput{ResourceArn: &arn})
	if err != nil {
		return nil, classifyAwsError(err, "glue:GetTags")
	}
	return toInterfaceMap(resp.Tags), nil
}

// --- Schema Registries --------------------------------------------------------

func (a *mqlAwsGlue) schemaRegistries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSchemaRegistries(conn), 5)
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

func (a *mqlAwsGlue) getSchemaRegistries(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getSchemaRegistries>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewListRegistriesPaginator(svc, &glue.ListRegistriesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, reg := range page.Registries {
					mqlReg, err := newMqlAwsGlueSchemaRegistry(a.MqlRuntime, region, reg)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlReg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsGlueSchemaRegistry(runtime *plugin.Runtime, region string, reg glue_types.RegistryListItem) (*mqlAwsGlueSchemaRegistry, error) {
	regArn := convert.ToValue(reg.RegistryArn)
	id := regArn
	if id == "" {
		id = fmt.Sprintf("glue/schema-registry/%s/%s", region, convert.ToValue(reg.RegistryName))
	}

	resource, err := CreateResource(runtime, "aws.glue.schemaRegistry",
		map[string]*llx.RawData{
			"__id":        llx.StringData(id),
			"name":        llx.StringDataPtr(reg.RegistryName),
			"registryArn": llx.StringDataPtr(reg.RegistryArn),
			"region":      llx.StringData(region),
			"description": llx.StringDataPtr(reg.Description),
			"status":      llx.StringData(string(reg.Status)),
			"createdAt":   llx.TimeDataPtr(parseGlueAPITime(reg.CreatedTime)),
			"updatedAt":   llx.TimeDataPtr(parseGlueAPITime(reg.UpdatedTime)),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueSchemaRegistry), nil
}

func (a *mqlAwsGlueSchemaRegistry) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Glue(a.Region.Data)
	ctx := context.Background()
	arn := a.RegistryArn.Data

	if arn == "" {
		return nil, nil
	}
	resp, err := svc.GetTags(ctx, &glue.GetTagsInput{ResourceArn: &arn})
	if err != nil {
		return nil, classifyAwsError(err, "glue:GetTags")
	}
	return toInterfaceMap(resp.Tags), nil
}

// --- Schemas ------------------------------------------------------------------

func (a *mqlAwsGlue) schemas() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSchemas(conn), 5)
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

func (a *mqlAwsGlue) getSchemas(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getSchemas>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			// ListSchemas with no RegistryId returns schemas across the default
			// registry plus any user-managed registries in the region.
			paginator := glue.NewListSchemasPaginator(svc, &glue.ListSchemasInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, s := range page.Schemas {
					schemaDetails := fetchGlueSchemaDetails(ctx, conn, region, s)
					mqlSchema, err := newMqlAwsGlueSchema(a.MqlRuntime, region, s, schemaDetails)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSchema)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// glueSchemaDetails captures the fields returned by GetSchema that ListSchemas
// does not include.
type glueSchemaDetails struct {
	dataFormat              string
	compatibility           string
	latestVersionNumber     int64
	nextSchemaVersionNumber int64
	schemaCheckpoint        int64
	description             string
	registryArn             string
}

// fetchGlueSchemaDetails enriches a SchemaListItem with the metadata returned
// by GetSchema (data format, compatibility mode, version pointers, checkpoint,
// registry ARN). On access-denied or any other GetSchema failure the error is
// logged and a zero-value details struct is returned so the schema is still
// listed with the fields that ListSchemas provided.
func fetchGlueSchemaDetails(ctx context.Context, conn *connection.AwsConnection, region string, s glue_types.SchemaListItem) glueSchemaDetails {
	d := glueSchemaDetails{}
	if s.SchemaArn == nil || *s.SchemaArn == "" {
		return d
	}
	svc := conn.Glue(region)
	resp, err := svc.GetSchema(ctx, &glue.GetSchemaInput{SchemaId: &glue_types.SchemaId{SchemaArn: s.SchemaArn}})
	if err != nil {
		if !Is400AccessDeniedError(err) {
			log.Warn().Err(err).Str("schema", convert.ToValue(s.SchemaName)).Msg("glue>GetSchema failed; partial schema data only")
		}
		return d
	}
	if resp == nil {
		return d
	}
	d.dataFormat = string(resp.DataFormat)
	d.compatibility = string(resp.Compatibility)
	if resp.LatestSchemaVersion != nil {
		d.latestVersionNumber = *resp.LatestSchemaVersion
	}
	if resp.NextSchemaVersion != nil {
		d.nextSchemaVersionNumber = *resp.NextSchemaVersion
	}
	if resp.SchemaCheckpoint != nil {
		d.schemaCheckpoint = *resp.SchemaCheckpoint
	}
	if resp.Description != nil {
		d.description = *resp.Description
	}
	if resp.RegistryArn != nil {
		d.registryArn = *resp.RegistryArn
	}
	return d
}

func newMqlAwsGlueSchema(runtime *plugin.Runtime, region string, s glue_types.SchemaListItem, d glueSchemaDetails) (*mqlAwsGlueSchema, error) {
	id := convert.ToValue(s.SchemaArn)
	if id == "" {
		id = fmt.Sprintf("glue/schema/%s/%s/%s", region, convert.ToValue(s.RegistryName), convert.ToValue(s.SchemaName))
	}

	description := d.description
	if description == "" {
		description = convert.ToValue(s.Description)
	}

	resource, err := CreateResource(runtime, "aws.glue.schema",
		map[string]*llx.RawData{
			"__id":                    llx.StringData(id),
			"schemaName":              llx.StringDataPtr(s.SchemaName),
			"schemaArn":               llx.StringDataPtr(s.SchemaArn),
			"registryName":            llx.StringDataPtr(s.RegistryName),
			"registryArn":             llx.StringData(d.registryArn),
			"region":                  llx.StringData(region),
			"description":             llx.StringData(description),
			"dataFormat":              llx.StringData(d.dataFormat),
			"compatibility":           llx.StringData(d.compatibility),
			"schemaStatus":            llx.StringData(string(s.SchemaStatus)),
			"latestVersionNumber":     llx.IntData(d.latestVersionNumber),
			"nextSchemaVersionNumber": llx.IntData(d.nextSchemaVersionNumber),
			"schemaCheckpoint":        llx.IntData(d.schemaCheckpoint),
			"createdAt":               llx.TimeDataPtr(parseGlueAPITime(s.CreatedTime)),
			"updatedAt":               llx.TimeDataPtr(parseGlueAPITime(s.UpdatedTime)),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueSchema), nil
}

func (a *mqlAwsGlueSchema) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Glue(a.Region.Data)
	ctx := context.Background()
	arn := a.SchemaArn.Data

	if arn == "" {
		return nil, nil
	}
	resp, err := svc.GetTags(ctx, &glue.GetTagsInput{ResourceArn: &arn})
	if err != nil {
		return nil, classifyAwsError(err, "glue:GetTags")
	}
	return toInterfaceMap(resp.Tags), nil
}

// --- Resource Policies --------------------------------------------------------

func (a *mqlAwsGlue) resourcePolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getResourcePolicies(conn), 5)
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

func (a *mqlAwsGlue) getResourcePolicies(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("glue>getResourcePolicies>calling aws with region %s", region)

			svc := conn.Glue(region)
			ctx := context.Background()
			res := []any{}

			paginator := glue.NewGetResourcePoliciesPaginator(svc, &glue.GetResourcePoliciesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, policy := range page.GetResourcePoliciesResponseList {
					mqlPolicy, err := newMqlAwsGlueResourcePolicy(a.MqlRuntime, region, policy)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlPolicy)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsGlueResourcePolicy(runtime *plugin.Runtime, region string, policy glue_types.GluePolicy) (*mqlAwsGlueResourcePolicy, error) {
	hash := convert.ToValue(policy.PolicyHash)
	id := fmt.Sprintf("glue/resource-policy/%s/%s", region, hash)

	resource, err := CreateResource(runtime, "aws.glue.resourcePolicy",
		map[string]*llx.RawData{
			"__id":         llx.StringData(id),
			"policyHash":   llx.StringData(hash),
			"region":       llx.StringData(region),
			"policyInJson": llx.StringDataPtr(policy.PolicyInJson),
			"createdAt":    llx.TimeDataPtr(policy.CreateTime),
			"updatedAt":    llx.TimeDataPtr(policy.UpdateTime),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsGlueResourcePolicy), nil
}

// parseGlueAPITime parses Glue's string-formatted timestamps (used by the
// Schema Registry APIs). Returns nil time when the input is nil or unparseable.
func parseGlueAPITime(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	// Try a few common layouts that Glue uses across Schema Registry APIs.
	layouts := []string{
		time.RFC3339Nano,
		time.RFC3339,
		"2006-01-02T15:04:05.000Z",
		"2006-01-02T15:04:05Z",
	}
	for _, layout := range layouts {
		if t, err := time.Parse(layout, *s); err == nil {
			return &t
		}
	}
	return nil
}
