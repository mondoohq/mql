// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/macie2"
	"github.com/aws/aws-sdk-go-v2/service/macie2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	mqlTypes "go.mondoo.com/mql/types"
)

func (a *mqlAwsMacie) id() (string, error) {
	return ResourceAwsMacie, nil
}

func (a *mqlAwsMacie) sessions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2/config", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}

		session, err := svc.GetMacieSession(ctx, &macie2.GetMacieSessionInput{})
		if err != nil {
			return nil, err
		}

		// Get bucket statistics for S3 bucket count
		bucketStats, err := svc.GetBucketStatistics(ctx, &macie2.GetBucketStatisticsInput{})
		var s3BucketCount int
		if err == nil && bucketStats.BucketCount != nil {
			s3BucketCount = int(*bucketStats.BucketCount)
		}

		mqlSession, err := CreateResource(a.MqlRuntime, ResourceAwsMacieSession,
			map[string]*llx.RawData{
				"arn":                        llx.StringData(generateMacieSessionArn(conn.AccountId(), region)),
				"region":                     llx.StringData(region),
				"status":                     llx.StringData(string(session.Status)),
				"createdAt":                  llx.TimeDataPtr(session.CreatedAt),
				"updatedAt":                  llx.TimeDataPtr(session.UpdatedAt),
				"findingPublishingFrequency": llx.StringData(string(session.FindingPublishingFrequency)),
				"serviceRole":                llx.StringDataPtr(session.ServiceRole),
				"s3BucketCount":              llx.IntData(int64(s3BucketCount)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSession)
		return res, nil
	})
}

func (a *mqlAwsMacie) classificationJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}

		params := &macie2.ListClassificationJobsInput{}
		paginator := macie2.NewListClassificationJobsPaginator(svc, params)
		for paginator.HasMorePages() {
			jobs, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, job := range jobs.Items {
				jobId := ""
				if job.JobId != nil {
					jobId = *job.JobId
				}
				jobArn := generateClassificationJobArn(conn.AccountId(), region, jobId)
				mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsMacieClassificationJob,
					map[string]*llx.RawData{
						"arn":       llx.StringData(jobArn),
						"jobId":     llx.StringDataPtr(job.JobId),
						"name":      llx.StringDataPtr(job.Name),
						"region":    llx.StringData(region),
						"status":    llx.StringData(string(job.JobStatus)),
						"jobType":   llx.StringData(string(job.JobType)),
						"createdAt": llx.TimeDataPtr(job.CreatedAt),
					})
				if err != nil {
					return nil, err
				}
				mqlJob.(*mqlAwsMacieClassificationJob).cacheJob = &job
				res = append(res, mqlJob)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsMacie) findings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}

		params := &macie2.ListFindingsInput{}
		paginator := macie2.NewListFindingsPaginator(svc, params)
		for paginator.HasMorePages() {
			findings, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			// Get finding details for all finding IDs
			if len(findings.FindingIds) > 0 {
				detailsRes, err := fetchMacieFindings(svc, region, findings.FindingIds, a.MqlRuntime)
				if err != nil {
					return nil, err
				}
				res = append(res, detailsRes...)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsMacie) customDataIdentifiers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}

		params := &macie2.ListCustomDataIdentifiersInput{}
		paginator := macie2.NewListCustomDataIdentifiersPaginator(svc, params)
		for paginator.HasMorePages() {
			identifiers, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, identifier := range identifiers.Items {
				mqlIdentifier, err := CreateResource(a.MqlRuntime, ResourceAwsMacieCustomDataIdentifier,
					map[string]*llx.RawData{
						"id":        llx.StringDataPtr(identifier.Id),
						"arn":       llx.StringDataPtr(identifier.Arn),
						"name":      llx.StringDataPtr(identifier.Name),
						"createdAt": llx.TimeDataPtr(identifier.CreatedAt),
					})
				if err != nil {
					return nil, err
				}
				mqlIdentifier.(*mqlAwsMacieCustomDataIdentifier).cacheIdentifier = &identifier
				mqlIdentifier.(*mqlAwsMacieCustomDataIdentifier).cacheRegion = region
				res = append(res, mqlIdentifier)
			}
		}
		return res, nil
	})
}

// Resource ID implementations
func (a *mqlAwsMacieSession) id() (string, error) {
	return a.Arn.Data, nil
}

// Field implementations for Macie session
func (a *mqlAwsMacieSession) findingPublishingFrequency() (string, error) {
	return a.FindingPublishingFrequency.Data, nil
}

func (a *mqlAwsMacieSession) serviceRole() (string, error) {
	return a.ServiceRole.Data, nil
}

func (a *mqlAwsMacieSession) s3BucketCount() (int64, error) {
	return a.S3BucketCount.Data, nil
}

func (a *mqlAwsMacieClassificationJob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsMacieFinding) id() (string, error) {
	return a.Id.Data, nil
}

// Field implementations for Macie finding
func (a *mqlAwsMacieFinding) classificationDetails() (any, error) {
	return a.ClassificationDetails.Data, nil
}

func (a *mqlAwsMacieFinding) resourcesAffected() (any, error) {
	return a.ResourcesAffected.Data, nil
}

func (a *mqlAwsMacieCustomDataIdentifier) id() (string, error) {
	return a.Id.Data, nil
}

// Internal cache structures
type mqlAwsMacieClassificationJobInternal struct {
	cacheJob          *types.JobSummary
	cacheStaticBucket []string
	detailsFetched    bool
	detailsLock       sync.Mutex
}

type mqlAwsMacieCustomDataIdentifierInternal struct {
	cacheIdentifier *types.CustomDataIdentifierSummary
	cacheRegion     string
	detailsFetched  bool
	detailsLock     sync.Mutex
}

// Populate detailed data for classification job
func (a *mqlAwsMacieClassificationJob) populateJobDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	jobId := a.JobId.Data

	svc := conn.Macie2(region)
	ctx := context.Background()

	job, err := svc.DescribeClassificationJob(ctx, &macie2.DescribeClassificationJobInput{
		JobId: &jobId,
	})
	if err != nil {
		return err
	}

	// Set optional fields if available
	if job.LastRunTime != nil {
		a.LastRunTime = plugin.TValue[*time.Time]{Data: job.LastRunTime, State: plugin.StateIsSet}
	}
	if job.SamplingPercentage != nil {
		a.SamplingPercentage = plugin.TValue[int64]{Data: int64(*job.SamplingPercentage), State: plugin.StateIsSet}
	}
	if job.S3JobDefinition != nil && job.S3JobDefinition.BucketDefinitions != nil {
		bucketDefs, _ := convert.JsonToDictSlice(job.S3JobDefinition.BucketDefinitions)
		a.BucketDefinitions = plugin.TValue[[]any]{Data: bucketDefs, State: plugin.StateIsSet}
		for _, bd := range job.S3JobDefinition.BucketDefinitions {
			a.cacheStaticBucket = append(a.cacheStaticBucket, bd.Buckets...)
		}
	}
	if job.ScheduleFrequency != nil {
		scheduleFreq, _ := convert.JsonToDict(job.ScheduleFrequency)
		a.ScheduleFrequency = plugin.TValue[any]{Data: scheduleFreq, State: plugin.StateIsSet}
	}
	if job.Statistics != nil {
		stats, _ := convert.JsonToDict(job.Statistics)
		a.Statistics = plugin.TValue[any]{Data: stats, State: plugin.StateIsSet}
	}
	if job.Tags != nil {
		a.Tags = plugin.TValue[map[string]any]{Data: convert.MapToInterfaceMap(job.Tags), State: plugin.StateIsSet}
	}

	a.detailsFetched = true
	return nil
}

// Populate detailed data for custom data identifier
func (a *mqlAwsMacieCustomDataIdentifier) populateIdentifierDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	identifierId := a.Id.Data

	svc := conn.Macie2(a.cacheRegion)
	ctx := context.Background()

	identifier, err := svc.GetCustomDataIdentifier(ctx, &macie2.GetCustomDataIdentifierInput{
		Id: &identifierId,
	})
	if err != nil {
		return err
	}

	// Set optional fields if available
	if identifier.Description != nil {
		a.Description = plugin.TValue[string]{Data: *identifier.Description, State: plugin.StateIsSet}
	}
	if identifier.Regex != nil {
		a.Regex = plugin.TValue[string]{Data: *identifier.Regex, State: plugin.StateIsSet}
	}
	if identifier.Keywords != nil {
		keywords := make([]any, len(identifier.Keywords))
		for i, kw := range identifier.Keywords {
			keywords[i] = kw
		}
		a.Keywords = plugin.TValue[[]any]{Data: keywords, State: plugin.StateIsSet}
	}
	if identifier.Tags != nil {
		a.Tags = plugin.TValue[map[string]any]{Data: convert.MapToInterfaceMap(identifier.Tags), State: plugin.StateIsSet}
	}

	a.detailsFetched = true
	return nil
}

// Field implementations for classification job
func (a *mqlAwsMacieClassificationJob) lastRunTime() (*time.Time, error) {
	return nil, a.populateJobDetails()
}

func (a *mqlAwsMacieClassificationJob) samplingPercentage() (int64, error) {
	return 0, a.populateJobDetails()
}

func (a *mqlAwsMacieClassificationJob) bucketDefinitions() ([]any, error) {
	return nil, a.populateJobDetails()
}

func (a *mqlAwsMacieClassificationJob) scheduleFrequency() (any, error) {
	return nil, a.populateJobDetails()
}

func (a *mqlAwsMacieClassificationJob) statistics() (any, error) {
	return nil, a.populateJobDetails()
}

func (a *mqlAwsMacieClassificationJob) tags() (map[string]any, error) {
	return nil, a.populateJobDetails()
}

// Field implementations for custom data identifier
func (a *mqlAwsMacieCustomDataIdentifier) description() (string, error) {
	return "", a.populateIdentifierDetails()
}

func (a *mqlAwsMacieCustomDataIdentifier) regex() (string, error) {
	return "", a.populateIdentifierDetails()
}

func (a *mqlAwsMacieCustomDataIdentifier) keywords() ([]any, error) {
	return nil, a.populateIdentifierDetails()
}

func (a *mqlAwsMacieCustomDataIdentifier) tags() (map[string]any, error) {
	return nil, a.populateIdentifierDetails()
}

// Helper functions
func fetchMacieFindings(svc *macie2.Client, region string, findingIds []string, runtime *plugin.Runtime) ([]any, error) {
	res := []any{}
	ctx := context.Background()

	// Process findings in chunks of 50 (API limit)
	for chunk := range slices.Chunk(findingIds, 50) {
		findingDetails, err := svc.GetFindings(ctx, &macie2.GetFindingsInput{
			FindingIds: chunk,
		})
		if err != nil {
			if IsMacieNotEnabledError(err) {
				log.Debug().Str("region", region).Msg("Macie is not enabled in region")
				return res, nil
			}
			return nil, err
		}

		for _, finding := range findingDetails.Findings {
			mqlFinding, err := newMqlMacieFinding(runtime, finding, region)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFinding)
		}
	}
	return res, nil
}

func newMqlMacieFinding(runtime *plugin.Runtime, finding types.Finding, region string) (*mqlAwsMacieFinding, error) {
	var severity any
	if finding.Severity != nil {
		severityDict, _ := convert.JsonToDict(finding.Severity)
		severity = severityDict
	}

	var classificationDetails any
	if finding.ClassificationDetails != nil {
		classificationDict, _ := convert.JsonToDict(finding.ClassificationDetails)
		classificationDetails = classificationDict
	}

	var resourcesAffected any
	bucketName, bucketArn, objectKey := "", "", ""
	if finding.ResourcesAffected != nil {
		resourcesDict, _ := convert.JsonToDict(finding.ResourcesAffected)
		resourcesAffected = resourcesDict
		if finding.ResourcesAffected.S3Bucket != nil {
			if finding.ResourcesAffected.S3Bucket.Name != nil {
				bucketName = *finding.ResourcesAffected.S3Bucket.Name
			}
			if finding.ResourcesAffected.S3Bucket.Arn != nil {
				bucketArn = *finding.ResourcesAffected.S3Bucket.Arn
			}
		}
		if finding.ResourcesAffected.S3Object != nil && finding.ResourcesAffected.S3Object.Key != nil {
			objectKey = *finding.ResourcesAffected.S3Object.Key
		}
	}

	accountId := ""
	if finding.AccountId != nil {
		accountId = *finding.AccountId
	}
	findingId := ""
	if finding.Id != nil {
		findingId = *finding.Id
	}
	findingArn := generateFindingArn(accountId, region, findingId)
	count := int64(0)
	if finding.Count != nil {
		count = *finding.Count
	}
	res, err := CreateResource(runtime, ResourceAwsMacieFinding, map[string]*llx.RawData{
		"id":                    llx.StringDataPtr(finding.Id),
		"arn":                   llx.StringData(findingArn),
		"region":                llx.StringData(region),
		"accountId":             llx.StringDataPtr(finding.AccountId),
		"type":                  llx.StringData(string(finding.Type)),
		"severity":              llx.DictData(severity),
		"category":              llx.StringData(string(finding.Category)),
		"archived":              llx.BoolDataPtr(finding.Archived),
		"count":                 llx.IntData(count),
		"createdAt":             llx.TimeDataPtr(finding.CreatedAt),
		"updatedAt":             llx.TimeDataPtr(finding.UpdatedAt),
		"title":                 llx.StringDataPtr(finding.Title),
		"description":           llx.StringDataPtr(finding.Description),
		"classificationDetails": llx.DictData(classificationDetails),
		"resourcesAffected":     llx.DictData(resourcesAffected),
		"bucketName":            llx.StringData(bucketName),
		"bucketArn":             llx.StringData(bucketArn),
		"objectKey":             llx.StringData(objectKey),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsMacieFinding), nil
}

func generateMacieSessionArn(accountId, region string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":session"
}

func generateClassificationJobArn(accountId, region, jobId string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":classification-job/" + jobId
}

func generateFindingArn(accountId, region, findingId string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":finding/" + findingId
}

func generateMacieInvitationArn(accountId, region, invitationId string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":invitation/" + invitationId
}

func generateMacieAdministratorArn(accountId, region, adminAccountId string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":administrator/" + adminAccountId
}

func generateMacieAutomatedDiscoveryArn(accountId, region string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":automated-discovery"
}

func generateMacieClassificationExportArn(accountId, region string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":classification-export"
}

func generateMacieMemberArn(accountId, region, memberAccountId string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":member/" + memberAccountId
}

// session.serviceRoleIamRole resolves the service-role ARN to an aws.iam.role
func (a *mqlAwsMacieSession) serviceRoleIamRole() (*mqlAwsIamRole, error) {
	roleArn := a.ServiceRole.Data
	if roleArn == "" {
		a.ServiceRoleIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

// finding.bucket resolves the affected S3 bucket
func (a *mqlAwsMacieFinding) bucket() (*mqlAwsS3Bucket, error) {
	if a.BucketName.Data == "" {
		a.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, ResourceAwsS3Bucket,
		map[string]*llx.RawData{"name": llx.StringData(a.BucketName.Data)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

// classificationJob.buckets returns the static bucket selection for the job (empty for dynamic bucketCriteria jobs)
func (a *mqlAwsMacieClassificationJob) buckets() ([]any, error) {
	if err := a.populateJobDetails(); err != nil {
		return nil, err
	}
	res := []any{}
	for _, name := range a.cacheStaticBucket {
		if name == "" {
			continue
		}
		mqlBucket, err := NewResource(a.MqlRuntime, ResourceAwsS3Bucket,
			map[string]*llx.RawData{"name": llx.StringData(name)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBucket)
	}
	return res, nil
}

// ============================================================================
// aws.macie.bucket — DescribeBuckets coverage
// ============================================================================

// errMacieBucketNotCovered reports a bucket that Macie does not hold in its
// inventory, either because Macie is not enabled in the region or because the
// bucket is outside the monitored set. macieCoverage turns it into a null field,
// which is what the schema promises; any other error is a real failure.
//
// The init has to answer with an error rather than no resource: returning
// (args, nil, nil) makes the runtime build the resource from the partial args,
// leaving every field unset rather than null, and every such husk shares one
// cache key because its arn is never set.
var errMacieBucketNotCovered = errors.New("bucket is not in Macie's inventory")

func initAwsMacieBucket(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args["name"] == nil && args["arn"] == nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	var bucketName, region string
	if args["name"] != nil {
		bucketName = args["name"].Value.(string)
	} else {
		arnVal := args["arn"].Value.(string)
		parts := strings.SplitN(arnVal, ":::", 2)
		if len(parts) != 2 {
			return nil, nil, fmt.Errorf("%q is not an s3 bucket arn", arnVal)
		}
		bucketName = parts[1]
	}
	if args["region"] != nil {
		region = args["region"].Value.(string)
	}

	if region == "" {
		log.Warn().Str("bucket", bucketName).Msg("aws.macie.bucket initialized without region — scanning every enabled region serially. Pass `region` for a single targeted lookup")
		regions, err := conn.Regions()
		if err != nil {
			return args, nil, err
		}
		for _, r := range regions {
			res, err := describeMacieBucket(runtime, conn, r, bucketName)
			if err != nil {
				if IsMacieNotEnabledError(err) {
					continue
				}
				log.Warn().Err(err).Str("region", r).Str("bucket", bucketName).Msg("failed to describe Macie bucket")
				continue
			}
			if res != nil {
				return args, res, nil
			}
		}
		return args, nil, errMacieBucketNotCovered
	}

	res, err := describeMacieBucket(runtime, conn, region, bucketName)
	if err != nil {
		return args, nil, err
	}
	if res == nil {
		return args, nil, errMacieBucketNotCovered
	}
	return args, res, nil
}

func describeMacieBucket(runtime *plugin.Runtime, conn *connection.AwsConnection, region, bucketName string) (*mqlAwsMacieBucket, error) {
	svc := conn.Macie2(region)
	ctx := context.Background()
	resp, err := svc.DescribeBuckets(ctx, &macie2.DescribeBucketsInput{
		Criteria: map[string]types.BucketCriteriaAdditionalProperties{
			"bucketName": {Eq: []string{bucketName}},
		},
	})
	if err != nil {
		if IsMacieNotEnabledError(err) {
			return nil, nil
		}
		return nil, err
	}
	for _, bm := range resp.Buckets {
		if bm.BucketName == nil || *bm.BucketName != bucketName {
			continue
		}
		mqlBucket, err := newMqlMacieBucket(runtime, bm, region)
		if err != nil {
			return nil, err
		}
		return mqlBucket, nil
	}
	return nil, nil
}

func (a *mqlAwsMacie) buckets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		paginator := macie2.NewDescribeBucketsPaginator(svc, &macie2.DescribeBucketsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, bm := range page.Buckets {
				mqlBucket, err := newMqlMacieBucket(a.MqlRuntime, bm, region)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlBucket)
			}
		}
		return res, nil
	})
}

func newMqlMacieBucket(runtime *plugin.Runtime, bm types.BucketMetadata, region string) (*mqlAwsMacieBucket, error) {
	publicAccess, _ := convert.JsonToDict(bm.PublicAccess)
	serverSideEncryption, _ := convert.JsonToDict(bm.ServerSideEncryption)
	mqlSse, err := newMqlMacieBucketServerSideEncryption(runtime, convert.ToValue(bm.BucketArn), region, bm.ServerSideEncryption)
	if err != nil {
		return nil, err
	}
	jobDetails, _ := convert.JsonToDict(bm.JobDetails)
	replicationDetails, _ := convert.JsonToDict(bm.ReplicationDetails)
	objectCountByEncryptionType, _ := convert.JsonToDict(bm.ObjectCountByEncryptionType)
	unclassifiableObjectCount, _ := convert.JsonToDict(bm.UnclassifiableObjectCount)
	unclassifiableObjectSizeInBytes, _ := convert.JsonToDict(bm.UnclassifiableObjectSizeInBytes)

	tags := map[string]any{}
	for _, kv := range bm.Tags {
		if kv.Key == nil {
			continue
		}
		if kv.Value == nil {
			tags[*kv.Key] = ""
		} else {
			tags[*kv.Key] = *kv.Value
		}
	}

	bucketName := ""
	if bm.BucketName != nil {
		bucketName = *bm.BucketName
	}
	bucketArn := ""
	if bm.BucketArn != nil {
		bucketArn = *bm.BucketArn
	} else {
		bucketArn = "arn:aws:s3:::" + bucketName
	}

	classifiable := int64(0)
	if bm.ClassifiableObjectCount != nil {
		classifiable = *bm.ClassifiableObjectCount
	}
	classifiableSize := int64(0)
	if bm.ClassifiableSizeInBytes != nil {
		classifiableSize = *bm.ClassifiableSizeInBytes
	}
	objectCount := int64(0)
	if bm.ObjectCount != nil {
		objectCount = *bm.ObjectCount
	}
	sizeInBytes := int64(0)
	if bm.SizeInBytes != nil {
		sizeInBytes = *bm.SizeInBytes
	}
	sizeInBytesCompressed := int64(0)
	if bm.SizeInBytesCompressed != nil {
		sizeInBytesCompressed = *bm.SizeInBytesCompressed
	}
	sensitivityScore := int64(0)
	if bm.SensitivityScore != nil {
		sensitivityScore = int64(*bm.SensitivityScore)
	}
	versioning := false
	if bm.Versioning != nil {
		versioning = *bm.Versioning
	}
	errorMessage := ""
	if bm.ErrorMessage != nil {
		errorMessage = *bm.ErrorMessage
	}

	res, err := CreateResource(runtime, ResourceAwsMacieBucket, map[string]*llx.RawData{
		"arn":                                llx.StringData(bucketArn),
		"name":                               llx.StringData(bucketName),
		"region":                             llx.StringData(region),
		"accountId":                          llx.StringDataPtr(bm.AccountId),
		"bucketCreatedAt":                    llx.TimeDataPtr(bm.BucketCreatedAt),
		"lastUpdated":                        llx.TimeDataPtr(bm.LastUpdated),
		"lastAutomatedDiscoveryTime":         llx.TimeDataPtr(bm.LastAutomatedDiscoveryTime),
		"classifiableObjectCount":            llx.IntData(classifiable),
		"classifiableSizeInBytes":            llx.IntData(classifiableSize),
		"objectCount":                        llx.IntData(objectCount),
		"sizeInBytes":                        llx.IntData(sizeInBytes),
		"sizeInBytesCompressed":              llx.IntData(sizeInBytesCompressed),
		"sensitivityScore":                   llx.IntData(sensitivityScore),
		"sharedAccess":                       llx.StringData(string(bm.SharedAccess)),
		"publicAccess":                       llx.DictData(publicAccess),
		"serverSideEncryption":               llx.DictData(serverSideEncryption),
		"defaultEncryption":                  mqlSse,
		"versioning":                         llx.BoolData(versioning),
		"allowsUnencryptedObjectUploads":     llx.StringData(string(bm.AllowsUnencryptedObjectUploads)),
		"automatedDiscoveryMonitoringStatus": llx.StringData(string(bm.AutomatedDiscoveryMonitoringStatus)),
		"jobDetails":                         llx.DictData(jobDetails),
		"replicationDetails":                 llx.DictData(replicationDetails),
		"objectCountByEncryptionType":        llx.DictData(objectCountByEncryptionType),
		"unclassifiableObjectCount":          llx.DictData(unclassifiableObjectCount),
		"unclassifiableObjectSizeInBytes":    llx.DictData(unclassifiableObjectSizeInBytes),
		"errorCode":                          llx.StringData(string(bm.ErrorCode)),
		"errorMessage":                       llx.StringData(errorMessage),
		"tags":                               llx.MapData(tags, mqlTypes.String),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsMacieBucket), nil
}

// newMqlMacieBucketServerSideEncryption builds the bucket's default encryption
// settings. A nil block means Macie reported no encryption settings for the
// bucket at all, which is reported as null rather than as encryption being off.
func newMqlMacieBucketServerSideEncryption(runtime *plugin.Runtime, bucketArn, region string, sse *types.BucketServerSideEncryption) (*llx.RawData, error) {
	if sse == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.macie.bucket.encryption", map[string]*llx.RawData{
		"__id": llx.StringData(bucketArn + "/serverSideEncryption"),
		"type": llx.StringData(string(sse.Type)),
	})
	if err != nil {
		return nil, err
	}
	mqlSse := res.(*mqlAwsMacieBucketEncryption)
	// Macie reports the default encryption key as an ARN or as a bare key ID,
	// which is why this is a key reference rather than an ARN.
	mqlSse.cacheKmsKeyRef = sse.KmsMasterKeyId
	mqlSse.region = region
	return llx.ResourceData(mqlSse, "aws.macie.bucket.encryption"), nil
}

type mqlAwsMacieBucketEncryptionInternal struct {
	cacheKmsKeyRef *string
	region         string
}

func (a *mqlAwsMacieBucketEncryption) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheKmsKeyRef, a.region, &a.KmsKey.State)
}

func (a *mqlAwsMacieBucket) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsMacieBucket) bucket() (*mqlAwsS3Bucket, error) {
	if a.Name.Data == "" {
		a.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, ResourceAwsS3Bucket,
		map[string]*llx.RawData{"name": llx.StringData(a.Name.Data)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

// ============================================================================
// aws.s3.bucket.macieCoverage — inverse traversal
// ============================================================================

func (a *mqlAwsS3Bucket) macieCoverage() (*mqlAwsMacieBucket, error) {
	name := a.Name.Data
	if name == "" {
		a.MacieCoverage.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	locTValue := a.GetLocation()
	region := ""
	if locTValue != nil && locTValue.Error == nil {
		region = locTValue.Data
	}

	mqlBucket, err := NewResource(a.MqlRuntime, ResourceAwsMacieBucket, map[string]*llx.RawData{
		"name":   llx.StringData(name),
		"region": llx.StringData(region),
	})
	if err != nil {
		if errors.Is(err, errMacieBucketNotCovered) {
			a.MacieCoverage.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	return mqlBucket.(*mqlAwsMacieBucket), nil
}

// ============================================================================
// aws.macie.allowList
// ============================================================================

type mqlAwsMacieAllowListInternal struct {
	cacheRegion    string
	detailsFetched bool
	detailsLock    sync.Mutex
}

func (a *mqlAwsMacie) allowLists() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		paginator := macie2.NewListAllowListsPaginator(svc, &macie2.ListAllowListsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, item := range page.AllowLists {
				mqlList, err := CreateResource(a.MqlRuntime, ResourceAwsMacieAllowList,
					map[string]*llx.RawData{
						"id":        llx.StringDataPtr(item.Id),
						"arn":       llx.StringDataPtr(item.Arn),
						"region":    llx.StringData(region),
						"name":      llx.StringDataPtr(item.Name),
						"createdAt": llx.TimeDataPtr(item.CreatedAt),
						"updatedAt": llx.TimeDataPtr(item.UpdatedAt),
					})
				if err != nil {
					return nil, err
				}
				mqlList.(*mqlAwsMacieAllowList).cacheRegion = region
				res = append(res, mqlList)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsMacieAllowList) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsMacieAllowList) populateDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	id := a.Id.Data
	svc := conn.Macie2(a.cacheRegion)
	ctx := context.Background()
	resp, err := svc.GetAllowList(ctx, &macie2.GetAllowListInput{Id: &id})
	if err != nil {
		return err
	}

	description := ""
	if resp.Description != nil {
		description = *resp.Description
	}
	a.Description = plugin.TValue[string]{Data: description, State: plugin.StateIsSet}

	status := ""
	statusDescription := ""
	if resp.Status != nil {
		status = string(resp.Status.Code)
		if resp.Status.Description != nil {
			statusDescription = *resp.Status.Description
		}
	}
	a.Status = plugin.TValue[string]{Data: status, State: plugin.StateIsSet}
	a.StatusDescription = plugin.TValue[string]{Data: statusDescription, State: plugin.StateIsSet}

	criteriaDict, _ := convert.JsonToDict(resp.Criteria)
	a.Criteria = plugin.TValue[any]{Data: criteriaDict, State: plugin.StateIsSet}

	if resp.Tags != nil {
		a.Tags = plugin.TValue[map[string]any]{Data: convert.MapToInterfaceMap(resp.Tags), State: plugin.StateIsSet}
	} else {
		a.Tags = plugin.TValue[map[string]any]{Data: map[string]any{}, State: plugin.StateIsSet}
	}

	a.detailsFetched = true
	return nil
}

func (a *mqlAwsMacieAllowList) description() (string, error) {
	return "", a.populateDetails()
}

func (a *mqlAwsMacieAllowList) status() (string, error) {
	return "", a.populateDetails()
}

func (a *mqlAwsMacieAllowList) statusDescription() (string, error) {
	return "", a.populateDetails()
}

func (a *mqlAwsMacieAllowList) criteria() (any, error) {
	return nil, a.populateDetails()
}

func (a *mqlAwsMacieAllowList) tags() (map[string]any, error) {
	return nil, a.populateDetails()
}

// ============================================================================
// aws.macie.findingsFilter
// ============================================================================

type mqlAwsMacieFindingsFilterInternal struct {
	cacheRegion    string
	detailsFetched bool
	detailsLock    sync.Mutex
}

func (a *mqlAwsMacie) findingsFilters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		paginator := macie2.NewListFindingsFiltersPaginator(svc, &macie2.ListFindingsFiltersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, item := range page.FindingsFilterListItems {
				var itemTags map[string]any
				if item.Tags != nil {
					itemTags = convert.MapToInterfaceMap(item.Tags)
				}
				mqlFilter, err := CreateResource(a.MqlRuntime, ResourceAwsMacieFindingsFilter,
					map[string]*llx.RawData{
						"id":     llx.StringDataPtr(item.Id),
						"arn":    llx.StringDataPtr(item.Arn),
						"region": llx.StringData(region),
						"name":   llx.StringDataPtr(item.Name),
						"action": llx.StringData(string(item.Action)),
						"tags":   llx.MapData(itemTags, mqlTypes.String),
					})
				if err != nil {
					return nil, err
				}
				mqlFilter.(*mqlAwsMacieFindingsFilter).cacheRegion = region
				res = append(res, mqlFilter)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsMacieFindingsFilter) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsMacieFindingsFilter) populateDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	id := a.Id.Data
	svc := conn.Macie2(a.cacheRegion)
	ctx := context.Background()
	resp, err := svc.GetFindingsFilter(ctx, &macie2.GetFindingsFilterInput{Id: &id})
	if err != nil {
		return err
	}

	description := ""
	if resp.Description != nil {
		description = *resp.Description
	}
	a.Description = plugin.TValue[string]{Data: description, State: plugin.StateIsSet}

	position := int64(0)
	if resp.Position != nil {
		position = int64(*resp.Position)
	}
	a.Position = plugin.TValue[int64]{Data: position, State: plugin.StateIsSet}

	criteriaDict, _ := convert.JsonToDict(resp.FindingCriteria)
	a.FindingCriteria = plugin.TValue[any]{Data: criteriaDict, State: plugin.StateIsSet}

	a.detailsFetched = true
	return nil
}

func (a *mqlAwsMacieFindingsFilter) description() (string, error) {
	return "", a.populateDetails()
}

func (a *mqlAwsMacieFindingsFilter) position() (int64, error) {
	return 0, a.populateDetails()
}

func (a *mqlAwsMacieFindingsFilter) findingCriteria() (any, error) {
	return nil, a.populateDetails()
}

// ============================================================================
// aws.macie.member
// ============================================================================

func (a *mqlAwsMacie) members() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		onlyAssociated := "false"
		paginator := macie2.NewListMembersPaginator(svc, &macie2.ListMembersInput{
			OnlyAssociated: &onlyAssociated,
		})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, m := range page.Members {
				memberAccountId := ""
				if m.AccountId != nil {
					memberAccountId = *m.AccountId
				}
				arn := ""
				if m.Arn != nil {
					arn = *m.Arn
				} else {
					arn = generateMacieMemberArn(conn.AccountId(), region, memberAccountId)
				}
				var memberTags map[string]any
				if m.Tags != nil {
					memberTags = convert.MapToInterfaceMap(m.Tags)
				}
				mqlMember, err := CreateResource(a.MqlRuntime, ResourceAwsMacieMember,
					map[string]*llx.RawData{
						"accountId":              llx.StringData(memberAccountId),
						"arn":                    llx.StringData(arn),
						"region":                 llx.StringData(region),
						"administratorAccountId": llx.StringDataPtr(m.AdministratorAccountId),
						"email":                  llx.StringDataPtr(m.Email),
						"relationshipStatus":     llx.StringData(string(m.RelationshipStatus)),
						"invitedAt":              llx.TimeDataPtr(m.InvitedAt),
						"updatedAt":              llx.TimeDataPtr(m.UpdatedAt),
						"tags":                   llx.MapData(memberTags, mqlTypes.String),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlMember)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsMacieMember) id() (string, error) {
	return a.Arn.Data, nil
}

// ============================================================================
// aws.macie.invitation
// ============================================================================

func (a *mqlAwsMacie) invitations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		paginator := macie2.NewListInvitationsPaginator(svc, &macie2.ListInvitationsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, inv := range page.Invitations {
				mqlInv, err := CreateResource(a.MqlRuntime, ResourceAwsMacieInvitation,
					map[string]*llx.RawData{
						"invitationId":       llx.StringDataPtr(inv.InvitationId),
						"accountId":          llx.StringDataPtr(inv.AccountId),
						"region":             llx.StringData(region),
						"relationshipStatus": llx.StringData(string(inv.RelationshipStatus)),
						"invitedAt":          llx.TimeDataPtr(inv.InvitedAt),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlInv)
			}
		}
		return res, nil
	})
}

func (a *mqlAwsMacieInvitation) id() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return generateMacieInvitationArn(conn.AccountId(), a.Region.Data, a.InvitationId.Data), nil
}

// ============================================================================
// aws.macie.administrator
// ============================================================================

func (a *mqlAwsMacie) administrators() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2/config", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		resp, err := svc.GetAdministratorAccount(ctx, &macie2.GetAdministratorAccountInput{})
		if err != nil {
			return nil, err
		}
		if resp.Administrator == nil || resp.Administrator.AccountId == nil {
			return res, nil
		}
		adm := resp.Administrator
		mqlAdmin, err := CreateResource(a.MqlRuntime, ResourceAwsMacieAdministrator,
			map[string]*llx.RawData{
				"accountId":          llx.StringDataPtr(adm.AccountId),
				"region":             llx.StringData(region),
				"invitationId":       llx.StringDataPtr(adm.InvitationId),
				"invitedAt":          llx.TimeDataPtr(adm.InvitedAt),
				"relationshipStatus": llx.StringData(string(adm.RelationshipStatus)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAdmin)
		return res, nil
	})
}

func (a *mqlAwsMacieAdministrator) id() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return generateMacieAdministratorArn(conn.AccountId(), a.Region.Data, a.AccountId.Data), nil
}

// ============================================================================
// aws.macie.automatedDiscoveryConfiguration
// ============================================================================

func (a *mqlAwsMacie) automatedDiscoveryConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2/config", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		resp, err := svc.GetAutomatedDiscoveryConfiguration(ctx, &macie2.GetAutomatedDiscoveryConfigurationInput{})
		if err != nil {
			return nil, err
		}
		classificationScopeId := ""
		if resp.ClassificationScopeId != nil {
			classificationScopeId = *resp.ClassificationScopeId
		}
		sensitivityTemplateId := ""
		if resp.SensitivityInspectionTemplateId != nil {
			sensitivityTemplateId = *resp.SensitivityInspectionTemplateId
		}
		mqlConfig, err := CreateResource(a.MqlRuntime, ResourceAwsMacieAutomatedDiscoveryConfiguration,
			map[string]*llx.RawData{
				"region":                          llx.StringData(region),
				"status":                          llx.StringData(string(resp.Status)),
				"autoEnableOrganizationMembers":   llx.StringData(string(resp.AutoEnableOrganizationMembers)),
				"classificationScopeId":           llx.StringData(classificationScopeId),
				"sensitivityInspectionTemplateId": llx.StringData(sensitivityTemplateId),
				"firstEnabledAt":                  llx.TimeDataPtr(resp.FirstEnabledAt),
				"disabledAt":                      llx.TimeDataPtr(resp.DisabledAt),
				"lastUpdatedAt":                   llx.TimeDataPtr(resp.LastUpdatedAt),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
		return res, nil
	})
}

func (a *mqlAwsMacieAutomatedDiscoveryConfiguration) id() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return generateMacieAutomatedDiscoveryArn(conn.AccountId(), a.Region.Data), nil
}

// ============================================================================
// aws.macie.classificationExportConfiguration
// ============================================================================

func (a *mqlAwsMacie) classificationExportConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		resp, err := svc.GetClassificationExportConfiguration(ctx, &macie2.GetClassificationExportConfigurationInput{})
		if err != nil {
			return nil, err
		}
		if resp.Configuration == nil || resp.Configuration.S3Destination == nil {
			return res, nil
		}
		dest := resp.Configuration.S3Destination
		bucketName := ""
		if dest.BucketName != nil {
			bucketName = *dest.BucketName
		}
		keyPrefix := ""
		if dest.KeyPrefix != nil {
			keyPrefix = *dest.KeyPrefix
		}
		expectedBucketOwner := ""
		if dest.ExpectedBucketOwner != nil {
			expectedBucketOwner = *dest.ExpectedBucketOwner
		}
		kmsKeyArn := ""
		if dest.KmsKeyArn != nil {
			kmsKeyArn = *dest.KmsKeyArn
		}
		mqlConfig, err := CreateResource(a.MqlRuntime, ResourceAwsMacieClassificationExportConfiguration,
			map[string]*llx.RawData{
				"region":              llx.StringData(region),
				"s3BucketName":        llx.StringData(bucketName),
				"s3KeyPrefix":         llx.StringData(keyPrefix),
				"expectedBucketOwner": llx.StringData(expectedBucketOwner),
				"kmsKeyArn":           llx.StringData(kmsKeyArn),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
		return res, nil
	})
}

func (a *mqlAwsMacieClassificationExportConfiguration) id() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return generateMacieClassificationExportArn(conn.AccountId(), a.Region.Data), nil
}

func (a *mqlAwsMacieClassificationExportConfiguration) bucket() (*mqlAwsS3Bucket, error) {
	name := a.S3BucketName.Data
	if name == "" {
		a.Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlBucket, err := NewResource(a.MqlRuntime, ResourceAwsS3Bucket,
		map[string]*llx.RawData{"name": llx.StringData(name)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsMacieClassificationExportConfiguration) kmsKey() (*mqlAwsKmsKey, error) {
	keyArn := a.KmsKeyArn.Data
	if keyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringData(keyArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// ============================================================================
// aws.macie.revealConfiguration
// ============================================================================

func (a *mqlAwsMacie) revealConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	return perRegion(conn, "macie2", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Macie2(region)
		res := []any{}
		resp, err := svc.GetRevealConfiguration(ctx, &macie2.GetRevealConfigurationInput{})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Msg("no permission to read macie reveal configuration")
				return res, nil
			}
			return nil, err
		}
		if resp.Configuration == nil {
			return res, nil
		}

		var retrievalMode, roleName string
		if rc := resp.RetrievalConfiguration; rc != nil {
			retrievalMode = string(rc.RetrievalMode)
			roleName = convert.ToValue(rc.RoleName)
		}

		mqlConfig, err := CreateResource(a.MqlRuntime, "aws.macie.revealConfiguration",
			map[string]*llx.RawData{
				"__id":          llx.StringData(generateMacieRevealConfigurationArn(conn.AccountId(), region)),
				"region":        llx.StringData(region),
				"status":        llx.StringData(string(resp.Configuration.Status)),
				"retrievalMode": llx.StringData(retrievalMode),
				"roleName":      llx.StringData(roleName),
				"kmsKeyArn":     llx.StringData(convert.ToValue(resp.Configuration.KmsKeyId)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlConfig)
		return res, nil
	})
}

func generateMacieRevealConfigurationArn(accountId, region string) string {
	return "arn:aws:macie2:" + region + ":" + accountId + ":reveal-configuration"
}

func (a *mqlAwsMacieRevealConfiguration) id() (string, error) {
	return a.__id, nil
}

// retrievalIamRole resolves the role Macie assumes to retrieve sensitive data
// samples. The API reports a role name rather than an ARN, and only for the
// ASSUME_ROLE retrieval mode; CALLER_CREDENTIALS uses the viewer's own
// credentials and names no role.
func (a *mqlAwsMacieRevealConfiguration) retrievalIamRole() (*mqlAwsIamRole, error) {
	roleName := a.RoleName.Data
	if roleName == "" {
		a.RetrievalIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	roleArn := "arn:aws:iam::" + conn.AccountId() + ":role/" + roleName
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsMacieRevealConfiguration) kmsKey() (*mqlAwsKmsKey, error) {
	keyArn := a.KmsKeyArn.Data
	if keyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringData(keyArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// ============================================================================
// Macie findings publication
// ============================================================================

type mqlAwsMacieSessionInternal struct {
	publicationFetched                 bool
	publicationLock                    sync.Mutex
	cachePublishClassificationFindings bool
	cachePublishPolicyFindings         bool
	publicationClassificationIsKnown   bool
}

// fetchFindingsPublication reads whether Macie forwards its findings to
// Security Hub. Both flags come from one call, so the two fields share it.
func (a *mqlAwsMacieSession) fetchFindingsPublication() error {
	if a.publicationFetched {
		return nil
	}
	a.publicationLock.Lock()
	defer a.publicationLock.Unlock()
	if a.publicationFetched {
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Macie2(a.Region.Data)
	resp, err := svc.GetFindingsPublicationConfiguration(context.Background(),
		&macie2.GetFindingsPublicationConfigurationInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("region", a.Region.Data).
				Msg("no permission to read macie findings publication configuration")
			a.publicationFetched = true
			return nil
		}
		return err
	}

	if shc := resp.SecurityHubConfiguration; shc != nil {
		a.cachePublishClassificationFindings = convert.ToValue(shc.PublishClassificationFindings)
		a.cachePublishPolicyFindings = convert.ToValue(shc.PublishPolicyFindings)
		a.publicationClassificationIsKnown = true
	}
	a.publicationFetched = true
	return nil
}

func (a *mqlAwsMacieSession) publishClassificationFindings() (bool, error) {
	if err := a.fetchFindingsPublication(); err != nil {
		return false, err
	}
	if !a.publicationClassificationIsKnown {
		a.PublishClassificationFindings.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return a.cachePublishClassificationFindings, nil
}

func (a *mqlAwsMacieSession) publishPolicyFindings() (bool, error) {
	if err := a.fetchFindingsPublication(); err != nil {
		return false, err
	}
	if !a.publicationClassificationIsKnown {
		a.PublishPolicyFindings.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return a.cachePublishPolicyFindings, nil
}
