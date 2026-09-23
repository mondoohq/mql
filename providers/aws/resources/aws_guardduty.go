// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/guardduty"
	"github.com/aws/aws-sdk-go-v2/service/guardduty/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	mqlTypes "go.mondoo.com/mql/types"
)

// guarddutyDetailConcurrency caps the per-detector fan-out of GetIPSet and
// GetThreatIntelSet calls. There is no batch API; fanning out shrinks the wall
// clock for detectors with many IP or threat-intel sets.
const guarddutyDetailConcurrency = 10

func (a *mqlAwsGuardduty) id() (string, error) {
	return "aws.guardduty", nil
}

func (a *mqlAwsGuardduty) detectors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDetectors(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsGuarddutyDetector) id() (string, error) {
	return a.Id.Data, nil
}

const guarddutyDetectorArnPattern = "arn:aws:guardduty:%s:%s:detector/%s"

func (a *mqlAwsGuarddutyDetector) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(guarddutyDetectorArnPattern, a.Region.Data, conn.AccountId(), a.Id.Data), nil
}

func (a *mqlAwsGuardduty) getDetectors(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Guardduty(region)
			ctx := context.Background()

			res := []any{}
			params := &guardduty.ListDetectorsInput{}
			paginator := guardduty.NewListDetectorsPaginator(svc, params)
			for paginator.HasMorePages() {
				detectors, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, id := range detectors.DetectorIds {
					mqlCluster, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector",
						map[string]*llx.RawData{
							"id":     llx.StringData(id),
							"region": llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCluster)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsGuarddutyDetectorInternal struct {
	cachedDetector *guardduty.GetDetectorOutput
}

func (a *mqlAwsGuarddutyDetector) populateData() error {
	if a.cachedDetector != nil {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	// default set values
	a.Status = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	a.FindingPublishingFrequency = plugin.TValue[string]{State: plugin.StateIsSet | plugin.StateIsNull}
	a.Tags = plugin.TValue[map[string]any]{State: plugin.StateIsSet | plugin.StateIsNull}
	a.CreatedAt = plugin.TValue[*time.Time]{State: plugin.StateIsSet | plugin.StateIsNull}
	a.UpdatedAt = plugin.TValue[*time.Time]{State: plugin.StateIsSet | plugin.StateIsNull}

	idVal := a.GetId()
	if idVal.Error != nil {
		return idVal.Error
	}
	regionVal := a.GetRegion()
	if regionVal.Error != nil {
		return regionVal.Error
	}
	detectorId := idVal.Data
	region := regionVal.Data

	svc := conn.Guardduty(region)

	ctx := context.Background()
	detector, err := svc.GetDetector(ctx, &guardduty.GetDetectorInput{
		DetectorId: &detectorId,
	})
	if err != nil {
		return err
	}

	// Cache the detector response for typed feature method
	a.cachedDetector = detector

	a.Status = plugin.TValue[string]{Data: string(detector.Status), State: plugin.StateIsSet}
	a.FindingPublishingFrequency = plugin.TValue[string]{Data: string(detector.FindingPublishingFrequency), State: plugin.StateIsSet}
	a.Tags = plugin.TValue[map[string]any]{Data: convert.MapToInterfaceMap(detector.Tags), State: plugin.StateIsSet}

	if detector.CreatedAt != nil {
		if createdAt, err := time.Parse(time.RFC3339, *detector.CreatedAt); err == nil {
			a.CreatedAt = plugin.TValue[*time.Time]{Data: &createdAt, State: plugin.StateIsSet}
		}
	}
	if detector.UpdatedAt != nil {
		if updatedAt, err := time.Parse(time.RFC3339, *detector.UpdatedAt); err == nil {
			a.UpdatedAt = plugin.TValue[*time.Time]{Data: &updatedAt, State: plugin.StateIsSet}
		}
	}

	return nil
}

func (a *mqlAwsGuarddutyDetector) status() (string, error) {
	return "", a.populateData()
}

func (a *mqlAwsGuarddutyDetector) tags() (map[string]any, error) {
	return nil, a.populateData()
}

func (a *mqlAwsGuarddutyDetector) findingPublishingFrequency() (string, error) {
	return "", a.populateData()
}

func (a *mqlAwsGuarddutyDetector) createdAt() (*time.Time, error) {
	return nil, a.populateData()
}

func (a *mqlAwsGuarddutyDetector) updatedAt() (*time.Time, error) {
	return nil, a.populateData()
}

func (a *mqlAwsGuarddutyDetector) findings() ([]any, error) {
	detectorId := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Guardduty(region)
	params := &guardduty.ListFindingsInput{
		DetectorId: &detectorId,
		FindingCriteria: &types.FindingCriteria{
			Criterion: map[string]types.Condition{
				"service.archived": {
					Equals: []string{"false"},
				},
			},
		},
	}
	return fetchFindings(svc, detectorId, region, params, a.MqlRuntime)
}

func (a *mqlAwsGuardduty) findings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	// we need to retrieve all the detectors first and we group them by region to request all findings
	detectorMap := map[string][]string{}
	detectorList := a.GetDetectors()
	if detectorList.Error != nil {
		return nil, detectorList.Error
	}
	for _, detector := range detectorList.Data {
		detectorInstance, ok := detector.(*mqlAwsGuarddutyDetector)
		if !ok {
			return nil, errors.New("error casting to detector instance")
		}

		region := detectorInstance.GetRegion().Data
		if detectorMap[region] == nil {
			detectorMap[region] = []string{}
		}

		detectorMap[region] = append(detectorMap[region], detectorInstance.GetId().Data)
	}

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.listFindings(conn, detectorMap), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsGuardduty) listFindings(conn *connection.AwsConnection, detectorMap map[string][]string) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Guardduty(region)

			res := []any{}
			detectorList := detectorMap[region]
			for _, detectorId := range detectorList {
				params := &guardduty.ListFindingsInput{
					DetectorId: &detectorId,
					FindingCriteria: &types.FindingCriteria{
						Criterion: map[string]types.Condition{
							"region": {
								Equals: []string{region},
							},
							"service.archived": {
								Equals: []string{"false"},
							},
						},
					},
				}
				findings, err := fetchFindings(svc, detectorId, region, params, a.MqlRuntime)
				if err != nil {
					return nil, err
				}
				res = append(res, findings...)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// fetchFindings list all findings for a detector and fetches the details to create the MQL resources
func fetchFindings(svc *guardduty.Client, detectorId string, regionVal string, params *guardduty.ListFindingsInput, runtime *plugin.Runtime) ([]any, error) {
	res := []any{}
	ctx := context.Background()
	findingIds := []string{}
	paginator := guardduty.NewListFindingsPaginator(svc, params)
	for paginator.HasMorePages() {
		// fetch all finding ids, we can only fetch 50 at a time, that is the default
		detectors, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", regionVal).Msg("error accessing region for AWS API")
				return nil, nil
			}
			return nil, err
		}

		findingIds = append(findingIds, detectors.FindingIds...)
	}

	// fetch all findings, we can only fetch 50 at a time
	fetched := 0
	for findingIdsChunk := range slices.Chunk(findingIds, 50) {
		findingDetails, err := svc.GetFindings(ctx, &guardduty.GetFindingsInput{
			FindingIds: findingIdsChunk,
			DetectorId: &detectorId,
		})
		if err != nil {
			return nil, err
		}

		for _, finding := range findingDetails.Findings {
			fetched++
			mqlFinding, err := newMqlAwsGuardDutyFinding(runtime, finding)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlFinding)
		}
	}
	return res, nil
}

type mqlAwsGuarddutyFindingInternal struct {
	cachedResource *types.Resource
}

func newMqlAwsGuardDutyFinding(runtime *plugin.Runtime, finding types.Finding) (*mqlAwsGuarddutyFinding, error) {
	var severity float64
	if finding.Severity != nil {
		severity = *finding.Severity
	}

	var confidence float64
	if finding.Confidence != nil {
		confidence = *finding.Confidence
	}

	var serviceName string
	var actionType string
	var count int64
	if finding.Service != nil {
		serviceName = convert.ToValue(finding.Service.ServiceName)
		if finding.Service.Count != nil {
			count = int64(*finding.Service.Count)
		}
		if finding.Service.Action != nil {
			actionType = convert.ToValue(finding.Service.Action.ActionType)
		}
	}

	var resourceType string
	if finding.Resource != nil {
		resourceType = convert.ToValue(finding.Resource.ResourceType)
	}

	res, err := CreateResource(runtime, "aws.guardduty.finding", map[string]*llx.RawData{
		"__id":         llx.StringDataPtr(finding.Arn),
		"arn":          llx.StringDataPtr(finding.Arn),
		"id":           llx.StringDataPtr(finding.Id),
		"region":       llx.StringDataPtr(finding.Region),
		"title":        llx.StringDataPtr(finding.Title),
		"description":  llx.StringDataPtr(finding.Description),
		"severity":     llx.FloatData(severity),
		"confidence":   llx.FloatData(confidence),
		"type":         llx.StringDataPtr(finding.Type),
		"createdAt":    llx.TimeDataPtr(parseAwsTimestampPtr(finding.CreatedAt)),
		"updatedAt":    llx.TimeDataPtr(parseAwsTimestampPtr(finding.UpdatedAt)),
		"accountId":    llx.StringDataPtr(finding.AccountId),
		"resourceType": llx.StringData(resourceType),
		"service":      llx.StringData(serviceName),
		"actionType":   llx.StringData(actionType),
		"count":        llx.IntData(count),
	})
	if err != nil {
		return nil, err
	}
	mqlFinding := res.(*mqlAwsGuarddutyFinding)
	mqlFinding.cachedResource = finding.Resource
	return mqlFinding, nil
}

func (a *mqlAwsGuarddutyFinding) resourceDetails() (any, error) {
	if a.cachedResource == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cachedResource)
}

func parseAwsTimestampPtr(value *string) *time.Time {
	if value == nil {
		return nil
	}
	return parseAwsTimestamp(*value)
}

// awsTimestampLayouts lists every shape a string timestamp arrives in from the
// AWS APIs that hand back timestamps as strings instead of typed times. They
// are tried in order; the first that parses wins.
var awsTimestampLayouts = []string{
	// The common case, e.g. "2026-04-09T05:40:04Z" or "2026-04-09T05:40:04+00:00".
	time.RFC3339,
	// Some AWS APIs (e.g., Lambda layers) return timestamps with a non-RFC3339
	// timezone offset like "2026-04-12T18:11:01.019+0000" (missing colon).
	"2006-01-02T15:04:05.000-0700",
	// The same offset shape without fractional seconds, e.g. Lambda provisioned
	// concurrency: "2026-08-31T20:11:24+0000". The layout above demands the
	// fractional part, so this form needs its own entry.
	"2006-01-02T15:04:05-0700",
	// Some AWS APIs (e.g., EC2 Verified Access) return timestamps without
	// timezone info like "2026-04-09T05:40:04". Read as UTC in that case.
	"2006-01-02T15:04:05",
}

func parseAwsTimestamp(value string) *time.Time {
	for _, layout := range awsTimestampLayouts {
		timestamp, err := time.Parse(layout, value)
		if err != nil {
			continue
		}
		// A layout carrying no zone parses into UTC already; normalizing keeps
		// the location explicit rather than the zero Location value.
		if layout == "2006-01-02T15:04:05" {
			timestamp = timestamp.UTC()
		}
		return &timestamp
	}
	log.Warn().Str("timestamp", value).Msg("failed to parse timestamp")
	return nil
}

func (a *mqlAwsGuarddutyDetector) featureConfigurations() ([]any, error) {
	// Ensure detector data is populated (which caches the response)
	if err := a.populateData(); err != nil {
		return nil, err
	}

	if a.cachedDetector == nil {
		return []any{}, nil
	}

	detectorId := a.Id.Data
	res := []any{}
	for i, feat := range a.cachedDetector.Features {
		additionalConfig, _ := convert.JsonToDictSlice(feat.AdditionalConfiguration)
		mqlFeat, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector.feature",
			map[string]*llx.RawData{
				"__id":                    llx.StringData(fmt.Sprintf("%s/feature/%d", detectorId, i)),
				"name":                    llx.StringData(string(feat.Name)),
				"status":                  llx.StringData(string(feat.Status)),
				"updatedAt":               llx.TimeDataPtr(feat.UpdatedAt),
				"additionalConfiguration": llx.ArrayData(additionalConfig, mqlTypes.Dict),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFeat)
	}
	return res, nil
}

func (a *mqlAwsGuarddutyDetector) publishingDestinations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	detectorId := a.Id.Data
	region := a.Region.Data
	svc := conn.Guardduty(region)
	ctx := context.Background()

	resp, err := svc.ListPublishingDestinations(ctx, &guardduty.ListPublishingDestinationsInput{
		DetectorId: &detectorId,
	})
	if err != nil {
		return nil, classifyAwsError(err, "guardduty:ListPublishingDestinations")
	}

	// The list response already carries destinationId, destinationType, and
	// status. The per-destination DescribePublishingDestination call is only
	// needed for the s3Bucket()/kmsKey() references, so it is deferred to
	// fetchDetail() and made only when one of those fields is accessed.
	res := []any{}
	for _, dest := range resp.Destinations {
		mqlDest, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector.publishingDestination",
			map[string]*llx.RawData{
				"__id":            llx.StringData(fmt.Sprintf("%s/publishingDestination/%s", detectorId, convert.ToValue(dest.DestinationId))),
				"destinationId":   llx.StringDataPtr(dest.DestinationId),
				"destinationType": llx.StringData(string(dest.DestinationType)),
				"status":          llx.StringData(string(dest.Status)),
			})
		if err != nil {
			return nil, err
		}

		mqlDestRes := mqlDest.(*mqlAwsGuarddutyDetectorPublishingDestination)
		mqlDestRes.detectorId = detectorId
		mqlDestRes.region = region
		res = append(res, mqlDestRes)
	}
	return res, nil
}

type mqlAwsGuarddutyDetectorPublishingDestinationInternal struct {
	detectorId     string
	region         string
	fetched        atomic.Bool
	lock           sync.Mutex
	cacheBucketArn *string
	cacheKmsKeyArn *string
	fetchErr       error
}

// fetchDetail lazily calls DescribePublishingDestination once to resolve the
// destination's S3 bucket and KMS key, shared by s3Bucket() and kmsKey().
func (a *mqlAwsGuarddutyDetectorPublishingDestination) fetchDetail() error {
	if a.fetched.Load() {
		return a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched.Load() {
		return a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Guardduty(a.region)
	destinationId := a.DestinationId.Data
	detail, err := svc.DescribePublishingDestination(context.Background(), &guardduty.DescribePublishingDestinationInput{
		DetectorId:    &a.detectorId,
		DestinationId: &destinationId,
	})
	if err != nil {
		a.fetchErr = err
		a.fetched.Store(true)
		return err
	}
	if detail.DestinationProperties != nil {
		a.cacheBucketArn = detail.DestinationProperties.DestinationArn
		a.cacheKmsKeyArn = detail.DestinationProperties.KmsKeyArn
	}
	a.fetched.Store(true)
	return nil
}

func (a *mqlAwsGuarddutyDetectorPublishingDestination) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsGuarddutyDetectorPublishingDestination) s3Bucket() (*mqlAwsS3Bucket, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	if a.cacheBucketArn == nil || *a.cacheBucketArn == "" {
		a.S3Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// The destination ARN is an S3 bucket ARN like arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/prefix
	// Extract just the bucket name
	bucketArn := *a.cacheBucketArn
	parts := strings.Split(bucketArn, ":::")
	if len(parts) < 2 {
		a.S3Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	bucketName := strings.Split(parts[1], "/")[0]

	mqlBucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{"name": llx.StringData(bucketName)})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsGuarddutyDetectorPublishingDestination) kmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetail(); err != nil {
		return nil, err
	}
	if a.cacheKmsKeyArn == nil || *a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsGuarddutyDetector) ipSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	detectorId := a.Id.Data
	region := a.Region.Data
	svc := conn.Guardduty(region)
	ctx := context.Background()

	res := []any{}
	paginator := guardduty.NewListIPSetsPaginator(svc, &guardduty.ListIPSetsInput{
		DetectorId: &detectorId,
	})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "guardduty:ListIPSets")
		}
		details := make([]*guardduty.GetIPSetOutput, len(resp.IpSetIds))
		var wg sync.WaitGroup
		sem := make(chan struct{}, guarddutyDetailConcurrency)
		for i, ipSetId := range resp.IpSetIds {
			wg.Add(1)
			go func(idx int, id string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				detail, err := svc.GetIPSet(ctx, &guardduty.GetIPSetInput{
					DetectorId: &detectorId,
					IpSetId:    &id,
				})
				if err != nil {
					log.Warn().Err(err).Str("ipSetId", id).Msg("could not get IP set details")
					return
				}
				details[idx] = detail
			}(i, ipSetId)
		}
		wg.Wait()

		for i, ipSetId := range resp.IpSetIds {
			detail := details[i]
			if detail == nil {
				continue
			}
			mqlIpSet, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector.ipSet",
				map[string]*llx.RawData{
					"__id":     llx.StringData(fmt.Sprintf("%s/ipSet/%s", detectorId, ipSetId)),
					"id":       llx.StringData(ipSetId),
					"name":     llx.StringDataPtr(detail.Name),
					"format":   llx.StringData(string(detail.Format)),
					"location": llx.StringDataPtr(detail.Location),
					"status":   llx.StringData(string(detail.Status)),
					"tags":     llx.MapData(convert.MapToInterfaceMap(detail.Tags), mqlTypes.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlIpSet)
		}
	}
	return res, nil
}

func (a *mqlAwsGuarddutyDetector) threatIntelSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	detectorId := a.Id.Data
	region := a.Region.Data
	svc := conn.Guardduty(region)
	ctx := context.Background()

	res := []any{}
	paginator := guardduty.NewListThreatIntelSetsPaginator(svc, &guardduty.ListThreatIntelSetsInput{
		DetectorId: &detectorId,
	})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "guardduty:ListThreatIntelSets")
		}
		details := make([]*guardduty.GetThreatIntelSetOutput, len(resp.ThreatIntelSetIds))
		var wg sync.WaitGroup
		sem := make(chan struct{}, guarddutyDetailConcurrency)
		for i, tiSetId := range resp.ThreatIntelSetIds {
			wg.Add(1)
			go func(idx int, id string) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()
				detail, err := svc.GetThreatIntelSet(ctx, &guardduty.GetThreatIntelSetInput{
					DetectorId:       &detectorId,
					ThreatIntelSetId: &id,
				})
				if err != nil {
					log.Warn().Err(err).Str("threatIntelSetId", id).Msg("could not get threat intel set details")
					return
				}
				details[idx] = detail
			}(i, tiSetId)
		}
		wg.Wait()

		for i, tiSetId := range resp.ThreatIntelSetIds {
			detail := details[i]
			if detail == nil {
				continue
			}
			mqlTiSet, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector.threatIntelSet",
				map[string]*llx.RawData{
					"__id":     llx.StringData(fmt.Sprintf("%s/threatIntelSet/%s", detectorId, tiSetId)),
					"id":       llx.StringData(tiSetId),
					"name":     llx.StringDataPtr(detail.Name),
					"format":   llx.StringData(string(detail.Format)),
					"location": llx.StringDataPtr(detail.Location),
					"status":   llx.StringData(string(detail.Status)),
					"tags":     llx.MapData(convert.MapToInterfaceMap(detail.Tags), mqlTypes.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTiSet)
		}
	}
	return res, nil
}

func (a *mqlAwsGuarddutyDetector) coverageStatistics() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	detectorId := a.Id.Data
	region := a.Region.Data
	svc := conn.Guardduty(region)
	ctx := context.Background()

	resp, err := svc.GetCoverageStatistics(ctx, &guardduty.GetCoverageStatisticsInput{
		DetectorId: &detectorId,
		StatisticsType: []types.CoverageStatisticsType{
			types.CoverageStatisticsTypeCountByResourceType,
		},
	})
	if err != nil {
		return nil, classifyAwsError(err, "guardduty:GetCoverageStatistics")
	}

	res := []any{}
	if resp.CoverageStatistics != nil && resp.CoverageStatistics.CountByResourceType != nil {
		for resourceType, count := range resp.CoverageStatistics.CountByResourceType {
			mqlStat, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector.coverageStatistic",
				map[string]*llx.RawData{
					"__id":         llx.StringData(fmt.Sprintf("%s/coverage/%s", detectorId, resourceType)),
					"resourceType": llx.StringData(resourceType),
					"count":        llx.IntData(count),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlStat)
		}
	}
	return res, nil
}

func (a *mqlAwsGuarddutyDetectorFeature) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsGuarddutyDetectorIpSet) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsGuarddutyDetectorThreatIntelSet) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsGuarddutyDetectorCoverageStatistic) id() (string, error) {
	return a.__id, nil
}

// GuardDuty detector filters
func (a *mqlAwsGuarddutyDetector) filters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	detectorId := a.Id.Data
	region := a.Region.Data
	svc := conn.Guardduty(region)
	ctx := context.Background()

	res := []any{}
	paginator := guardduty.NewListFiltersPaginator(svc, &guardduty.ListFiltersInput{
		DetectorId: &detectorId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "guardduty:ListFilters")
		}
		for _, filterName := range page.FilterNames {
			detail, err := svc.GetFilter(ctx, &guardduty.GetFilterInput{
				DetectorId: &detectorId,
				FilterName: &filterName,
			})
			if err != nil {
				log.Warn().Err(err).Str("filter", filterName).Msg("could not get filter details")
				continue
			}

			findingCriteria, _ := convert.JsonToDict(detail.FindingCriteria)

			mqlFilter, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector.filter",
				map[string]*llx.RawData{
					"__id":   llx.StringData(fmt.Sprintf("%s/%s/filter/%s", region, detectorId, filterName)),
					"name":   llx.StringDataPtr(detail.Name),
					"region": llx.StringData(region),
					"action": llx.StringData(string(detail.Action)),
				})
			if err != nil {
				return nil, err
			}
			cast := mqlFilter.(*mqlAwsGuarddutyDetectorFilter)
			cast.Description = plugin.TValue[string]{Data: convert.ToValue(detail.Description), State: plugin.StateIsSet}
			cast.Rank = plugin.TValue[int64]{Data: int64(convert.ToValue(detail.Rank)), State: plugin.StateIsSet}
			cast.FindingCriteria = plugin.TValue[any]{Data: findingCriteria, State: plugin.StateIsSet}
			cast.Tags = plugin.TValue[map[string]any]{Data: convert.MapToInterfaceMap(detail.Tags), State: plugin.StateIsSet}

			res = append(res, mqlFilter)
		}
	}
	return res, nil
}

func (a *mqlAwsGuarddutyDetectorFilter) id() (string, error) {
	return a.__id, nil
}

// description, rank, findingCriteria, tags are eagerly populated
func (a *mqlAwsGuarddutyDetectorFilter) description() (string, error) { return "", nil }
func (a *mqlAwsGuarddutyDetectorFilter) rank() (int64, error)         { return 0, nil }
func (a *mqlAwsGuarddutyDetectorFilter) findingCriteria() (map[string]any, error) {
	return nil, nil
}
func (a *mqlAwsGuarddutyDetectorFilter) tags() (map[string]any, error) { return nil, nil }

// GuardDuty detector members
func (a *mqlAwsGuarddutyDetector) members() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	detectorId := a.Id.Data
	region := a.Region.Data
	svc := conn.Guardduty(region)
	ctx := context.Background()

	res := []any{}
	paginator := guardduty.NewListMembersPaginator(svc, &guardduty.ListMembersInput{
		DetectorId: &detectorId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "guardduty:ListMembers")
		}
		for _, member := range page.Members {
			invitedAt := parseGuardDutyTimestamp(member.InvitedAt)
			updatedAt := parseGuardDutyTimestamp(member.UpdatedAt)

			mqlMember, err := CreateResource(a.MqlRuntime, "aws.guardduty.detector.member",
				map[string]*llx.RawData{
					"__id":               llx.StringData(fmt.Sprintf("%s/%s/member/%s", region, detectorId, convert.ToValue(member.AccountId))),
					"accountId":          llx.StringDataPtr(member.AccountId),
					"region":             llx.StringData(region),
					"email":              llx.StringDataPtr(member.Email),
					"relationshipStatus": llx.StringDataPtr(member.RelationshipStatus),
					"invitedAt":          llx.TimeDataPtr(invitedAt),
					"updatedAt":          llx.TimeDataPtr(updatedAt),
					"administratorId":    llx.StringDataPtr(member.AdministratorId),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlMember)
		}
	}
	return res, nil
}

func (a *mqlAwsGuarddutyDetectorMember) id() (string, error) {
	return a.__id, nil
}

// parseGuardDutyTimestamp converts a GuardDuty member timestamp to *time.Time.
//
// These arrive as ISO-8601 strings, the same shape the detector path parses
// with RFC3339. The previous implementation assumed epoch seconds and used
// fmt.Sscanf(s, "%f", ...), which does not require consuming the whole input:
// on "2023-01-19T20:31:32.152Z" it read the leading "2023", reported no error,
// and produced 1970-01-01T00:33:43Z for every member.
//
// Epoch input is still accepted so the behaviour is a superset of both
// readings, since the SDK types the field as an opaque *string.
func parseGuardDutyTimestamp(s *string) *time.Time {
	if s == nil || *s == "" {
		return nil
	}
	if t := parseAwsTimestamp(*s); t != nil {
		return t
	}
	// fall back to an epoch-second string, but only when the value is entirely
	// numeric -- a partial numeric prefix is what caused the original bug.
	if epoch, err := strconv.ParseFloat(*s, 64); err == nil {
		t := time.Unix(int64(epoch), 0).UTC()
		return &t
	}
	return nil
}
