// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail"
	"github.com/aws/aws-sdk-go-v2/service/cloudtrail/types"

	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	mqlTypes "go.mondoo.com/mql/types"
)

func (a *mqlAwsCloudtrail) id() (string, error) {
	return "aws.cloudtrail", nil
}

func (a *mqlAwsCloudtrail) trails() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTrails(conn), 5)
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

func initAwsCloudtrailTrail(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) >= 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformCloudtrailTrail); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil && args["name"] == nil {
		return nil, nil, errors.New("arn or name required to fetch aws cloudtrail trail")
	}

	// We match the requested trail by ARN when supplied, otherwise by name.
	// A CloudTrail ARN cannot be synthesized from the name alone (it needs the
	// region and account), so never fabricate one — match the name directly.
	var arnVal, nameVal string
	if args["arn"] != nil {
		arnVal = args["arn"].Value.(string)
	}
	if args["name"] != nil {
		nameVal = args["name"].Value.(string)
	}

	if arnVal == "" && nameVal == "" {
		return nil, nil, errors.New("arn or name required to fetch aws cloudtrail trail")
	}

	log.Debug().Str("arn", arnVal).Str("name", nameVal).Msg("init cloudtrail trail")

	if cached := cachedByArn(runtime, ResourceAwsCloudtrailTrail, arnVal); cached != nil {
		return args, cached, nil
	}

	// Targeted lookup: when we have a real ARN, derive the home region from it
	// (or use an explicit region arg) and fetch just this one trail instead of
	// describing every trail in every region.
	if arnVal != "" {
		var region string
		if parsed, err := arn.Parse(arnVal); err == nil && strings.HasPrefix(parsed.Resource, "trail/") {
			region = parsed.Region
		}
		if args["region"] != nil {
			if r, ok := args["region"].Value.(string); ok && r != "" {
				region = r
			}
		}
		if region != "" {
			conn := runtime.Connection.(*connection.AwsConnection)
			svc := conn.Cloudtrail(region)
			resp, err := svc.GetTrail(context.Background(), &cloudtrail.GetTrailInput{Name: &arnVal})
			if err != nil {
				if !Is400AccessDeniedError(err) {
					var notFound *types.TrailNotFoundException
					if !errors.As(err, &notFound) {
						return nil, nil, err
					}
				}
			} else if resp.Trail != nil {
				trail, err := buildCloudtrailTrailResource(runtime, *resp.Trail)
				if err != nil {
					return nil, nil, err
				}
				return args, trail, nil
			}
		}
	}

	// Fallback: scan all trails (when we only have a name, or the ARN carries
	// no usable region).
	obj, err := CreateResource(runtime, "aws.cloudtrail", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	awsCloudtrail := obj.(*mqlAwsCloudtrail)

	rawResources := awsCloudtrail.GetTrails()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	for _, rawResource := range rawResources.Data {
		trail := rawResource.(*mqlAwsCloudtrailTrail)
		if (arnVal != "" && trail.Arn.Data == arnVal) || (nameVal != "" && trail.Name.Data == nameVal) {
			return args, trail, nil
		}
	}
	return args, nil, errors.New("cloudtrail trail does not exist")
}

// buildCloudtrailTrailResource maps an SDK trail into an aws.cloudtrail.trail
// resource and primes the trailCache so the status / event-selector lazy
// accessors resolve against the same data. Shared by the list path and the
// targeted init lookup.
func buildCloudtrailTrailResource(runtime *plugin.Runtime, trail types.Trail) (*mqlAwsCloudtrailTrail, error) {
	args := map[string]*llx.RawData{
		"arn":                        llx.StringDataPtr(trail.TrailARN),
		"name":                       llx.StringDataPtr(trail.Name),
		"isMultiRegionTrail":         llx.BoolDataPtr(trail.IsMultiRegionTrail),
		"isOrganizationTrail":        llx.BoolDataPtr(trail.IsOrganizationTrail),
		"logFileValidationEnabled":   llx.BoolDataPtr(trail.LogFileValidationEnabled),
		"includeGlobalServiceEvents": llx.BoolDataPtr(trail.IncludeGlobalServiceEvents),
		"region":                     llx.StringDataPtr(trail.HomeRegion),
		"hasInsightSelectors":        llx.BoolDataPtr(trail.HasInsightSelectors),
		"hasCustomEventSelectors":    llx.BoolDataPtr(trail.HasCustomEventSelectors),
	}

	mqlTrail, err := CreateResource(runtime, "aws.cloudtrail.trail", args)
	if err != nil {
		return nil, err
	}
	cast := mqlTrail.(*mqlAwsCloudtrailTrail)
	cast.trailCache = trail
	return cast, nil
}

type mqlAwsCloudtrailTrailInternal struct {
	trailCache           types.Trail
	cachedTrailStatus    *cloudtrail.GetTrailStatusOutput
	trailStatusLock      sync.Mutex
	cachedEventSelectors *cloudtrail.GetEventSelectorsOutput
	eventSelectorsLock   sync.Mutex
}

func (a *mqlAwsCloudtrail) getTrails(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cloudtrail>getTrails>calling aws with region %s", region)

			svc := conn.Cloudtrail(region)
			ctx := context.Background()
			res := []any{}

			// no pagination required
			trailsResp, err := svc.DescribeTrails(ctx, &cloudtrail.DescribeTrailsInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, errors.Wrap(err, "could not gather aws cloudtrail trails")
			}
			for _, trail := range trailsResp.TrailList {
				// only include trail if this region is the home region for the trail
				// we do this to avoid getting duped results from multiregion trails
				if region != convert.ToValue(trail.HomeRegion) {
					continue
				}
				mqlTrail, err := buildCloudtrailTrailResource(a.MqlRuntime, trail)
				if err != nil {
					return nil, err
				}

				res = append(res, mqlTrail)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// referencedResourceUnavailable reports an error that a retry will not change:
// the referenced resource is gone, or this caller may not read it.
//
// A trail keeps naming a role, topic, bucket, log group or key after that target
// is deleted, and a scan may legitimately lack permission to read it. Both are
// permanent for this scan, so the reference is reported as null rather than
// failing the field - which, because a field error renders as the value of the
// enclosing collection, would cost the caller every trail.
//
// A throttle, a 5xx or a network failure is deliberately excluded. There the
// target may well exist and simply could not be resolved right now, so reporting
// null would assert an absence that was never established.
func referencedResourceUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if Is400AccessDeniedError(err) {
		return true
	}
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	switch apiErr.ErrorCode() {
	case "NoSuchEntity", "NotFound", "NotFoundException", "ResourceNotFoundException":
		return true
	}
	return false
}

func (a *mqlAwsCloudtrailTrail) snsTopic() (*mqlAwsSnsTopic, error) {
	if a.trailCache.SnsTopicARN == nil || *a.trailCache.SnsTopicARN == "" {
		a.SnsTopic.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlTopic, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.trailCache.SnsTopicARN)},
	)
	if err != nil {
		if !referencedResourceUnavailable(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("topic", convert.ToValue(a.trailCache.SnsTopicARN)).
			Msg("cannot resolve the trail's sns topic")
		a.SnsTopic.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlTopic.(*mqlAwsSnsTopic), nil
}

func (a *mqlAwsCloudtrailTrail) cloudWatchLogsRole() (*mqlAwsIamRole, error) {
	if a.trailCache.CloudWatchLogsRoleArn == nil || *a.trailCache.CloudWatchLogsRoleArn == "" {
		a.CloudWatchLogsRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.trailCache.CloudWatchLogsRoleArn)},
	)
	if err != nil {
		if !referencedResourceUnavailable(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("role", convert.ToValue(a.trailCache.CloudWatchLogsRoleArn)).
			Msg("cannot resolve the trail's cloudwatch logs role")
		a.CloudWatchLogsRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsCloudtrailTrail) s3bucket() (*mqlAwsS3Bucket, error) {
	if a.trailCache.S3BucketName != nil {
		mqlBucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
			map[string]*llx.RawData{"name": llx.StringDataPtr(a.trailCache.S3BucketName)},
		)
		if err == nil {
			return mqlBucket.(*mqlAwsS3Bucket), nil
		}
		if !referencedResourceUnavailable(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("bucket", convert.ToValue(a.trailCache.S3BucketName)).
			Msg("cannot resolve the trail's s3 bucket")
	}
	a.S3bucket.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsCloudtrailTrail) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.trailCache.CloudWatchLogsLogGroupArn != nil {
		mqlLoggroup, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup",
			map[string]*llx.RawData{"arn": llx.StringDataPtr(a.trailCache.CloudWatchLogsLogGroupArn)},
		)
		if err == nil {
			return mqlLoggroup.(*mqlAwsCloudwatchLoggroup), nil
		}
		if !referencedResourceUnavailable(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("logGroup", convert.ToValue(a.trailCache.CloudWatchLogsLogGroupArn)).
			Msg("cannot resolve the trail's log group")
	}
	a.LogGroup.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsCloudtrailTrail) kmsKey() (*mqlAwsKmsKey, error) {
	// add kms key if there is one
	if a.trailCache.KmsKeyId != nil {
		mqlKeyResource, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
			map[string]*llx.RawData{"arn": llx.StringDataPtr(a.trailCache.KmsKeyId)},
		)
		if err == nil {
			return mqlKeyResource.(*mqlAwsKmsKey), nil
		}
		if !referencedResourceUnavailable(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("key", convert.ToValue(a.trailCache.KmsKeyId)).
			Msg("cannot resolve the trail's kms key")
	}
	a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (a *mqlAwsCloudtrailTrail) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCloudtrailTrail) getTrailStatus() (*cloudtrail.GetTrailStatusOutput, error) {
	if a.cachedTrailStatus != nil {
		return a.cachedTrailStatus, nil
	}
	a.trailStatusLock.Lock()
	defer a.trailStatusLock.Unlock()
	if a.cachedTrailStatus != nil {
		return a.cachedTrailStatus, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudtrail(a.Region.Data)
	ctx := context.Background()

	arnValue := a.Arn.Data
	trailstatus, err := svc.GetTrailStatus(ctx, &cloudtrail.GetTrailStatusInput{
		Name: &arnValue,
	})
	if err != nil {
		return nil, err
	}
	a.cachedTrailStatus = trailstatus
	return trailstatus, nil
}

func (a *mqlAwsCloudtrailTrail) isLogging() (bool, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return false, err
	}
	return convert.ToValue(trailstatus.IsLogging), nil
}

func (a *mqlAwsCloudtrailTrail) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudtrail(a.Region.Data)
	ctx := context.Background()

	arnValue := a.Arn.Data
	resp, err := svc.ListTags(ctx, &cloudtrail.ListTagsInput{
		ResourceIdList: []string{arnValue},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}

	tags := map[string]any{}
	for _, resourceTag := range resp.ResourceTagList {
		for _, tag := range resourceTag.TagsList {
			tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
		}
	}
	return tags, nil
}

func (a *mqlAwsCloudtrailTrail) getEventSelectorsData() (*cloudtrail.GetEventSelectorsOutput, error) {
	if a.cachedEventSelectors != nil {
		return a.cachedEventSelectors, nil
	}
	a.eventSelectorsLock.Lock()
	defer a.eventSelectorsLock.Unlock()
	if a.cachedEventSelectors != nil {
		return a.cachedEventSelectors, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudtrail(a.Region.Data)
	ctx := context.Background()

	arnValue := a.Arn.Data
	resp, err := svc.GetEventSelectors(ctx, &cloudtrail.GetEventSelectorsInput{
		TrailName: &arnValue,
	})
	if err != nil {
		return nil, err
	}
	a.cachedEventSelectors = resp
	return resp, nil
}

// Advanced event selector field names, and the event category that carries
// management events. CloudTrail documents these as case-sensitive, but they are
// compared case-insensitively here so a hand-written trail definition that
// differs in case is not read as selecting nothing.
const (
	advancedSelectorFieldEventCategory = "eventCategory"
	advancedSelectorFieldReadOnly      = "readOnly"
	eventCategoryManagement            = "Management"
)

// containsFold reports whether values holds s, ignoring case. The elements are
// the runtime's []any form of a string list.
func containsFold(values []any, s string) bool {
	for _, v := range values {
		if str, ok := v.(string); ok && strings.EqualFold(str, s) {
			return true
		}
	}
	return false
}

// fieldSelectorConstrains reports whether a field selector places any condition
// on its field. Every match kind counts: a NotEquals or a prefix match narrows
// the selector just as an Equals does.
func fieldSelectorConstrains(fs *mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector) (bool, error) {
	for _, get := range []func() *plugin.TValue[[]any]{
		fs.GetEquals, fs.GetNotEquals,
		fs.GetStartsWith, fs.GetNotStartsWith,
		fs.GetEndsWith, fs.GetNotEndsWith,
	} {
		values := get()
		if values.Error != nil {
			return false, values.Error
		}
		if len(values.Data) > 0 {
			return true, nil
		}
	}
	return false, nil
}

// advancedSelectorsCaptureAllManagementEvents reports whether a set of advanced
// event selectors logs management events for both reads and writes.
//
// An advanced selector says what it captures through its field selectors rather
// than through a readWriteType enum: it selects management events with
// `eventCategory Equals ["Management"]`, and it captures both directions unless
// it also constrains `readOnly`, which narrows it to one of them.
func advancedSelectorsCaptureAllManagementEvents(selectors []any) (bool, error) {
	for _, raw := range selectors {
		sel, ok := raw.(*mqlAwsCloudtrailTrailAdvancedEventSelector)
		if !ok {
			continue
		}

		fieldSelectors := sel.GetFieldSelectors()
		if fieldSelectors.Error != nil {
			return false, fieldSelectors.Error
		}

		selectsManagement := false
		restrictsReadOnly := false

		for _, rawFs := range fieldSelectors.Data {
			fs, ok := rawFs.(*mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector)
			if !ok {
				continue
			}
			field := fs.GetField()
			if field.Error != nil {
				return false, field.Error
			}

			switch {
			case strings.EqualFold(field.Data, advancedSelectorFieldEventCategory):
				equals := fs.GetEquals()
				if equals.Error != nil {
					return false, equals.Error
				}
				if containsFold(equals.Data, eventCategoryManagement) {
					selectsManagement = true
				}
			case strings.EqualFold(field.Data, advancedSelectorFieldReadOnly):
				constrains, err := fieldSelectorConstrains(fs)
				if err != nil {
					return false, err
				}
				restrictsReadOnly = restrictsReadOnly || constrains
			}
		}

		if selectsManagement && !restrictsReadOnly {
			return true, nil
		}
	}
	return false, nil
}

// capturesAllManagementEvents reports whether the trail logs management events
// for both reads and writes.
//
// A trail configures that through one of two mutually exclusive mechanisms, and
// GetEventSelectors returns whichever one the trail uses. Classic event
// selectors say it with includeManagementEvents plus readWriteType "All";
// advanced event selectors say it with field selectors, and are what
// CloudFormation and Terraform produce. Reading only the classic ones reported
// false for every trail configured the modern way, which is a false positive on
// a compliant trail.
func (a *mqlAwsCloudtrailTrail) capturesAllManagementEvents() (bool, error) {
	entries := a.GetEventSelectorEntries()
	if entries.Error != nil {
		return false, entries.Error
	}
	for _, e := range entries.Data {
		sel, ok := e.(*mqlAwsCloudtrailTrailEventSelector)
		if !ok {
			continue
		}
		mgmt := sel.GetIncludeManagementEvents()
		if mgmt.Error != nil {
			return false, mgmt.Error
		}
		rw := sel.GetReadWriteType()
		if rw.Error != nil {
			return false, rw.Error
		}
		if mgmt.Data && rw.Data == "All" {
			return true, nil
		}
	}

	advanced := a.GetAdvancedEventSelectors()
	if advanced.Error != nil {
		return false, advanced.Error
	}
	return advancedSelectorsCaptureAllManagementEvents(advanced.Data)
}

func (a *mqlAwsCloudtrailTrail) eventSelectorEntries() ([]any, error) {
	resp, err := a.getEventSelectorsData()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i, sel := range resp.EventSelectors {
		// Build data resource sub-resources
		dataResources := []any{}
		for j, dr := range sel.DataResources {
			values := make([]any, len(dr.Values))
			for k, v := range dr.Values {
				values[k] = v
			}
			mqlDr, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.trail.eventSelector.dataResource",
				map[string]*llx.RawData{
					"__id":   llx.StringData(fmt.Sprintf("%s/eventSelector/%d/dataResource/%d", a.Arn.Data, i, j)),
					"type":   llx.StringDataPtr(dr.Type),
					"values": llx.ArrayData(values, mqlTypes.String),
				})
			if err != nil {
				return nil, err
			}
			dataResources = append(dataResources, mqlDr)
		}

		excludeSources := make([]any, len(sel.ExcludeManagementEventSources))
		for j, s := range sel.ExcludeManagementEventSources {
			excludeSources[j] = s
		}

		mqlSel, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.trail.eventSelector",
			map[string]*llx.RawData{
				"__id":                          llx.StringData(fmt.Sprintf("%s/eventSelector/%d", a.Arn.Data, i)),
				"readWriteType":                 llx.StringData(string(sel.ReadWriteType)),
				"includeManagementEvents":       llx.BoolDataPtr(sel.IncludeManagementEvents),
				"dataResources":                 llx.ArrayData(dataResources, mqlTypes.Resource("aws.cloudtrail.trail.eventSelector.dataResource")),
				"excludeManagementEventSources": llx.ArrayData(excludeSources, mqlTypes.String),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSel)
	}
	return res, nil
}

func (a *mqlAwsCloudtrailTrail) advancedEventSelectors() ([]any, error) {
	resp, err := a.getEventSelectorsData()
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i, sel := range resp.AdvancedEventSelectors {
		fieldSelectors := []any{}
		for j, fs := range sel.FieldSelectors {
			toAnySlice := func(s []string) []any {
				r := make([]any, len(s))
				for k, v := range s {
					r[k] = v
				}
				return r
			}
			mqlFs, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.trail.advancedEventSelector.fieldSelector",
				map[string]*llx.RawData{
					"__id":          llx.StringData(fmt.Sprintf("%s/advancedEventSelector/%d/fieldSelector/%d", a.Arn.Data, i, j)),
					"field":         llx.StringDataPtr(fs.Field),
					"equals":        llx.ArrayData(toAnySlice(fs.Equals), mqlTypes.String),
					"startsWith":    llx.ArrayData(toAnySlice(fs.StartsWith), mqlTypes.String),
					"endsWith":      llx.ArrayData(toAnySlice(fs.EndsWith), mqlTypes.String),
					"notEquals":     llx.ArrayData(toAnySlice(fs.NotEquals), mqlTypes.String),
					"notStartsWith": llx.ArrayData(toAnySlice(fs.NotStartsWith), mqlTypes.String),
					"notEndsWith":   llx.ArrayData(toAnySlice(fs.NotEndsWith), mqlTypes.String),
				})
			if err != nil {
				return nil, err
			}
			fieldSelectors = append(fieldSelectors, mqlFs)
		}

		mqlSel, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.trail.advancedEventSelector",
			map[string]*llx.RawData{
				"__id":           llx.StringData(fmt.Sprintf("%s/advancedEventSelector/%d", a.Arn.Data, i)),
				"name":           llx.StringDataPtr(sel.Name),
				"fieldSelectors": llx.ArrayData(fieldSelectors, mqlTypes.Resource("aws.cloudtrail.trail.advancedEventSelector.fieldSelector")),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSel)
	}
	return res, nil
}

func (a *mqlAwsCloudtrailTrail) insightSelectorEntries() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudtrail(a.Region.Data)
	ctx := context.Background()

	arnValue := a.Arn.Data
	resp, err := svc.GetInsightSelectors(ctx, &cloudtrail.GetInsightSelectorsInput{
		TrailName: &arnValue,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		var insightErr *types.InsightNotEnabledException
		if errors.As(err, &insightErr) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for i, sel := range resp.InsightSelectors {
		mqlSel, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.trail.insightSelector",
			map[string]*llx.RawData{
				"__id":        llx.StringData(fmt.Sprintf("%s/insightSelector/%d", a.Arn.Data, i)),
				"insightType": llx.StringData(string(sel.InsightType)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSel)
	}
	return res, nil
}

func (a *mqlAwsCloudtrailTrail) latestDeliveryError() (string, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return "", err
	}
	return convert.ToValue(trailstatus.LatestDeliveryError), nil
}

func (a *mqlAwsCloudtrailTrail) latestDigestDeliveredAt() (*time.Time, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return nil, err
	}
	return trailstatus.LatestDigestDeliveryTime, nil
}

func (a *mqlAwsCloudtrailTrail) latestDeliveredAt() (*time.Time, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return nil, err
	}
	return trailstatus.LatestDeliveryTime, nil
}

func (a *mqlAwsCloudtrailTrail) latestNotifiedAt() (*time.Time, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return nil, err
	}
	return trailstatus.LatestNotificationTime, nil
}

func (a *mqlAwsCloudtrailTrail) startLoggingAt() (*time.Time, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return nil, err
	}
	return trailstatus.StartLoggingTime, nil
}

func (a *mqlAwsCloudtrailTrail) stoppedLoggingAt() (*time.Time, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return nil, err
	}
	return trailstatus.StopLoggingTime, nil
}

func (a *mqlAwsCloudtrailTrail) latestCloudWatchLogsDeliveredAt() (*time.Time, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return nil, err
	}
	return trailstatus.LatestCloudWatchLogsDeliveryTime, nil
}

func (a *mqlAwsCloudtrailTrail) latestDeliveryAttemptedAt() (string, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return "", err
	}
	return convert.ToValue(trailstatus.LatestDeliveryAttemptTime), nil
}

func (a *mqlAwsCloudtrailTrail) latestDeliveryAttemptSucceededAt() (string, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return "", err
	}
	return convert.ToValue(trailstatus.LatestDeliveryAttemptSucceeded), nil
}

func (a *mqlAwsCloudtrailTrail) latestNotificationAttemptedAt() (string, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return "", err
	}
	return convert.ToValue(trailstatus.LatestNotificationAttemptTime), nil
}

func (a *mqlAwsCloudtrailTrail) latestNotificationAttemptSucceededAt() (string, error) {
	trailstatus, err := a.getTrailStatus()
	if err != nil {
		return "", err
	}
	return convert.ToValue(trailstatus.LatestNotificationAttemptSucceeded), nil
}

func (a *mqlAwsCloudtrailTrailEventSelector) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsCloudtrailTrailEventSelectorDataResource) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsCloudtrailTrailAdvancedEventSelector) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsCloudtrailTrailAdvancedEventSelectorFieldSelector) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsCloudtrailTrailInsightSelector) id() (string, error) {
	return a.__id, nil
}

// CloudTrail event data stores
func (a *mqlAwsCloudtrail) eventDataStores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEventDataStores(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudtrail) getEventDataStores(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Cloudtrail(region)
			ctx := context.Background()
			res := []any{}

			paginator := cloudtrail.NewListEventDataStoresPaginator(svc, &cloudtrail.ListEventDataStoresInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for CloudTrail event data stores")
						return res, nil
					}
					return nil, err
				}
				for _, eds := range page.EventDataStores {
					mqlEds, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.eventDataStore",
						map[string]*llx.RawData{
							"__id":   llx.StringData(convert.ToValue(eds.EventDataStoreArn)),
							"arn":    llx.StringDataPtr(eds.EventDataStoreArn),
							"name":   llx.StringDataPtr(eds.Name),
							"status": llx.StringData(string(eds.Status)),
							"region": llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					cast := mqlEds.(*mqlAwsCloudtrailEventDataStore)
					cast.cacheRegion = region
					res = append(res, mqlEds)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsCloudtrailEventDataStoreInternal struct {
	cacheRegion string
	detail      *cloudtrail.GetEventDataStoreOutput
	fetched     bool
	fetchErr    error
	lock        sync.Mutex
}

func (a *mqlAwsCloudtrailEventDataStore) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCloudtrailEventDataStore) fetchDetail() (*cloudtrail.GetEventDataStoreOutput, error) {
	if a.fetched {
		return a.detail, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.detail, a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Cloudtrail(a.cacheRegion)
	arn := a.Arn.Data

	resp, err := svc.GetEventDataStore(ctx, &cloudtrail.GetEventDataStoreInput{
		EventDataStore: &arn,
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	a.detail = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsCloudtrailEventDataStore) multiRegionEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	return convert.ToValue(detail.MultiRegionEnabled), nil
}

func (a *mqlAwsCloudtrailEventDataStore) organizationEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	return convert.ToValue(detail.OrganizationEnabled), nil
}

func (a *mqlAwsCloudtrailEventDataStore) retentionPeriod() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.RetentionPeriod != nil {
		return int64(*detail.RetentionPeriod), nil
	}
	return 0, nil
}

func (a *mqlAwsCloudtrailEventDataStore) terminationProtectionEnabled() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	return convert.ToValue(detail.TerminationProtectionEnabled), nil
}

func (a *mqlAwsCloudtrailEventDataStore) createdAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return detail.CreatedTimestamp, nil
}

func (a *mqlAwsCloudtrailEventDataStore) updatedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return detail.UpdatedTimestamp, nil
}

func (a *mqlAwsCloudtrailEventDataStore) advancedEventSelectors() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	res := []any{}
	for i, aes := range detail.AdvancedEventSelectors {
		fieldSelectors := []any{}
		for j, fs := range aes.FieldSelectors {
			toAny := func(ss []string) []any {
				r := make([]any, len(ss))
				for k, s := range ss {
					r[k] = s
				}
				return r
			}
			mqlFs, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.trail.advancedEventSelector.fieldSelector",
				map[string]*llx.RawData{
					"__id":          llx.StringData(fmt.Sprintf("%s/aes/%d/fs/%d", a.Arn.Data, i, j)),
					"field":         llx.StringDataPtr(fs.Field),
					"equals":        llx.ArrayData(toAny(fs.Equals), mqlTypes.String),
					"startsWith":    llx.ArrayData(toAny(fs.StartsWith), mqlTypes.String),
					"endsWith":      llx.ArrayData(toAny(fs.EndsWith), mqlTypes.String),
					"notEquals":     llx.ArrayData(toAny(fs.NotEquals), mqlTypes.String),
					"notStartsWith": llx.ArrayData(toAny(fs.NotStartsWith), mqlTypes.String),
					"notEndsWith":   llx.ArrayData(toAny(fs.NotEndsWith), mqlTypes.String),
				})
			if err != nil {
				return nil, err
			}
			fieldSelectors = append(fieldSelectors, mqlFs)
		}
		mqlAes, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.trail.advancedEventSelector",
			map[string]*llx.RawData{
				"__id":           llx.StringData(fmt.Sprintf("%s/aes/%d", a.Arn.Data, i)),
				"name":           llx.StringDataPtr(aes.Name),
				"fieldSelectors": llx.ArrayData(fieldSelectors, mqlTypes.Resource("aws.cloudtrail.trail.advancedEventSelector.fieldSelector")),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAes)
	}
	return res, nil
}

func (a *mqlAwsCloudtrailEventDataStore) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail.KmsKeyId == nil || *detail.KmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.KmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsCloudtrailEventDataStore) billingMode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(detail.BillingMode), nil
}

func (a *mqlAwsCloudtrailEventDataStore) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudtrail(a.cacheRegion)
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.ListTags(ctx, &cloudtrail.ListTagsInput{
		ResourceIdList: []string{arn},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}

	tags := map[string]any{}
	for _, tagList := range resp.ResourceTagList {
		for _, tag := range tagList.TagsList {
			tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
		}
	}
	return tags, nil
}

func (a *mqlAwsCloudtrailEventDataStore) federationStatus() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(detail.FederationStatus), nil
}

func (a *mqlAwsCloudtrailEventDataStore) federationRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail.FederationRoleArn == nil || *detail.FederationRoleArn == "" {
		a.FederationRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, ResourceAwsIamRole,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(detail.FederationRoleArn),
		})
	if err != nil {
		if !referencedResourceUnavailable(err) {
			return nil, err
		}
		log.Warn().Err(err).Str("role", convert.ToValue(detail.FederationRoleArn)).
			Msg("cannot resolve the event data store's federation role")
		a.FederationRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

// CloudTrail channels
func (a *mqlAwsCloudtrail) channels() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getChannels(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsCloudtrail) getChannels(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Cloudtrail(region)
			ctx := context.Background()
			res := []any{}

			paginator := cloudtrail.NewListChannelsPaginator(svc, &cloudtrail.ListChannelsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for CloudTrail channels")
						return res, nil
					}
					return nil, err
				}
				for _, ch := range page.Channels {
					mqlCh, err := CreateResource(a.MqlRuntime, "aws.cloudtrail.channel",
						map[string]*llx.RawData{
							"__id":   llx.StringData(convert.ToValue(ch.ChannelArn)),
							"arn":    llx.StringDataPtr(ch.ChannelArn),
							"name":   llx.StringDataPtr(ch.Name),
							"region": llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					cast := mqlCh.(*mqlAwsCloudtrailChannel)
					cast.cacheRegion = region
					res = append(res, mqlCh)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsCloudtrailChannelInternal struct {
	cacheRegion string
	detail      *cloudtrail.GetChannelOutput
	fetched     bool
	fetchErr    error
	lock        sync.Mutex
}

func (a *mqlAwsCloudtrailChannel) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsCloudtrailChannel) fetchDetail() (*cloudtrail.GetChannelOutput, error) {
	if a.fetched {
		return a.detail, a.fetchErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.detail, a.fetchErr
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	ctx := context.Background()
	svc := conn.Cloudtrail(a.cacheRegion)
	arn := a.Arn.Data

	resp, err := svc.GetChannel(ctx, &cloudtrail.GetChannelInput{
		Channel: &arn,
	})
	if err != nil {
		a.fetchErr = err
		a.fetched = true
		return nil, err
	}
	a.detail = resp
	a.fetched = true
	return resp, nil
}

func (a *mqlAwsCloudtrailChannel) sourceType() (string, error) {
	// The CloudTrail API has no explicit SourceType field.
	// Service-linked channels (created by AWS services) use the naming convention
	// "aws-service-channel/<service>/<suffix>".
	name := a.Name.Data
	if strings.HasPrefix(name, "aws-service-channel/") {
		return "AWS_SERVICE", nil
	}
	return "CUSTOM", nil
}

func (a *mqlAwsCloudtrailChannel) source() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.Source), nil
}

func (a *mqlAwsCloudtrailChannel) destinations() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	dests, err := convert.JsonToDictSlice(detail.Destinations)
	if err != nil {
		return nil, err
	}
	return dests, nil
}

func (a *mqlAwsCloudtrailChannel) ingestionStatus() (map[string]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDict(detail.IngestionStatus)
}

func (a *mqlAwsCloudtrailChannel) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Cloudtrail(a.cacheRegion)
	ctx := context.Background()
	arn := a.Arn.Data

	resp, err := svc.ListTags(ctx, &cloudtrail.ListTagsInput{
		ResourceIdList: []string{arn},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}

	tags := map[string]any{}
	for _, tagList := range resp.ResourceTagList {
		for _, tag := range tagList.TagsList {
			tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
		}
	}
	return tags, nil
}
