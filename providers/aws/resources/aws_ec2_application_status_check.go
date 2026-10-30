// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	mqltypes "go.mondoo.com/mql/types"
)

func (a *mqlAwsEc2ApplicationStatusCheck) id() (string, error) {
	return "aws.ec2.applicationStatusCheck/" + a.Region.Data + "/" + a.Id.Data, nil
}

func (a *mqlAwsEc2) applicationStatusChecks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getApplicationStatusChecks(conn), 5)
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

func (a *mqlAwsEc2) getApplicationStatusChecks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ec2>getApplicationStatusChecks>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			// The service ships no paginator for this operation, so the token
			// loop is manual. IncludeAll adds the checks that have been deleted
			// and are still inside their post-deletion grace period; they are
			// reported with deleted set, so a caller can tell them from the
			// checks currently guarding an application.
			var nextToken *string
			for {
				resp, err := svc.DescribeApplicationStatusChecks(ctx, &ec2.DescribeApplicationStatusChecksInput{
					IncludeAll: aws.Bool(true),
					NextToken:  nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS API")
						return jobpool.JobResult(res), nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("application status checks not available in region")
						return jobpool.JobResult(res), nil
					}
					return nil, err
				}

				for _, check := range resp.ApplicationStatusChecks {
					mqlCheck, err := newMqlAwsEc2ApplicationStatusCheck(a.MqlRuntime, region, check)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCheck)
				}

				if resp.NextToken == nil || *resp.NextToken == "" {
					break
				}
				nextToken = resp.NextToken
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsEc2ApplicationStatusCheck(runtime *plugin.Runtime, region string, check types.ApplicationStatusCheckResponseObject) (plugin.Resource, error) {
	healthCheckPaths := []any{}
	for _, hcp := range check.HealthCheckPaths {
		d, err := convert.JsonToDict(hcp)
		if err != nil {
			log.Warn().Err(err).Msg("failed to convert application status check health check path")
			continue
		}
		healthCheckPaths = append(healthCheckPaths, d)
	}

	targetTags := map[string]any{}
	for _, t := range check.TargetTagAssociations {
		if t.Key != nil {
			targetTags[*t.Key] = convert.ToValue(t.Value)
		}
	}

	checkId := convert.ToValue(check.ApplicationStatusCheckId)
	mqlCheck, err := CreateResource(runtime, "aws.ec2.applicationStatusCheck",
		map[string]*llx.RawData{
			"__id":                             llx.StringData("aws.ec2.applicationStatusCheck/" + region + "/" + checkId),
			"id":                               llx.StringData(checkId),
			"region":                           llx.StringData(region),
			"protocol":                         llx.StringData(string(check.Protocol)),
			"port":                             llx.IntDataDefault(check.Port, 0),
			"path":                             llx.StringDataPtr(check.Path),
			"healthCheckPaths":                 llx.ArrayData(healthCheckPaths, mqltypes.Dict),
			"statusCodeMatcher":                llx.StringDataPtr(check.StatusCodeMatcher),
			"interval":                         llx.IntDataDefault(check.Interval, 0),
			"timeout":                          llx.IntDataDefault(check.Timeout, 0),
			"successThreshold":                 llx.IntDataDefault(check.SuccessThreshold, 0),
			"failureThreshold":                 llx.IntDataDefault(check.FailureThreshold, 0),
			"initializationGracePeriodSeconds": llx.IntDataDefault(check.InitializationGracePeriodSeconds, 0),
			"aggregation":                      llx.StringData(string(check.Aggregation)),
			"deviceIndex":                      llx.IntDataDefault(check.DeviceIndex, 0),
			"ipScope":                          llx.StringData(string(check.IpScope)),
			"ipVersion":                        llx.StringData(string(check.IpVersion)),
			"targetTags":                       llx.MapData(targetTags, mqltypes.String),
			"createdAt":                        llx.TimeDataPtr(check.CreationTime),
			"lastUpdatedAt":                    llx.TimeDataPtr(check.LastUpdatedAt),
			"deletedAt":                        llx.TimeDataPtr(check.DeletionTime),
			"deleted":                          llx.BoolData(check.DeletionTime != nil),
			"tags":                             llx.MapData(toInterfaceMap(ec2TagsToMap(check.Tags)), mqltypes.String),
		})
	if err != nil {
		return nil, err
	}
	return mqlCheck, nil
}

type mqlAwsEc2ApplicationStatusCheckInternal struct {
	cachedStatusesFetched bool
	cachedStatuses        []any
	statusesLock          sync.Mutex
}

// statuses reports the current per-instance result of this check. The service
// returns every instance's application status in one call rather than per
// check, so the response is filtered down to the details carrying this check's
// id.
func (a *mqlAwsEc2ApplicationStatusCheck) statuses() ([]any, error) {
	a.statusesLock.Lock()
	defer a.statusesLock.Unlock()
	if a.cachedStatusesFetched {
		return a.cachedStatuses, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	res := []any{}

	var nextToken *string
	for {
		resp, err := svc.DescribeApplicationStatus(ctx, &ec2.DescribeApplicationStatusInput{
			NextToken: nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.cachedStatusesFetched = true
				a.cachedStatuses = res
				return res, nil
			}
			return nil, err
		}
		// a page can carry no statuses and still continue, so only the token
		// decides whether there is more to read
		if resp.ApplicationStatuses != nil {
			for _, inst := range resp.ApplicationStatuses.Instances {
				if inst.ApplicationStatus == nil {
					continue
				}
				overall := string(inst.ApplicationStatus.Status)
				for _, detail := range inst.ApplicationStatus.Details {
					if convert.ToValue(detail.ApplicationStatusCheckId) != a.Id.Data {
						continue
					}
					mqlStatus, err := a.newStatus(inst, detail, overall)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlStatus)
				}
			}
		}

		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}

	a.cachedStatusesFetched = true
	a.cachedStatuses = res
	return res, nil
}

func (a *mqlAwsEc2ApplicationStatusCheck) newStatus(inst types.InstanceApplicationStatus, detail types.ApplicationStatusDetail, overall string) (plugin.Resource, error) {
	instanceId := convert.ToValue(inst.InstanceId)

	var reasonCode, reasonProtocol string
	var reasonStatusCode int64
	if detail.Reason != nil {
		reasonCode = convert.ToValue(detail.Reason.Code)
		reasonProtocol = convert.ToValue(detail.Reason.Protocol)
		if detail.Reason.StatusCode != nil {
			reasonStatusCode = int64(*detail.Reason.StatusCode)
		}
	}

	mqlStatus, err := CreateResource(a.MqlRuntime, "aws.ec2.applicationStatusCheck.status",
		map[string]*llx.RawData{
			"__id":              llx.StringData("aws.ec2.applicationStatusCheck.status/" + a.Region.Data + "/" + a.Id.Data + "/" + instanceId),
			"status":            llx.StringData(string(detail.Status)),
			"applicationStatus": llx.StringData(overall),
			"aggregation":       llx.StringData(string(detail.Aggregation)),
			"reasonCode":        llx.StringData(reasonCode),
			"reasonProtocol":    llx.StringData(reasonProtocol),
			"reasonStatusCode":  llx.IntData(reasonStatusCode),
			"statusSince":       llx.TimeDataPtr(detail.StatusSince),
			"statusTimestamp":   llx.TimeDataPtr(detail.StatusTimeStamp),
			"checkUpdateTime":   llx.TimeDataPtr(detail.CheckUpdateTime),
		})
	if err != nil {
		return nil, err
	}
	mqlStatus.(*mqlAwsEc2ApplicationStatusCheckStatus).cacheInstanceId = instanceId
	mqlStatus.(*mqlAwsEc2ApplicationStatusCheckStatus).cacheRegion = a.Region.Data
	return mqlStatus, nil
}

type mqlAwsEc2ApplicationStatusCheckStatusInternal struct {
	cacheInstanceId string
	cacheRegion     string
}

func (a *mqlAwsEc2ApplicationStatusCheckStatus) instance() (*mqlAwsEc2Instance, error) {
	if a.cacheInstanceId == "" {
		a.Instance.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// initAwsEc2Instance resolves by arn only, so build it from the instance id
	// rather than passing the id through.
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	instanceArn := fmt.Sprintf(ec2InstanceArnPattern, a.cacheRegion, conn.AccountId(), a.cacheInstanceId)
	mqlInstance, err := NewResource(a.MqlRuntime, "aws.ec2.instance",
		map[string]*llx.RawData{"arn": llx.StringData(instanceArn)})
	if err != nil {
		return nil, err
	}
	return mqlInstance.(*mqlAwsEc2Instance), nil
}
