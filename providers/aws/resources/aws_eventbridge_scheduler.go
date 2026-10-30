// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/scheduler"
	scheduler_types "github.com/aws/aws-sdk-go-v2/service/scheduler/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsEventbridge) schedules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSchedules(conn), 5)
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

func (a *mqlAwsEventbridge) getSchedules(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("eventbridge>getSchedules>calling aws with region %s", region)

			svc := conn.Scheduler(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListSchedules(ctx, &scheduler.ListSchedulesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("scheduler not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, sched := range resp.Schedules {
					mqlSched, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule",
						map[string]*llx.RawData{
							"__id":      llx.StringDataPtr(sched.Arn),
							"arn":       llx.StringDataPtr(sched.Arn),
							"name":      llx.StringDataPtr(sched.Name),
							"region":    llx.StringData(region),
							"groupName": llx.StringDataPtr(sched.GroupName),
							"state":     llx.StringData(string(sched.State)),
							"createdAt": llx.TimeDataPtr(sched.CreationDate),
							"updatedAt": llx.TimeDataPtr(sched.LastModificationDate),
						})
					if err != nil {
						return nil, err
					}
					mqlSchedRes := mqlSched.(*mqlAwsEventbridgeSchedule)
					mqlSchedRes.cacheName = sched.Name
					mqlSchedRes.cacheGroupName = sched.GroupName
					mqlSchedRes.cacheRegion = region
					res = append(res, mqlSchedRes)
				}

				if resp.NextToken == nil {
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

type mqlAwsEventbridgeScheduleInternal struct {
	cacheName      *string
	cacheGroupName *string
	cacheRegion    string
	cacheRoleArn   *string
	cacheKmsKeyArn *string
	cacheDescribe  *scheduler.GetScheduleOutput
	cacheDLQArn    *string
	fetched        bool
	lock           sync.Mutex
	tagsOnce       sync.Once
	tagsResp       map[string]any
	tagsErr        error
}

func (a *mqlAwsEventbridgeSchedule) fetchDetails() error {
	if a.fetched {
		return nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return nil
	}

	if a.cacheName == nil {
		a.fetched = true
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Scheduler(a.cacheRegion)
	ctx := context.Background()

	input := &scheduler.GetScheduleInput{
		Name: a.cacheName,
	}
	if a.cacheGroupName != nil {
		input.GroupName = a.cacheGroupName
	}

	resp, err := svc.GetSchedule(ctx, input)
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("schedule", *a.cacheName).Msg("access denied getting schedule details")
			a.fetched = true
			return nil
		}
		return err
	}

	if resp.ScheduleExpression != nil {
		a.ScheduleExpression = plugin.TValue[string]{Data: *resp.ScheduleExpression, State: plugin.StateIsSet}
	} else {
		a.ScheduleExpression = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
	}
	if resp.Description != nil {
		a.Description = plugin.TValue[string]{Data: *resp.Description, State: plugin.StateIsSet}
	} else {
		a.Description = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
	}
	if resp.Target != nil {
		if resp.Target.Arn != nil {
			a.TargetArn = plugin.TValue[string]{Data: *resp.Target.Arn, State: plugin.StateIsSet}
		} else {
			a.TargetArn = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
		}
		a.cacheRoleArn = resp.Target.RoleArn
		if resp.Target.DeadLetterConfig != nil {
			a.cacheDLQArn = resp.Target.DeadLetterConfig.Arn
		}
	} else {
		a.TargetArn = plugin.TValue[string]{Data: "", State: plugin.StateIsSet}
	}
	a.cacheKmsKeyArn = resp.KmsKeyArn
	a.cacheDescribe = resp

	a.fetched = true
	return nil
}

func (a *mqlAwsEventbridgeSchedule) scheduleExpressionTimezone() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.ScheduleExpressionTimezone == nil {
		a.ScheduleExpressionTimezone.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *a.cacheDescribe.ScheduleExpressionTimezone, nil
}

func (a *mqlAwsEventbridgeSchedule) startDate() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.StartDate == nil {
		a.StartDate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.cacheDescribe.StartDate, nil
}

func (a *mqlAwsEventbridgeSchedule) endDate() (*time.Time, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.EndDate == nil {
		a.EndDate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.cacheDescribe.EndDate, nil
}

func (a *mqlAwsEventbridgeSchedule) actionAfterCompletion() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	if a.cacheDescribe == nil {
		a.ActionAfterCompletion.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return string(a.cacheDescribe.ActionAfterCompletion), nil
}

func (a *mqlAwsEventbridgeSchedule) group() (*mqlAwsEventbridgeScheduleGroup, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheGroupName == nil || *a.cacheGroupName == "" {
		a.Group.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// Look up via the parent eventbridge resource's scheduleGroups list (already cached).
	parent, err := CreateResource(a.MqlRuntime, "aws.eventbridge", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	groups := parent.(*mqlAwsEventbridge).GetScheduleGroups()
	if groups.Error != nil {
		return nil, groups.Error
	}
	for _, raw := range groups.Data {
		g := raw.(*mqlAwsEventbridgeScheduleGroup)
		if g.Name.Data == *a.cacheGroupName && g.Region.Data == a.cacheRegion {
			return g, nil
		}
	}
	a.Group.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsEventbridgeSchedule) deadLetterQueue() (*mqlAwsSqsQueue, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDLQArn == nil || *a.cacheDLQArn == "" {
		a.DeadLetterQueue.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sqs.queue", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheDLQArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSqsQueue), nil
}

func (a *mqlAwsEventbridgeSchedule) retryPolicy() (*mqlAwsEventbridgeScheduleRetryPolicy, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.Target == nil || a.cacheDescribe.Target.RetryPolicy == nil {
		a.RetryPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	rp := a.cacheDescribe.Target.RetryPolicy
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.retryPolicy", map[string]*llx.RawData{
		"__id":                     llx.StringData(a.Arn.Data + "/retryPolicy"),
		"maximumEventAgeInSeconds": llx.IntDataDefault(rp.MaximumEventAgeInSeconds, 0),
		"maximumRetryAttempts":     llx.IntDataDefault(rp.MaximumRetryAttempts, 0),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgeScheduleRetryPolicy), nil
}

func (a *mqlAwsEventbridgeSchedule) flexibleTimeWindow() (*mqlAwsEventbridgeScheduleFlexibleTimeWindow, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.FlexibleTimeWindow == nil {
		a.FlexibleTimeWindow.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	ftw := a.cacheDescribe.FlexibleTimeWindow
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.flexibleTimeWindow", map[string]*llx.RawData{
		"__id":                   llx.StringData(a.Arn.Data + "/flexibleTimeWindow"),
		"mode":                   llx.StringData(string(ftw.Mode)),
		"maximumWindowInMinutes": llx.IntDataDefault(ftw.MaximumWindowInMinutes, 0),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgeScheduleFlexibleTimeWindow), nil
}

func (a *mqlAwsEventbridgeSchedule) target() (*mqlAwsEventbridgeScheduleTarget, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheDescribe == nil || a.cacheDescribe.Target == nil {
		a.Target.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	t := a.cacheDescribe.Target
	roleArn := ""
	if t.RoleArn != nil {
		roleArn = *t.RoleArn
	}
	input := ""
	if t.Input != nil {
		input = *t.Input
	}
	tgtArn := ""
	if t.Arn != nil {
		tgtArn = *t.Arn
	}
	tgtType := scheduleTargetType(tgtArn, t)
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.target", map[string]*llx.RawData{
		"__id":       llx.StringData(a.Arn.Data + "/target"),
		"arn":        llx.StringData(tgtArn),
		"input":      llx.StringData(input),
		"targetType": llx.StringData(tgtType),
	})
	if err != nil {
		return nil, err
	}
	res.(*mqlAwsEventbridgeScheduleTarget).cacheRoleArn = roleArn
	mqlTgt := res.(*mqlAwsEventbridgeScheduleTarget)
	mqlTgt.cacheScheduleArn = a.Arn.Data
	mqlTgt.cacheRegion = a.cacheRegion
	mqlTgt.cacheTarget = t
	return mqlTgt, nil
}

// scheduleTargetType discriminates the target type for audit queries. Order
// matters: more specific ARN prefixes (universal target) first.
func scheduleTargetType(arnVal string, t *scheduler_types.Target) string {
	switch {
	case strings.HasPrefix(arnVal, "arn:aws:scheduler:::aws-sdk:"):
		return "universal"
	case strings.HasPrefix(arnVal, "arn:aws:lambda:"):
		return "lambda"
	case strings.HasPrefix(arnVal, "arn:aws:sqs:"):
		return "sqs"
	case strings.HasPrefix(arnVal, "arn:aws:sns:"):
		return "sns"
	case strings.HasPrefix(arnVal, "arn:aws:states:"):
		return "stepFunction"
	case strings.HasPrefix(arnVal, "arn:aws:kinesis:"):
		return "kinesis"
	case strings.HasPrefix(arnVal, "arn:aws:firehose:"):
		return "firehose"
	case strings.HasPrefix(arnVal, "arn:aws:ecs:"):
		return "ecs"
	case strings.HasPrefix(arnVal, "arn:aws:events:"):
		return "eventBridge"
	case strings.HasPrefix(arnVal, "arn:aws:sagemaker:") && strings.Contains(arnVal, ":pipeline/"):
		return "sagemakerPipeline"
	case strings.HasPrefix(arnVal, "arn:aws:codebuild:"):
		return "codebuild"
	}
	if t != nil {
		if t.EcsParameters != nil {
			return "ecs"
		}
		if t.EventBridgeParameters != nil {
			return "eventBridge"
		}
		if t.KinesisParameters != nil {
			return "kinesis"
		}
		if t.SageMakerPipelineParameters != nil {
			return "sagemakerPipeline"
		}
		if t.SqsParameters != nil {
			return "sqs"
		}
	}
	return "unknown"
}

func (a *mqlAwsEventbridgeSchedule) tags() (map[string]any, error) {
	a.tagsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Scheduler(a.cacheRegion)
		ctx := context.Background()
		arnVal := a.Arn.Data
		resp, err := svc.ListTagsForResource(ctx, &scheduler.ListTagsForResourceInput{
			ResourceArn: &arnVal,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.tagsResp = map[string]any{}
				return
			}
			a.tagsErr = err
			return
		}
		out := map[string]any{}
		for _, t := range resp.Tags {
			if t.Key != nil && t.Value != nil {
				out[*t.Key] = *t.Value
			}
		}
		a.tagsResp = out
	})
	return a.tagsResp, a.tagsErr
}

// ---------- target sub-resource accessors ----------

type mqlAwsEventbridgeScheduleTargetInternal struct {
	cacheRoleArn     string
	cacheScheduleArn string
	cacheRegion      string
	cacheTarget      *scheduler_types.Target
}

func (a *mqlAwsEventbridgeScheduleTarget) ecsParameters() (*mqlAwsEventbridgeScheduleTargetEcsParameters, error) {
	if a.cacheTarget == nil || a.cacheTarget.EcsParameters == nil {
		a.EcsParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTarget.EcsParameters
	cps, _ := convert.JsonToDictSlice(p.CapacityProviderStrategy)
	pc, _ := convert.JsonToDictSlice(p.PlacementConstraints)
	ps, _ := convert.JsonToDictSlice(p.PlacementStrategy)

	subnetIds := []any{}
	sgIds := []any{}
	assignPublicIp := ""
	if p.NetworkConfiguration != nil && p.NetworkConfiguration.AwsvpcConfiguration != nil {
		assignPublicIp = string(p.NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp)
		for _, s := range p.NetworkConfiguration.AwsvpcConfiguration.Subnets {
			subnetIds = append(subnetIds, s)
		}
		for _, sg := range p.NetworkConfiguration.AwsvpcConfiguration.SecurityGroups {
			sgIds = append(sgIds, sg)
		}
	}
	// p.Tags is []map[string]string. The Scheduler SDK returns one key per
	// inner map, so a flat merge is safe; if AWS ever changes that contract,
	// later entries will overwrite earlier ones with the same key.
	tags := map[string]any{}
	for _, m := range p.Tags {
		for k, v := range m {
			tags[k] = v
		}
	}

	taskCount := int64(0)
	if p.TaskCount != nil {
		taskCount = int64(*p.TaskCount)
	}

	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.target.ecsParameters", map[string]*llx.RawData{
		"__id":                     llx.StringData(a.cacheScheduleArn + "/target/ecsParameters"),
		"taskDefinitionArn":        llx.StringDataPtr(p.TaskDefinitionArn),
		"taskCount":                llx.IntData(taskCount),
		"launchType":               llx.StringData(string(p.LaunchType)),
		"enableExecuteCommand":     llx.BoolDataPtr(p.EnableExecuteCommand),
		"enableEcsManagedTags":     llx.BoolDataPtr(p.EnableECSManagedTags),
		"group":                    llx.StringDataPtr(p.Group),
		"platformVersion":          llx.StringDataPtr(p.PlatformVersion),
		"propagateTags":            llx.StringData(string(p.PropagateTags)),
		"referenceId":              llx.StringDataPtr(p.ReferenceId),
		"assignPublicIp":           llx.StringData(assignPublicIp),
		"capacityProviderStrategy": llx.ArrayData(cps, types.Dict),
		"placementConstraints":     llx.ArrayData(pc, types.Dict),
		"placementStrategy":        llx.ArrayData(ps, types.Dict),
		"tags":                     llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgeScheduleTargetEcsParameters)
	if p.TaskDefinitionArn != nil {
		mqlRes.cacheTaskDefArn = *p.TaskDefinitionArn
	}
	mqlRes.cacheRegion = a.cacheRegion
	for _, v := range subnetIds {
		mqlRes.cacheSubnetIds = append(mqlRes.cacheSubnetIds, v.(string))
	}
	for _, v := range sgIds {
		mqlRes.cacheSGIds = append(mqlRes.cacheSGIds, v.(string))
	}
	return mqlRes, nil
}

type mqlAwsEventbridgeScheduleTargetEcsParametersInternal struct {
	cacheRegion     string
	cacheTaskDefArn string
	cacheSubnetIds  []string
	cacheSGIds      []string
}

// Assumes the ECS task runs in the same region as the schedule. Cross-region
// targets are unsupported by Scheduler today; if AWS ever allows them, this
// will need to dispatch on per-target region instead of cacheRegion.
const scheduleSubnetArnFmt = "arn:aws:ec2:%s:%s:subnet/%s"

func (a *mqlAwsEventbridgeScheduleTargetEcsParameters) taskDefinition() (*mqlAwsEcsTaskDefinition, error) {
	if a.cacheTaskDefArn == "" {
		a.TaskDefinition.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.taskDefinition", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheTaskDefArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsTaskDefinition), nil
}

func (a *mqlAwsEventbridgeScheduleTargetEcsParameters) subnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, id := range a.cacheSubnetIds {
		ref, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(scheduleSubnetArnFmt, a.cacheRegion, conn.AccountId(), id)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsEventbridgeScheduleTargetEcsParameters) securityGroups() ([]any, error) {
	if len(a.cacheSGIds) == 0 {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, id := range a.cacheSGIds {
		ref, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup", map[string]*llx.RawData{
			"arn": llx.StringData(NewSecurityGroupArn(a.cacheRegion, conn.AccountId(), id)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, ref)
	}
	return res, nil
}

func (a *mqlAwsEventbridgeScheduleTarget) eventBridgeParameters() (*mqlAwsEventbridgeScheduleTargetEventBridgeParameters, error) {
	if a.cacheTarget == nil || a.cacheTarget.EventBridgeParameters == nil {
		a.EventBridgeParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTarget.EventBridgeParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.target.eventBridgeParameters", map[string]*llx.RawData{
		"__id":       llx.StringData(a.cacheScheduleArn + "/target/eventBridgeParameters"),
		"detailType": llx.StringDataPtr(p.DetailType),
		"source":     llx.StringDataPtr(p.Source),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgeScheduleTargetEventBridgeParameters), nil
}

func (a *mqlAwsEventbridgeScheduleTarget) kinesisParameters() (*mqlAwsEventbridgeScheduleTargetKinesisParameters, error) {
	if a.cacheTarget == nil || a.cacheTarget.KinesisParameters == nil {
		a.KinesisParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTarget.KinesisParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.target.kinesisParameters", map[string]*llx.RawData{
		"__id":         llx.StringData(a.cacheScheduleArn + "/target/kinesisParameters"),
		"partitionKey": llx.StringDataPtr(p.PartitionKey),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgeScheduleTargetKinesisParameters), nil
}

func (a *mqlAwsEventbridgeScheduleTarget) sagemakerParameters() (*mqlAwsEventbridgeScheduleTargetSagemakerParameters, error) {
	if a.cacheTarget == nil || a.cacheTarget.SageMakerPipelineParameters == nil {
		a.SagemakerParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTarget.SageMakerPipelineParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.target.sagemakerParameters", map[string]*llx.RawData{
		"__id": llx.StringData(a.cacheScheduleArn + "/target/sagemakerParameters"),
	})
	if err != nil {
		return nil, err
	}
	mqlRes := res.(*mqlAwsEventbridgeScheduleTargetSagemakerParameters)
	mqlRes.cacheScheduleArn = a.cacheScheduleArn
	mqlRes.cacheParams = p.PipelineParameterList
	return mqlRes, nil
}

type mqlAwsEventbridgeScheduleTargetSagemakerParametersInternal struct {
	cacheScheduleArn string
	cacheParams      []scheduler_types.SageMakerPipelineParameter
}

func (a *mqlAwsEventbridgeScheduleTargetSagemakerParameters) pipelineParameters() (map[string]any, error) {
	out := map[string]any{}
	for _, p := range a.cacheParams {
		if p.Name == nil {
			continue
		}
		val := ""
		if p.Value != nil {
			val = *p.Value
		}
		out[*p.Name] = val
	}
	return out, nil
}

func (a *mqlAwsEventbridgeScheduleTarget) sqsParameters() (*mqlAwsEventbridgeScheduleTargetSqsParameters, error) {
	if a.cacheTarget == nil || a.cacheTarget.SqsParameters == nil {
		a.SqsParameters.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	p := a.cacheTarget.SqsParameters
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.target.sqsParameters", map[string]*llx.RawData{
		"__id":           llx.StringData(a.cacheScheduleArn + "/target/sqsParameters"),
		"messageGroupId": llx.StringDataPtr(p.MessageGroupId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgeScheduleTargetSqsParameters), nil
}

func (a *mqlAwsEventbridgeScheduleTarget) universalTarget() (*mqlAwsEventbridgeScheduleTargetUniversalTarget, error) {
	if a.cacheTarget == nil || a.cacheTarget.Arn == nil {
		a.UniversalTarget.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	arnVal := *a.cacheTarget.Arn
	if !strings.HasPrefix(arnVal, "arn:aws:scheduler:::aws-sdk:") {
		a.UniversalTarget.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	service, action := parseUniversalTargetArn(arnVal)
	res, err := CreateResource(a.MqlRuntime, "aws.eventbridge.schedule.target.universalTarget", map[string]*llx.RawData{
		"__id":    llx.StringData(a.cacheScheduleArn + "/target/universalTarget"),
		"service": llx.StringData(service),
		"action":  llx.StringData(action),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEventbridgeScheduleTargetUniversalTarget), nil
}

// parseUniversalTargetArn extracts (service, action) from
// arn:aws:scheduler:::aws-sdk:<service>:<action>. On malformed input both
// return values are empty strings — caller can detect and report.
func parseUniversalTargetArn(arnVal string) (service, action string) {
	const prefix = "arn:aws:scheduler:::aws-sdk:"
	if !strings.HasPrefix(arnVal, prefix) {
		return "", ""
	}
	rest := strings.TrimPrefix(arnVal, prefix)
	idx := strings.Index(rest, ":")
	if idx <= 0 || idx == len(rest)-1 {
		return "", ""
	}
	return rest[:idx], rest[idx+1:]
}

// ---------- scheduleGroup accessors ----------

type mqlAwsEventbridgeScheduleGroupInternal struct {
	tagsOnce sync.Once
	tagsResp map[string]any
	tagsErr  error
}

func (a *mqlAwsEventbridgeScheduleGroup) tags() (map[string]any, error) {
	a.tagsOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Scheduler(a.Region.Data)
		ctx := context.Background()
		arnVal := a.Arn.Data
		resp, err := svc.ListTagsForResource(ctx, &scheduler.ListTagsForResourceInput{
			ResourceArn: &arnVal,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				a.tagsResp = map[string]any{}
				return
			}
			a.tagsErr = err
			return
		}
		out := map[string]any{}
		for _, t := range resp.Tags {
			if t.Key != nil && t.Value != nil {
				out[*t.Key] = *t.Value
			}
		}
		a.tagsResp = out
	})
	return a.tagsResp, a.tagsErr
}

// schedules is a backref filtered over the top-level eventbridge.schedules list
// — no extra API calls beyond what schedules() already issues.
func (a *mqlAwsEventbridgeScheduleGroup) schedules() ([]any, error) {
	parent, err := CreateResource(a.MqlRuntime, "aws.eventbridge", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	all := parent.(*mqlAwsEventbridge).GetSchedules()
	if all.Error != nil {
		return nil, all.Error
	}
	res := []any{}
	for _, raw := range all.Data {
		s := raw.(*mqlAwsEventbridgeSchedule)
		if s.GroupName.Data == a.Name.Data && s.Region.Data == a.Region.Data {
			res = append(res, s)
		}
	}
	return res, nil
}

func (a *mqlAwsEventbridgeSchedule) scheduleExpression() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsEventbridgeSchedule) description() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsEventbridgeSchedule) targetArn() (string, error) {
	return "", a.fetchDetails()
}

func (a *mqlAwsEventbridgeSchedule) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEventbridgeScheduleTarget) iamRole() (*mqlAwsIamRole, error) {
	roleArn := a.cacheRoleArn
	if roleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(roleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsEventbridgeSchedule) kmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheKmsKeyArn == nil || *a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEventbridge) scheduleGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getScheduleGroups(conn), 5)
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

func (a *mqlAwsEventbridge) getScheduleGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("eventbridge>getScheduleGroups>calling aws with region %s", region)

			svc := conn.Scheduler(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListScheduleGroups(ctx, &scheduler.ListScheduleGroupsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("scheduler not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, sg := range resp.ScheduleGroups {
					mqlSg, err := CreateResource(a.MqlRuntime, "aws.eventbridge.scheduleGroup",
						map[string]*llx.RawData{
							"__id":      llx.StringDataPtr(sg.Arn),
							"arn":       llx.StringDataPtr(sg.Arn),
							"name":      llx.StringDataPtr(sg.Name),
							"region":    llx.StringData(region),
							"state":     llx.StringData(string(sg.State)),
							"createdAt": llx.TimeDataPtr(sg.CreationDate),
							"updatedAt": llx.TimeDataPtr(sg.LastModificationDate),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSg)
				}

				if resp.NextToken == nil {
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
