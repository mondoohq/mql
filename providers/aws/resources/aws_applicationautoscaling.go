// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/applicationautoscaling"
	aatypes "github.com/aws/aws-sdk-go-v2/service/applicationautoscaling/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsApplicationAutoscaling) id() (string, error) {
	return "aws.applicationAutoscaling." + a.Namespace.Data, nil
}

// scalableTargetArn returns the ARN that identifies a scalable target.
//
// Application Auto Scaling reports one, and it is what should be used. The
// fallback matters for the identity as much as for the value: a scalable target
// is keyed by its resource AND its dimension, so a DynamoDB table with both
// read and write autoscaling has two targets sharing one resourceId. The
// previous ARN was assembled without the dimension, so the two collapsed onto
// one cache row - the read target was reported twice and the write target's
// policies were never reachable.
func scalableTargetArn(target aatypes.ScalableTarget, region, accountID string) string {
	if arn := convert.ToValue(target.ScalableTargetARN); arn != "" {
		return arn
	}
	return fmt.Sprintf("arn:aws:application-autoscaling:%s:%s:%s/%s/%s",
		region, accountID, string(target.ServiceNamespace),
		convert.ToValue(target.ResourceId), string(target.ScalableDimension))
}

func (a *mqlAwsApplicationAutoscalingTarget) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsApplicationAutoscalingPolicy) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsApplicationAutoscalingScheduledAction) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsApplicationAutoscaling) scalableTargets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	namespace := a.Namespace.Data
	if namespace == "" {
		return nil, errors.New("namespace required for application autoscaling query. please specify one of [comprehend, rds, sagemaker, appstream, elasticmapreduce, dynamodb, lambda, ecs, cassandra, ec2, neptune, kafka, custom-resource, elasticache]")
	}

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTargets(conn, aatypes.ServiceNamespace(namespace)), 5)
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

func (a *mqlAwsApplicationAutoscaling) getTargets(conn *connection.AwsConnection, namespace aatypes.ServiceNamespace) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("appautoscaling>getTargets>calling aws with region %s", region)

			svc := conn.ApplicationAutoscaling(region)
			ctx := context.Background()

			res := []any{}
			params := &applicationautoscaling.DescribeScalableTargetsInput{ServiceNamespace: namespace}
			paginator := applicationautoscaling.NewDescribeScalableTargetsPaginator(svc, params)
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather application autoscaling scalable targets")
				}

				for _, target := range resp.ScalableTargets {
					targetState, err := convert.JsonToDict(target.SuspendedState)
					if err != nil {
						return nil, err
					}
					mqlSTarget, err := CreateResource(a.MqlRuntime, "aws.applicationAutoscaling.target",
						map[string]*llx.RawData{
							"arn":               llx.StringData(scalableTargetArn(target, region, conn.AccountId())),
							"namespace":         llx.StringData(string(target.ServiceNamespace)),
							"resourceId":        llx.StringData(convert.ToValue(target.ResourceId)),
							"region":            llx.StringData(region),
							"scalableDimension": llx.StringData(string(target.ScalableDimension)),
							"minCapacity":       llx.IntDataDefault(target.MinCapacity, 0),
							"maxCapacity":       llx.IntDataDefault(target.MaxCapacity, 0),
							"suspendedState":    llx.MapData(targetState, types.Any),
							"createdAt":         llx.TimeDataPtr(target.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSTarget)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsApplicationAutoscalingTarget) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	namespace := a.Namespace.Data
	resourceId := a.ResourceId.Data
	scalableDimension := a.ScalableDimension.Data

	svc := conn.ApplicationAutoscaling(region)
	ctx := context.Background()
	res := []any{}

	ns := aatypes.ServiceNamespace(namespace)
	sd := aatypes.ScalableDimension(scalableDimension)
	params := &applicationautoscaling.DescribeScalingPoliciesInput{
		ServiceNamespace:  ns,
		ResourceId:        &resourceId,
		ScalableDimension: sd,
	}
	paginator := applicationautoscaling.NewDescribeScalingPoliciesPaginator(svc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather application autoscaling policies")
		}

		for _, policy := range page.ScalingPolicies {
			alarms := []any{}
			for _, alarm := range policy.Alarms {
				alarmDict, err := convert.JsonToDict(alarm)
				if err != nil {
					return nil, err
				}
				alarms = append(alarms, alarmDict)
			}

			targetTrackingConfig, err := convert.JsonToDict(policy.TargetTrackingScalingPolicyConfiguration)
			if err != nil {
				return nil, err
			}

			stepScalingConfig, err := convert.JsonToDict(policy.StepScalingPolicyConfiguration)
			if err != nil {
				return nil, err
			}

			predictiveScalingConfig, err := convert.JsonToDict(policy.PredictiveScalingPolicyConfiguration)
			if err != nil {
				return nil, err
			}

			mqlPolicy, err := CreateResource(a.MqlRuntime, "aws.applicationAutoscaling.policy",
				map[string]*llx.RawData{
					"arn":                     llx.StringDataPtr(policy.PolicyARN),
					"name":                    llx.StringDataPtr(policy.PolicyName),
					"policyType":              llx.StringData(string(policy.PolicyType)),
					"resourceId":              llx.StringDataPtr(policy.ResourceId),
					"scalableDimension":       llx.StringData(string(policy.ScalableDimension)),
					"namespace":               llx.StringData(string(policy.ServiceNamespace)),
					"createdAt":               llx.TimeDataPtr(policy.CreationTime),
					"alarms":                  llx.ArrayData(alarms, types.Dict),
					"targetTrackingConfig":    llx.DictData(targetTrackingConfig),
					"stepScalingConfig":       llx.DictData(stepScalingConfig),
					"predictiveScalingConfig": llx.DictData(predictiveScalingConfig),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlPolicy)
		}
	}

	return res, nil
}

func (a *mqlAwsApplicationAutoscalingTarget) scheduledActions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	namespace := a.Namespace.Data
	resourceId := a.ResourceId.Data
	scalableDimension := a.ScalableDimension.Data

	svc := conn.ApplicationAutoscaling(region)
	ctx := context.Background()
	res := []any{}

	ns := aatypes.ServiceNamespace(namespace)
	sd := aatypes.ScalableDimension(scalableDimension)
	params := &applicationautoscaling.DescribeScheduledActionsInput{
		ServiceNamespace:  ns,
		ResourceId:        &resourceId,
		ScalableDimension: sd,
	}
	paginator := applicationautoscaling.NewDescribeScheduledActionsPaginator(svc, params)
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, errors.Wrap(err, "could not gather application autoscaling scheduled actions")
		}

		for _, action := range page.ScheduledActions {
			scalableTargetAction, err := convert.JsonToDict(action.ScalableTargetAction)
			if err != nil {
				return nil, err
			}

			mqlAction, err := CreateResource(a.MqlRuntime, "aws.applicationAutoscaling.scheduledAction",
				map[string]*llx.RawData{
					"arn":                  llx.StringDataPtr(action.ScheduledActionARN),
					"name":                 llx.StringDataPtr(action.ScheduledActionName),
					"schedule":             llx.StringDataPtr(action.Schedule),
					"timezone":             llx.StringDataPtr(action.Timezone),
					"resourceId":           llx.StringDataPtr(action.ResourceId),
					"scalableDimension":    llx.StringData(string(action.ScalableDimension)),
					"namespace":            llx.StringData(string(action.ServiceNamespace)),
					"createdAt":            llx.TimeDataPtr(action.CreationTime),
					"startAt":              llx.TimeDataPtr(action.StartTime),
					"endAt":                llx.TimeDataPtr(action.EndTime),
					"scalableTargetAction": llx.DictData(scalableTargetAction),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlAction)
		}
	}

	return res, nil
}
