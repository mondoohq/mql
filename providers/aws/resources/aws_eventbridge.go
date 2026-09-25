// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/eventbridge"
	eventbridge_types "github.com/aws/aws-sdk-go-v2/service/eventbridge/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsEventbridge) id() (string, error) {
	return "aws.eventbridge", nil
}

func (a *mqlAwsEventbridge) eventBuses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEventBuses(conn), 5)
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

func (a *mqlAwsEventbridge) getEventBuses(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("eventbridge>getEventBuses>calling aws with region %s", region)

			svc := conn.EventBridge(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListEventBuses(ctx, &eventbridge.ListEventBusesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, bus := range resp.EventBuses {
					mqlBus, err := CreateResource(a.MqlRuntime, "aws.eventbridge.eventBus",
						map[string]*llx.RawData{
							"__id":      llx.StringDataPtr(bus.Arn),
							"arn":       llx.StringDataPtr(bus.Arn),
							"name":      llx.StringDataPtr(bus.Name),
							"createdAt": llx.TimeDataPtr(bus.CreationTime),
							"region":    llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlBus)
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

func (a *mqlAwsEventbridge) rules() ([]any, error) {
	obj := a.GetEventBuses()
	if obj.Error != nil {
		return nil, obj.Error
	}
	buses := obj.Data
	res := []any{}
	for _, b := range buses {
		bus := b.(*mqlAwsEventbridgeEventBus)
		rules, err := bus.rules()
		if err != nil {
			return nil, err
		}
		res = append(res, rules...)
	}
	return res, nil
}

func (a *mqlAwsEventbridgeEventBus) policy() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeEventBus(ctx, &eventbridge.DescribeEventBusInput{
		Name: &a.Name.Data,
	})
	if err != nil {
		return "", classifyAwsError(err, "events:DescribeEventBus")
	}
	if resp.Policy == nil {
		return "", nil
	}
	return *resp.Policy, nil
}

func (a *mqlAwsEventbridgeEventBus) tags() (map[string]any, error) {
	arn := a.Arn.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(region)
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{
		ResourceARN: &arn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "events:ListTagsForResource")
	}
	tags := make(map[string]any)
	for _, t := range resp.Tags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsEventbridgeEventBus) rules() ([]any, error) {
	busName := a.Name.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.ListRules(ctx, &eventbridge.ListRulesInput{
			EventBusName: &busName,
			NextToken:    nextToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "events:ListRules")
		}

		for _, rule := range resp.Rules {
			mqlRule, err := CreateResource(a.MqlRuntime, "aws.eventbridge.rule",
				map[string]*llx.RawData{
					"__id":               llx.StringDataPtr(rule.Arn),
					"arn":                llx.StringDataPtr(rule.Arn),
					"name":               llx.StringDataPtr(rule.Name),
					"region":             llx.StringData(region),
					"eventBusName":       llx.StringDataPtr(rule.EventBusName),
					"state":              llx.StringData(string(rule.State)),
					"description":        llx.StringDataPtr(rule.Description),
					"eventPattern":       llx.StringDataPtr(rule.EventPattern),
					"scheduleExpression": llx.StringDataPtr(rule.ScheduleExpression),
				})
			if err != nil {
				return nil, err
			}
			mqlRuleRes := mqlRule.(*mqlAwsEventbridgeRule)
			mqlRuleRes.cacheRoleArn = rule.RoleArn
			res = append(res, mqlRuleRes)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

type mqlAwsEventbridgeRuleInternal struct {
	cacheRoleArn *string
}

func (a *mqlAwsEventbridgeRule) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsEventbridgeRule) tags() (map[string]any, error) {
	arn := a.Arn.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(region)
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &eventbridge.ListTagsForResourceInput{
		ResourceARN: &arn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "events:ListTagsForResource")
	}
	tags := make(map[string]any)
	for _, t := range resp.Tags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

// listTargets fetches every target for the rule, paginating as needed. It
// backs both the deprecated targets() dict view and the typed eventTargets().
func (a *mqlAwsEventbridgeRule) listTargets() ([]eventbridge_types.Target, error) {
	ruleName := a.Name.Data
	busName := a.EventBusName.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.EventBridge(region)
	ctx := context.Background()

	var allTargets []eventbridge_types.Target
	var nextToken *string
	for {
		resp, err := svc.ListTargetsByRule(ctx, &eventbridge.ListTargetsByRuleInput{
			Rule:         &ruleName,
			EventBusName: &busName,
			NextToken:    nextToken,
		})
		if err != nil {
			return nil, err
		}
		allTargets = append(allTargets, resp.Targets...)
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return allTargets, nil
}

func (a *mqlAwsEventbridgeRule) eventTargets() ([]any, error) {
	region := a.Region.Data
	ruleArn := a.Arn.Data

	allTargets, err := a.listTargets()
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(allTargets))
	for _, t := range allTargets {
		var inputTransformer any
		if t.InputTransformer != nil {
			d, err := convert.JsonToDict(t.InputTransformer)
			if err != nil {
				return nil, err
			}
			inputTransformer = d
		}

		var retryMaxAttempts, retryMaxEventAgeSeconds *int64
		if t.RetryPolicy != nil {
			retryMaxAttempts = int32PtrToInt64Ptr(t.RetryPolicy.MaximumRetryAttempts)
			retryMaxEventAgeSeconds = int32PtrToInt64Ptr(t.RetryPolicy.MaximumEventAgeInSeconds)
		}

		mqlTarget, err := CreateResource(a.MqlRuntime, "aws.eventbridge.rule.target",
			map[string]*llx.RawData{
				// Target.Id is only unique within the rule, so qualify the cache
				// key with the rule ARN while exposing the plain id as a field.
				"__id":                    llx.StringData(ruleArn + "/" + convert.ToValue(t.Id)),
				"id":                      llx.StringDataPtr(t.Id),
				"arn":                     llx.StringDataPtr(t.Arn),
				"input":                   llx.StringDataPtr(t.Input),
				"inputPath":               llx.StringDataPtr(t.InputPath),
				"inputTransformer":        llx.DictData(inputTransformer),
				"retryMaxAttempts":        llx.IntDataPtr(retryMaxAttempts),
				"retryMaxEventAgeSeconds": llx.IntDataPtr(retryMaxEventAgeSeconds),
			})
		if err != nil {
			return nil, err
		}
		mqlTargetRes := mqlTarget.(*mqlAwsEventbridgeRuleTarget)
		mqlTargetRes.region = region
		mqlTargetRes.cacheRoleArn = t.RoleArn
		if t.DeadLetterConfig != nil {
			mqlTargetRes.cacheDeadLetterArn = t.DeadLetterConfig.Arn
		}
		res = append(res, mqlTargetRes)
	}
	return res, nil
}

func int32PtrToInt64Ptr(v *int32) *int64 {
	if v == nil {
		return nil
	}
	i := int64(*v)
	return &i
}

type mqlAwsEventbridgeRuleTargetInternal struct {
	region             string
	cacheRoleArn       *string
	cacheDeadLetterArn *string
}

func (a *mqlAwsEventbridgeRuleTarget) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsEventbridgeRuleTarget) deadLetterQueue() (*mqlAwsSqsQueue, error) {
	if a.cacheDeadLetterArn == nil || *a.cacheDeadLetterArn == "" {
		a.DeadLetterQueue.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	parsedArn, err := arn.Parse(*a.cacheDeadLetterArn)
	if err != nil {
		return nil, err
	}
	// "https://sqs.us-east-1.amazonaws.com/921877552404/my-queue"
	url := fmt.Sprintf("https://sqs.%s.amazonaws.com/%s/%s", parsedArn.Region, parsedArn.AccountID, parsedArn.Resource)
	q, err := NewResource(a.MqlRuntime, "aws.sqs.queue",
		map[string]*llx.RawData{
			"arn":    llx.StringDataPtr(a.cacheDeadLetterArn),
			"url":    llx.StringData(url),
			"region": llx.StringData(parsedArn.Region),
		})
	if err != nil {
		return nil, err
	}
	return q.(*mqlAwsSqsQueue), nil
}
