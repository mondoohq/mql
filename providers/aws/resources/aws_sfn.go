// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/sfn"
	sfntypes "github.com/aws/aws-sdk-go-v2/service/sfn/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsSfn) id() (string, error) {
	return "aws.sfn", nil
}

func (a *mqlAwsSfn) stateMachines() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getStateMachines(conn), 5)
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

func (a *mqlAwsSfn) getStateMachines(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("sfn>getStateMachines>calling aws with region %s", region)

			svc := conn.Sfn(region)
			ctx := context.Background()
			res := []any{}

			paginator := sfn.NewListStateMachinesPaginator(svc, &sfn.ListStateMachinesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("Step Functions is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, sm := range page.StateMachines {
					mqlSm, err := CreateResource(a.MqlRuntime, "aws.sfn.stateMachine",
						map[string]*llx.RawData{
							"__id":      llx.StringDataPtr(sm.StateMachineArn),
							"arn":       llx.StringDataPtr(sm.StateMachineArn),
							"name":      llx.StringDataPtr(sm.Name),
							"region":    llx.StringData(region),
							"type":      llx.StringData(string(sm.Type)),
							"createdAt": llx.TimeDataPtr(sm.CreationDate),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSm)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSfnStateMachine) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsSfnStateMachineInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *sfn.DescribeStateMachineOutput
}

func (a *mqlAwsSfnStateMachine) fetchDetail() (*sfn.DescribeStateMachineOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Sfn(region)
	ctx := context.Background()

	smArn := a.Arn.Data
	resp, err := svc.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: &smArn,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsSfnStateMachine) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Status), nil
}

func (a *mqlAwsSfnStateMachine) description() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Description), nil
}

func (a *mqlAwsSfnStateMachine) revisionId() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.RevisionId), nil
}

func (a *mqlAwsSfnStateMachine) label() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Label), nil
}

func (a *mqlAwsSfnStateMachine) definition() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Definition), nil
}

func (a *mqlAwsSfnStateMachine) iamRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.RoleArn == nil || *resp.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(resp.RoleArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSfnStateMachine) loggingLevel() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.LoggingConfiguration == nil {
		return string(sfntypes.LogLevelOff), nil
	}
	return string(resp.LoggingConfiguration.Level), nil
}

func (a *mqlAwsSfnStateMachine) loggingIncludeExecutionData() (bool, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if resp.LoggingConfiguration == nil {
		return false, nil
	}
	return resp.LoggingConfiguration.IncludeExecutionData, nil
}

func (a *mqlAwsSfnStateMachine) loggingDestinations() ([]any, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.LoggingConfiguration == nil {
		return []any{}, nil
	}
	out := make([]any, 0, len(resp.LoggingConfiguration.Destinations))
	for _, d := range resp.LoggingConfiguration.Destinations {
		if d.CloudWatchLogsLogGroup == nil || d.CloudWatchLogsLogGroup.LogGroupArn == nil {
			continue
		}
		mqlLg, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup",
			map[string]*llx.RawData{
				"arn": llx.StringDataPtr(d.CloudWatchLogsLogGroup.LogGroupArn),
			})
		if err != nil {
			return nil, err
		}
		out = append(out, mqlLg)
	}
	return out, nil
}

func (a *mqlAwsSfnStateMachine) tracingEnabled() (bool, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if resp.TracingConfiguration == nil {
		return false, nil
	}
	return resp.TracingConfiguration.Enabled, nil
}

func (a *mqlAwsSfnStateMachine) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Sfn(region)
	ctx := context.Background()

	smArn := a.Arn.Data
	resp, err := svc.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{
		ResourceArn: &smArn,
	})
	if err != nil {
		return nil, err
	}
	return sfnTagsToMap(resp.Tags), nil
}

func (a *mqlAwsSfnStateMachine) encryptionType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.EncryptionConfiguration == nil {
		return string(sfntypes.EncryptionTypeAwsOwnedKey), nil
	}
	return string(resp.EncryptionConfiguration.Type), nil
}

func (a *mqlAwsSfnStateMachine) encryptionKmsKeyId() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.EncryptionConfiguration == nil {
		return "", nil
	}
	return convert.ToValue(resp.EncryptionConfiguration.KmsKeyId), nil
}

func (a *mqlAwsSfnStateMachine) kmsKey() (*mqlAwsKmsKey, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.EncryptionConfiguration == nil ||
		resp.EncryptionConfiguration.Type != sfntypes.EncryptionTypeCustomerManagedKmsKey ||
		resp.EncryptionConfiguration.KmsKeyId == nil || *resp.EncryptionConfiguration.KmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	keyRef := *resp.EncryptionConfiguration.KmsKeyId
	args := map[string]*llx.RawData{
		"arn":    llx.StringData(keyRef),
		"region": llx.StringData(a.Region.Data),
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key", args)
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSfnStateMachine) encryptionKmsDataKeyReusePeriodSeconds() (int64, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if resp.EncryptionConfiguration == nil || resp.EncryptionConfiguration.KmsDataKeyReusePeriodSeconds == nil {
		return 0, nil
	}
	return int64(*resp.EncryptionConfiguration.KmsDataKeyReusePeriodSeconds), nil
}

func (a *mqlAwsSfnStateMachine) versions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Sfn(region)
	ctx := context.Background()

	smArn := a.Arn.Data
	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.ListStateMachineVersions(ctx, &sfn.ListStateMachineVersionsInput{
			StateMachineArn: &smArn,
			NextToken:       nextToken,
		})
		if err != nil {
			return nil, classifyAwsError(err, "states:ListStateMachineVersions")
		}
		for _, v := range resp.StateMachineVersions {
			mqlVersion, err := CreateResource(a.MqlRuntime, "aws.sfn.stateMachineVersion",
				map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(v.StateMachineVersionArn),
					"arn":       llx.StringDataPtr(v.StateMachineVersionArn),
					"createdAt": llx.TimeDataPtr(v.CreationDate),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVersion)
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

// State machine versions

type mqlAwsSfnStateMachineVersionInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *sfn.DescribeStateMachineOutput
}

func (a *mqlAwsSfnStateMachineVersion) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSfnStateMachineVersion) fetchDetail() (*sfn.DescribeStateMachineOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	versionArn := a.Arn.Data
	region, err := sfnRegionFromVersionArn(versionArn)
	if err != nil {
		return nil, err
	}
	svc := conn.Sfn(region)
	ctx := context.Background()

	resp, err := svc.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: &versionArn,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsSfnStateMachineVersion) description() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Description), nil
}

func (a *mqlAwsSfnStateMachineVersion) revisionId() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.RevisionId), nil
}

func initAwsSfnStateMachineVersion(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	raw, ok := args["arn"]
	if !ok || raw == nil {
		return nil, nil, errors.New("arn required to fetch aws.sfn.stateMachineVersion")
	}
	versionArn, ok := raw.Value.(string)
	if !ok || versionArn == "" {
		return nil, nil, errors.New("arn required to fetch aws.sfn.stateMachineVersion")
	}

	region, err := sfnRegionFromVersionArn(versionArn)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Sfn(region)
	ctx := context.Background()
	resp, err := svc.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: &versionArn,
	})
	if err != nil {
		return nil, nil, err
	}

	res, err := CreateResource(runtime, "aws.sfn.stateMachineVersion",
		map[string]*llx.RawData{
			"__id":      llx.StringData(versionArn),
			"arn":       llx.StringData(versionArn),
			"createdAt": llx.TimeDataPtr(resp.CreationDate),
		})
	if err != nil {
		return nil, nil, err
	}
	mqlRes := res.(*mqlAwsSfnStateMachineVersion)
	mqlRes.fetched = true
	mqlRes.descResp = resp
	return nil, mqlRes, nil
}

// sfnRegionFromVersionArn extracts the AWS region from a Step Functions
// state machine (or version) ARN. The arn package accepts the version ARN
// form (resource has a trailing `:<versionNumber>`) without modification.
func sfnRegionFromVersionArn(versionArn string) (string, error) {
	if !strings.HasPrefix(versionArn, "arn:") {
		return "", errors.New("invalid state machine version ARN")
	}
	parsed, err := arn.Parse(versionArn)
	if err != nil {
		return "", err
	}
	return parsed.Region, nil
}

// Activities

func (a *mqlAwsSfn) activities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getActivities(conn), 5)
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

func (a *mqlAwsSfn) getActivities(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sfn(region)
			ctx := context.Background()
			res := []any{}

			paginator := sfn.NewListActivitiesPaginator(svc, &sfn.ListActivitiesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, activity := range page.Activities {
					mqlActivity, err := CreateResource(a.MqlRuntime, "aws.sfn.activity",
						map[string]*llx.RawData{
							"__id":      llx.StringDataPtr(activity.ActivityArn),
							"arn":       llx.StringDataPtr(activity.ActivityArn),
							"name":      llx.StringDataPtr(activity.Name),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(activity.CreationDate),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlActivity)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSfnActivity) id() (string, error) {
	return a.Arn.Data, nil
}

func sfnTagsToMap(tags []sfntypes.Tag) map[string]any {
	return tagsToMap(tags, func(t sfntypes.Tag) *string { return t.Key }, func(t sfntypes.Tag) *string { return t.Value })
}
