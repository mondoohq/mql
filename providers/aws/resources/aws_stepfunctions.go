// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/sfn"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsStepfunctions) id() (string, error) {
	return "aws.stepfunctions", nil
}

func (a *mqlAwsStepfunctions) stateMachines() ([]any, error) {
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

func (a *mqlAwsStepfunctions) getStateMachines(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("stepfunctions>getStateMachines>calling aws with region %s", region)

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
					mqlSm, err := CreateResource(a.MqlRuntime, "aws.stepfunctions.stateMachine",
						map[string]*llx.RawData{
							"__id":   llx.StringDataPtr(sm.StateMachineArn),
							"arn":    llx.StringDataPtr(sm.StateMachineArn),
							"name":   llx.StringDataPtr(sm.Name),
							"region": llx.StringData(region),
							"type":   llx.StringData(string(sm.Type)),
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

func (a *mqlAwsStepfunctionsStateMachine) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsStepfunctionsStateMachineInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *sfn.DescribeStateMachineOutput
}

func (a *mqlAwsStepfunctionsStateMachine) fetchDetail() (*sfn.DescribeStateMachineOutput, error) {
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

	arnVal := a.Arn.Data
	resp, err := svc.DescribeStateMachine(ctx, &sfn.DescribeStateMachineInput{
		StateMachineArn: &arnVal,
	})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsStepfunctionsStateMachine) status() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.Status), nil
}

func (a *mqlAwsStepfunctionsStateMachine) definition() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(resp.Definition), nil
}

func (a *mqlAwsStepfunctionsStateMachine) iamRole() (*mqlAwsIamRole, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	roleArn := convert.ToValue(resp.RoleArn)
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

func (a *mqlAwsStepfunctionsStateMachine) createdAt() (*time.Time, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return resp.CreationDate, nil
}

func (a *mqlAwsStepfunctionsStateMachine) loggingConfiguration() (*mqlAwsStepfunctionsStateMachineLoggingConfiguration, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if resp.LoggingConfiguration == nil {
		a.LoggingConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	lc := resp.LoggingConfiguration
	level := string(lc.Level)
	includeExecutionData := lc.IncludeExecutionData

	destinations := []any{}
	for _, dest := range lc.Destinations {
		d, err := convert.JsonToDict(dest)
		if err != nil {
			return nil, err
		}
		destinations = append(destinations, d)
	}

	res, err := CreateResource(a.MqlRuntime, "aws.stepfunctions.stateMachine.loggingConfiguration",
		map[string]*llx.RawData{
			"__id":                 llx.StringData(a.Arn.Data + "/loggingConfiguration"),
			"level":                llx.StringData(level),
			"includeExecutionData": llx.BoolData(includeExecutionData),
			"destinations":         llx.ArrayData(destinations, types.Dict),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsStepfunctionsStateMachineLoggingConfiguration), nil
}

func (a *mqlAwsStepfunctionsStateMachine) tracingEnabled() (bool, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if resp.TracingConfiguration == nil {
		return false, nil
	}
	return resp.TracingConfiguration.Enabled, nil
}

func (a *mqlAwsStepfunctionsStateMachine) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Sfn(region)
	ctx := context.Background()

	arnVal := a.Arn.Data
	tags := make(map[string]any)
	resp, err := svc.ListTagsForResource(ctx, &sfn.ListTagsForResourceInput{
		ResourceArn: &arnVal,
	})
	if err != nil {
		return nil, err
	}
	for _, tag := range resp.Tags {
		tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
	}
	return tags, nil
}

func (a *mqlAwsStepfunctionsStateMachineLoggingConfiguration) id() (string, error) {
	return a.Level.Data, nil
}
