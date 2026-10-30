// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/appflow"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsAppflow) id() (string, error) {
	return "aws.appflow", nil
}

// Flows

func (a *mqlAwsAppflow) flows() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getFlows(conn), 5)
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

func (a *mqlAwsAppflow) getFlows(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("appflow>getFlows>calling aws with region %s", region)

			svc := conn.AppFlow(region)
			ctx := context.Background()
			res := []any{}

			paginator := appflow.NewListFlowsPaginator(svc, &appflow.ListFlowsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS AppFlow flows API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, flow := range page.Flows {
					args := map[string]*llx.RawData{
						"__id":                     llx.StringDataPtr(flow.FlowArn),
						"arn":                      llx.StringDataPtr(flow.FlowArn),
						"name":                     llx.StringDataPtr(flow.FlowName),
						"region":                   llx.StringData(region),
						"description":              llx.StringDataPtr(flow.Description),
						"flowStatus":               llx.StringData(string(flow.FlowStatus)),
						"sourceConnectorType":      llx.StringData(string(flow.SourceConnectorType)),
						"destinationConnectorType": llx.StringData(string(flow.DestinationConnectorType)),
						"triggerType":              llx.StringData(string(flow.TriggerType)),
						"createdBy":                llx.StringDataPtr(flow.CreatedBy),
						"createdAt":                llx.TimeDataPtr(flow.CreatedAt),
						"lastUpdatedAt":            llx.TimeDataPtr(flow.LastUpdatedAt),
						"tags":                     llx.MapData(convert.MapToInterfaceMap(flow.Tags), types.String),
					}
					mqlFlow, err := CreateResource(a.MqlRuntime, "aws.appflow.flow", args)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlFlow)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsAppflowFlow) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppflowFlowInternal struct {
	fetched  bool
	lock     sync.Mutex
	descResp *appflow.DescribeFlowOutput
}

func (a *mqlAwsAppflowFlow) fetchDetail() (*appflow.DescribeFlowOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppFlow(a.Region.Data)
	flowName := a.Name.Data
	resp, err := svc.DescribeFlow(context.Background(), &appflow.DescribeFlowInput{FlowName: &flowName})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsAppflowFlow) kmsKey() (*mqlAwsKmsKey, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	kmsArn := convert.ToValue(resp.KmsArn)
	if kmsArn == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(kmsArn)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// Connector profiles

func (a *mqlAwsAppflow) connectorProfiles() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConnectorProfiles(conn), 5)
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

func (a *mqlAwsAppflow) getConnectorProfiles(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("appflow>getConnectorProfiles>calling aws with region %s", region)

			svc := conn.AppFlow(region)
			ctx := context.Background()
			res := []any{}

			paginator := appflow.NewDescribeConnectorProfilesPaginator(svc, &appflow.DescribeConnectorProfilesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS AppFlow connector profiles API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, profile := range page.ConnectorProfileDetails {
					mqlProfile, err := CreateResource(a.MqlRuntime, "aws.appflow.connectorProfile",
						map[string]*llx.RawData{
							"__id":           llx.StringDataPtr(profile.ConnectorProfileArn),
							"arn":            llx.StringDataPtr(profile.ConnectorProfileArn),
							"name":           llx.StringDataPtr(profile.ConnectorProfileName),
							"region":         llx.StringData(region),
							"connectorType":  llx.StringData(string(profile.ConnectorType)),
							"connectorLabel": llx.StringDataPtr(profile.ConnectorLabel),
							"connectionMode": llx.StringData(string(profile.ConnectionMode)),
							"createdAt":      llx.TimeDataPtr(profile.CreatedAt),
							"lastUpdatedAt":  llx.TimeDataPtr(profile.LastUpdatedAt),
						})
					if err != nil {
						return nil, err
					}
					mqlProfile.(*mqlAwsAppflowConnectorProfile).cacheCredentialsArn = convert.ToValue(profile.CredentialsArn)
					res = append(res, mqlProfile)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsAppflowConnectorProfile) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsAppflowConnectorProfileInternal struct {
	cacheCredentialsArn string
}

func (a *mqlAwsAppflowConnectorProfile) credentials() (*mqlAwsSecretsmanagerSecret, error) {
	if a.cacheCredentialsArn == "" {
		a.Credentials.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlSecret, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheCredentialsArn)})
	if err != nil {
		return nil, err
	}
	return mqlSecret.(*mqlAwsSecretsmanagerSecret), nil
}
