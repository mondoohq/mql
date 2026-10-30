// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/detective"
	detectivetypes "github.com/aws/aws-sdk-go-v2/service/detective/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsDetective) id() (string, error) {
	return "aws.detective", nil
}

func (a *mqlAwsDetective) graphs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getGraphs(conn), 5)
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

func (a *mqlAwsDetective) getGraphs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Detective(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListGraphs(ctx, &detective.ListGraphsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Detective")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("AWS Detective is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, g := range resp.GraphList {
					mqlGraph, err := CreateResource(a.MqlRuntime, "aws.detective.graph",
						map[string]*llx.RawData{
							"__id":      llx.StringDataPtr(g.Arn),
							"arn":       llx.StringDataPtr(g.Arn),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(g.CreatedTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlGraph)
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

func (a *mqlAwsDetectiveGraph) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsDetectiveGraph) members() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	graphArn := a.Arn.Data
	region := a.Region.Data
	svc := conn.Detective(region)
	ctx := context.Background()

	res := []any{}
	var nextToken *string
	for {
		resp, err := svc.ListMembers(ctx, &detective.ListMembersInput{
			GraphArn:  &graphArn,
			NextToken: nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("graphArn", graphArn).Msg("access denied listing Detective members")
				return res, nil
			}
			return nil, err
		}

		for _, m := range resp.MemberDetails {
			mqlMember, err := newMqlAwsDetectiveGraphMember(a.MqlRuntime, region, m)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlMember)
		}

		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

func newMqlAwsDetectiveGraphMember(runtime *plugin.Runtime, region string, m detectivetypes.MemberDetail) (plugin.Resource, error) {
	graphArn := convert.ToValue(m.GraphArn)
	accountId := convert.ToValue(m.AccountId)

	ingestStates := make(map[string]any, len(m.DatasourcePackageIngestStates))
	for pkg, state := range m.DatasourcePackageIngestStates {
		ingestStates[string(pkg)] = string(state)
	}

	volumeUsage := make(map[string]any, len(m.VolumeUsageByDatasourcePackage))
	for pkg, info := range m.VolumeUsageByDatasourcePackage {
		entry := map[string]any{}
		if info.VolumeUsageInBytes != nil {
			entry["volumeUsageInBytes"] = *info.VolumeUsageInBytes
		}
		if info.VolumeUsageUpdateTime != nil {
			// dict values must be JSON-native; a time.Time fails conversion at
			// query time with "unsupported child type: time.Time".
			entry["volumeUsageUpdateTime"] = info.VolumeUsageUpdateTime.Format(time.RFC3339)
		}
		volumeUsage[string(pkg)] = entry
	}

	return CreateResource(runtime, "aws.detective.graph.member",
		map[string]*llx.RawData{
			"__id":                           llx.StringData(fmt.Sprintf("%s/member/%s", graphArn, accountId)),
			"graphArn":                       llx.StringDataPtr(m.GraphArn),
			"region":                         llx.StringData(region),
			"accountId":                      llx.StringDataPtr(m.AccountId),
			"email":                          llx.StringDataPtr(m.EmailAddress),
			"administratorId":                llx.StringDataPtr(m.AdministratorId),
			"status":                         llx.StringData(string(m.Status)),
			"disabledReason":                 llx.StringData(string(m.DisabledReason)),
			"invitedAt":                      llx.TimeDataPtr(m.InvitedTime),
			"updatedAt":                      llx.TimeDataPtr(m.UpdatedTime),
			"invitationType":                 llx.StringData(string(m.InvitationType)),
			"datasourcePackageIngestStates":  llx.MapData(ingestStates, types.String),
			"volumeUsageByDatasourcePackage": llx.MapData(volumeUsage, types.Dict),
		})
}

func (a *mqlAwsDetectiveGraphMember) id() (string, error) {
	return fmt.Sprintf("%s/member/%s", a.GraphArn.Data, a.AccountId.Data), nil
}

func (a *mqlAwsDetectiveGraph) datasourcePackages() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	graphArn := a.Arn.Data
	region := a.Region.Data
	svc := conn.Detective(region)
	ctx := context.Background()

	res := map[string]any{}
	var nextToken *string
	for {
		resp, err := svc.ListDatasourcePackages(ctx, &detective.ListDatasourcePackagesInput{
			GraphArn:  &graphArn,
			NextToken: nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("graphArn", graphArn).Msg("access denied listing Detective data-source packages")
				return res, nil
			}
			return nil, err
		}
		for pkg, info := range resp.DatasourcePackages {
			res[string(pkg)] = string(info.DatasourcePackageIngestState)
		}
		if resp.NextToken == nil || *resp.NextToken == "" {
			break
		}
		nextToken = resp.NextToken
	}
	return res, nil
}

func (a *mqlAwsDetectiveGraph) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	graphArn := a.Arn.Data
	region := a.Region.Data
	svc := conn.Detective(region)
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &detective.ListTagsForResourceInput{ResourceArn: &graphArn})
	if err != nil {
		if Is400AccessDeniedError(err) {
			log.Warn().Str("graphArn", graphArn).Msg("access denied listing Detective tags")
			return map[string]any{}, nil
		}
		return nil, err
	}
	return convert.MapToInterfaceMap(resp.Tags), nil
}

func (a *mqlAwsDetective) organizationAdminAccounts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getOrganizationAdminAccounts(conn), 5)
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

func (a *mqlAwsDetective) getOrganizationAdminAccounts(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Detective(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.ListOrganizationAdminAccounts(ctx, &detective.ListOrganizationAdminAccountsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Detective administrators")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("AWS Detective is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, admin := range resp.Administrators {
					accountId := convert.ToValue(admin.AccountId)
					graphArn := convert.ToValue(admin.GraphArn)
					mqlAdmin, err := CreateResource(a.MqlRuntime, "aws.detective.organizationAdminAccount",
						map[string]*llx.RawData{
							"__id":           llx.StringData(fmt.Sprintf("%s/%s/%s", region, graphArn, accountId)),
							"accountId":      llx.StringDataPtr(admin.AccountId),
							"graphArn":       llx.StringDataPtr(admin.GraphArn),
							"region":         llx.StringData(region),
							"delegationTime": llx.TimeDataPtr(admin.DelegationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAdmin)
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

func (a *mqlAwsDetectiveOrganizationAdminAccount) graph() (*mqlAwsDetectiveGraph, error) {
	graphArn := a.GraphArn.Data
	if graphArn == "" {
		a.Graph.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlGraph, err := NewResource(a.MqlRuntime, "aws.detective.graph",
		map[string]*llx.RawData{
			"__id":   llx.StringData(graphArn),
			"arn":    llx.StringData(graphArn),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return mqlGraph.(*mqlAwsDetectiveGraph), nil
}
