// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ram"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsRam) id() (string, error) {
	return "aws.ram", nil
}

func (a *mqlAwsRam) resourceShares() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getResourceShares(conn), 5)
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

func (a *mqlAwsRam) getResourceShares(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ram>getResourceShares>calling aws with region %s", region)

			svc := conn.Ram(region)
			ctx := context.Background()
			res := []any{}

			paginator := ram.NewGetResourceSharesPaginator(svc, &ram.GetResourceSharesInput{
				ResourceOwner: ramtypes.ResourceOwnerSelf,
			})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("RAM is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, share := range page.ResourceShares {
					tags := make(map[string]any)
					for _, tag := range share.Tags {
						tags[convert.ToValue(tag.Key)] = convert.ToValue(tag.Value)
					}

					mqlShare, err := CreateResource(a.MqlRuntime, "aws.ram.resourceShare",
						map[string]*llx.RawData{
							"__id":                    llx.StringDataPtr(share.ResourceShareArn),
							"arn":                     llx.StringDataPtr(share.ResourceShareArn),
							"name":                    llx.StringDataPtr(share.Name),
							"region":                  llx.StringData(region),
							"status":                  llx.StringData(string(share.Status)),
							"owningAccountId":         llx.StringDataPtr(share.OwningAccountId),
							"allowExternalPrincipals": llx.BoolData(convert.ToValue(share.AllowExternalPrincipals)),
							"createdAt":               llx.TimeDataPtr(share.CreationTime),
							"tags":                    llx.MapData(tags, types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlShare)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRamResourceShare) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsRamResourceShare) principals() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Ram(region)
	ctx := context.Background()

	arn := a.Arn.Data
	res := []any{}
	paginator := ram.NewListPrincipalsPaginator(svc, &ram.ListPrincipalsInput{
		ResourceOwner:     ramtypes.ResourceOwnerSelf,
		ResourceShareArns: []string{arn},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, principal := range page.Principals {
			res = append(res, map[string]any{
				"id":               convert.ToValue(principal.Id),
				"resourceShareArn": convert.ToValue(principal.ResourceShareArn),
				// Must be a plain bool: llx's dict encoder accepts only
				// JSON-native values, so a *bool here failed the whole field with
				// "unsupported child type: *bool" for every share that has a
				// principal -- which is every share worth auditing.
				"external": convert.ToValue(principal.External),
			})
		}
	}
	return res, nil
}

func (a *mqlAwsRamResourceShare) resources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	svc := conn.Ram(region)
	ctx := context.Background()

	arn := a.Arn.Data
	res := []any{}
	paginator := ram.NewListResourcesPaginator(svc, &ram.ListResourcesInput{
		ResourceOwner:     ramtypes.ResourceOwnerSelf,
		ResourceShareArns: []string{arn},
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, resource := range page.Resources {
			res = append(res, map[string]any{
				"arn":              convert.ToValue(resource.Arn),
				"type":             convert.ToValue(resource.Type),
				"resourceShareArn": convert.ToValue(resource.ResourceShareArn),
				"status":           string(resource.Status),
			})
		}
	}
	return res, nil
}
