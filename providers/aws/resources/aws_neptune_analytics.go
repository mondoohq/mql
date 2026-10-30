// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/neptunegraph"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsNeptuneAnalytics) id() (string, error) {
	return "aws.neptuneAnalytics", nil
}

func (a *mqlAwsNeptuneAnalytics) graphs() ([]any, error) {
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

func (a *mqlAwsNeptuneAnalytics) getGraphs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("neptuneAnalytics>getGraphs>calling aws with region %s", region)

			svc := conn.NeptuneGraph(region)
			ctx := context.Background()
			res := []any{}

			paginator := neptunegraph.NewListGraphsPaginator(svc, &neptunegraph.ListGraphsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("neptune-graph service not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, g := range page.Graphs {
					mqlGraph, err := CreateResource(a.MqlRuntime, "aws.neptuneAnalytics.graph",
						map[string]*llx.RawData{
							"__id":               llx.StringDataPtr(g.Arn),
							"arn":                llx.StringDataPtr(g.Arn),
							"id":                 llx.StringDataPtr(g.Id),
							"name":               llx.StringDataPtr(g.Name),
							"region":             llx.StringData(region),
							"status":             llx.StringData(string(g.Status)),
							"endpoint":           llx.StringDataPtr(g.Endpoint),
							"deletionProtection": llx.BoolDataPtr(g.DeletionProtection),
							"publicConnectivity": llx.BoolDataPtr(g.PublicConnectivity),
							"provisionedMemory":  llx.IntDataDefault(g.ProvisionedMemory, 0),
							"replicaCount":       llx.IntDataDefault(g.ReplicaCount, 0),
						})
					if err != nil {
						return nil, err
					}
					mqlGraph.(*mqlAwsNeptuneAnalyticsGraph).cacheKmsKeyIdentifier = g.KmsKeyIdentifier
					res = append(res, mqlGraph)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsNeptuneAnalyticsGraphInternal struct {
	cacheKmsKeyIdentifier *string

	detailOnce sync.Once
	detailErr  error
	detail     *neptunegraph.GetGraphOutput
}

func (a *mqlAwsNeptuneAnalyticsGraph) fetchDetail() (*neptunegraph.GetGraphOutput, error) {
	a.detailOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.NeptuneGraph(a.Region.Data)
		ctx := context.Background()
		id := a.Id.Data
		a.detail, a.detailErr = svc.GetGraph(ctx, &neptunegraph.GetGraphInput{
			GraphIdentifier: &id,
		})
	})
	return a.detail, a.detailErr
}

func (a *mqlAwsNeptuneAnalyticsGraph) kmsKey() (*mqlAwsKmsKey, error) {
	// Neptune Analytics returns the literal sentinel "AWS_OWNED_KEY" when the
	// graph is encrypted with the AWS-owned key rather than a customer-managed
	// key — there is no real KMS key to resolve in that case.
	if a.cacheKmsKeyIdentifier == nil || *a.cacheKmsKeyIdentifier == "" || *a.cacheKmsKeyIdentifier == "AWS_OWNED_KEY" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyIdentifier),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsNeptuneAnalyticsGraph) createdAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return detail.CreateTime, nil
}

func (a *mqlAwsNeptuneAnalyticsGraph) buildNumber() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.BuildNumber), nil
}

func (a *mqlAwsNeptuneAnalyticsGraph) statusReason() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.StatusReason), nil
}

func (a *mqlAwsNeptuneAnalyticsGraph) sourceSnapshotId() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return convert.ToValue(detail.SourceSnapshotId), nil
}

func (a *mqlAwsNeptuneAnalyticsGraph) vectorSearchDimension() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail.VectorSearchConfiguration == nil || detail.VectorSearchConfiguration.Dimension == nil {
		return 0, nil
	}
	return int64(*detail.VectorSearchConfiguration.Dimension), nil
}

func (a *mqlAwsNeptuneAnalyticsGraph) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.NeptuneGraph(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.ListTagsForResource(ctx, &neptunegraph.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		return nil, err
	}
	tags := make(map[string]any, len(resp.Tags))
	for k, v := range resp.Tags {
		tags[k] = v
	}
	return tags, nil
}
