// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/dax"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// isDaxAccessDeniedError checks for the DAX-specific access denied error which uses
// InvalidParameterValueException instead of the standard AccessDenied error code.
func isDaxAccessDeniedError(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "InvalidParameterValueException") &&
		strings.Contains(err.Error(), "Access Denied")
}

func (a *mqlAwsDynamodb) daxClusters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDaxClusters(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsDynamodb) getDaxClusters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Dax(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeClusters(ctx, &dax.DescribeClustersInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) || isDaxAccessDeniedError(err) {
						log.Debug().Str("region", region).Msg("skipping DAX: service not available or access denied in region")
						return res, nil
					}
					return nil, err
				}

				for _, cluster := range resp.Clusters {
					var sseStatus string
					if cluster.SSEDescription != nil {
						sseStatus = string(cluster.SSEDescription.Status)
					}

					mqlCluster, err := CreateResource(a.MqlRuntime, "aws.dynamodb.dax.cluster",
						map[string]*llx.RawData{
							"arn":                           llx.StringDataPtr(cluster.ClusterArn),
							"clusterName":                   llx.StringDataPtr(cluster.ClusterName),
							"description":                   llx.StringDataPtr(cluster.Description),
							"nodeType":                      llx.StringDataPtr(cluster.NodeType),
							"status":                        llx.StringDataPtr(cluster.Status),
							"totalNodes":                    llx.IntDataDefault(cluster.TotalNodes, 0),
							"activeNodes":                   llx.IntDataDefault(cluster.ActiveNodes, 0),
							"region":                        llx.StringData(region),
							"sseStatus":                     llx.StringData(sseStatus),
							"encrypted":                     llx.BoolData(sseStatus == "ENABLED"),
							"clusterEndpointEncryptionType": llx.StringData(string(cluster.ClusterEndpointEncryptionType)),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCluster)
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

func (a *mqlAwsDynamodbDaxCluster) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsDynamodbDaxClusterInternal struct {
	tagsFetched bool
	cacheTags   map[string]any
	tagsLock    sync.Mutex
}

func (a *mqlAwsDynamodbDaxCluster) tags() (map[string]any, error) {
	if a.tagsFetched {
		return a.cacheTags, nil
	}
	a.tagsLock.Lock()
	defer a.tagsLock.Unlock()
	if a.tagsFetched {
		return a.cacheTags, nil
	}

	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Dax(region)
	ctx := context.Background()

	arnVal := a.Arn.Data
	tags := make(map[string]any)
	var nextToken *string
	for {
		resp, err := svc.ListTags(ctx, &dax.ListTagsInput{ResourceName: &arnVal, NextToken: nextToken})
		if err != nil {
			return nil, err
		}
		for _, t := range resp.Tags {
			if t.Key != nil && t.Value != nil {
				tags[*t.Key] = *t.Value
			}
		}
		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}
	a.tagsFetched = true
	a.cacheTags = tags
	return tags, nil
}
