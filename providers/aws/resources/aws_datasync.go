// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/datasync"
	datasynctypes "github.com/aws/aws-sdk-go-v2/service/datasync/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsDatasync) id() (string, error) {
	return "aws.datasync", nil
}

// Tasks

func (a *mqlAwsDatasync) tasks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTasks(conn), 5)
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

func (a *mqlAwsDatasync) getTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("datasync>getTasks>calling aws with region %s", region)

			svc := conn.DataSync(region)
			ctx := context.Background()
			res := []any{}

			paginator := datasync.NewListTasksPaginator(svc, &datasync.ListTasksInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS DataSync tasks API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, task := range page.Tasks {
					mqlTask, err := CreateResource(a.MqlRuntime, "aws.datasync.task",
						map[string]*llx.RawData{
							"__id":     llx.StringDataPtr(task.TaskArn),
							"arn":      llx.StringDataPtr(task.TaskArn),
							"name":     llx.StringDataPtr(task.Name),
							"region":   llx.StringData(region),
							"status":   llx.StringData(string(task.Status)),
							"taskMode": llx.StringData(string(task.TaskMode)),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTask)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDatasyncTask) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsDatasyncTaskInternal struct {
	lazyTags
	fetched  bool
	lock     sync.Mutex
	descResp *datasync.DescribeTaskOutput
}

func (a *mqlAwsDatasyncTask) fetchDetail() (*datasync.DescribeTaskOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DataSync(a.Region.Data)
	taskArn := a.Arn.Data
	resp, err := svc.DescribeTask(context.Background(), &datasync.DescribeTaskInput{TaskArn: &taskArn})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsDatasyncTask) locationRef(arn string, field *plugin.TValue[*mqlAwsDatasyncLocation]) (*mqlAwsDatasyncLocation, error) {
	if arn == "" {
		field.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlLoc, err := NewResource(a.MqlRuntime, "aws.datasync.location",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return mqlLoc.(*mqlAwsDatasyncLocation), nil
}

func (a *mqlAwsDatasyncTask) sourceLocation() (*mqlAwsDatasyncLocation, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return a.locationRef(convert.ToValue(resp.SourceLocationArn), &a.SourceLocation)
}

func (a *mqlAwsDatasyncTask) destinationLocation() (*mqlAwsDatasyncLocation, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return a.locationRef(convert.ToValue(resp.DestinationLocationArn), &a.DestinationLocation)
}

func (a *mqlAwsDatasyncTask) cloudwatchLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	logGroupArn := convert.ToValue(resp.CloudWatchLogGroupArn)
	if logGroupArn == "" {
		a.CloudwatchLogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlLogGroup, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup",
		map[string]*llx.RawData{"arn": llx.StringData(logGroupArn)})
	if err != nil {
		return nil, err
	}
	return mqlLogGroup.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsDatasyncTask) logLevel() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Options == nil {
		return "", nil
	}
	return string(resp.Options.LogLevel), nil
}

func (a *mqlAwsDatasyncTask) verifyMode() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Options == nil {
		return "", nil
	}
	return string(resp.Options.VerifyMode), nil
}

func (a *mqlAwsDatasyncTask) scheduleExpression() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Schedule == nil {
		return "", nil
	}
	return convert.ToValue(resp.Schedule.ScheduleExpression), nil
}

func (a *mqlAwsDatasyncTask) scheduleStatus() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.Schedule == nil {
		return "", nil
	}
	return string(resp.Schedule.Status), nil
}

func (a *mqlAwsDatasyncTask) createdAt() (*time.Time, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return resp.CreationTime, nil
}

// Locations

// initAwsDatasyncLocation resolves a location referenced by ARN, as a task's
// source and destination are, from the account's location list. Returning
// the bare args instead built a location with only its ARN set, and because
// init runs before the cache lookup, that blank copy also replaced the full
// one aws.datasync.locations had cached under the same ARN.
func initAwsDatasyncLocation(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	arnRaw, ok := args["arn"]
	if !ok || arnRaw == nil {
		return nil, nil, errors.New("aws.datasync.location requires an arn")
	}
	wantArn, ok := arnRaw.Value.(string)
	if !ok || wantArn == "" {
		return nil, nil, errors.New("aws.datasync.location requires an arn")
	}
	svc, err := NewResource(runtime, "aws.datasync", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	locations := svc.(*mqlAwsDatasync).GetLocations()
	if locations.Error != nil {
		return nil, nil, locations.Error
	}
	for _, raw := range locations.Data {
		if loc, ok := raw.(*mqlAwsDatasyncLocation); ok && loc.Arn.Data == wantArn {
			return args, loc, nil
		}
	}
	return nil, nil, fmt.Errorf("aws.datasync.location with arn %q not found", wantArn)
}

func (a *mqlAwsDatasync) locations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLocations(conn), 5)
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

func (a *mqlAwsDatasync) getLocations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("datasync>getLocations>calling aws with region %s", region)

			svc := conn.DataSync(region)
			ctx := context.Background()
			res := []any{}

			paginator := datasync.NewListLocationsPaginator(svc, &datasync.ListLocationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS DataSync locations API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, location := range page.Locations {
					uri := convert.ToValue(location.LocationUri)
					mqlLocation, err := CreateResource(a.MqlRuntime, "aws.datasync.location",
						map[string]*llx.RawData{
							"__id":         llx.StringDataPtr(location.LocationArn),
							"arn":          llx.StringDataPtr(location.LocationArn),
							"locationUri":  llx.StringData(uri),
							"locationType": llx.StringData(locationTypeFromUri(uri)),
							"region":       llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlLocation)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// locationTypeFromUri extracts the scheme from a DataSync location URI of the
// form TYPE://GLOBAL_ID/SUBDIR (e.g. "s3://my-bucket/prefix" -> "s3").
func locationTypeFromUri(uri string) string {
	scheme, _, found := strings.Cut(uri, "://")
	if !found {
		return ""
	}
	return scheme
}

func (a *mqlAwsDatasyncLocation) id() (string, error) {
	return a.Arn.Data, nil
}

// Agents

func (a *mqlAwsDatasync) agents() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAgents(conn), 5)
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

func (a *mqlAwsDatasync) getAgents(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("datasync>getAgents>calling aws with region %s", region)

			svc := conn.DataSync(region)
			ctx := context.Background()
			res := []any{}

			paginator := datasync.NewListAgentsPaginator(svc, &datasync.ListAgentsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS DataSync agents API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						return res, nil
					}
					return nil, err
				}

				for _, agent := range page.Agents {
					version := ""
					if agent.Platform != nil {
						version = convert.ToValue(agent.Platform.Version)
					}
					mqlAgent, err := CreateResource(a.MqlRuntime, "aws.datasync.agent",
						map[string]*llx.RawData{
							"__id":    llx.StringDataPtr(agent.AgentArn),
							"arn":     llx.StringDataPtr(agent.AgentArn),
							"name":    llx.StringDataPtr(agent.Name),
							"region":  llx.StringData(region),
							"status":  llx.StringData(string(agent.Status)),
							"version": llx.StringData(version),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAgent)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsDatasyncAgent) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsDatasyncAgentInternal struct {
	lazyTags
	fetched  bool
	lock     sync.Mutex
	descResp *datasync.DescribeAgentOutput
}

func (a *mqlAwsDatasyncAgent) fetchDetail() (*datasync.DescribeAgentOutput, error) {
	if a.fetched {
		return a.descResp, nil
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.fetched {
		return a.descResp, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.DataSync(a.Region.Data)
	agentArn := a.Arn.Data
	resp, err := svc.DescribeAgent(context.Background(), &datasync.DescribeAgentInput{AgentArn: &agentArn})
	if err != nil {
		return nil, err
	}
	a.fetched = true
	a.descResp = resp
	return resp, nil
}

func (a *mqlAwsDatasyncAgent) endpointType() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	return string(resp.EndpointType), nil
}

func (a *mqlAwsDatasyncAgent) vpcEndpointId() (string, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if resp.PrivateLinkConfig == nil {
		return "", nil
	}
	return convert.ToValue(resp.PrivateLinkConfig.VpcEndpointId), nil
}

func (a *mqlAwsDatasyncAgent) createdAt() (*time.Time, error) {
	resp, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	return resp.CreationTime, nil
}

type mqlAwsDatasyncLocationInternal struct {
	lazyTags
}

func (a *mqlAwsDatasyncTask) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return datasyncTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsDatasyncLocation) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return datasyncTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

func (a *mqlAwsDatasyncAgent) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return datasyncTagsForArn(a.MqlRuntime, a.Region.Data, a.Arn.Data)
	})
}

// datasyncTagsForArn reads the tags of a DataSync task, location, or agent,
// following the paginated ListTagsForResource response to the end.
func datasyncTagsForArn(runtime *plugin.Runtime, region, resourceArn string) (map[string]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.DataSync(region)
	ctx := context.Background()
	tags := map[string]any{}
	paginator := datasync.NewListTagsForResourcePaginator(svc, &datasync.ListTagsForResourceInput{ResourceArn: &resourceArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				if plugin.StructuredErrors() {
					return nil, llx.Forbidden(err, llx.WithPermissions("datasync:ListTagsForResource"))
				}
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		for k, v := range tagsToMap(page.Tags,
			func(t datasynctypes.TagListEntry) *string { return t.Key },
			func(t datasynctypes.TagListEntry) *string { return t.Value }) {
			tags[k] = v
		}
	}
	return tags, nil
}
