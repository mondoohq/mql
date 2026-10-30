// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// ---- Init for lineageGroup cross-reference ----

func initAwsSagemakerLineageGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker lineage group")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetLineageGroups()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			lg := rawResource.(*mqlAwsSagemakerLineageGroup)
			if lg.Arn.Data == arnVal {
				return args, lg, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.lineageGroup with arn %q not found", arnVal)
}

// ---- Artifacts ----

func (a *mqlAwsSagemaker) artifacts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getArtifacts(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getArtifacts(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListArtifactsPaginator(svc, &sagemaker.ListArtifactsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, art := range page.ArtifactSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, art.ArtifactArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					var sourceUri string
					if art.Source != nil {
						sourceUri = convert.ToValue(art.Source.SourceUri)
					}

					mqlArt, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerArtifact,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(art.ArtifactArn),
							"name":           llx.StringDataPtr(art.ArtifactName),
							"artifactType":   llx.StringDataPtr(art.ArtifactType),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(art.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(art.LastModifiedTime),
							"sourceUri":      llx.StringData(sourceUri),
						})
					if err != nil {
						return nil, err
					}
					m := mqlArt.(*mqlAwsSagemakerArtifact)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
					}
					res = append(res, mqlArt)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerArtifactInternal struct {
	sagemakerTagsCache
	detailsLock          sync.Mutex
	detailsFetched       bool
	cacheProperties      map[string]any
	cacheLineageGroupArn string
}

func (a *mqlAwsSagemakerArtifact) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerArtifact) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerArtifact) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.DescribeArtifact(ctx, &sagemaker.DescribeArtifactInput{ArtifactArn: &arn})
	if err != nil {
		return err
	}
	a.cacheLineageGroupArn = convert.ToValue(resp.LineageGroupArn)
	a.cacheProperties = make(map[string]any, len(resp.Properties))
	for k, v := range resp.Properties {
		a.cacheProperties[k] = v
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerArtifact) properties() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheProperties, nil
}

func (a *mqlAwsSagemakerArtifact) lineageGroupArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheLineageGroupArn, nil
}

func (a *mqlAwsSagemakerArtifact) lineageGroup() (*mqlAwsSagemakerLineageGroup, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheLineageGroupArn == "" {
		a.LineageGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.lineageGroup",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheLineageGroupArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerLineageGroup), nil
}

// ---- Actions ----

func (a *mqlAwsSagemaker) actions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getActions(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getActions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListActionsPaginator(svc, &sagemaker.ListActionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, act := range page.ActionSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, act.ActionArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					var sourceUri string
					if act.Source != nil {
						sourceUri = convert.ToValue(act.Source.SourceUri)
					}

					mqlAct, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAction,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(act.ActionArn),
							"name":           llx.StringDataPtr(act.ActionName),
							"actionType":     llx.StringDataPtr(act.ActionType),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(act.Status)),
							"createdAt":      llx.TimeDataPtr(act.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(act.LastModifiedTime),
							"sourceUri":      llx.StringData(sourceUri),
						})
					if err != nil {
						return nil, err
					}
					m := mqlAct.(*mqlAwsSagemakerAction)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
					}
					res = append(res, mqlAct)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerActionInternal struct {
	sagemakerTagsCache
	detailsLock          sync.Mutex
	detailsFetched       bool
	cacheDescription     string
	cacheProperties      map[string]any
	cacheLineageGroupArn string
}

func (a *mqlAwsSagemakerAction) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerAction) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerAction) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeAction(ctx, &sagemaker.DescribeActionInput{ActionName: &name})
	if err != nil {
		return err
	}
	a.cacheDescription = convert.ToValue(resp.Description)
	a.cacheLineageGroupArn = convert.ToValue(resp.LineageGroupArn)
	a.cacheProperties = make(map[string]any, len(resp.Properties))
	for k, v := range resp.Properties {
		a.cacheProperties[k] = v
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerAction) description() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheDescription, nil
}

func (a *mqlAwsSagemakerAction) properties() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheProperties, nil
}

func (a *mqlAwsSagemakerAction) lineageGroupArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheLineageGroupArn, nil
}

func (a *mqlAwsSagemakerAction) lineageGroup() (*mqlAwsSagemakerLineageGroup, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheLineageGroupArn == "" {
		a.LineageGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.lineageGroup",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheLineageGroupArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerLineageGroup), nil
}

// ---- Contexts ----

func (a *mqlAwsSagemaker) contexts() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getContexts(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getContexts(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListContextsPaginator(svc, &sagemaker.ListContextsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, c := range page.ContextSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, c.ContextArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					var sourceUri string
					if c.Source != nil {
						sourceUri = convert.ToValue(c.Source.SourceUri)
					}

					mqlCtx, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerContext,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(c.ContextArn),
							"name":           llx.StringDataPtr(c.ContextName),
							"contextType":    llx.StringDataPtr(c.ContextType),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(c.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(c.LastModifiedTime),
							"sourceUri":      llx.StringData(sourceUri),
						})
					if err != nil {
						return nil, err
					}
					m := mqlCtx.(*mqlAwsSagemakerContext)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
					}
					res = append(res, mqlCtx)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerContextInternal struct {
	sagemakerTagsCache
	detailsLock          sync.Mutex
	detailsFetched       bool
	cacheDescription     string
	cacheProperties      map[string]any
	cacheLineageGroupArn string
}

func (a *mqlAwsSagemakerContext) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerContext) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerContext) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeContext(ctx, &sagemaker.DescribeContextInput{ContextName: &name})
	if err != nil {
		return err
	}
	a.cacheDescription = convert.ToValue(resp.Description)
	a.cacheLineageGroupArn = convert.ToValue(resp.LineageGroupArn)
	a.cacheProperties = make(map[string]any, len(resp.Properties))
	for k, v := range resp.Properties {
		a.cacheProperties[k] = v
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerContext) description() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheDescription, nil
}

func (a *mqlAwsSagemakerContext) properties() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheProperties, nil
}

func (a *mqlAwsSagemakerContext) lineageGroupArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheLineageGroupArn, nil
}

func (a *mqlAwsSagemakerContext) lineageGroup() (*mqlAwsSagemakerLineageGroup, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheLineageGroupArn == "" {
		a.LineageGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.lineageGroup",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheLineageGroupArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerLineageGroup), nil
}

// ---- Associations ----

func (a *mqlAwsSagemaker) associations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAssociations(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getAssociations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListAssociationsPaginator(svc, &sagemaker.ListAssociationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, as := range page.AssociationSummaries {
					mqlAs, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAssociation,
						map[string]*llx.RawData{
							"region":          llx.StringData(region),
							"associationType": llx.StringData(string(as.AssociationType)),
							"createdAt":       llx.TimeDataPtr(as.CreationTime),
							"sourceArn":       llx.StringDataPtr(as.SourceArn),
							"sourceName":      llx.StringDataPtr(as.SourceName),
							"sourceType":      llx.StringDataPtr(as.SourceType),
							"destinationArn":  llx.StringDataPtr(as.DestinationArn),
							"destinationName": llx.StringDataPtr(as.DestinationName),
							"destinationType": llx.StringDataPtr(as.DestinationType),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlAs)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsSagemakerAssociation) id() (string, error) {
	return a.Region.Data + "|" + a.SourceArn.Data + "|" + a.DestinationArn.Data + "|" + a.AssociationType.Data, nil
}

// ---- Lineage Groups ----

func (a *mqlAwsSagemaker) lineageGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLineageGroups(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getLineageGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Sagemaker(region)
			ctx := context.Background()
			res := []any{}

			paginator := sagemaker.NewListLineageGroupsPaginator(svc, &sagemaker.ListLineageGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, lg := range page.LineageGroupSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, lg.LineageGroupArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlLg, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerLineageGroup,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(lg.LineageGroupArn),
							"name":           llx.StringDataPtr(lg.LineageGroupName),
							"displayName":    llx.StringDataPtr(lg.DisplayName),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(lg.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(lg.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					m := mqlLg.(*mqlAwsSagemakerLineageGroup)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
					}
					res = append(res, mqlLg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerLineageGroupInternal struct {
	sagemakerTagsCache
	detailsLock      sync.Mutex
	detailsFetched   bool
	cacheDescription string
}

func (a *mqlAwsSagemakerLineageGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerLineageGroup) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerLineageGroup) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	name := a.Name.Data
	resp, err := svc.DescribeLineageGroup(ctx, &sagemaker.DescribeLineageGroupInput{LineageGroupName: &name})
	if err != nil {
		return err
	}
	a.cacheDescription = convert.ToValue(resp.Description)
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerLineageGroup) description() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheDescription, nil
}
