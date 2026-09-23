// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/qbusiness"
	qbusinesstypes "github.com/aws/aws-sdk-go-v2/service/qbusiness/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsQBusiness) id() (string, error) {
	return "aws.qBusiness", nil
}

// --- Applications ---

func (a *mqlAwsQBusiness) applications() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getApplications(conn), 5)
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

func (a *mqlAwsQBusiness) getApplications(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			svc := conn.QBusiness(region)
			ctx := context.Background()
			res := []any{}
			paginator := qbusiness.NewListApplicationsPaginator(svc, &qbusiness.ListApplicationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Q Business API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("q business is not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, app := range page.Applications {
					appId := convert.ToValue(app.ApplicationId)
					mqlApp, err := CreateResource(a.MqlRuntime, "aws.qBusiness.application", map[string]*llx.RawData{
						"__id":         llx.StringData(region + "/" + appId),
						"id":           llx.StringDataPtr(app.ApplicationId),
						"name":         llx.StringDataPtr(app.DisplayName),
						"region":       llx.StringData(region),
						"status":       llx.StringData(string(app.Status)),
						"identityType": llx.StringData(string(app.IdentityType)),
						"createdAt":    llx.TimeDataPtr(app.CreatedAt),
						"updatedAt":    llx.TimeDataPtr(app.UpdatedAt),
					})
					if err != nil {
						return nil, err
					}
					mqlAppRes := mqlApp.(*mqlAwsQBusinessApplication)
					mqlAppRes.cacheRegion = region
					res = append(res, mqlAppRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsQBusinessApplicationInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     bool
	detail      *qbusiness.GetApplicationOutput

	indicesLock    sync.Mutex
	indicesFetched bool
	indices_       []qbusinesstypes.Index
}

// listIndices lists the application's indices once and caches the summaries,
// so indices() and dataSources() share a single ListIndices round-trip.
func (a *mqlAwsQBusinessApplication) listIndices() ([]qbusinesstypes.Index, error) {
	if a.indicesFetched {
		return a.indices_, nil
	}
	a.indicesLock.Lock()
	defer a.indicesLock.Unlock()
	if a.indicesFetched {
		return a.indices_, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.Id.Data
	indices := []qbusinesstypes.Index{}
	paginator := qbusiness.NewListIndicesPaginator(svc, &qbusiness.ListIndicesInput{ApplicationId: &appId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "qbusiness:ListIndices")
		}
		indices = append(indices, page.Indices...)
	}
	a.indices_ = indices
	a.indicesFetched = true
	return indices, nil
}

func (a *mqlAwsQBusinessApplication) id() (string, error) {
	return a.Region.Data + "/" + a.Id.Data, nil
}

func (a *mqlAwsQBusinessApplication) fetchDetail() (*qbusiness.GetApplicationOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.Id.Data
	detail, err := svc.GetApplication(ctx, &qbusiness.GetApplicationInput{ApplicationId: &appId})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsQBusinessApplication) arn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.ApplicationArn), nil
}

func (a *mqlAwsQBusinessApplication) description() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.Description), nil
}

func (a *mqlAwsQBusinessApplication) roleArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.RoleArn), nil
}

func (a *mqlAwsQBusinessApplication) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.RoleArn == nil || *detail.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsQBusinessApplication) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.EncryptionConfiguration == nil || detail.EncryptionConfiguration.KmsKeyId == nil || *detail.EncryptionConfiguration.KmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key", map[string]*llx.RawData{
		"arn":    llx.StringDataPtr(detail.EncryptionConfiguration.KmsKeyId),
		"region": llx.StringData(a.Region.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsQBusinessApplication) indices() ([]any, error) {
	indices, err := a.listIndices()
	if err != nil {
		return nil, err
	}
	appId := a.Id.Data
	region := a.Region.Data
	res := []any{}
	for _, idx := range indices {
		indexId := convert.ToValue(idx.IndexId)
		mqlIdx, err := CreateResource(a.MqlRuntime, "aws.qBusiness.index", map[string]*llx.RawData{
			"__id":          llx.StringData(region + "/" + appId + "/index/" + indexId),
			"id":            llx.StringDataPtr(idx.IndexId),
			"applicationId": llx.StringData(appId),
			"name":          llx.StringDataPtr(idx.DisplayName),
			"region":        llx.StringData(region),
			"status":        llx.StringData(string(idx.Status)),
			"createdAt":     llx.TimeDataPtr(idx.CreatedAt),
			"updatedAt":     llx.TimeDataPtr(idx.UpdatedAt),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlIdx)
	}
	return res, nil
}

func (a *mqlAwsQBusinessApplication) dataSources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.Id.Data
	region := a.Region.Data
	res := []any{}

	indices, err := a.listIndices()
	if err != nil {
		return nil, err
	}
	for _, idx := range indices {
		indexId := convert.ToValue(idx.IndexId)
		dsPaginator := qbusiness.NewListDataSourcesPaginator(svc, &qbusiness.ListDataSourcesInput{
			ApplicationId: &appId,
			IndexId:       idx.IndexId,
		})
		for dsPaginator.HasMorePages() {
			dsPage, err := dsPaginator.NextPage(ctx)
			if err != nil {
				return nil, classifyAwsError(err, "qbusiness:ListDataSources")
			}
			for _, ds := range dsPage.DataSources {
				dataSourceId := convert.ToValue(ds.DataSourceId)
				mqlDs, err := CreateResource(a.MqlRuntime, "aws.qBusiness.dataSource", map[string]*llx.RawData{
					"__id":          llx.StringData(region + "/" + appId + "/" + indexId + "/datasource/" + dataSourceId),
					"id":            llx.StringDataPtr(ds.DataSourceId),
					"applicationId": llx.StringData(appId),
					"indexId":       llx.StringData(indexId),
					"name":          llx.StringDataPtr(ds.DisplayName),
					"type":          llx.StringDataPtr(ds.Type),
					"region":        llx.StringData(region),
					"status":        llx.StringData(string(ds.Status)),
					"createdAt":     llx.TimeDataPtr(ds.CreatedAt),
					"updatedAt":     llx.TimeDataPtr(ds.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				mqlDsRes := mqlDs.(*mqlAwsQBusinessDataSource)
				mqlDsRes.cacheRegion = region
				res = append(res, mqlDsRes)
			}
		}
	}
	return res, nil
}

func (a *mqlAwsQBusinessApplication) retrievers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.Id.Data
	region := a.Region.Data
	res := []any{}
	paginator := qbusiness.NewListRetrieversPaginator(svc, &qbusiness.ListRetrieversInput{ApplicationId: &appId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "qbusiness:ListRetrievers")
		}
		for _, r := range page.Retrievers {
			retrieverId := convert.ToValue(r.RetrieverId)
			mqlR, err := CreateResource(a.MqlRuntime, "aws.qBusiness.retriever", map[string]*llx.RawData{
				"__id":          llx.StringData(region + "/" + appId + "/retriever/" + retrieverId),
				"id":            llx.StringDataPtr(r.RetrieverId),
				"applicationId": llx.StringData(appId),
				"name":          llx.StringDataPtr(r.DisplayName),
				"region":        llx.StringData(region),
				"type":          llx.StringData(string(r.Type)),
				"status":        llx.StringData(string(r.Status)),
			})
			if err != nil {
				return nil, err
			}
			mqlRRes := mqlR.(*mqlAwsQBusinessRetriever)
			mqlRRes.cacheRegion = region
			res = append(res, mqlRRes)
		}
	}
	return res, nil
}

func (a *mqlAwsQBusinessApplication) plugins() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.Id.Data
	region := a.Region.Data
	res := []any{}
	paginator := qbusiness.NewListPluginsPaginator(svc, &qbusiness.ListPluginsInput{ApplicationId: &appId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "qbusiness:ListPlugins")
		}
		for _, p := range page.Plugins {
			pluginId := convert.ToValue(p.PluginId)
			mqlP, err := CreateResource(a.MqlRuntime, "aws.qBusiness.plugin", map[string]*llx.RawData{
				"__id":          llx.StringData(region + "/" + appId + "/plugin/" + pluginId),
				"id":            llx.StringDataPtr(p.PluginId),
				"applicationId": llx.StringData(appId),
				"name":          llx.StringDataPtr(p.DisplayName),
				"region":        llx.StringData(region),
				"type":          llx.StringData(string(p.Type)),
				"serverUrl":     llx.StringDataPtr(p.ServerUrl),
				"state":         llx.StringData(string(p.State)),
				"buildStatus":   llx.StringData(string(p.BuildStatus)),
				"createdAt":     llx.TimeDataPtr(p.CreatedAt),
				"updatedAt":     llx.TimeDataPtr(p.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlP)
		}
	}
	return res, nil
}

func (a *mqlAwsQBusinessApplication) webExperiences() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.Id.Data
	region := a.Region.Data
	res := []any{}
	paginator := qbusiness.NewListWebExperiencesPaginator(svc, &qbusiness.ListWebExperiencesInput{ApplicationId: &appId})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "qbusiness:ListWebExperiences")
		}
		for _, w := range page.WebExperiences {
			webExperienceId := convert.ToValue(w.WebExperienceId)
			mqlW, err := CreateResource(a.MqlRuntime, "aws.qBusiness.webExperience", map[string]*llx.RawData{
				"__id":            llx.StringData(region + "/" + appId + "/webexperience/" + webExperienceId),
				"id":              llx.StringDataPtr(w.WebExperienceId),
				"applicationId":   llx.StringData(appId),
				"region":          llx.StringData(region),
				"defaultEndpoint": llx.StringDataPtr(w.DefaultEndpoint),
				"status":          llx.StringData(string(w.Status)),
				"createdAt":       llx.TimeDataPtr(w.CreatedAt),
				"updatedAt":       llx.TimeDataPtr(w.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlW)
		}
	}
	return res, nil
}

// --- Index ---

func (a *mqlAwsQBusinessIndex) id() (string, error) {
	return a.Region.Data + "/" + a.ApplicationId.Data + "/index/" + a.Id.Data, nil
}

// --- Data source ---

type mqlAwsQBusinessDataSourceInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     bool
	detail      *qbusiness.GetDataSourceOutput
}

func (a *mqlAwsQBusinessDataSource) id() (string, error) {
	return a.Region.Data + "/" + a.ApplicationId.Data + "/" + a.IndexId.Data + "/datasource/" + a.Id.Data, nil
}

func (a *mqlAwsQBusinessDataSource) fetchDetail() (*qbusiness.GetDataSourceOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.ApplicationId.Data
	indexId := a.IndexId.Data
	dataSourceId := a.Id.Data
	detail, err := svc.GetDataSource(ctx, &qbusiness.GetDataSourceInput{
		ApplicationId: &appId,
		IndexId:       &indexId,
		DataSourceId:  &dataSourceId,
	})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsQBusinessDataSource) roleArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.RoleArn), nil
}

func (a *mqlAwsQBusinessDataSource) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.RoleArn == nil || *detail.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsQBusinessDataSource) syncSchedule() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.SyncSchedule), nil
}

// --- Retriever ---

type mqlAwsQBusinessRetrieverInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     bool
	detail      *qbusiness.GetRetrieverOutput
}

func (a *mqlAwsQBusinessRetriever) id() (string, error) {
	return a.Region.Data + "/" + a.ApplicationId.Data + "/retriever/" + a.Id.Data, nil
}

func (a *mqlAwsQBusinessRetriever) fetchDetail() (*qbusiness.GetRetrieverOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.QBusiness(a.cacheRegion)
	ctx := context.Background()
	appId := a.ApplicationId.Data
	retrieverId := a.Id.Data
	detail, err := svc.GetRetriever(ctx, &qbusiness.GetRetrieverInput{
		ApplicationId: &appId,
		RetrieverId:   &retrieverId,
	})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsQBusinessRetriever) roleArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.RoleArn), nil
}

func (a *mqlAwsQBusinessRetriever) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.RoleArn == nil || *detail.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

// --- Plugin ---

func (a *mqlAwsQBusinessPlugin) id() (string, error) {
	return a.Region.Data + "/" + a.ApplicationId.Data + "/plugin/" + a.Id.Data, nil
}

// --- Web experience ---

func (a *mqlAwsQBusinessWebExperience) id() (string, error) {
	return a.Region.Data + "/" + a.ApplicationId.Data + "/webexperience/" + a.Id.Data, nil
}
