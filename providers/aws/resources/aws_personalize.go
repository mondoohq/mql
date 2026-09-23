// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/personalize"
	personalizetypes "github.com/aws/aws-sdk-go-v2/service/personalize/types"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// logPersonalizeDescribeWarn logs a warning when a best-effort Personalize
// Describe call fails for a reason other than access-denied. The list summaries
// omit some detail fields, so a swallowed Describe error would otherwise leave
// those fields at their defaults and look like real values; logging keeps the
// gap observable. Access-denied is expected under least-privilege and stays quiet.
func logPersonalizeDescribeWarn(err error, resource, arn string) {
	if err == nil || Is400AccessDeniedError(err) {
		return
	}
	log.Warn().Err(err).Str("arn", arn).Msgf("could not describe personalize %s", resource)
}

func (a *mqlAwsPersonalizeDatasetGroup) id() (string, error) { return a.Arn.Data, nil }
func (a *mqlAwsPersonalizeDataset) id() (string, error)      { return a.Arn.Data, nil }
func (a *mqlAwsPersonalizeSolution) id() (string, error)     { return a.Arn.Data, nil }
func (a *mqlAwsPersonalizeCampaign) id() (string, error)     { return a.Arn.Data, nil }
func (a *mqlAwsPersonalizeRecommender) id() (string, error)  { return a.Arn.Data, nil }
func (a *mqlAwsPersonalizeEventTracker) id() (string, error) { return a.Arn.Data, nil }
func (a *mqlAwsPersonalizeFilter) id() (string, error)       { return a.Arn.Data, nil }
func (a *mqlAwsPersonalizeSchema) id() (string, error)       { return a.Arn.Data, nil }

func (a *mqlAwsPersonalize) datasetGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getDatasetGroups(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsPersonalize) getDatasetGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("personalize>getDatasetGroups>region %s", region)
			svc := conn.Personalize(region)
			ctx := context.Background()
			res := []any{}

			paginator := personalize.NewListDatasetGroupsPaginator(svc, &personalize.ListDatasetGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Personalize API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("Personalize is not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, dg := range page.DatasetGroups {
					mqlDg, err := a.buildDatasetGroup(svc, region, dg)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlDg)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsPersonalizeDatasetGroupInternal struct {
	region         string
	cacheKmsKeyArn *string
	cacheRoleArn   *string
}

func (a *mqlAwsPersonalize) buildDatasetGroup(svc *personalize.Client, region string, dg personalizetypes.DatasetGroupSummary) (*mqlAwsPersonalizeDatasetGroup, error) {
	args := map[string]*llx.RawData{
		"arn":           llx.StringDataPtr(dg.DatasetGroupArn),
		"name":          llx.StringDataPtr(dg.Name),
		"status":        llx.StringDataPtr(dg.Status),
		"domain":        llx.StringData(string(dg.Domain)),
		"failureReason": llx.StringDataPtr(dg.FailureReason),
		"region":        llx.StringData(region),
		"createdAt":     llx.TimeDataPtr(dg.CreationDateTime),
		"updatedAt":     llx.TimeDataPtr(dg.LastUpdatedDateTime),
	}
	resource, err := CreateResource(a.MqlRuntime, "aws.personalize.datasetGroup", args)
	if err != nil {
		return nil, err
	}
	mqlDg := resource.(*mqlAwsPersonalizeDatasetGroup)
	mqlDg.region = region

	// The list summary omits the KMS key and service role; fetch them so the
	// kmsKey and iamRole accessors can resolve. Best-effort: leave both null on
	// an access-denied response rather than failing the whole collection.
	detail, err := svc.DescribeDatasetGroup(context.Background(), &personalize.DescribeDatasetGroupInput{DatasetGroupArn: dg.DatasetGroupArn})
	if err != nil {
		if !Is400AccessDeniedError(err) {
			log.Warn().Err(err).Str("arn", aws.ToString(dg.DatasetGroupArn)).Msg("could not describe personalize dataset group")
		}
		return mqlDg, nil
	}
	if detail.DatasetGroup != nil {
		mqlDg.cacheKmsKeyArn = detail.DatasetGroup.KmsKeyArn
		mqlDg.cacheRoleArn = detail.DatasetGroup.RoleArn
	}
	return mqlDg, nil
}

func (a *mqlAwsPersonalizeDatasetGroup) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyArn == nil || *a.cacheKmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheKmsKeyArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsPersonalizeDatasetGroup) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role", map[string]*llx.RawData{
		"arn": llx.StringDataPtr(a.cacheRoleArn),
	})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

type mqlAwsPersonalizeDatasetInternal struct {
	region         string
	cacheSchemaArn *string
}

func (a *mqlAwsPersonalizeDatasetGroup) datasets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Personalize(a.region)
	ctx := context.Background()
	res := []any{}

	paginator := personalize.NewListDatasetsPaginator(svc, &personalize.ListDatasetsInput{DatasetGroupArn: &a.Arn.Data})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "personalize:ListDatasets")
		}
		for _, ds := range page.Datasets {
			args := map[string]*llx.RawData{
				"arn":         llx.StringDataPtr(ds.DatasetArn),
				"name":        llx.StringDataPtr(ds.Name),
				"datasetType": llx.StringDataPtr(ds.DatasetType),
				"status":      llx.StringDataPtr(ds.Status),
				"createdAt":   llx.TimeDataPtr(ds.CreationDateTime),
				"updatedAt":   llx.TimeDataPtr(ds.LastUpdatedDateTime),
			}
			resource, err := CreateResource(a.MqlRuntime, "aws.personalize.dataset", args)
			if err != nil {
				return nil, err
			}
			mqlDs := resource.(*mqlAwsPersonalizeDataset)
			mqlDs.region = a.region
			// The schema ARN is only returned by DescribeDataset; cache it for the
			// schema accessor.
			detail, err := svc.DescribeDataset(ctx, &personalize.DescribeDatasetInput{DatasetArn: ds.DatasetArn})
			if err != nil {
				logPersonalizeDescribeWarn(err, "dataset", aws.ToString(ds.DatasetArn))
			} else if detail.Dataset != nil {
				mqlDs.cacheSchemaArn = detail.Dataset.SchemaArn
			}
			res = append(res, mqlDs)
		}
	}
	return res, nil
}

func (a *mqlAwsPersonalizeDataset) schema() (*mqlAwsPersonalizeSchema, error) {
	if a.cacheSchemaArn == nil || *a.cacheSchemaArn == "" {
		a.Schema.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Personalize(a.region)
	detail, err := svc.DescribeSchema(context.Background(), &personalize.DescribeSchemaInput{SchemaArn: a.cacheSchemaArn})
	if err != nil {
		return nil, classifyAwsError(err, "personalize:DescribeSchema")
	}
	if detail.Schema == nil {
		a.Schema.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return buildSchemaResource(a.MqlRuntime, detail.Schema)
}

func (a *mqlAwsPersonalizeDatasetGroup) solutions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Personalize(a.region)
	ctx := context.Background()
	res := []any{}

	paginator := personalize.NewListSolutionsPaginator(svc, &personalize.ListSolutionsInput{DatasetGroupArn: &a.Arn.Data})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "personalize:ListSolutions")
		}
		for _, s := range page.Solutions {
			args := map[string]*llx.RawData{
				"arn":           llx.StringDataPtr(s.SolutionArn),
				"name":          llx.StringDataPtr(s.Name),
				"status":        llx.StringDataPtr(s.Status),
				"recipe":        llx.StringDataPtr(s.RecipeArn),
				"eventType":     llx.StringData(""),
				"performAutoML": llx.BoolData(false),
				"performHPO":    llx.BoolData(false),
				"createdAt":     llx.TimeDataPtr(s.CreationDateTime),
				"updatedAt":     llx.TimeDataPtr(s.LastUpdatedDateTime),
			}
			// eventType, performAutoML and performHPO come only from DescribeSolution.
			detail, err := svc.DescribeSolution(ctx, &personalize.DescribeSolutionInput{SolutionArn: s.SolutionArn})
			if err != nil {
				logPersonalizeDescribeWarn(err, "solution", aws.ToString(s.SolutionArn))
			} else if detail.Solution != nil {
				args["eventType"] = llx.StringDataPtr(detail.Solution.EventType)
				args["performAutoML"] = llx.BoolData(detail.Solution.PerformAutoML)
				args["performHPO"] = llx.BoolData(detail.Solution.PerformHPO)
			}
			resource, err := CreateResource(a.MqlRuntime, "aws.personalize.solution", args)
			if err != nil {
				return nil, err
			}
			mqlSol := resource.(*mqlAwsPersonalizeSolution)
			mqlSol.region = a.region
			res = append(res, mqlSol)
		}
	}
	return res, nil
}

type mqlAwsPersonalizeSolutionInternal struct {
	region string
}

func (a *mqlAwsPersonalizeSolution) campaigns() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Personalize(a.region)
	ctx := context.Background()
	res := []any{}

	paginator := personalize.NewListCampaignsPaginator(svc, &personalize.ListCampaignsInput{SolutionArn: &a.Arn.Data})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "personalize:ListCampaigns")
		}
		for _, c := range page.Campaigns {
			args := map[string]*llx.RawData{
				"arn":               llx.StringDataPtr(c.CampaignArn),
				"name":              llx.StringDataPtr(c.Name),
				"status":            llx.StringDataPtr(c.Status),
				"failureReason":     llx.StringDataPtr(c.FailureReason),
				"solutionVersion":   llx.StringData(""),
				"minProvisionedTPS": llx.NilData,
				"createdAt":         llx.TimeDataPtr(c.CreationDateTime),
				"updatedAt":         llx.TimeDataPtr(c.LastUpdatedDateTime),
			}
			// The serving capacity and solution version come only from DescribeCampaign.
			detail, err := svc.DescribeCampaign(ctx, &personalize.DescribeCampaignInput{CampaignArn: c.CampaignArn})
			if err != nil {
				logPersonalizeDescribeWarn(err, "campaign", aws.ToString(c.CampaignArn))
			} else if detail.Campaign != nil {
				args["solutionVersion"] = llx.StringDataPtr(detail.Campaign.SolutionVersionArn)
				args["minProvisionedTPS"] = llx.IntDataPtr(detail.Campaign.MinProvisionedTPS)
			}
			resource, err := CreateResource(a.MqlRuntime, "aws.personalize.campaign", args)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}
	return res, nil
}

func (a *mqlAwsPersonalizeDatasetGroup) recommenders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Personalize(a.region)
	ctx := context.Background()
	res := []any{}

	paginator := personalize.NewListRecommendersPaginator(svc, &personalize.ListRecommendersInput{DatasetGroupArn: &a.Arn.Data})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "personalize:ListRecommenders")
		}
		for _, r := range page.Recommenders {
			failureReason := ""
			// RecommenderSummary omits failureReason; DescribeRecommender supplies it.
			detail, err := svc.DescribeRecommender(ctx, &personalize.DescribeRecommenderInput{RecommenderArn: r.RecommenderArn})
			if err != nil {
				logPersonalizeDescribeWarn(err, "recommender", aws.ToString(r.RecommenderArn))
			} else if detail.Recommender != nil {
				failureReason = aws.ToString(detail.Recommender.FailureReason)
			}
			args := map[string]*llx.RawData{
				"arn":           llx.StringDataPtr(r.RecommenderArn),
				"name":          llx.StringDataPtr(r.Name),
				"status":        llx.StringDataPtr(r.Status),
				"recipe":        llx.StringDataPtr(r.RecipeArn),
				"failureReason": llx.StringData(failureReason),
				"createdAt":     llx.TimeDataPtr(r.CreationDateTime),
				"updatedAt":     llx.TimeDataPtr(r.LastUpdatedDateTime),
			}
			resource, err := CreateResource(a.MqlRuntime, "aws.personalize.recommender", args)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}
	return res, nil
}

func (a *mqlAwsPersonalizeDatasetGroup) eventTrackers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Personalize(a.region)
	ctx := context.Background()
	res := []any{}

	paginator := personalize.NewListEventTrackersPaginator(svc, &personalize.ListEventTrackersInput{DatasetGroupArn: &a.Arn.Data})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "personalize:ListEventTrackers")
		}
		for _, et := range page.EventTrackers {
			trackingId := ""
			accountId := ""
			// The tracking ID and account come only from DescribeEventTracker.
			detail, err := svc.DescribeEventTracker(ctx, &personalize.DescribeEventTrackerInput{EventTrackerArn: et.EventTrackerArn})
			if err != nil {
				logPersonalizeDescribeWarn(err, "event tracker", aws.ToString(et.EventTrackerArn))
			} else if detail.EventTracker != nil {
				trackingId = aws.ToString(detail.EventTracker.TrackingId)
				accountId = aws.ToString(detail.EventTracker.AccountId)
			}
			args := map[string]*llx.RawData{
				"arn":        llx.StringDataPtr(et.EventTrackerArn),
				"name":       llx.StringDataPtr(et.Name),
				"status":     llx.StringDataPtr(et.Status),
				"trackingId": llx.StringData(trackingId),
				"accountId":  llx.StringData(accountId),
				"createdAt":  llx.TimeDataPtr(et.CreationDateTime),
				"updatedAt":  llx.TimeDataPtr(et.LastUpdatedDateTime),
			}
			resource, err := CreateResource(a.MqlRuntime, "aws.personalize.eventTracker", args)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}
	return res, nil
}

func (a *mqlAwsPersonalizeDatasetGroup) filters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Personalize(a.region)
	ctx := context.Background()
	res := []any{}

	paginator := personalize.NewListFiltersPaginator(svc, &personalize.ListFiltersInput{DatasetGroupArn: &a.Arn.Data})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "personalize:ListFilters")
		}
		for _, f := range page.Filters {
			filterExpression := ""
			// The filter expression comes only from DescribeFilter.
			detail, err := svc.DescribeFilter(ctx, &personalize.DescribeFilterInput{FilterArn: f.FilterArn})
			if err != nil {
				logPersonalizeDescribeWarn(err, "filter", aws.ToString(f.FilterArn))
			} else if detail.Filter != nil {
				filterExpression = aws.ToString(detail.Filter.FilterExpression)
			}
			args := map[string]*llx.RawData{
				"arn":              llx.StringDataPtr(f.FilterArn),
				"name":             llx.StringDataPtr(f.Name),
				"status":           llx.StringDataPtr(f.Status),
				"filterExpression": llx.StringData(filterExpression),
				"createdAt":        llx.TimeDataPtr(f.CreationDateTime),
				"updatedAt":        llx.TimeDataPtr(f.LastUpdatedDateTime),
			}
			resource, err := CreateResource(a.MqlRuntime, "aws.personalize.filter", args)
			if err != nil {
				return nil, err
			}
			res = append(res, resource)
		}
	}
	return res, nil
}

func (a *mqlAwsPersonalize) schemas() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSchemas(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsPersonalize) getSchemas(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("personalize>getSchemas>region %s", region)
			svc := conn.Personalize(region)
			ctx := context.Background()
			res := []any{}

			paginator := personalize.NewListSchemasPaginator(svc, &personalize.ListSchemasInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS Personalize API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("Personalize is not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, sm := range page.Schemas {
					// ListSchemas omits the raw Avro definition; DescribeSchema supplies it.
					detail, err := svc.DescribeSchema(ctx, &personalize.DescribeSchemaInput{SchemaArn: sm.SchemaArn})
					if err != nil {
						if Is400AccessDeniedError(err) {
							continue
						}
						return nil, err
					}
					if detail.Schema == nil {
						continue
					}
					mqlSchema, err := buildSchemaResource(a.MqlRuntime, detail.Schema)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSchema)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// buildSchemaResource maps a Personalize DatasetSchema into an MQL resource.
// Callers must pass a non-nil schema; the two call sites guard for nil and set
// the field state or skip the entry accordingly.
func buildSchemaResource(runtime *plugin.Runtime, schema *personalizetypes.DatasetSchema) (*mqlAwsPersonalizeSchema, error) {
	args := map[string]*llx.RawData{
		"arn":       llx.StringDataPtr(schema.SchemaArn),
		"name":      llx.StringDataPtr(schema.Name),
		"domain":    llx.StringData(string(schema.Domain)),
		"schema":    llx.StringDataPtr(schema.Schema),
		"createdAt": llx.TimeDataPtr(schema.CreationDateTime),
		"updatedAt": llx.TimeDataPtr(schema.LastUpdatedDateTime),
	}
	resource, err := CreateResource(runtime, "aws.personalize.schema", args)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsPersonalizeSchema), nil
}
