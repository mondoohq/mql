// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

// parseSagemakerArn extracts (partition, region, accountID, resourceName) from a SageMaker ARN.
// Returns empty strings for missing parts.
func parseSagemakerArn(arn string) (partition, region, account, name string) {
	parts := strings.Split(arn, ":")
	if len(parts) >= 6 {
		partition = parts[1]
		region = parts[3]
		account = parts[4]
		if slash := strings.Index(parts[5], "/"); slash >= 0 {
			name = parts[5][slash+1:]
		}
	}
	return
}

func initAwsSagemakerExperiment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker experiment")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetExperiments()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			e := rawResource.(*mqlAwsSagemakerExperiment)
			if e.Arn.Data == arnVal {
				return args, e, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.experiment with arn %q not found", arnVal)
}

func initAwsSagemakerModel(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSagemakerModel); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker model")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetModels()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			m := rawResource.(*mqlAwsSagemakerModel)
			if m.Arn.Data == arnVal {
				return args, m, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.model with arn %q not found", arnVal)
}

// ---- Experiments ----

func (a *mqlAwsSagemaker) experiments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getExperiments(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getExperiments(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListExperimentsPaginator(svc, &sagemaker.ListExperimentsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, exp := range page.ExperimentSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, exp.ExperimentArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("experiment", exp.ExperimentArn).Msg("skipping sagemaker experiment due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlExp, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerExperiment,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(exp.ExperimentArn),
							"name":           llx.StringDataPtr(exp.ExperimentName),
							"displayName":    llx.StringDataPtr(exp.DisplayName),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(exp.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(exp.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					e := mqlExp.(*mqlAwsSagemakerExperiment)
					if eagerTags != nil {
						e.cacheTags = eagerTags
						e.tagsFetched = true
					}
					res = append(res, mqlExp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerExperimentInternal struct {
	sagemakerTagsCache
	detailsFetched   bool
	detailsLock      sync.Mutex
	cacheDescription *string
	cacheSourceArn   *string
	cacheSourceType  string
}

func (a *mqlAwsSagemakerExperiment) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerExperiment) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerExperiment) fetchDetails() error {
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
	resp, err := svc.DescribeExperiment(ctx, &sagemaker.DescribeExperimentInput{ExperimentName: &name})
	if err != nil {
		return err
	}

	a.cacheDescription = resp.Description
	if resp.Source != nil {
		a.cacheSourceArn = resp.Source.SourceArn
		a.cacheSourceType = convert.ToValue(resp.Source.SourceType)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerExperiment) description() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return convert.ToValue(a.cacheDescription), nil
}

func (a *mqlAwsSagemakerExperiment) source() (*mqlAwsSagemakerExperimentSource, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheSourceArn == nil {
		a.Source.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerExperimentSource,
		map[string]*llx.RawData{
			"__id":       llx.StringData(a.Arn.Data + "/source"),
			"sourceArn":  llx.StringDataPtr(a.cacheSourceArn),
			"sourceType": llx.StringData(a.cacheSourceType),
		})
	if err != nil {
		return nil, err
	}
	r := mqlRes.(*mqlAwsSagemakerExperimentSource)
	r.cacheParentArn = a.Arn.Data
	return r, nil
}

type mqlAwsSagemakerExperimentSourceInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerExperimentSource) id() (string, error) {
	return a.cacheParentArn + "/source", nil
}

// ---- Trials ----

func (a *mqlAwsSagemaker) trials() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTrials(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getTrials(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListTrialsPaginator(svc, &sagemaker.ListTrialsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, trial := range page.TrialSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, trial.TrialArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("trial", trial.TrialArn).Msg("skipping sagemaker trial due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlTrial, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTrial,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(trial.TrialArn),
							"name":           llx.StringDataPtr(trial.TrialName),
							"displayName":    llx.StringDataPtr(trial.DisplayName),
							"region":         llx.StringData(region),
							"createdAt":      llx.TimeDataPtr(trial.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(trial.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					t := mqlTrial.(*mqlAwsSagemakerTrial)
					if eagerTags != nil {
						t.cacheTags = eagerTags
						t.tagsFetched = true
					}
					res = append(res, mqlTrial)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerTrialInternal struct {
	sagemakerTagsCache
	detailsFetched      bool
	detailsLock         sync.Mutex
	cacheExperimentName string
	cacheSourceArn      *string
	cacheSourceType     string
}

func (a *mqlAwsSagemakerTrial) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerTrial) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerTrial) fetchDetails() error {
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
	resp, err := svc.DescribeTrial(ctx, &sagemaker.DescribeTrialInput{TrialName: &name})
	if err != nil {
		return err
	}

	a.cacheExperimentName = convert.ToValue(resp.ExperimentName)
	if resp.Source != nil {
		a.cacheSourceArn = resp.Source.SourceArn
		a.cacheSourceType = convert.ToValue(resp.Source.SourceType)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerTrial) experiment() (*mqlAwsSagemakerExperiment, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheExperimentName == "" {
		a.Experiment.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	partition := "aws"
	if parts := strings.SplitN(a.Arn.Data, ":", 3); len(parts) >= 2 {
		partition = parts[1]
	}
	experimentArn := fmt.Sprintf("arn:%s:sagemaker:%s:%s:experiment/%s", partition, a.Region.Data, conn.AccountId(), a.cacheExperimentName)
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.experiment",
		map[string]*llx.RawData{
			"arn":    llx.StringData(experimentArn),
			"name":   llx.StringData(a.cacheExperimentName),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerExperiment), nil
}

func (a *mqlAwsSagemakerTrial) source() (*mqlAwsSagemakerTrialSource, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheSourceArn == nil {
		a.Source.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTrialSource,
		map[string]*llx.RawData{
			"__id":       llx.StringData(a.Arn.Data + "/source"),
			"sourceArn":  llx.StringDataPtr(a.cacheSourceArn),
			"sourceType": llx.StringData(a.cacheSourceType),
		})
	if err != nil {
		return nil, err
	}
	r := mqlRes.(*mqlAwsSagemakerTrialSource)
	r.cacheParentArn = a.Arn.Data
	return r, nil
}

func (a *mqlAwsSagemakerTrial) components() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Sagemaker(a.Region.Data)
	ctx := context.Background()
	trialName := a.Name.Data

	res := []any{}
	paginator := sagemaker.NewListTrialComponentsPaginator(svc, &sagemaker.ListTrialComponentsInput{
		TrialName: &trialName,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, tc := range page.TrialComponentSummaries {
			var status string
			if tc.Status != nil {
				status = string(tc.Status.PrimaryStatus)
			}
			mqlTC, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTrialComponent,
				map[string]*llx.RawData{
					"arn":            llx.StringDataPtr(tc.TrialComponentArn),
					"name":           llx.StringDataPtr(tc.TrialComponentName),
					"displayName":    llx.StringDataPtr(tc.DisplayName),
					"region":         llx.StringData(a.Region.Data),
					"status":         llx.StringData(status),
					"createdAt":      llx.TimeDataPtr(tc.CreationTime),
					"lastModifiedAt": llx.TimeDataPtr(tc.LastModifiedTime),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlTC)
		}
	}
	return res, nil
}

type mqlAwsSagemakerTrialSourceInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerTrialSource) id() (string, error) {
	return a.cacheParentArn + "/source", nil
}

// ---- Trial Components ----

func (a *mqlAwsSagemaker) trialComponents() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTrialComponents(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getTrialComponents(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListTrialComponentsPaginator(svc, &sagemaker.ListTrialComponentsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, tc := range page.TrialComponentSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, tc.TrialComponentArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("trialComponent", tc.TrialComponentArn).Msg("skipping sagemaker trial component due to filters")
							continue
						}
						eagerTags = tags
					}

					var status string
					if tc.Status != nil {
						status = string(tc.Status.PrimaryStatus)
					}

					mqlTC, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTrialComponent,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(tc.TrialComponentArn),
							"name":           llx.StringDataPtr(tc.TrialComponentName),
							"displayName":    llx.StringDataPtr(tc.DisplayName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(status),
							"createdAt":      llx.TimeDataPtr(tc.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(tc.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					tcRes := mqlTC.(*mqlAwsSagemakerTrialComponent)
					if eagerTags != nil {
						tcRes.cacheTags = eagerTags
						tcRes.tagsFetched = true
					}
					res = append(res, mqlTC)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerTrialComponentInternal struct {
	sagemakerTagsCache
	detailsFetched       bool
	detailsLock          sync.Mutex
	cacheSourceArn       *string
	cacheSourceType      string
	cacheMetrics         []any
	cacheParameters      any
	cacheInputArtifacts  any
	cacheOutputArtifacts any
}

func (a *mqlAwsSagemakerTrialComponent) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerTrialComponent) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerTrialComponent) fetchDetails() error {
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
	resp, err := svc.DescribeTrialComponent(ctx, &sagemaker.DescribeTrialComponentInput{TrialComponentName: &name})
	if err != nil {
		return err
	}

	if resp.Source != nil {
		a.cacheSourceArn = resp.Source.SourceArn
		a.cacheSourceType = convert.ToValue(resp.Source.SourceType)
	}

	if params, err := convert.JsonToDict(resp.Parameters); err == nil {
		a.cacheParameters = params
	}
	if in, err := convert.JsonToDict(resp.InputArtifacts); err == nil {
		a.cacheInputArtifacts = in
	}
	if out, err := convert.JsonToDict(resp.OutputArtifacts); err == nil {
		a.cacheOutputArtifacts = out
	}

	// Build metrics
	metrics := make([]any, 0, len(resp.Metrics))
	for _, m := range resp.Metrics {
		var minVal, maxVal, avgVal, lastVal, stdDevVal float64
		var countVal int64
		if m.Min != nil {
			minVal = *m.Min
		}
		if m.Max != nil {
			maxVal = *m.Max
		}
		if m.Avg != nil {
			avgVal = *m.Avg
		}
		if m.Count != nil {
			countVal = int64(*m.Count)
		}
		if m.Last != nil {
			lastVal = *m.Last
		}
		if m.StdDev != nil {
			stdDevVal = *m.StdDev
		}
		mqlMetric, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTrialComponentMetricSummary,
			map[string]*llx.RawData{
				"__id":       llx.StringData(a.Arn.Data + "/metric/" + convert.ToValue(m.MetricName)),
				"metricName": llx.StringDataPtr(m.MetricName),
				"sourceArn":  llx.StringDataPtr(m.SourceArn),
				"min":        llx.FloatData(minVal),
				"max":        llx.FloatData(maxVal),
				"avg":        llx.FloatData(avgVal),
				"count":      llx.IntData(countVal),
				"last":       llx.FloatData(lastVal),
				"stdDev":     llx.FloatData(stdDevVal),
			})
		if err != nil {
			return err
		}
		ms := mqlMetric.(*mqlAwsSagemakerTrialComponentMetricSummary)
		ms.cacheParentArn = a.Arn.Data
		metrics = append(metrics, mqlMetric)
	}
	a.cacheMetrics = metrics
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerTrialComponent) source() (*mqlAwsSagemakerTrialComponentSource, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheSourceArn == nil {
		a.Source.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTrialComponentSource,
		map[string]*llx.RawData{
			"__id":       llx.StringData(a.Arn.Data + "/source"),
			"sourceArn":  llx.StringDataPtr(a.cacheSourceArn),
			"sourceType": llx.StringData(a.cacheSourceType),
		})
	if err != nil {
		return nil, err
	}
	r := mqlRes.(*mqlAwsSagemakerTrialComponentSource)
	r.cacheParentArn = a.Arn.Data
	return r, nil
}

func (a *mqlAwsSagemakerTrialComponent) metrics() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheMetrics, nil
}

func (a *mqlAwsSagemakerTrialComponent) parameters() (any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheParameters, nil
}

func (a *mqlAwsSagemakerTrialComponent) inputArtifacts() (any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheInputArtifacts, nil
}

func (a *mqlAwsSagemakerTrialComponent) outputArtifacts() (any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheOutputArtifacts, nil
}

type mqlAwsSagemakerTrialComponentSourceInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerTrialComponentSource) id() (string, error) {
	return a.cacheParentArn + "/source", nil
}

type mqlAwsSagemakerTrialComponentMetricSummaryInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerTrialComponentMetricSummary) id() (string, error) {
	return a.cacheParentArn + "/metric/" + a.MetricName.Data, nil
}

// ---- Projects ----

func (a *mqlAwsSagemaker) projects() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getProjects(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getProjects(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListProjectsPaginator(svc, &sagemaker.ListProjectsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, proj := range page.ProjectSummaryList {
					mqlProj, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerProject,
						map[string]*llx.RawData{
							"arn":         llx.StringDataPtr(proj.ProjectArn),
							"name":        llx.StringDataPtr(proj.ProjectName),
							"projectId":   llx.StringDataPtr(proj.ProjectId),
							"description": llx.StringDataPtr(proj.ProjectDescription),
							"region":      llx.StringData(region),
							"status":      llx.StringData(string(proj.ProjectStatus)),
							"createdAt":   llx.TimeDataPtr(proj.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlProj)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerProjectInternal struct {
	sagemakerTagsCache
	detailsFetched                       bool
	detailsLock                          sync.Mutex
	cacheProvisioningProductId           string
	cacheProvisioningArtifactId          string
	cacheProvisioningPathId              string
	cacheProvisioningParams              []any
	cacheProvisionedProductId            string
	cacheProvisionedProductStatusMessage string
}

func (a *mqlAwsSagemakerProject) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerProject) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerProject) fetchDetails() error {
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
	resp, err := svc.DescribeProject(ctx, &sagemaker.DescribeProjectInput{ProjectName: &name})
	if err != nil {
		return err
	}

	if resp.ServiceCatalogProvisioningDetails != nil {
		a.cacheProvisioningProductId = convert.ToValue(resp.ServiceCatalogProvisioningDetails.ProductId)
		a.cacheProvisioningArtifactId = convert.ToValue(resp.ServiceCatalogProvisioningDetails.ProvisioningArtifactId)
		a.cacheProvisioningPathId = convert.ToValue(resp.ServiceCatalogProvisioningDetails.PathId)

		params := make([]any, 0, len(resp.ServiceCatalogProvisioningDetails.ProvisioningParameters))
		for _, p := range resp.ServiceCatalogProvisioningDetails.ProvisioningParameters {
			mqlParam, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerProjectProvisioningParameter,
				map[string]*llx.RawData{
					"__id":  llx.StringData(a.Arn.Data + "/provisioningParam/" + convert.ToValue(p.Key)),
					"key":   llx.StringDataPtr(p.Key),
					"value": llx.StringDataPtr(p.Value),
				})
			if err != nil {
				return err
			}
			pp := mqlParam.(*mqlAwsSagemakerProjectProvisioningParameter)
			pp.cacheParentArn = a.Arn.Data
			params = append(params, mqlParam)
		}
		a.cacheProvisioningParams = params
	}
	if resp.ServiceCatalogProvisionedProductDetails != nil {
		a.cacheProvisionedProductId = convert.ToValue(resp.ServiceCatalogProvisionedProductDetails.ProvisionedProductId)
		a.cacheProvisionedProductStatusMessage = convert.ToValue(resp.ServiceCatalogProvisionedProductDetails.ProvisionedProductStatusMessage)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerProject) serviceCatalogProvisioningDetails() (*mqlAwsSagemakerProjectProvisioningDetails, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheProvisioningProductId == "" {
		a.ServiceCatalogProvisioningDetails.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerProjectProvisioningDetails,
		map[string]*llx.RawData{
			"__id":                   llx.StringData(a.Arn.Data + "/provisioningDetails"),
			"productId":              llx.StringData(a.cacheProvisioningProductId),
			"provisioningArtifactId": llx.StringData(a.cacheProvisioningArtifactId),
			"pathId":                 llx.StringData(a.cacheProvisioningPathId),
		})
	if err != nil {
		return nil, err
	}
	pd := mqlRes.(*mqlAwsSagemakerProjectProvisioningDetails)
	pd.cacheParentArn = a.Arn.Data
	pd.cacheParams = a.cacheProvisioningParams
	return pd, nil
}

func (a *mqlAwsSagemakerProject) serviceCatalogProvisionedProductDetails() (*mqlAwsSagemakerProjectProvisionedProductDetails, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheProvisionedProductId == "" {
		a.ServiceCatalogProvisionedProductDetails.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerProjectProvisionedProductDetails,
		map[string]*llx.RawData{
			"__id":                            llx.StringData(a.Arn.Data + "/provisionedProductDetails"),
			"provisionedProductId":            llx.StringData(a.cacheProvisionedProductId),
			"provisionedProductStatusMessage": llx.StringData(a.cacheProvisionedProductStatusMessage),
		})
	if err != nil {
		return nil, err
	}
	ppd := mqlRes.(*mqlAwsSagemakerProjectProvisionedProductDetails)
	ppd.cacheParentArn = a.Arn.Data
	return ppd, nil
}

type mqlAwsSagemakerProjectProvisioningDetailsInternal struct {
	cacheParentArn string
	cacheParams    []any
}

func (a *mqlAwsSagemakerProjectProvisioningDetails) id() (string, error) {
	return a.cacheParentArn + "/provisioningDetails", nil
}

func (a *mqlAwsSagemakerProjectProvisioningDetails) provisioningParameters() ([]any, error) {
	return a.cacheParams, nil
}

type mqlAwsSagemakerProjectProvisioningParameterInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerProjectProvisioningParameter) id() (string, error) {
	return a.cacheParentArn + "/provisioningParam/" + a.Key.Data, nil
}

type mqlAwsSagemakerProjectProvisionedProductDetailsInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerProjectProvisionedProductDetails) id() (string, error) {
	return a.cacheParentArn + "/provisionedProductDetails", nil
}

// ---- Hyperparameter Tuning Jobs ----

func (a *mqlAwsSagemaker) hyperParameterTuningJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getHyperParameterTuningJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getHyperParameterTuningJobs(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListHyperParameterTuningJobsPaginator(svc, &sagemaker.ListHyperParameterTuningJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.HyperParameterTuningJobSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, job.HyperParameterTuningJobArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("hpTuningJob", job.HyperParameterTuningJobArn).Msg("skipping sagemaker hyperparameter tuning job due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHyperParameterTuningJob,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(job.HyperParameterTuningJobArn),
							"name":           llx.StringDataPtr(job.HyperParameterTuningJobName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(job.HyperParameterTuningJobStatus)),
							"createdAt":      llx.TimeDataPtr(job.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(job.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					j := mqlJob.(*mqlAwsSagemakerHyperParameterTuningJob)
					if eagerTags != nil {
						j.cacheTags = eagerTags
						j.tagsFetched = true
					}
					res = append(res, mqlJob)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerHyperParameterTuningJobInternal struct {
	sagemakerTagsCache
	detailsFetched           bool
	detailsLock              sync.Mutex
	cacheStrategy            string
	cacheObjectiveType       string
	cacheObjectiveMetricName string
	cacheMaxTrainingJobs     int64
	cacheMaxParallelJobs     int64
	cacheMaxRuntimeInSeconds int64
	cacheParameterRanges     []any
	cacheCompleted           int64
	cacheInProgress          int64
	cacheRetryableError      int64
	cacheNonRetryableError   int64
	cacheStopped             int64
	cacheBestTrainingJob     any
	cacheFailureReason       string
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) fetchDetails() error {
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
	resp, err := svc.DescribeHyperParameterTuningJob(ctx, &sagemaker.DescribeHyperParameterTuningJobInput{
		HyperParameterTuningJobName: &name,
	})
	if err != nil {
		return err
	}

	if resp.HyperParameterTuningJobConfig != nil {
		a.cacheStrategy = string(resp.HyperParameterTuningJobConfig.Strategy)
		if resp.HyperParameterTuningJobConfig.HyperParameterTuningJobObjective != nil {
			a.cacheObjectiveType = string(resp.HyperParameterTuningJobConfig.HyperParameterTuningJobObjective.Type)
			a.cacheObjectiveMetricName = convert.ToValue(resp.HyperParameterTuningJobConfig.HyperParameterTuningJobObjective.MetricName)
		}
		if resp.HyperParameterTuningJobConfig.ResourceLimits != nil {
			rl := resp.HyperParameterTuningJobConfig.ResourceLimits
			if rl.MaxNumberOfTrainingJobs != nil {
				a.cacheMaxTrainingJobs = int64(*rl.MaxNumberOfTrainingJobs)
			}
			if rl.MaxParallelTrainingJobs != nil {
				a.cacheMaxParallelJobs = int64(*rl.MaxParallelTrainingJobs)
			}
			if rl.MaxRuntimeInSeconds != nil {
				a.cacheMaxRuntimeInSeconds = int64(*rl.MaxRuntimeInSeconds)
			}
		}

		// Build parameter ranges - merge continuous, integer, and categorical
		ranges := make([]any, 0)
		if resp.HyperParameterTuningJobConfig.ParameterRanges != nil {
			pr := resp.HyperParameterTuningJobConfig.ParameterRanges
			for _, r := range pr.ContinuousParameterRanges {
				mqlRange, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHyperParameterTuningJobParameterRange,
					map[string]*llx.RawData{
						"__id":        llx.StringData(a.Arn.Data + "/parameterRange/" + convert.ToValue(r.Name)),
						"name":        llx.StringDataPtr(r.Name),
						"type":        llx.StringData("Continuous"),
						"minValue":    llx.StringDataPtr(r.MinValue),
						"maxValue":    llx.StringDataPtr(r.MaxValue),
						"scalingType": llx.StringData(string(r.ScalingType)),
						"values":      llx.ArrayData(nil, types.String),
					})
				if err != nil {
					return err
				}
				pr := mqlRange.(*mqlAwsSagemakerHyperParameterTuningJobParameterRange)
				pr.cacheParentArn = a.Arn.Data
				ranges = append(ranges, mqlRange)
			}
			for _, r := range pr.IntegerParameterRanges {
				mqlRange, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHyperParameterTuningJobParameterRange,
					map[string]*llx.RawData{
						"__id":        llx.StringData(a.Arn.Data + "/parameterRange/" + convert.ToValue(r.Name)),
						"name":        llx.StringDataPtr(r.Name),
						"type":        llx.StringData("Integer"),
						"minValue":    llx.StringDataPtr(r.MinValue),
						"maxValue":    llx.StringDataPtr(r.MaxValue),
						"scalingType": llx.StringData(string(r.ScalingType)),
						"values":      llx.ArrayData(nil, types.String),
					})
				if err != nil {
					return err
				}
				pr := mqlRange.(*mqlAwsSagemakerHyperParameterTuningJobParameterRange)
				pr.cacheParentArn = a.Arn.Data
				ranges = append(ranges, mqlRange)
			}
			for _, r := range pr.CategoricalParameterRanges {
				vals := make([]any, 0, len(r.Values))
				for _, v := range r.Values {
					vals = append(vals, v)
				}
				mqlRange, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHyperParameterTuningJobParameterRange,
					map[string]*llx.RawData{
						"__id":        llx.StringData(a.Arn.Data + "/parameterRange/" + convert.ToValue(r.Name)),
						"name":        llx.StringDataPtr(r.Name),
						"type":        llx.StringData("Categorical"),
						"minValue":    llx.StringData(""),
						"maxValue":    llx.StringData(""),
						"scalingType": llx.StringData(""),
						"values":      llx.ArrayData(vals, types.String),
					})
				if err != nil {
					return err
				}
				pr := mqlRange.(*mqlAwsSagemakerHyperParameterTuningJobParameterRange)
				pr.cacheParentArn = a.Arn.Data
				ranges = append(ranges, mqlRange)
			}
		}
		a.cacheParameterRanges = ranges
	}

	if resp.TrainingJobStatusCounters != nil {
		tc := resp.TrainingJobStatusCounters
		if tc.Completed != nil {
			a.cacheCompleted = int64(*tc.Completed)
		}
		if tc.InProgress != nil {
			a.cacheInProgress = int64(*tc.InProgress)
		}
		if tc.RetryableError != nil {
			a.cacheRetryableError = int64(*tc.RetryableError)
		}
		if tc.NonRetryableError != nil {
			a.cacheNonRetryableError = int64(*tc.NonRetryableError)
		}
		if tc.Stopped != nil {
			a.cacheStopped = int64(*tc.Stopped)
		}
	}

	a.cacheBestTrainingJob, _ = convert.JsonToDict(resp.BestTrainingJob)
	a.cacheFailureReason = convert.ToValue(resp.FailureReason)
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) strategy() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheStrategy, nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) objectiveMetric() (*mqlAwsSagemakerHyperParameterTuningJobObjective, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheObjectiveMetricName == "" {
		a.ObjectiveMetric.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHyperParameterTuningJobObjective,
		map[string]*llx.RawData{
			"__id":       llx.StringData(a.Arn.Data + "/objective"),
			"type":       llx.StringData(a.cacheObjectiveType),
			"metricName": llx.StringData(a.cacheObjectiveMetricName),
		})
	if err != nil {
		return nil, err
	}
	obj := mqlRes.(*mqlAwsSagemakerHyperParameterTuningJobObjective)
	obj.cacheParentArn = a.Arn.Data
	return obj, nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) resourceLimits() (*mqlAwsSagemakerHyperParameterTuningJobResourceLimits, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHyperParameterTuningJobResourceLimits,
		map[string]*llx.RawData{
			"__id":                    llx.StringData(a.Arn.Data + "/resourceLimits"),
			"maxNumberOfTrainingJobs": llx.IntData(a.cacheMaxTrainingJobs),
			"maxParallelTrainingJobs": llx.IntData(a.cacheMaxParallelJobs),
			"maxRuntimeInSeconds":     llx.IntData(a.cacheMaxRuntimeInSeconds),
		})
	if err != nil {
		return nil, err
	}
	rl := mqlRes.(*mqlAwsSagemakerHyperParameterTuningJobResourceLimits)
	rl.cacheParentArn = a.Arn.Data
	return rl, nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) parameterRanges() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheParameterRanges, nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) trainingJobStatusCounters() (*mqlAwsSagemakerHyperParameterTuningJobStatusCounters, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHyperParameterTuningJobStatusCounters,
		map[string]*llx.RawData{
			"__id":              llx.StringData(a.Arn.Data + "/statusCounters"),
			"completed":         llx.IntData(a.cacheCompleted),
			"inProgress":        llx.IntData(a.cacheInProgress),
			"retryableError":    llx.IntData(a.cacheRetryableError),
			"nonRetryableError": llx.IntData(a.cacheNonRetryableError),
			"stopped":           llx.IntData(a.cacheStopped),
		})
	if err != nil {
		return nil, err
	}
	sc := mqlRes.(*mqlAwsSagemakerHyperParameterTuningJobStatusCounters)
	sc.cacheParentArn = a.Arn.Data
	return sc, nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) bestTrainingJob() (any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheBestTrainingJob, nil
}

func (a *mqlAwsSagemakerHyperParameterTuningJob) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

type mqlAwsSagemakerHyperParameterTuningJobObjectiveInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerHyperParameterTuningJobObjective) id() (string, error) {
	return a.cacheParentArn + "/objective", nil
}

type mqlAwsSagemakerHyperParameterTuningJobResourceLimitsInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerHyperParameterTuningJobResourceLimits) id() (string, error) {
	return a.cacheParentArn + "/resourceLimits", nil
}

type mqlAwsSagemakerHyperParameterTuningJobParameterRangeInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerHyperParameterTuningJobParameterRange) id() (string, error) {
	return a.cacheParentArn + "/parameterRange/" + a.Name.Data, nil
}

type mqlAwsSagemakerHyperParameterTuningJobStatusCountersInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerHyperParameterTuningJobStatusCounters) id() (string, error) {
	return a.cacheParentArn + "/statusCounters", nil
}

// ---- Transform Jobs ----

func (a *mqlAwsSagemaker) transformJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTransformJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getTransformJobs(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListTransformJobsPaginator(svc, &sagemaker.ListTransformJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.TransformJobSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, job.TransformJobArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("transformJob", job.TransformJobArn).Msg("skipping sagemaker transform job due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTransformJob,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(job.TransformJobArn),
							"name":      llx.StringDataPtr(job.TransformJobName),
							"region":    llx.StringData(region),
							"status":    llx.StringData(string(job.TransformJobStatus)),
							"createdAt": llx.TimeDataPtr(job.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					j := mqlJob.(*mqlAwsSagemakerTransformJob)
					if eagerTags != nil {
						j.cacheTags = eagerTags
						j.tagsFetched = true
					}
					res = append(res, mqlJob)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerTransformJobInternal struct {
	sagemakerTagsCache
	detailsFetched               bool
	detailsLock                  sync.Mutex
	cacheFailureReason           string
	cacheModelName               string
	cacheMaxConcurrentTransforms int64
	cacheMaxPayloadInMB          int64
	cacheBatchStrategy           string
	// Transform input
	hasInput                  bool
	cacheInputS3Uri           string
	cacheInputDataSource      string
	cacheInputContentType     string
	cacheInputCompressionType string
	cacheInputSplitType       string
	// Transform output
	hasOutput               bool
	cacheOutputS3Uri        string
	cacheOutputAccept       string
	cacheOutputAssembleWith string
	cacheOutputKmsKeyId     *string
	// Transform resources
	hasResources               bool
	cacheResourceInstanceType  string
	cacheResourceInstanceCount int64
	cacheResourceVolumeKmsKey  *string
}

func (a *mqlAwsSagemakerTransformJob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerTransformJob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerTransformJob) fetchDetails() error {
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
	resp, err := svc.DescribeTransformJob(ctx, &sagemaker.DescribeTransformJobInput{TransformJobName: &name})
	if err != nil {
		return err
	}

	a.cacheFailureReason = convert.ToValue(resp.FailureReason)
	a.cacheModelName = convert.ToValue(resp.ModelName)
	a.cacheBatchStrategy = string(resp.BatchStrategy)
	if resp.MaxConcurrentTransforms != nil {
		a.cacheMaxConcurrentTransforms = int64(*resp.MaxConcurrentTransforms)
	}
	if resp.MaxPayloadInMB != nil {
		a.cacheMaxPayloadInMB = int64(*resp.MaxPayloadInMB)
	}

	if resp.TransformInput != nil {
		a.hasInput = true
		ti := resp.TransformInput
		a.cacheInputContentType = convert.ToValue(ti.ContentType)
		a.cacheInputCompressionType = string(ti.CompressionType)
		a.cacheInputSplitType = string(ti.SplitType)
		if ti.DataSource != nil && ti.DataSource.S3DataSource != nil {
			a.cacheInputS3Uri = convert.ToValue(ti.DataSource.S3DataSource.S3Uri)
			a.cacheInputDataSource = string(ti.DataSource.S3DataSource.S3DataType)
		}
	}

	if resp.TransformOutput != nil {
		a.hasOutput = true
		to := resp.TransformOutput
		a.cacheOutputS3Uri = convert.ToValue(to.S3OutputPath)
		a.cacheOutputAccept = convert.ToValue(to.Accept)
		a.cacheOutputAssembleWith = string(to.AssembleWith)
		a.cacheOutputKmsKeyId = to.KmsKeyId
	}

	if resp.TransformResources != nil {
		a.hasResources = true
		tr := resp.TransformResources
		a.cacheResourceInstanceType = string(tr.InstanceType)
		if tr.InstanceCount != nil {
			a.cacheResourceInstanceCount = int64(*tr.InstanceCount)
		}
		a.cacheResourceVolumeKmsKey = tr.VolumeKmsKeyId
	}

	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerTransformJob) modelName() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheModelName, nil
}

func (a *mqlAwsSagemakerTransformJob) maxConcurrentTransforms() (int64, error) {
	if err := a.fetchDetails(); err != nil {
		return 0, err
	}
	return a.cacheMaxConcurrentTransforms, nil
}

func (a *mqlAwsSagemakerTransformJob) maxPayloadInMB() (int64, error) {
	if err := a.fetchDetails(); err != nil {
		return 0, err
	}
	return a.cacheMaxPayloadInMB, nil
}

func (a *mqlAwsSagemakerTransformJob) batchStrategy() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheBatchStrategy, nil
}

func (a *mqlAwsSagemakerTransformJob) model() (*mqlAwsSagemakerModel, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheModelName == "" {
		a.Model.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	partition := "aws"
	if parts := strings.SplitN(a.Arn.Data, ":", 3); len(parts) >= 2 {
		partition = parts[1]
	}
	modelArn := fmt.Sprintf("arn:%s:sagemaker:%s:%s:model/%s", partition, a.Region.Data, conn.AccountId(), a.cacheModelName)
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.model",
		map[string]*llx.RawData{
			"arn":    llx.StringData(modelArn),
			"name":   llx.StringData(a.cacheModelName),
			"region": llx.StringData(a.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerModel), nil
}

func (a *mqlAwsSagemakerTransformJob) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

func (a *mqlAwsSagemakerTransformJob) transformInput() (*mqlAwsSagemakerTransformJobInput, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if !a.hasInput {
		a.TransformInput.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTransformJobInput,
		map[string]*llx.RawData{
			"__id":            llx.StringData(a.Arn.Data + "/transformInput"),
			"s3Uri":           llx.StringData(a.cacheInputS3Uri),
			"dataSource":      llx.StringData(a.cacheInputDataSource),
			"contentType":     llx.StringData(a.cacheInputContentType),
			"compressionType": llx.StringData(a.cacheInputCompressionType),
			"splitType":       llx.StringData(a.cacheInputSplitType),
		})
	if err != nil {
		return nil, err
	}
	ti := mqlRes.(*mqlAwsSagemakerTransformJobInput)
	ti.cacheParentArn = a.Arn.Data
	return ti, nil
}

func (a *mqlAwsSagemakerTransformJob) transformOutput() (*mqlAwsSagemakerTransformJobOutput, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if !a.hasOutput {
		a.TransformOutput.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTransformJobOutput,
		map[string]*llx.RawData{
			"__id":         llx.StringData(a.Arn.Data + "/transformOutput"),
			"s3Uri":        llx.StringData(a.cacheOutputS3Uri),
			"accept":       llx.StringData(a.cacheOutputAccept),
			"assembleWith": llx.StringData(a.cacheOutputAssembleWith),
		})
	if err != nil {
		return nil, err
	}
	to := mqlRes.(*mqlAwsSagemakerTransformJobOutput)
	to.cacheParentArn = a.Arn.Data
	to.cacheKmsKeyId = a.cacheOutputKmsKeyId
	return to, nil
}

func (a *mqlAwsSagemakerTransformJob) transformResources() (*mqlAwsSagemakerTransformJobResources, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if !a.hasResources {
		a.TransformResources.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerTransformJobResources,
		map[string]*llx.RawData{
			"__id":          llx.StringData(a.Arn.Data + "/transformResources"),
			"instanceType":  llx.StringData(a.cacheResourceInstanceType),
			"instanceCount": llx.IntData(a.cacheResourceInstanceCount),
		})
	if err != nil {
		return nil, err
	}
	tr := mqlRes.(*mqlAwsSagemakerTransformJobResources)
	tr.cacheParentArn = a.Arn.Data
	tr.cacheVolumeKmsKeyId = a.cacheResourceVolumeKmsKey
	return tr, nil
}

type mqlAwsSagemakerTransformJobInputInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerTransformJobInput) id() (string, error) {
	return a.cacheParentArn + "/transformInput", nil
}

type mqlAwsSagemakerTransformJobOutputInternal struct {
	cacheParentArn string
	cacheKmsKeyId  *string
}

func (a *mqlAwsSagemakerTransformJobOutput) id() (string, error) {
	return a.cacheParentArn + "/transformOutput", nil
}

func (a *mqlAwsSagemakerTransformJobOutput) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

type mqlAwsSagemakerTransformJobResourcesInternal struct {
	cacheParentArn      string
	cacheVolumeKmsKeyId *string
}

func (a *mqlAwsSagemakerTransformJobResources) id() (string, error) {
	return a.cacheParentArn + "/transformResources", nil
}

func (a *mqlAwsSagemakerTransformJobResources) volumeKmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheVolumeKmsKeyId == nil || *a.cacheVolumeKmsKeyId == "" {
		a.VolumeKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheVolumeKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

// ---- AutoML Jobs ----

func (a *mqlAwsSagemaker) autoMLJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAutoMLJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsSagemaker) getAutoMLJobs(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListAutoMLJobsPaginator(svc, &sagemaker.ListAutoMLJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.AutoMLJobSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, job.AutoMLJobArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							log.Debug().Interface("autoMLJob", job.AutoMLJobArn).Msg("skipping sagemaker automl job due to filters")
							continue
						}
						eagerTags = tags
					}

					mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAutoMLJob,
						map[string]*llx.RawData{
							"arn":            llx.StringDataPtr(job.AutoMLJobArn),
							"name":           llx.StringDataPtr(job.AutoMLJobName),
							"region":         llx.StringData(region),
							"status":         llx.StringData(string(job.AutoMLJobStatus)),
							"createdAt":      llx.TimeDataPtr(job.CreationTime),
							"lastModifiedAt": llx.TimeDataPtr(job.LastModifiedTime),
						})
					if err != nil {
						return nil, err
					}
					j := mqlJob.(*mqlAwsSagemakerAutoMLJob)
					if eagerTags != nil {
						j.cacheTags = eagerTags
						j.tagsFetched = true
					}
					res = append(res, mqlJob)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerAutoMLJobInternal struct {
	sagemakerTagsCache
	detailsFetched       bool
	detailsLock          sync.Mutex
	cacheRoleArn         *string
	cacheFailureReason   string
	cacheInputChannels   []any
	cacheOutputS3Uri     string
	cacheOutputKmsKeyId  *string
	cacheCandidateName   string
	cacheCandidateStatus string
	cacheObjMetricName   string
	cacheObjMetricValue  float64
}

func (a *mqlAwsSagemakerAutoMLJob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerAutoMLJob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerAutoMLJob) fetchDetails() error {
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
	resp, err := svc.DescribeAutoMLJob(ctx, &sagemaker.DescribeAutoMLJobInput{AutoMLJobName: &name})
	if err != nil {
		return err
	}

	a.cacheRoleArn = resp.RoleArn
	a.cacheFailureReason = convert.ToValue(resp.FailureReason)

	// Input channels
	channels := make([]any, 0, len(resp.InputDataConfig))
	for i, ch := range resp.InputDataConfig {
		var s3Uri, s3DataType string
		if ch.DataSource != nil && ch.DataSource.S3DataSource != nil {
			s3Uri = convert.ToValue(ch.DataSource.S3DataSource.S3Uri)
			s3DataType = string(ch.DataSource.S3DataSource.S3DataType)
		}
		mqlCh, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAutoMLJobInputChannel,
			map[string]*llx.RawData{
				// Keyed by position, not by target attribute: the target attribute
				// is the column the job predicts and is the same on every channel
				// of a job, so keying on it merged the training and validation
				// channels into one and hid the validation dataset's S3 URI.
				"__id":                llx.StringData(autoMLInputChannelCacheKey(a.Arn.Data, i)),
				"targetAttributeName": llx.StringDataPtr(ch.TargetAttributeName),
				"contentType":         llx.StringDataPtr(ch.ContentType),
				"compressionType":     llx.StringData(string(ch.CompressionType)),
				"s3Uri":               llx.StringData(s3Uri),
				"s3DataType":          llx.StringData(s3DataType),
			})
		if err != nil {
			return err
		}
		ic := mqlCh.(*mqlAwsSagemakerAutoMLJobInputChannel)
		ic.cacheParentArn = a.Arn.Data
		ic.cacheIndex = i
		channels = append(channels, mqlCh)
	}
	a.cacheInputChannels = channels

	// Output config
	if resp.OutputDataConfig != nil {
		a.cacheOutputS3Uri = convert.ToValue(resp.OutputDataConfig.S3OutputPath)
		a.cacheOutputKmsKeyId = resp.OutputDataConfig.KmsKeyId
	}

	// Best candidate
	if resp.BestCandidate != nil {
		a.cacheCandidateName = convert.ToValue(resp.BestCandidate.CandidateName)
		a.cacheCandidateStatus = string(resp.BestCandidate.CandidateStatus)
		if resp.BestCandidate.FinalAutoMLJobObjectiveMetric != nil {
			a.cacheObjMetricName = string(resp.BestCandidate.FinalAutoMLJobObjectiveMetric.MetricName)
			if resp.BestCandidate.FinalAutoMLJobObjectiveMetric.Value != nil {
				a.cacheObjMetricValue = float64(*resp.BestCandidate.FinalAutoMLJobObjectiveMetric.Value)
			}
		}
	}

	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerAutoMLJob) inputDataConfig() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	return a.cacheInputChannels, nil
}

func (a *mqlAwsSagemakerAutoMLJob) outputDataConfig() (*mqlAwsSagemakerAutoMLJobOutputConfig, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheOutputS3Uri == "" {
		a.OutputDataConfig.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAutoMLJobOutputConfig,
		map[string]*llx.RawData{
			"__id":  llx.StringData(a.Arn.Data + "/outputConfig"),
			"s3Uri": llx.StringData(a.cacheOutputS3Uri),
		})
	if err != nil {
		return nil, err
	}
	oc := mqlRes.(*mqlAwsSagemakerAutoMLJobOutputConfig)
	oc.cacheParentArn = a.Arn.Data
	oc.cacheKmsKeyId = a.cacheOutputKmsKeyId
	return oc, nil
}

func (a *mqlAwsSagemakerAutoMLJob) iamRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheRoleArn == nil || *a.cacheRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsSagemakerAutoMLJob) bestCandidate() (*mqlAwsSagemakerAutoMLJobCandidate, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheCandidateName == "" {
		a.BestCandidate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRes, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerAutoMLJobCandidate,
		map[string]*llx.RawData{
			"__id":                 llx.StringData(a.Arn.Data + "/bestCandidate"),
			"candidateName":        llx.StringData(a.cacheCandidateName),
			"candidateStatus":      llx.StringData(a.cacheCandidateStatus),
			"objectiveMetricName":  llx.StringData(a.cacheObjMetricName),
			"objectiveMetricValue": llx.FloatData(a.cacheObjMetricValue),
		})
	if err != nil {
		return nil, err
	}
	bc := mqlRes.(*mqlAwsSagemakerAutoMLJobCandidate)
	bc.cacheParentArn = a.Arn.Data
	return bc, nil
}

func (a *mqlAwsSagemakerAutoMLJob) failureReason() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheFailureReason, nil
}

type mqlAwsSagemakerAutoMLJobInputChannelInternal struct {
	cacheParentArn string
	cacheIndex     int
}

// autoMLInputChannelCacheKey identifies one input channel of an AutoML job by
// its position in the job's channel list. A channel has nothing else that
// distinguishes it: the target attribute names the column being predicted and
// is identical across a job's channels, and the S3 URI is what a caller is
// trying to read rather than something to key on.
func autoMLInputChannelCacheKey(jobArn string, index int) string {
	return jobArn + "/inputChannel/" + strconv.Itoa(index)
}

// id is a fallback only. cacheIndex is assigned after CreateResource has
// computed the key, so this cannot see the position; the creator passes the
// real key as __id.
func (a *mqlAwsSagemakerAutoMLJobInputChannel) id() (string, error) {
	return autoMLInputChannelCacheKey(a.cacheParentArn, a.cacheIndex), nil
}

type mqlAwsSagemakerAutoMLJobOutputConfigInternal struct {
	cacheParentArn string
	cacheKmsKeyId  *string
}

func (a *mqlAwsSagemakerAutoMLJobOutputConfig) id() (string, error) {
	return a.cacheParentArn + "/outputConfig", nil
}

func (a *mqlAwsSagemakerAutoMLJobOutputConfig) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

type mqlAwsSagemakerAutoMLJobCandidateInternal struct {
	cacheParentArn string
}

func (a *mqlAwsSagemakerAutoMLJobCandidate) id() (string, error) {
	return a.cacheParentArn + "/bestCandidate", nil
}
