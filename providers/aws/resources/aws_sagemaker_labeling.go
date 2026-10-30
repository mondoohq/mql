// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/sagemaker"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

// ---- Init functions for cross-referenced labeling resources ----

func initAwsSagemakerWorkforce(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker workforce")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetWorkforces()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			wf := rawResource.(*mqlAwsSagemakerWorkforce)
			if wf.Arn.Data == arnVal {
				return args, wf, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.workforce with arn %q not found", arnVal)
}

func initAwsSagemakerWorkteam(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker workteam")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetWorkteams()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			wt := rawResource.(*mqlAwsSagemakerWorkteam)
			if wt.Arn.Data == arnVal {
				return args, wt, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.workteam with arn %q not found", arnVal)
}

func initAwsSagemakerHumanTaskUi(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve sagemaker human task UI")
	}
	arnVal := args["arn"].Value.(string)

	obj, err := CreateResource(runtime, "aws.sagemaker", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	sm := obj.(*mqlAwsSagemaker)

	rawResources := sm.GetHumanTaskUis()
	if rawResources.Error == nil {
		for _, rawResource := range rawResources.Data {
			ht := rawResource.(*mqlAwsSagemakerHumanTaskUi)
			if ht.Arn.Data == arnVal {
				return args, ht, nil
			}
		}
	}

	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.sagemaker.humanTaskUi with arn %q not found", arnVal)
}

// ---- Labeling Jobs ----

func (a *mqlAwsSagemaker) labelingJobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLabelingJobs(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getLabelingJobs(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListLabelingJobsPaginator(svc, &sagemaker.ListLabelingJobsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, job := range page.LabelingJobSummaryList {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, job.LabelingJobArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					var humans, machines, unlabeled, total int64
					if job.LabelCounters != nil {
						if job.LabelCounters.HumanLabeled != nil {
							humans = int64(*job.LabelCounters.HumanLabeled)
						}
						if job.LabelCounters.MachineLabeled != nil {
							machines = int64(*job.LabelCounters.MachineLabeled)
						}
						if job.LabelCounters.Unlabeled != nil {
							unlabeled = int64(*job.LabelCounters.Unlabeled)
						}
						if job.LabelCounters.TotalLabeled != nil {
							total = int64(*job.LabelCounters.TotalLabeled)
						}
					}

					mqlJob, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerLabelingJob,
						map[string]*llx.RawData{
							"arn":             llx.StringDataPtr(job.LabelingJobArn),
							"name":            llx.StringDataPtr(job.LabelingJobName),
							"region":          llx.StringData(region),
							"status":          llx.StringData(string(job.LabelingJobStatus)),
							"createdAt":       llx.TimeDataPtr(job.CreationTime),
							"lastModifiedAt":  llx.TimeDataPtr(job.LastModifiedTime),
							"humansLabeled":   llx.IntData(humans),
							"machinesLabeled": llx.IntData(machines),
							"unlabeled":       llx.IntData(unlabeled),
							"totalLabeled":    llx.IntData(total),
							"failureReason":   llx.StringDataPtr(job.FailureReason),
						})
					if err != nil {
						return nil, err
					}
					m := mqlJob.(*mqlAwsSagemakerLabelingJob)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
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

type mqlAwsSagemakerLabelingJobInternal struct {
	sagemakerTagsCache
	detailsLock                   sync.Mutex
	detailsFetched                bool
	cacheRoleArn                  *string
	cacheLabelAttributeName       string
	cacheInputS3Uri               string
	cacheOutputS3Uri              string
	cacheOutputKmsKeyId           *string
	cacheLabelCategoryConfigS3Uri string
	cacheWorkteamArn              string
	cacheHumanTaskUiArn           string
}

func (a *mqlAwsSagemakerLabelingJob) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerLabelingJob) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerLabelingJob) fetchDetails() error {
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
	resp, err := svc.DescribeLabelingJob(ctx, &sagemaker.DescribeLabelingJobInput{LabelingJobName: &name})
	if err != nil {
		return err
	}
	a.cacheRoleArn = resp.RoleArn
	a.cacheLabelAttributeName = convert.ToValue(resp.LabelAttributeName)
	a.cacheLabelCategoryConfigS3Uri = convert.ToValue(resp.LabelCategoryConfigS3Uri)
	if resp.InputConfig != nil && resp.InputConfig.DataSource != nil && resp.InputConfig.DataSource.S3DataSource != nil {
		a.cacheInputS3Uri = convert.ToValue(resp.InputConfig.DataSource.S3DataSource.ManifestS3Uri)
	}
	if resp.OutputConfig != nil {
		a.cacheOutputS3Uri = convert.ToValue(resp.OutputConfig.S3OutputPath)
		a.cacheOutputKmsKeyId = resp.OutputConfig.KmsKeyId
	}
	if resp.HumanTaskConfig != nil {
		a.cacheWorkteamArn = convert.ToValue(resp.HumanTaskConfig.WorkteamArn)
		if resp.HumanTaskConfig.UiConfig != nil {
			a.cacheHumanTaskUiArn = convert.ToValue(resp.HumanTaskConfig.UiConfig.HumanTaskUiArn)
		}
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerLabelingJob) workteam() (*mqlAwsSagemakerWorkteam, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheWorkteamArn == "" {
		a.Workteam.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.workteam",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheWorkteamArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerWorkteam), nil
}

func (a *mqlAwsSagemakerLabelingJob) humanTaskUi() (*mqlAwsSagemakerHumanTaskUi, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheHumanTaskUiArn == "" {
		a.HumanTaskUi.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.humanTaskUi",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheHumanTaskUiArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerHumanTaskUi), nil
}

func (a *mqlAwsSagemakerLabelingJob) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsSagemakerLabelingJob) labelAttributeName() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheLabelAttributeName, nil
}

func (a *mqlAwsSagemakerLabelingJob) inputS3Uri() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheInputS3Uri, nil
}

func (a *mqlAwsSagemakerLabelingJob) outputS3Uri() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheOutputS3Uri, nil
}

func (a *mqlAwsSagemakerLabelingJob) outputKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheOutputKmsKeyId == nil || *a.cacheOutputKmsKeyId == "" {
		a.OutputKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheOutputKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerLabelingJob) labelCategoryConfigS3Uri() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheLabelCategoryConfigS3Uri, nil
}

// ---- Workforces ----

func (a *mqlAwsSagemaker) workforces() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getWorkforces(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getWorkforces(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListWorkforcesPaginator(svc, &sagemaker.ListWorkforcesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, wf := range page.Workforces {
					mqlWf, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerWorkforce,
						map[string]*llx.RawData{
							"arn":           llx.StringDataPtr(wf.WorkforceArn),
							"name":          llx.StringDataPtr(wf.WorkforceName),
							"region":        llx.StringData(region),
							"createdAt":     llx.TimeDataPtr(wf.CreateDate),
							"ipAddressType": llx.StringData(string(wf.IpAddressType)),
							"failureReason": llx.StringDataPtr(wf.FailureReason),
							"subDomain":     llx.StringDataPtr(wf.SubDomain),
						})
					if err != nil {
						return nil, err
					}
					m := mqlWf.(*mqlAwsSagemakerWorkforce)
					if wf.SourceIpConfig != nil {
						for _, c := range wf.SourceIpConfig.Cidrs {
							m.cacheAllowedIpRanges = append(m.cacheAllowedIpRanges, c)
						}
					}
					if wf.CognitoConfig != nil {
						if d, err := convert.JsonToDict(wf.CognitoConfig); err == nil {
							m.cacheCognitoConfig = d
						}
					}
					if wf.OidcConfig != nil {
						if d, err := convert.JsonToDict(wf.OidcConfig); err == nil {
							m.cacheOidcConfig = d
						}
					}
					if wf.WorkforceVpcConfig != nil {
						m.cacheVpcId = wf.WorkforceVpcConfig.VpcId
						m.cacheSubnetIds = wf.WorkforceVpcConfig.Subnets
						accountID := conn.AccountId()
						sgArns := make([]string, 0, len(wf.WorkforceVpcConfig.SecurityGroupIds))
						for _, sgID := range wf.WorkforceVpcConfig.SecurityGroupIds {
							sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sgID))
						}
						m.setSecurityGroupArns(sgArns)
					}
					m.configsLoaded = true

					res = append(res, mqlWf)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerWorkforceInternal struct {
	sagemakerTagsCache
	securityGroupIdHandler
	configsLoaded        bool
	cacheCognitoConfig   any
	cacheOidcConfig      any
	cacheAllowedIpRanges []any
	cacheVpcId           *string
	cacheSubnetIds       []string
}

func (a *mqlAwsSagemakerWorkforce) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerWorkforce) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerWorkforce) cognitoConfig() (any, error) {
	return a.cacheCognitoConfig, nil
}

func (a *mqlAwsSagemakerWorkforce) oidcConfig() (any, error) {
	return a.cacheOidcConfig, nil
}

func (a *mqlAwsSagemakerWorkforce) allowedIpRanges() ([]any, error) {
	return a.cacheAllowedIpRanges, nil
}

func (a *mqlAwsSagemakerWorkforce) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{"id": llx.StringDataPtr(a.cacheVpcId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsSagemakerWorkforce) vpcSubnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return []any{}, nil
	}
	res := make([]any, 0, len(a.cacheSubnetIds))
	for _, id := range a.cacheSubnetIds {
		sub, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"id": llx.StringData(id)})
		if err != nil {
			return nil, err
		}
		res = append(res, sub)
	}
	return res, nil
}

func (a *mqlAwsSagemakerWorkforce) vpcSecurityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

// ---- Workteams ----

func (a *mqlAwsSagemaker) workteams() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getWorkteams(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getWorkteams(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListWorkteamsPaginator(svc, &sagemaker.ListWorkteamsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, wt := range page.Workteams {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, wt.WorkteamArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					memberDefs, err := convert.JsonToDictSlice(wt.MemberDefinitions)
					if err != nil {
						log.Warn().Err(err).Str("workteam", convert.ToValue(wt.WorkteamArn)).Msg("failed to convert sagemaker workteam member definitions")
					}

					mqlWt, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerWorkteam,
						map[string]*llx.RawData{
							"arn":               llx.StringDataPtr(wt.WorkteamArn),
							"name":              llx.StringDataPtr(wt.WorkteamName),
							"region":            llx.StringData(region),
							"description":       llx.StringDataPtr(wt.Description),
							"createdAt":         llx.TimeDataPtr(wt.CreateDate),
							"lastUpdatedAt":     llx.TimeDataPtr(wt.LastUpdatedDate),
							"workforceArn":      llx.StringDataPtr(wt.WorkforceArn),
							"workteamUrl":       llx.StringDataPtr(wt.SubDomain),
							"memberDefinitions": llx.ArrayData(memberDefs, "dict"),
						})
					if err != nil {
						return nil, err
					}
					m := mqlWt.(*mqlAwsSagemakerWorkteam)
					if wt.NotificationConfiguration != nil {
						m.cacheNotificationTopicArn = wt.NotificationConfiguration.NotificationTopicArn
					}
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
					}
					res = append(res, mqlWt)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerWorkteamInternal struct {
	sagemakerTagsCache
	cacheNotificationTopicArn *string
}

func (a *mqlAwsSagemakerWorkteam) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerWorkteam) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerWorkteam) workforce() (*mqlAwsSagemakerWorkforce, error) {
	wfArn := a.WorkforceArn.Data
	if wfArn == "" {
		a.Workforce.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.workforce",
		map[string]*llx.RawData{"arn": llx.StringData(wfArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerWorkforce), nil
}

func (a *mqlAwsSagemakerWorkteam) notificationTopic() (*mqlAwsSnsTopic, error) {
	if a.cacheNotificationTopicArn == nil || *a.cacheNotificationTopicArn == "" {
		a.NotificationTopic.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// Extract region from topic ARN (arn:partition:sns:region:account:topic-name)
	region := a.Region.Data
	parts := strings.Split(*a.cacheNotificationTopicArn, ":")
	if len(parts) >= 4 && parts[3] != "" {
		region = parts[3]
	}
	res, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{
			"arn":    llx.StringDataPtr(a.cacheNotificationTopicArn),
			"region": llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSnsTopic), nil
}

// ---- Human Task UIs ----

func (a *mqlAwsSagemaker) humanTaskUis() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getHumanTaskUis(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getHumanTaskUis(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListHumanTaskUisPaginator(svc, &sagemaker.ListHumanTaskUisInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, ht := range page.HumanTaskUiSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, ht.HumanTaskUiArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlHt, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerHumanTaskUi,
						map[string]*llx.RawData{
							"arn":       llx.StringDataPtr(ht.HumanTaskUiArn),
							"name":      llx.StringDataPtr(ht.HumanTaskUiName),
							"region":    llx.StringData(region),
							"createdAt": llx.TimeDataPtr(ht.CreationTime),
						})
					if err != nil {
						return nil, err
					}
					m := mqlHt.(*mqlAwsSagemakerHumanTaskUi)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
					}
					res = append(res, mqlHt)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerHumanTaskUiInternal struct {
	sagemakerTagsCache
	detailsLock         sync.Mutex
	detailsFetched      bool
	cacheStatus         string
	cacheTemplateUrl    string
	cacheTemplateSha256 string
}

func (a *mqlAwsSagemakerHumanTaskUi) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerHumanTaskUi) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerHumanTaskUi) fetchDetails() error {
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
	resp, err := svc.DescribeHumanTaskUi(ctx, &sagemaker.DescribeHumanTaskUiInput{HumanTaskUiName: &name})
	if err != nil {
		return err
	}
	a.cacheStatus = string(resp.HumanTaskUiStatus)
	if resp.UiTemplate != nil {
		a.cacheTemplateUrl = convert.ToValue(resp.UiTemplate.Url)
		a.cacheTemplateSha256 = convert.ToValue(resp.UiTemplate.ContentSha256)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerHumanTaskUi) status() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheStatus, nil
}

func (a *mqlAwsSagemakerHumanTaskUi) uiTemplateContentSha256() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheTemplateSha256, nil
}

func (a *mqlAwsSagemakerHumanTaskUi) uiTemplateUrl() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheTemplateUrl, nil
}

// ---- Flow Definitions ----

func (a *mqlAwsSagemaker) flowDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getFlowDefinitions(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsSagemaker) getFlowDefinitions(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := sagemaker.NewListFlowDefinitionsPaginator(svc, &sagemaker.ListFlowDefinitionsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, fd := range page.FlowDefinitionSummaries {
					var eagerTags map[string]any
					if conn.Filters.General.HasTags() {
						tags, err := getSagemakerTags(ctx, svc, fd.FlowDefinitionArn)
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
						eagerTags = tags
					}

					mqlFd, err := CreateResource(a.MqlRuntime, ResourceAwsSagemakerFlowDefinition,
						map[string]*llx.RawData{
							"arn":           llx.StringDataPtr(fd.FlowDefinitionArn),
							"name":          llx.StringDataPtr(fd.FlowDefinitionName),
							"region":        llx.StringData(region),
							"status":        llx.StringData(string(fd.FlowDefinitionStatus)),
							"createdAt":     llx.TimeDataPtr(fd.CreationTime),
							"failureReason": llx.StringDataPtr(fd.FailureReason),
						})
					if err != nil {
						return nil, err
					}
					m := mqlFd.(*mqlAwsSagemakerFlowDefinition)
					if eagerTags != nil {
						m.cacheTags = eagerTags
						m.tagsFetched.Store(true)
					}
					res = append(res, mqlFd)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSagemakerFlowDefinitionInternal struct {
	sagemakerTagsCache
	detailsLock                       sync.Mutex
	detailsFetched                    bool
	cacheRoleArn                      *string
	cacheOutputS3Uri                  string
	cacheOutputKmsKeyId               *string
	cacheWorkteamArn                  string
	cacheHumanTaskUiArn               string
	cacheTaskCount                    int64
	cacheHumanLoopActivationCondsJSON string
	cacheHumanLoopRequestSource       string
}

func (a *mqlAwsSagemakerFlowDefinition) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSagemakerFlowDefinition) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.fetchTags(conn, a.Region.Data, a.Arn.Data)
}

func (a *mqlAwsSagemakerFlowDefinition) fetchDetails() error {
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
	resp, err := svc.DescribeFlowDefinition(ctx, &sagemaker.DescribeFlowDefinitionInput{FlowDefinitionName: &name})
	if err != nil {
		return err
	}
	a.cacheRoleArn = resp.RoleArn
	if resp.OutputConfig != nil {
		a.cacheOutputS3Uri = convert.ToValue(resp.OutputConfig.S3OutputPath)
		a.cacheOutputKmsKeyId = resp.OutputConfig.KmsKeyId
	}
	if resp.HumanLoopConfig != nil {
		a.cacheWorkteamArn = convert.ToValue(resp.HumanLoopConfig.WorkteamArn)
		a.cacheHumanTaskUiArn = convert.ToValue(resp.HumanLoopConfig.HumanTaskUiArn)
		if resp.HumanLoopConfig.TaskCount != nil {
			a.cacheTaskCount = int64(*resp.HumanLoopConfig.TaskCount)
		}
	}
	if resp.HumanLoopActivationConfig != nil && resp.HumanLoopActivationConfig.HumanLoopActivationConditionsConfig != nil {
		a.cacheHumanLoopActivationCondsJSON = convert.ToValue(resp.HumanLoopActivationConfig.HumanLoopActivationConditionsConfig.HumanLoopActivationConditions)
	}
	if resp.HumanLoopRequestSource != nil {
		a.cacheHumanLoopRequestSource = string(resp.HumanLoopRequestSource.AwsManagedHumanLoopRequestSource)
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsSagemakerFlowDefinition) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsSagemakerFlowDefinition) outputS3Uri() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheOutputS3Uri, nil
}

func (a *mqlAwsSagemakerFlowDefinition) outputKmsKey() (*mqlAwsKmsKey, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheOutputKmsKeyId == nil || *a.cacheOutputKmsKeyId == "" {
		a.OutputKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheOutputKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSagemakerFlowDefinition) workteamArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheWorkteamArn, nil
}

func (a *mqlAwsSagemakerFlowDefinition) workteam() (*mqlAwsSagemakerWorkteam, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheWorkteamArn == "" {
		a.Workteam.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.workteam",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheWorkteamArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerWorkteam), nil
}

func (a *mqlAwsSagemakerFlowDefinition) humanTaskUiArn() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheHumanTaskUiArn, nil
}

func (a *mqlAwsSagemakerFlowDefinition) humanTaskUi() (*mqlAwsSagemakerHumanTaskUi, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheHumanTaskUiArn == "" {
		a.HumanTaskUi.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.sagemaker.humanTaskUi",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheHumanTaskUiArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSagemakerHumanTaskUi), nil
}

func (a *mqlAwsSagemakerFlowDefinition) taskCount() (int64, error) {
	if err := a.fetchDetails(); err != nil {
		return 0, err
	}
	return a.cacheTaskCount, nil
}

func (a *mqlAwsSagemakerFlowDefinition) humanLoopActivationConditions() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheHumanLoopActivationCondsJSON, nil
}

func (a *mqlAwsSagemakerFlowDefinition) humanLoopRequestSource() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	return a.cacheHumanLoopRequestSource, nil
}
