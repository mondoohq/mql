// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/batch"
	batch_types "github.com/aws/aws-sdk-go-v2/service/batch/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsBatch) id() (string, error) {
	return "aws.batch", nil
}

func (a *mqlAwsBatch) computeEnvironments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getComputeEnvironments(conn), 5)
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

func (a *mqlAwsBatch) getComputeEnvironments(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("batch>getComputeEnvironments>calling aws with region %s", region)

			svc := conn.Batch(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeComputeEnvironments(ctx, &batch.DescribeComputeEnvironmentsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("Batch is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, ce := range resp.ComputeEnvironments {
					tags := make(map[string]any)
					for k, v := range ce.Tags {
						tags[k] = v
					}

					mqlCe, err := CreateResource(a.MqlRuntime, "aws.batch.computeEnvironment",
						map[string]*llx.RawData{
							"__id":                       llx.StringDataPtr(ce.ComputeEnvironmentArn),
							"arn":                        llx.StringDataPtr(ce.ComputeEnvironmentArn),
							"name":                       llx.StringDataPtr(ce.ComputeEnvironmentName),
							"region":                     llx.StringData(region),
							"state":                      llx.StringData(string(ce.State)),
							"status":                     llx.StringData(string(ce.Status)),
							"statusReason":               llx.StringDataPtr(ce.StatusReason),
							"type":                       llx.StringData(string(ce.Type)),
							"containerOrchestrationType": llx.StringData(string(ce.ContainerOrchestrationType)),
							"tags":                       llx.MapData(tags, types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlCeRes := mqlCe.(*mqlAwsBatchComputeEnvironment)
					mqlCeRes.cacheComputeResources = ce.ComputeResources
					mqlCeRes.cacheEcsSettings = ce.EcsSettings
					mqlCeRes.cacheServiceRoleArn = ce.ServiceRole
					mqlCeRes.cacheEcsClusterArn = ce.EcsClusterArn
					mqlCeRes.cacheEks = ce.EksConfiguration
					mqlCeRes.cacheUpdatePolicy = ce.UpdatePolicy
					mqlCeRes.cacheUuid = ce.Uuid
					mqlCeRes.cacheRegion = region
					res = append(res, mqlCeRes)
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

type mqlAwsBatchComputeEnvironmentInternal struct {
	cacheComputeResources *batch_types.ComputeResource
	cacheEcsSettings      *batch_types.EcsSettings
	cacheServiceRoleArn   *string
	cacheEcsClusterArn    *string
	cacheEks              *batch_types.EksConfiguration
	cacheUpdatePolicy     *batch_types.UpdatePolicy
	cacheUuid             *string
	cacheRegion           string
}

func (a *mqlAwsBatchComputeEnvironment) maxVcpus() (int64, error) {
	if a.cacheComputeResources == nil || a.cacheComputeResources.MaxvCpus == nil {
		return 0, nil
	}
	return int64(*a.cacheComputeResources.MaxvCpus), nil
}

func (a *mqlAwsBatchComputeEnvironment) minVcpus() (int64, error) {
	if a.cacheComputeResources == nil || a.cacheComputeResources.MinvCpus == nil {
		return 0, nil
	}
	return int64(*a.cacheComputeResources.MinvCpus), nil
}

func (a *mqlAwsBatchComputeEnvironment) desiredVcpus() (int64, error) {
	if a.cacheComputeResources == nil || a.cacheComputeResources.DesiredvCpus == nil {
		return 0, nil
	}
	return int64(*a.cacheComputeResources.DesiredvCpus), nil
}

// containerInsights reports the CloudWatch Container Insights mode for the
// environment. A compute environment that is not ECS-backed reports no ECS
// settings at all, which is null rather than DISABLED: the service has not
// said Container Insights is off, it has said the setting does not apply.
func (a *mqlAwsBatchComputeEnvironment) containerInsights() (string, error) {
	if a.cacheEcsSettings == nil {
		a.ContainerInsights.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return string(a.cacheEcsSettings.ContainerInsights), nil
}

func (a *mqlAwsBatchComputeEnvironment) capacityTags() (map[string]any, error) {
	if a.cacheComputeResources == nil {
		return map[string]any{}, nil
	}
	tags := make(map[string]any, len(a.cacheComputeResources.CapacityTags))
	for k, v := range a.cacheComputeResources.CapacityTags {
		tags[k] = v
	}
	return tags, nil
}

func (a *mqlAwsBatchComputeEnvironment) computeResourceType() (string, error) {
	if a.cacheComputeResources == nil {
		return "", nil
	}
	return string(a.cacheComputeResources.Type), nil
}

func (a *mqlAwsBatchComputeEnvironment) instanceTypes() ([]any, error) {
	if a.cacheComputeResources == nil {
		return []any{}, nil
	}
	res := make([]any, len(a.cacheComputeResources.InstanceTypes))
	for i, t := range a.cacheComputeResources.InstanceTypes {
		res[i] = t
	}
	return res, nil
}

func (a *mqlAwsBatchComputeEnvironment) allocationStrategy() (string, error) {
	if a.cacheComputeResources == nil {
		return "", nil
	}
	return string(a.cacheComputeResources.AllocationStrategy), nil
}

func (a *mqlAwsBatchComputeEnvironment) subnets() ([]any, error) {
	if a.cacheComputeResources == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, subnetId := range a.cacheComputeResources.Subnets {
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{
				"id": llx.StringData(subnetId),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsBatchComputeEnvironment) securityGroups() ([]any, error) {
	if a.cacheComputeResources == nil {
		return []any{}, nil
	}
	res := []any{}
	for _, sgId := range a.cacheComputeResources.SecurityGroupIds {
		mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup",
			map[string]*llx.RawData{
				"id": llx.StringData(sgId),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSg)
	}
	return res, nil
}

func (a *mqlAwsBatchComputeEnvironment) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheServiceRoleArn == nil || *a.cacheServiceRoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheServiceRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBatchComputeEnvironment) serviceRole() (*mqlAwsIamRole, error) {
	if a.cacheServiceRoleArn == nil || *a.cacheServiceRoleArn == "" {
		a.ServiceRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheServiceRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBatchComputeEnvironment) ecsCluster() (*mqlAwsEcsCluster, error) {
	if a.cacheEcsClusterArn == nil || *a.cacheEcsClusterArn == "" {
		a.EcsCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ecs.cluster",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheEcsClusterArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEcsCluster), nil
}

func (a *mqlAwsBatchComputeEnvironment) instanceRole() (*mqlAwsIamInstanceProfile, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.InstanceRole == nil || *cr.InstanceRole == "" {
		a.InstanceRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// InstanceRole may be either a short name or a full ARN per AWS Batch docs.
	// initAwsIamInstanceProfile requires ARN form, so normalize.
	roleValue := *cr.InstanceRole
	if !strings.HasPrefix(roleValue, "arn:") {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		roleValue = fmt.Sprintf("arn:aws:iam::%s:instance-profile/%s", conn.AccountId(), roleValue)
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.instanceProfile",
		map[string]*llx.RawData{"arn": llx.StringData(roleValue)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamInstanceProfile), nil
}

func (a *mqlAwsBatchComputeEnvironment) spotIamFleetRole() (*mqlAwsIamRole, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.SpotIamFleetRole == nil || *cr.SpotIamFleetRole == "" {
		a.SpotIamFleetRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(cr.SpotIamFleetRole)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBatchComputeEnvironment) ec2KeyPair() (string, error) {
	if a.cacheComputeResources == nil {
		return "", nil
	}
	return convert.ToValue(a.cacheComputeResources.Ec2KeyPair), nil
}

func (a *mqlAwsBatchComputeEnvironment) bidPercentage() (int64, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.BidPercentage == nil {
		return 0, nil
	}
	return int64(*cr.BidPercentage), nil
}

func (a *mqlAwsBatchComputeEnvironment) placementGroup() (string, error) {
	if a.cacheComputeResources == nil {
		return "", nil
	}
	return convert.ToValue(a.cacheComputeResources.PlacementGroup), nil
}

func (a *mqlAwsBatchComputeEnvironment) imageId() (string, error) {
	if a.cacheComputeResources == nil {
		return "", nil
	}
	return convert.ToValue(a.cacheComputeResources.ImageId), nil
}

func (a *mqlAwsBatchComputeEnvironment) image() (*mqlAwsEc2Image, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.ImageId == nil || *cr.ImageId == "" {
		a.Image.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// initAwsEc2Image requires an ARN; AMI ARN format is
	// arn:aws:ec2:<region>::image/<imageId> (no account field).
	amiArn := fmt.Sprintf("arn:aws:ec2:%s::image/%s", a.cacheRegion, *cr.ImageId)
	res, err := NewResource(a.MqlRuntime, "aws.ec2.image",
		map[string]*llx.RawData{"arn": llx.StringData(amiArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Image), nil
}

func (a *mqlAwsBatchComputeEnvironment) ec2Configurations() ([]any, error) {
	if a.cacheComputeResources == nil {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(a.cacheComputeResources.Ec2Configuration)
}

func (a *mqlAwsBatchComputeEnvironment) launchTemplateId() (string, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.LaunchTemplate == nil {
		return "", nil
	}
	return convert.ToValue(cr.LaunchTemplate.LaunchTemplateId), nil
}

func (a *mqlAwsBatchComputeEnvironment) launchTemplateName() (string, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.LaunchTemplate == nil {
		return "", nil
	}
	return convert.ToValue(cr.LaunchTemplate.LaunchTemplateName), nil
}

func (a *mqlAwsBatchComputeEnvironment) launchTemplateVersion() (string, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.LaunchTemplate == nil {
		return "", nil
	}
	return convert.ToValue(cr.LaunchTemplate.Version), nil
}

func (a *mqlAwsBatchComputeEnvironment) launchTemplateOverrides() ([]any, error) {
	cr := a.cacheComputeResources
	if cr == nil || cr.LaunchTemplate == nil {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(cr.LaunchTemplate.Overrides)
}

func (a *mqlAwsBatchComputeEnvironment) eksCluster() (*mqlAwsEksCluster, error) {
	if a.cacheEks == nil || a.cacheEks.EksClusterArn == nil || *a.cacheEks.EksClusterArn == "" {
		a.EksCluster.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.eks.cluster",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheEks.EksClusterArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEksCluster), nil
}

func (a *mqlAwsBatchComputeEnvironment) eksKubernetesNamespace() (string, error) {
	if a.cacheEks == nil {
		return "", nil
	}
	return convert.ToValue(a.cacheEks.KubernetesNamespace), nil
}

func (a *mqlAwsBatchComputeEnvironment) updateTerminateJobsOnUpdate() (bool, error) {
	if a.cacheUpdatePolicy == nil || a.cacheUpdatePolicy.TerminateJobsOnUpdate == nil {
		return false, nil
	}
	return *a.cacheUpdatePolicy.TerminateJobsOnUpdate, nil
}

func (a *mqlAwsBatchComputeEnvironment) updateJobExecutionTimeoutMinutes() (int64, error) {
	if a.cacheUpdatePolicy == nil || a.cacheUpdatePolicy.JobExecutionTimeoutMinutes == nil {
		return 0, nil
	}
	return *a.cacheUpdatePolicy.JobExecutionTimeoutMinutes, nil
}

func (a *mqlAwsBatchComputeEnvironment) uuid() (string, error) {
	return convert.ToValue(a.cacheUuid), nil
}

func (a *mqlAwsBatch) jobQueues() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getJobQueues(conn), 5)
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

func (a *mqlAwsBatch) getJobQueues(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("batch>getJobQueues>calling aws with region %s", region)

			svc := conn.Batch(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeJobQueues(ctx, &batch.DescribeJobQueuesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("Batch is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, jq := range resp.JobQueues {
					tags := make(map[string]any)
					for k, v := range jq.Tags {
						tags[k] = v
					}

					ceOrder, err := convert.JsonToDictSlice(jq.ComputeEnvironmentOrder)
					if err != nil {
						return nil, err
					}

					jstla, err := convert.JsonToDictSlice(jq.JobStateTimeLimitActions)
					if err != nil {
						return nil, err
					}

					mqlJq, err := CreateResource(a.MqlRuntime, "aws.batch.jobQueue",
						map[string]*llx.RawData{
							"__id":         llx.StringDataPtr(jq.JobQueueArn),
							"arn":          llx.StringDataPtr(jq.JobQueueArn),
							"name":         llx.StringDataPtr(jq.JobQueueName),
							"region":       llx.StringData(region),
							"state":        llx.StringData(string(jq.State)),
							"status":       llx.StringData(string(jq.Status)),
							"statusReason": llx.StringDataPtr(jq.StatusReason),
							"priority":     llx.IntDataDefault(jq.Priority, 0),
							"tags":         llx.MapData(tags, types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlJqRes := mqlJq.(*mqlAwsBatchJobQueue)
					mqlJqRes.cacheComputeEnvironmentOrder = ceOrder
					mqlJqRes.cacheCEOrder = jq.ComputeEnvironmentOrder
					mqlJqRes.cacheSchedulingPolicyArn = jq.SchedulingPolicyArn
					mqlJqRes.cacheJobStateTimeLimitActions = jstla
					res = append(res, mqlJqRes)
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

type mqlAwsBatchJobQueueInternal struct {
	cacheComputeEnvironmentOrder  []any
	cacheCEOrder                  []batch_types.ComputeEnvironmentOrder
	cacheSchedulingPolicyArn      *string
	cacheJobStateTimeLimitActions []any
}

func (a *mqlAwsBatchJobQueue) schedulingPolicy() (*mqlAwsBatchSchedulingPolicy, error) {
	if a.cacheSchedulingPolicyArn == nil || *a.cacheSchedulingPolicyArn == "" {
		a.SchedulingPolicy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.batch.schedulingPolicy",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheSchedulingPolicyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBatchSchedulingPolicy), nil
}

func (a *mqlAwsBatchJobQueue) jobStateTimeLimitActions() ([]any, error) {
	if a.cacheJobStateTimeLimitActions == nil {
		return []any{}, nil
	}
	return a.cacheJobStateTimeLimitActions, nil
}

func (a *mqlAwsBatchJobQueue) computeEnvironmentOrder() ([]any, error) {
	return a.cacheComputeEnvironmentOrder, nil
}

func (a *mqlAwsBatchJobQueue) computeEnvironmentOrderTyped() ([]any, error) {
	res := make([]any, 0, len(a.cacheCEOrder))
	for _, entry := range a.cacheCEOrder {
		order := int64(0)
		if entry.Order != nil {
			order = int64(*entry.Order)
		}
		ceArn := convert.ToValue(entry.ComputeEnvironment)
		id := a.Arn.Data + "/ceOrder/" + ceArn
		mqlEntry, err := CreateResource(a.MqlRuntime, "aws.batch.jobQueue.computeEnvironmentOrder",
			map[string]*llx.RawData{
				"__id":                  llx.StringData(id),
				"order":                 llx.IntData(order),
				"computeEnvironmentArn": llx.StringData(ceArn),
			})
		if err != nil {
			return nil, err
		}
		mqlEntryRes := mqlEntry.(*mqlAwsBatchJobQueueComputeEnvironmentOrder)
		mqlEntryRes.cacheCEArn = entry.ComputeEnvironment
		res = append(res, mqlEntryRes)
	}
	return res, nil
}

type mqlAwsBatchJobQueueComputeEnvironmentOrderInternal struct {
	cacheCEArn *string
}

func (a *mqlAwsBatchJobQueueComputeEnvironmentOrder) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsBatchJobQueueComputeEnvironmentOrder) computeEnvironment() (*mqlAwsBatchComputeEnvironment, error) {
	if a.cacheCEArn == nil || *a.cacheCEArn == "" {
		a.ComputeEnvironment.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.batch.computeEnvironment",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheCEArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBatchComputeEnvironment), nil
}

func (a *mqlAwsBatch) jobDefinitions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getJobDefinitions(conn), 5)
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

// initAwsBatchJobDefinition resolves a single Batch job definition. When
// invoked for a discovered asset (aws-batch-jobdefinition platform), no args
// are passed, so the job definition ARN is read from the connection's asset
// identifier and used to select the matching definition from the parent
// collection.
func initAwsBatchJobDefinition(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformBatchJobdefinition); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] == nil {
		return args, nil, fmt.Errorf("arn required to fetch batch job definition")
	}

	obj, err := CreateResource(runtime, "aws.batch", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	jds := obj.(*mqlAwsBatch).GetJobDefinitions()
	if jds.Error != nil {
		return nil, nil, jds.Error
	}

	wantArn := args["arn"].Value.(string)
	for _, r := range jds.Data {
		jd := r.(*mqlAwsBatchJobDefinition)
		if jd.Arn.Data == wantArn {
			return args, jd, nil
		}
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.batch.jobDefinition with arn %q not found", wantArn)
}

func (a *mqlAwsBatch) getJobDefinitions(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("batch>getJobDefinitions>calling aws with region %s", region)

			svc := conn.Batch(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeJobDefinitions(ctx, &batch.DescribeJobDefinitionsInput{
					Status:    aws.String("ACTIVE"),
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("Batch is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, jd := range resp.JobDefinitions {
					tags := make(map[string]any)
					for k, v := range jd.Tags {
						tags[k] = v
					}

					mqlJd, err := CreateResource(a.MqlRuntime, "aws.batch.jobDefinition",
						map[string]*llx.RawData{
							"__id":     llx.StringDataPtr(jd.JobDefinitionArn),
							"arn":      llx.StringDataPtr(jd.JobDefinitionArn),
							"name":     llx.StringDataPtr(jd.JobDefinitionName),
							"region":   llx.StringData(region),
							"revision": llx.IntDataPtr(jd.Revision),
							"type":     llx.StringDataPtr(jd.Type),
							"status":   llx.StringDataPtr(jd.Status),
							"tags":     llx.MapData(tags, types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlJdRes := mqlJd.(*mqlAwsBatchJobDefinition)
					mqlJdRes.cacheContainerProperties = jd.ContainerProperties
					mqlJdRes.cacheNodeProperties = jd.NodeProperties
					mqlJdRes.cacheRetryStrategy = jd.RetryStrategy
					mqlJdRes.cacheTimeout = jd.Timeout
					mqlJdRes.cacheEks = jd.EksProperties
					mqlJdRes.cacheEcs = jd.EcsProperties
					mqlJdRes.cachePlatformCapabilities = jd.PlatformCapabilities
					mqlJdRes.cachePropagateTags = jd.PropagateTags
					mqlJdRes.cacheSchedulingPriority = jd.SchedulingPriority
					mqlJdRes.cacheParameters = jd.Parameters
					res = append(res, mqlJdRes)
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

type mqlAwsBatchJobDefinitionInternal struct {
	cacheContainerProperties  *batch_types.ContainerProperties
	cacheNodeProperties       *batch_types.NodeProperties
	cacheRetryStrategy        *batch_types.RetryStrategy
	cacheTimeout              *batch_types.JobTimeout
	cacheEks                  *batch_types.EksProperties
	cacheEcs                  *batch_types.EcsProperties
	cachePlatformCapabilities []batch_types.PlatformCapability
	cachePropagateTags        *bool
	cacheSchedulingPriority   *int32
	cacheParameters           map[string]string
}

func (a *mqlAwsBatchJobDefinition) platformCapabilities() ([]any, error) {
	res := make([]any, 0, len(a.cachePlatformCapabilities))
	for _, pc := range a.cachePlatformCapabilities {
		res = append(res, string(pc))
	}
	return res, nil
}

func (a *mqlAwsBatchJobDefinition) propagateTags() (bool, error) {
	if a.cachePropagateTags == nil {
		return false, nil
	}
	return *a.cachePropagateTags, nil
}

func (a *mqlAwsBatchJobDefinition) schedulingPriority() (int64, error) {
	if a.cacheSchedulingPriority == nil {
		return 0, nil
	}
	return int64(*a.cacheSchedulingPriority), nil
}

func (a *mqlAwsBatchJobDefinition) parameters() (map[string]any, error) {
	res := make(map[string]any)
	for k, v := range a.cacheParameters {
		res[k] = v
	}
	return res, nil
}

func (a *mqlAwsBatchJobDefinition) nodeMainNode() (int64, error) {
	if a.cacheNodeProperties == nil || a.cacheNodeProperties.MainNode == nil {
		return 0, nil
	}
	return int64(*a.cacheNodeProperties.MainNode), nil
}

func (a *mqlAwsBatchJobDefinition) nodeNumNodes() (int64, error) {
	if a.cacheNodeProperties == nil || a.cacheNodeProperties.NumNodes == nil {
		return 0, nil
	}
	return int64(*a.cacheNodeProperties.NumNodes), nil
}

func (a *mqlAwsBatchJobDefinition) nodeRangeProperties() ([]any, error) {
	res := []any{}
	if a.cacheNodeProperties == nil {
		return res, nil
	}
	for _, nrp := range a.cacheNodeProperties.NodeRangeProperties {
		targetNodes := convert.ToValue(nrp.TargetNodes)
		id := a.Arn.Data + "/nodeRange/" + targetNodes
		instanceTypes := make([]any, 0, len(nrp.InstanceTypes))
		for _, it := range nrp.InstanceTypes {
			instanceTypes = append(instanceTypes, it)
		}
		ecsDict := map[string]any{}
		if nrp.EcsProperties != nil {
			d, err := convert.JsonToDict(nrp.EcsProperties)
			if err != nil {
				return nil, err
			}
			ecsDict = d
		}
		mqlNrp, err := CreateResource(a.MqlRuntime, "aws.batch.jobDefinition.nodeRangeProperty",
			map[string]*llx.RawData{
				"__id":          llx.StringData(id),
				"targetNodes":   llx.StringData(targetNodes),
				"ecsProperties": llx.DictData(ecsDict),
				"instanceTypes": llx.ArrayData(instanceTypes, types.String),
			})
		if err != nil {
			return nil, err
		}
		mqlNrpRes := mqlNrp.(*mqlAwsBatchJobDefinitionNodeRangeProperty)
		mqlNrpRes.cacheContainer = nrp.Container
		mqlNrpRes.parentArn = a.Arn.Data
		res = append(res, mqlNrpRes)
	}
	return res, nil
}

type mqlAwsBatchJobDefinitionNodeRangePropertyInternal struct {
	cacheContainer *batch_types.ContainerProperties
	parentArn      string
}

func (a *mqlAwsBatchJobDefinitionNodeRangeProperty) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsBatchJobDefinitionNodeRangeProperty) container() (*mqlAwsBatchJobDefinitionContainerProperties, error) {
	if a.cacheContainer == nil {
		a.Container.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return buildBatchContainerProperties(a.MqlRuntime, a.__id, a.cacheContainer)
}

func (a *mqlAwsBatchJobDefinition) ecs() (any, error) {
	if a.cacheEcs == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheEcs)
}

// images flattens every container image referenced anywhere in the job
// definition — single-node container properties, multi-node node-range
// containers, ECS task containers, and EKS pod containers and init containers
// — and parses each reference into its registry, repository, tag, and digest.
// Duplicate references are collapsed so the result is the set of distinct
// images the definition pulls.
func (a *mqlAwsBatchJobDefinition) images() ([]any, error) {
	var refs []string
	refs = appendBatchContainerImage(refs, a.cacheContainerProperties)
	refs = appendBatchEcsImages(refs, a.cacheEcs)
	refs = appendBatchEksImages(refs, a.cacheEks)
	if a.cacheNodeProperties != nil {
		for i := range a.cacheNodeProperties.NodeRangeProperties {
			nrp := a.cacheNodeProperties.NodeRangeProperties[i]
			refs = appendBatchContainerImage(refs, nrp.Container)
			refs = appendBatchEcsImages(refs, nrp.EcsProperties)
			refs = appendBatchEksImages(refs, nrp.EksProperties)
		}
	}

	res := make([]any, 0, len(refs))
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		if ref == "" {
			continue
		}
		if _, ok := seen[ref]; ok {
			continue
		}
		seen[ref] = struct{}{}
		registry, repository, tag, digest := parseImageReference(ref)
		res = append(res, map[string]any{
			"image":      ref,
			"registry":   registry,
			"repository": repository,
			"tag":        tag,
			"digest":     digest,
		})
	}
	return res, nil
}

func appendBatchContainerImage(refs []string, cp *batch_types.ContainerProperties) []string {
	if cp != nil && cp.Image != nil {
		refs = append(refs, *cp.Image)
	}
	return refs
}

func appendBatchEcsImages(refs []string, ecs *batch_types.EcsProperties) []string {
	if ecs == nil {
		return refs
	}
	for _, tp := range ecs.TaskProperties {
		for _, c := range tp.Containers {
			if c.Image != nil {
				refs = append(refs, *c.Image)
			}
		}
	}
	return refs
}

func appendBatchEksImages(refs []string, eks *batch_types.EksProperties) []string {
	if eks == nil || eks.PodProperties == nil {
		return refs
	}
	for _, c := range eks.PodProperties.Containers {
		if c.Image != nil {
			refs = append(refs, *c.Image)
		}
	}
	for _, c := range eks.PodProperties.InitContainers {
		if c.Image != nil {
			refs = append(refs, *c.Image)
		}
	}
	return refs
}

// parseImageReference splits a container image reference into its registry
// host, repository, tag, and digest following Docker reference grammar. A
// reference with no registry host — a bare name like "nginx" or a
// single-segment path like "library/nginx" — normalizes to the "docker.io"
// registry, matching how container runtimes resolve it. The tag and digest are
// empty when the reference omits them.
func parseImageReference(ref string) (registry, repository, tag, digest string) {
	remainder := ref
	if i := strings.Index(remainder, "@"); i >= 0 {
		digest = remainder[i+1:]
		remainder = remainder[:i]
	}

	name := remainder
	if i := strings.IndexByte(remainder, '/'); i >= 0 {
		if first := remainder[:i]; strings.ContainsAny(first, ".:") || first == "localhost" {
			registry = first
			name = remainder[i+1:]
		}
	}
	if registry == "" {
		registry = "docker.io"
	}

	if i := strings.LastIndexByte(name, ':'); i >= 0 {
		tag = name[i+1:]
		repository = name[:i]
	} else {
		repository = name
	}
	return registry, repository, tag, digest
}

func (a *mqlAwsBatchJobDefinition) containerProperties() (any, error) {
	if a.cacheContainerProperties == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheContainerProperties)
}

func (a *mqlAwsBatchJobDefinition) container() (*mqlAwsBatchJobDefinitionContainerProperties, error) {
	cp := a.cacheContainerProperties
	if cp == nil {
		a.Container.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return buildBatchContainerProperties(a.MqlRuntime, a.Arn.Data+"/containerProperties", cp)
}

func buildBatchContainerProperties(runtime *plugin.Runtime, id string, cp *batch_types.ContainerProperties) (*mqlAwsBatchJobDefinitionContainerProperties, error) {
	image := convert.ToValue(cp.Image)
	vcpus := int64(0)
	if cp.Vcpus != nil {
		vcpus = int64(*cp.Vcpus)
	}
	memory := int64(0)
	if cp.Memory != nil {
		memory = int64(*cp.Memory)
	}
	command := make([]any, len(cp.Command))
	for i, c := range cp.Command {
		command[i] = c
	}

	env, err := convert.JsonToDictSlice(cp.Environment)
	if err != nil {
		return nil, err
	}
	resReqs, err := convert.JsonToDictSlice(cp.ResourceRequirements)
	if err != nil {
		return nil, err
	}
	logConfig, err := convert.JsonToDict(cp.LogConfiguration)
	if err != nil {
		return nil, err
	}
	linuxParams, err := convert.JsonToDict(cp.LinuxParameters)
	if err != nil {
		return nil, err
	}
	fargateConfig, err := convert.JsonToDict(cp.FargatePlatformConfiguration)
	if err != nil {
		return nil, err
	}

	privileged := false
	if cp.Privileged != nil {
		privileged = *cp.Privileged
	}
	readonlyRoot := false
	if cp.ReadonlyRootFilesystem != nil {
		readonlyRoot = *cp.ReadonlyRootFilesystem
	}

	res, err := CreateResource(runtime, "aws.batch.jobDefinition.containerProperties",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(id),
			"image":                  llx.StringData(image),
			"vcpus":                  llx.IntData(vcpus),
			"memory":                 llx.IntData(memory),
			"command":                llx.ArrayData(command, types.String),
			"environment":            llx.ArrayData(env, types.Dict),
			"privileged":             llx.BoolData(privileged),
			"readonlyRootFilesystem": llx.BoolData(readonlyRoot),
			"resourceRequirements":   llx.ArrayData(resReqs, types.Dict),
			"logConfiguration":       llx.DictData(logConfig),
			"linuxParameters":        llx.DictData(linuxParams),
			"fargateConfig":          llx.DictData(fargateConfig),
		})
	if err != nil {
		return nil, err
	}
	mqlCP := res.(*mqlAwsBatchJobDefinitionContainerProperties)
	mqlCP.cacheJobRoleArn = cp.JobRoleArn
	mqlCP.cacheExecutionRoleArn = cp.ExecutionRoleArn
	mqlCP.cacheCP = cp
	return mqlCP, nil
}

type mqlAwsBatchJobDefinitionContainerPropertiesInternal struct {
	cacheJobRoleArn       *string
	cacheExecutionRoleArn *string
	cacheCP               *batch_types.ContainerProperties
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) environmentVariables() (map[string]any, error) {
	res := make(map[string]any)
	if a.cacheCP == nil {
		return res, nil
	}
	for _, kv := range a.cacheCP.Environment {
		if kv.Name == nil {
			continue
		}
		res[*kv.Name] = convert.ToValue(kv.Value)
	}
	return res, nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) resourceRequirementsMap() (map[string]any, error) {
	res := make(map[string]any)
	if a.cacheCP == nil {
		return res, nil
	}
	for _, rr := range a.cacheCP.ResourceRequirements {
		res[string(rr.Type)] = convert.ToValue(rr.Value)
	}
	return res, nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) logDriver() (string, error) {
	if a.cacheCP == nil || a.cacheCP.LogConfiguration == nil {
		return "", nil
	}
	return string(a.cacheCP.LogConfiguration.LogDriver), nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) logOptions() (map[string]any, error) {
	res := make(map[string]any)
	if a.cacheCP == nil || a.cacheCP.LogConfiguration == nil {
		return res, nil
	}
	for k, v := range a.cacheCP.LogConfiguration.Options {
		res[k] = v
	}
	return res, nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) logSecretOptions() ([]any, error) {
	res := []any{}
	if a.cacheCP == nil || a.cacheCP.LogConfiguration == nil {
		return res, nil
	}
	return buildBatchSecrets(a.MqlRuntime, a.__id, "logSecretOptions", a.cacheCP.LogConfiguration.SecretOptions)
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) secrets() ([]any, error) {
	res := []any{}
	if a.cacheCP == nil {
		return res, nil
	}
	return buildBatchSecrets(a.MqlRuntime, a.__id, "secrets", a.cacheCP.Secrets)
}

func buildBatchSecrets(runtime *plugin.Runtime, parentID, kind string, secrets []batch_types.Secret) ([]any, error) {
	res := make([]any, 0, len(secrets))
	for i, s := range secrets {
		name := convert.ToValue(s.Name)
		valueFrom := convert.ToValue(s.ValueFrom)
		id := batchChildID(parentID+"/"+kind, name, i)
		mqlSecret, err := CreateResource(runtime, "aws.batch.jobDefinition.containerProperties.secret",
			map[string]*llx.RawData{
				"__id":      llx.StringData(id),
				"name":      llx.StringData(name),
				"valueFrom": llx.StringData(valueFrom),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSecret)
	}
	return res, nil
}

func (a *mqlAwsBatchJobDefinitionContainerPropertiesSecret) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsBatchJobDefinitionContainerPropertiesSecret) secretsManagerSecret() (*mqlAwsSecretsmanagerSecret, error) {
	vf := a.ValueFrom.Data
	if !strings.HasPrefix(vf, "arn:aws:secretsmanager:") {
		a.SecretsManagerSecret.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.secretsmanager.secret",
		map[string]*llx.RawData{"arn": llx.StringData(vf)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSecretsmanagerSecret), nil
}

func (a *mqlAwsBatchJobDefinitionContainerPropertiesSecret) ssmParameter() (*mqlAwsSsmParameter, error) {
	vf := a.ValueFrom.Data
	// Only resolve when valueFrom is an explicit SSM ARN. AWS Batch also accepts
	// bare parameter names, but we don't have enough context (region + account)
	// here to build a canonical ARN, and aws.ssm.parameter has no init to look
	// up by name. For bare-name references, auditors can still inspect the raw
	// valueFrom string.
	if !strings.HasPrefix(vf, "arn:aws:ssm:") {
		a.SsmParameter.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ssm.parameter",
		map[string]*llx.RawData{"arn": llx.StringData(vf)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsSsmParameter), nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) linuxInitProcessEnabled() (bool, error) {
	if a.cacheCP == nil || a.cacheCP.LinuxParameters == nil || a.cacheCP.LinuxParameters.InitProcessEnabled == nil {
		return false, nil
	}
	return *a.cacheCP.LinuxParameters.InitProcessEnabled, nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) linuxMaxSwap() (int64, error) {
	if a.cacheCP == nil || a.cacheCP.LinuxParameters == nil || a.cacheCP.LinuxParameters.MaxSwap == nil {
		return 0, nil
	}
	return int64(*a.cacheCP.LinuxParameters.MaxSwap), nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) linuxSharedMemorySize() (int64, error) {
	if a.cacheCP == nil || a.cacheCP.LinuxParameters == nil || a.cacheCP.LinuxParameters.SharedMemorySize == nil {
		return 0, nil
	}
	return int64(*a.cacheCP.LinuxParameters.SharedMemorySize), nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) linuxSwappiness() (int64, error) {
	if a.cacheCP == nil || a.cacheCP.LinuxParameters == nil || a.cacheCP.LinuxParameters.Swappiness == nil {
		return 0, nil
	}
	return int64(*a.cacheCP.LinuxParameters.Swappiness), nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) linuxDevices() ([]any, error) {
	if a.cacheCP == nil || a.cacheCP.LinuxParameters == nil {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(a.cacheCP.LinuxParameters.Devices)
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) linuxTmpfs() ([]any, error) {
	if a.cacheCP == nil || a.cacheCP.LinuxParameters == nil {
		return []any{}, nil
	}
	return convert.JsonToDictSlice(a.cacheCP.LinuxParameters.Tmpfs)
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) fargatePlatformVersion() (string, error) {
	if a.cacheCP == nil || a.cacheCP.FargatePlatformConfiguration == nil {
		return "", nil
	}
	return convert.ToValue(a.cacheCP.FargatePlatformConfiguration.PlatformVersion), nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) id() (string, error) {
	// __id is set via CreateResource args
	return a.__id, nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) jobRole() (*mqlAwsIamRole, error) {
	if a.cacheJobRoleArn == nil || *a.cacheJobRoleArn == "" {
		a.JobRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheJobRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBatchJobDefinitionContainerProperties) executionRole() (*mqlAwsIamRole, error) {
	if a.cacheExecutionRoleArn == nil || *a.cacheExecutionRoleArn == "" {
		a.ExecutionRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheExecutionRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBatchJobDefinition) nodeProperties() (any, error) {
	if a.cacheNodeProperties == nil {
		return nil, nil
	}
	dict, err := convert.JsonToDict(a.cacheNodeProperties)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (a *mqlAwsBatchJobDefinition) retryStrategy() (any, error) {
	if a.cacheRetryStrategy == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheRetryStrategy)
}

func (a *mqlAwsBatchJobDefinition) retry() (*mqlAwsBatchJobDefinitionRetryStrategy, error) {
	rs := a.cacheRetryStrategy
	if rs == nil {
		a.Retry.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	attempts := int64(0)
	if rs.Attempts != nil {
		attempts = int64(*rs.Attempts)
	}
	evalOnExit, err := convert.JsonToDictSlice(rs.EvaluateOnExit)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(a.MqlRuntime, "aws.batch.jobDefinition.retryStrategy",
		map[string]*llx.RawData{
			"__id":           llx.StringData(a.Arn.Data + "/retryStrategy"),
			"attempts":       llx.IntData(attempts),
			"evaluateOnExit": llx.ArrayData(evalOnExit, types.Dict),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBatchJobDefinitionRetryStrategy), nil
}

func (a *mqlAwsBatchJobDefinitionRetryStrategy) id() (string, error) {
	// __id is set via CreateResource args
	return a.__id, nil
}

func (a *mqlAwsBatchJobDefinition) timeout() (any, error) {
	if a.cacheTimeout == nil {
		return nil, nil
	}
	return convert.JsonToDict(a.cacheTimeout)
}

func (a *mqlAwsBatchJobDefinition) jobTimeout() (*mqlAwsBatchJobDefinitionTimeout, error) {
	t := a.cacheTimeout
	if t == nil {
		a.JobTimeout.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	attemptDuration := int64(0)
	if t.AttemptDurationSeconds != nil {
		attemptDuration = int64(*t.AttemptDurationSeconds)
	}

	res, err := CreateResource(a.MqlRuntime, "aws.batch.jobDefinition.timeout",
		map[string]*llx.RawData{
			"__id":                   llx.StringData(a.Arn.Data + "/timeout"),
			"attemptDurationSeconds": llx.IntData(attemptDuration),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBatchJobDefinitionTimeout), nil
}

func (a *mqlAwsBatchJobDefinitionTimeout) id() (string, error) {
	// __id is set via CreateResource args
	return a.__id, nil
}

func (a *mqlAwsBatch) schedulingPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSchedulingPolicies(conn), 5)
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

func (a *mqlAwsBatch) getSchedulingPolicies(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("batch>getSchedulingPolicies>calling aws with region %s", region)

			svc := conn.Batch(region)
			ctx := context.Background()
			res := []any{}

			// Collect all ARNs first (ListSchedulingPolicies returns summaries only).
			arns := []string{}
			var nextToken *string
			for {
				resp, err := svc.ListSchedulingPolicies(ctx, &batch.ListSchedulingPoliciesInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("Batch is not available in region")
						return res, nil
					}
					return nil, err
				}
				for _, sp := range resp.SchedulingPolicies {
					if sp.Arn != nil {
						arns = append(arns, *sp.Arn)
					}
				}
				if resp.NextToken == nil {
					break
				}
				nextToken = resp.NextToken
			}

			// Describe in batches of 100 (SDK max).
			for i := 0; i < len(arns); i += 100 {
				end := i + 100
				if end > len(arns) {
					end = len(arns)
				}
				resp, err := svc.DescribeSchedulingPolicies(ctx, &batch.DescribeSchedulingPoliciesInput{
					Arns: arns[i:end],
				})
				if err != nil {
					return nil, err
				}
				for _, sp := range resp.SchedulingPolicies {
					tags := make(map[string]any)
					for k, v := range sp.Tags {
						tags[k] = v
					}

					hasFSP := sp.FairsharePolicy != nil
					shareDecay := int64(0)
					computeReserve := int64(0)
					shareDist := []any{}
					if hasFSP {
						if sp.FairsharePolicy.ShareDecaySeconds != nil {
							shareDecay = int64(*sp.FairsharePolicy.ShareDecaySeconds)
						}
						if sp.FairsharePolicy.ComputeReservation != nil {
							computeReserve = int64(*sp.FairsharePolicy.ComputeReservation)
						}
						dist, err := convert.JsonToDictSlice(sp.FairsharePolicy.ShareDistribution)
						if err != nil {
							return nil, err
						}
						shareDist = dist
					}

					mqlSp, err := CreateResource(a.MqlRuntime, "aws.batch.schedulingPolicy",
						map[string]*llx.RawData{
							"__id":               llx.StringDataPtr(sp.Arn),
							"arn":                llx.StringDataPtr(sp.Arn),
							"name":               llx.StringDataPtr(sp.Name),
							"region":             llx.StringData(region),
							"hasFairSharePolicy": llx.BoolData(hasFSP),
							"shareDecaySeconds":  llx.IntData(shareDecay),
							"computeReservation": llx.IntData(computeReserve),
							"shareDistribution":  llx.ArrayData(shareDist, types.Dict),
							"tags":               llx.MapData(tags, types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsBatchJobDefinition) eks() (*mqlAwsBatchJobDefinitionEksPodProperties, error) {
	if a.cacheEks == nil || a.cacheEks.PodProperties == nil {
		a.Eks.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	pod := a.cacheEks.PodProperties

	imagePullSecrets := make([]any, 0, len(pod.ImagePullSecrets))
	for _, ips := range pod.ImagePullSecrets {
		imagePullSecrets = append(imagePullSecrets, convert.ToValue(ips.Name))
	}

	volumes, err := convert.JsonToDictSlice(pod.Volumes)
	if err != nil {
		return nil, err
	}

	metadata := map[string]any{}
	if pod.Metadata != nil {
		m, err := convert.JsonToDict(pod.Metadata)
		if err != nil {
			return nil, err
		}
		metadata = m
	}

	hostNetwork := false
	if pod.HostNetwork != nil {
		hostNetwork = *pod.HostNetwork
	}
	shareProcessNS := false
	if pod.ShareProcessNamespace != nil {
		shareProcessNS = *pod.ShareProcessNamespace
	}

	res, err := CreateResource(a.MqlRuntime, "aws.batch.jobDefinition.eksPodProperties",
		map[string]*llx.RawData{
			"__id":                  llx.StringData(a.Arn.Data + "/eks"),
			"serviceAccountName":    llx.StringData(convert.ToValue(pod.ServiceAccountName)),
			"hostNetwork":           llx.BoolData(hostNetwork),
			"shareProcessNamespace": llx.BoolData(shareProcessNS),
			"dnsPolicy":             llx.StringData(convert.ToValue(pod.DnsPolicy)),
			"imagePullSecrets":      llx.ArrayData(imagePullSecrets, types.String),
			"metadata":              llx.DictData(metadata),
			"volumes":               llx.ArrayData(volumes, types.Dict),
		})
	if err != nil {
		return nil, err
	}
	mqlEks := res.(*mqlAwsBatchJobDefinitionEksPodProperties)
	mqlEks.cacheContainers = pod.Containers
	mqlEks.cacheInitContainers = pod.InitContainers
	mqlEks.parentArn = a.Arn.Data
	return mqlEks, nil
}

type mqlAwsBatchJobDefinitionEksPodPropertiesInternal struct {
	cacheContainers     []batch_types.EksContainer
	cacheInitContainers []batch_types.EksContainer
	parentArn           string
}

func (a *mqlAwsBatchJobDefinitionEksPodProperties) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsBatchJobDefinitionEksPodProperties) containers() ([]any, error) {
	return buildBatchEksContainers(a.MqlRuntime, a.parentArn+"/eks/container", a.cacheContainers)
}

func (a *mqlAwsBatchJobDefinitionEksPodProperties) initContainers() ([]any, error) {
	return buildBatchEksContainers(a.MqlRuntime, a.parentArn+"/eks/initContainer", a.cacheInitContainers)
}

func buildBatchEksContainers(runtime *plugin.Runtime, idPrefix string, containers []batch_types.EksContainer) ([]any, error) {
	res := make([]any, 0, len(containers))
	for i, c := range containers {
		name := convert.ToValue(c.Name)
		// Container name is optional per the SDK; batchChildID falls back to
		// the loop index so unnamed siblings don't collide.
		id := batchChildID(idPrefix, name, i)

		command := make([]any, len(c.Command))
		for i, v := range c.Command {
			command[i] = v
		}
		args := make([]any, len(c.Args))
		for i, v := range c.Args {
			args[i] = v
		}
		env := make(map[string]any)
		for _, e := range c.Env {
			if e.Name == nil {
				continue
			}
			env[*e.Name] = convert.ToValue(e.Value)
		}
		volumeMounts, err := convert.JsonToDictSlice(c.VolumeMounts)
		if err != nil {
			return nil, err
		}
		resources := map[string]any{}
		if c.Resources != nil {
			r, err := convert.JsonToDict(c.Resources)
			if err != nil {
				return nil, err
			}
			resources = r
		}

		priv := false
		allowEsc := false
		roRoot := false
		runAsNonRoot := false
		runAsUser := int64(0)
		runAsGroup := int64(0)
		if c.SecurityContext != nil {
			sc := c.SecurityContext
			if sc.Privileged != nil {
				priv = *sc.Privileged
			}
			if sc.AllowPrivilegeEscalation != nil {
				allowEsc = *sc.AllowPrivilegeEscalation
			}
			if sc.ReadOnlyRootFilesystem != nil {
				roRoot = *sc.ReadOnlyRootFilesystem
			}
			if sc.RunAsNonRoot != nil {
				runAsNonRoot = *sc.RunAsNonRoot
			}
			if sc.RunAsUser != nil {
				runAsUser = *sc.RunAsUser
			}
			if sc.RunAsGroup != nil {
				runAsGroup = *sc.RunAsGroup
			}
		}

		mqlC, err := CreateResource(runtime, "aws.batch.jobDefinition.eksContainer",
			map[string]*llx.RawData{
				"__id":                      llx.StringData(id),
				"name":                      llx.StringData(name),
				"image":                     llx.StringData(convert.ToValue(c.Image)),
				"imagePullPolicy":           llx.StringData(convert.ToValue(c.ImagePullPolicy)),
				"command":                   llx.ArrayData(command, types.String),
				"args":                      llx.ArrayData(args, types.String),
				"env":                       llx.MapData(env, types.String),
				"resources":                 llx.DictData(resources),
				"volumeMounts":              llx.ArrayData(volumeMounts, types.Dict),
				"securityContextPrivileged": llx.BoolData(priv),
				"securityContextAllowPrivilegeEscalation": llx.BoolData(allowEsc),
				"securityContextReadOnlyRootFilesystem":   llx.BoolData(roRoot),
				"securityContextRunAsNonRoot":             llx.BoolData(runAsNonRoot),
				"securityContextRunAsUser":                llx.IntData(runAsUser),
				"securityContextRunAsGroup":               llx.IntData(runAsGroup),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlC)
	}
	return res, nil
}

func (a *mqlAwsBatchJobDefinitionEksContainer) id() (string, error) {
	return a.__id, nil
}

// batchJobActiveStatuses lists non-terminal job statuses. Terminal statuses
// (SUCCEEDED, FAILED) are excluded by default because they can number in the
// millions on long-lived queues.
var batchJobActiveStatuses = []batch_types.JobStatus{
	batch_types.JobStatusSubmitted,
	batch_types.JobStatusPending,
	batch_types.JobStatusRunnable,
	batch_types.JobStatusStarting,
	batch_types.JobStatusRunning,
}

// initAwsBatchComputeEnvironment lazily fetches a compute environment by ARN
// so that typed refs from other Batch resources (e.g., jobQueue.
// computeEnvironmentOrderTyped[*].computeEnvironment()) return a fully
// populated resource even when aws.batch.computeEnvironments() hasn't been
// listed.
func initAwsBatchComputeEnvironment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	arnRaw, ok := args["arn"]
	if !ok || arnRaw == nil {
		return nil, nil, nil
	}
	arnStr, ok := arnRaw.Value.(string)
	if !ok || arnStr == "" {
		return nil, nil, nil
	}

	parsed, err := arn.Parse(arnStr)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Batch(parsed.Region)
	ctx := context.Background()
	resp, err := svc.DescribeComputeEnvironments(ctx, &batch.DescribeComputeEnvironmentsInput{
		ComputeEnvironments: []string{arnStr},
	})
	if err != nil {
		return nil, nil, err
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	if len(resp.ComputeEnvironments) == 0 {
		return nil, nil, fmt.Errorf("aws.batch.computeEnvironment with arn %q not found", arnStr)
	}
	ce := resp.ComputeEnvironments[0]

	tags := make(map[string]any, len(ce.Tags))
	for k, v := range ce.Tags {
		tags[k] = v
	}

	res, err := CreateResource(runtime, "aws.batch.computeEnvironment",
		map[string]*llx.RawData{
			"__id":                       llx.StringDataPtr(ce.ComputeEnvironmentArn),
			"arn":                        llx.StringDataPtr(ce.ComputeEnvironmentArn),
			"name":                       llx.StringDataPtr(ce.ComputeEnvironmentName),
			"region":                     llx.StringData(parsed.Region),
			"state":                      llx.StringData(string(ce.State)),
			"status":                     llx.StringData(string(ce.Status)),
			"statusReason":               llx.StringDataPtr(ce.StatusReason),
			"type":                       llx.StringData(string(ce.Type)),
			"containerOrchestrationType": llx.StringData(string(ce.ContainerOrchestrationType)),
			"tags":                       llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, nil, err
	}
	mqlCeRes := res.(*mqlAwsBatchComputeEnvironment)
	mqlCeRes.cacheComputeResources = ce.ComputeResources
	mqlCeRes.cacheServiceRoleArn = ce.ServiceRole
	mqlCeRes.cacheEcsClusterArn = ce.EcsClusterArn
	mqlCeRes.cacheEks = ce.EksConfiguration
	mqlCeRes.cacheUpdatePolicy = ce.UpdatePolicy
	mqlCeRes.cacheUuid = ce.Uuid
	mqlCeRes.cacheRegion = parsed.Region
	return args, res, nil
}

// initAwsBatchSchedulingPolicy lazily fetches a scheduling policy by ARN so that
// `jobQueue.schedulingPolicy()` returns a fully populated resource even when
// `aws.batch.schedulingPolicies()` hasn't been listed.
func initAwsBatchSchedulingPolicy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Resource already fully populated (from a prior listing).
	if len(args) > 2 {
		return args, nil, nil
	}
	arnRaw, ok := args["arn"]
	if !ok || arnRaw == nil {
		return nil, nil, nil
	}
	arnStr, ok := arnRaw.Value.(string)
	if !ok || arnStr == "" {
		return nil, nil, nil
	}

	parsed, err := arn.Parse(arnStr)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Batch(parsed.Region)
	ctx := context.Background()
	resp, err := svc.DescribeSchedulingPolicies(ctx, &batch.DescribeSchedulingPoliciesInput{
		Arns: []string{arnStr},
	})
	if err != nil {
		return nil, nil, err
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	if len(resp.SchedulingPolicies) == 0 {
		return nil, nil, fmt.Errorf("aws.batch.schedulingPolicy with arn %q not found", arnStr)
	}
	sp := resp.SchedulingPolicies[0]

	tags := make(map[string]any, len(sp.Tags))
	for k, v := range sp.Tags {
		tags[k] = v
	}

	hasFSP := sp.FairsharePolicy != nil
	shareDecay := int64(0)
	computeReserve := int64(0)
	shareDist := []any{}
	if hasFSP {
		if sp.FairsharePolicy.ShareDecaySeconds != nil {
			shareDecay = int64(*sp.FairsharePolicy.ShareDecaySeconds)
		}
		if sp.FairsharePolicy.ComputeReservation != nil {
			computeReserve = int64(*sp.FairsharePolicy.ComputeReservation)
		}
		dist, err := convert.JsonToDictSlice(sp.FairsharePolicy.ShareDistribution)
		if err != nil {
			return nil, nil, err
		}
		shareDist = dist
	}

	res, err := CreateResource(runtime, "aws.batch.schedulingPolicy",
		map[string]*llx.RawData{
			"__id":               llx.StringDataPtr(sp.Arn),
			"arn":                llx.StringDataPtr(sp.Arn),
			"name":               llx.StringDataPtr(sp.Name),
			"region":             llx.StringData(parsed.Region),
			"hasFairSharePolicy": llx.BoolData(hasFSP),
			"shareDecaySeconds":  llx.IntData(shareDecay),
			"computeReservation": llx.IntData(computeReserve),
			"shareDistribution":  llx.ArrayData(shareDist, types.Dict),
			"tags":               llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAwsBatch) jobs() ([]any, error) {
	queues, err := a.jobQueues()
	if err != nil {
		return nil, err
	}

	// Fan out ListJobs+DescribeJobs across queues in parallel. Each queue is
	// already 5 paginated ListJobs (one per non-terminal status) + a batched
	// DescribeJobs, so serial iteration is O(queue-count) latency for
	// something that should be O(1) with fan-out.
	tasks := make([]*jobpool.Job, 0, len(queues))
	for _, q := range queues {
		jq := q.(*mqlAwsBatchJobQueue)
		f := func() (jobpool.JobResult, error) {
			jobs, err := jq.jobs()
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult(jobs), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}

	pool := jobpool.CreatePool(tasks, 5)
	pool.Run()
	if pool.HasErrors() {
		return nil, pool.GetErrors()
	}

	res := []any{}
	for i := range pool.Jobs {
		if pool.Jobs[i].Result != nil {
			res = append(res, pool.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsBatchJobQueue) jobs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Batch(a.Region.Data)
	ctx := context.Background()
	res := []any{}

	jobIds := []string{}
	for _, status := range batchJobActiveStatuses {
		var nextToken *string
		for {
			resp, err := svc.ListJobs(ctx, &batch.ListJobsInput{
				JobQueue:  aws.String(a.Arn.Data),
				JobStatus: status,
				NextToken: nextToken,
			})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("queue", a.Arn.Data).Msg("error accessing job queue for AWS Batch ListJobs")
					return res, nil
				}
				return nil, err
			}
			for _, s := range resp.JobSummaryList {
				if s.JobId != nil {
					jobIds = append(jobIds, *s.JobId)
				}
			}
			if resp.NextToken == nil {
				break
			}
			nextToken = resp.NextToken
		}
	}

	// Describe in batches of 100 (SDK max).
	for i := 0; i < len(jobIds); i += 100 {
		end := i + 100
		if end > len(jobIds) {
			end = len(jobIds)
		}
		resp, err := svc.DescribeJobs(ctx, &batch.DescribeJobsInput{
			Jobs: jobIds[i:end],
		})
		if err != nil {
			return nil, err
		}
		for _, j := range resp.Jobs {
			mqlJ, err := buildBatchJob(a.MqlRuntime, a.Region.Data, j)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlJ)
		}
	}
	return res, nil
}

func buildBatchJob(runtime *plugin.Runtime, region string, j batch_types.JobDetail) (plugin.Resource, error) {
	tags := make(map[string]any)
	for k, v := range j.Tags {
		tags[k] = v
	}
	params := make(map[string]any)
	for k, v := range j.Parameters {
		params[k] = v
	}

	createdAt := timeFromBatchMillis(j.CreatedAt)
	startedAt := timeFromBatchMillis(j.StartedAt)
	stoppedAt := timeFromBatchMillis(j.StoppedAt)

	attempts, err := convert.JsonToDictSlice(j.Attempts)
	if err != nil {
		return nil, err
	}
	arrayProps := map[string]any{}
	if j.ArrayProperties != nil {
		d, err := convert.JsonToDict(j.ArrayProperties)
		if err != nil {
			return nil, err
		}
		arrayProps = d
	}
	nodeDetails := map[string]any{}
	if j.NodeDetails != nil {
		d, err := convert.JsonToDict(j.NodeDetails)
		if err != nil {
			return nil, err
		}
		nodeDetails = d
	}
	containerDetail := map[string]any{}
	logStreamName := ""
	if j.Container != nil {
		d, err := convert.JsonToDict(j.Container)
		if err != nil {
			return nil, err
		}
		containerDetail = d
		logStreamName = convert.ToValue(j.Container.LogStreamName)
	}

	schedulingPriority := int64(0)
	if j.SchedulingPriority != nil {
		schedulingPriority = int64(*j.SchedulingPriority)
	}
	propagateTags := false
	if j.PropagateTags != nil {
		propagateTags = *j.PropagateTags
	}
	isCancelled := false
	if j.IsCancelled != nil {
		isCancelled = *j.IsCancelled
	}
	isTerminated := false
	if j.IsTerminated != nil {
		isTerminated = *j.IsTerminated
	}

	mqlJRaw, err := CreateResource(runtime, "aws.batch.job",
		map[string]*llx.RawData{
			"__id":               llx.StringDataPtr(j.JobArn),
			"id":                 llx.StringDataPtr(j.JobId),
			"arn":                llx.StringDataPtr(j.JobArn),
			"name":               llx.StringDataPtr(j.JobName),
			"region":             llx.StringData(region),
			"status":             llx.StringData(string(j.Status)),
			"statusReason":       llx.StringDataPtr(j.StatusReason),
			"createdAt":          llx.TimeDataPtr(createdAt),
			"startedAt":          llx.TimeDataPtr(startedAt),
			"stoppedAt":          llx.TimeDataPtr(stoppedAt),
			"jobDefinitionArn":   llx.StringDataPtr(j.JobDefinition),
			"jobQueueArn":        llx.StringDataPtr(j.JobQueue),
			"schedulingPriority": llx.IntData(schedulingPriority),
			"shareIdentifier":    llx.StringDataPtr(j.ShareIdentifier),
			"propagateTags":      llx.BoolData(propagateTags),
			"parameters":         llx.MapData(params, types.String),
			"container":          llx.DictData(containerDetail),
			"logStreamName":      llx.StringData(logStreamName),
			"attempts":           llx.ArrayData(attempts, types.Dict),
			"arrayProperties":    llx.DictData(arrayProps),
			"nodeDetails":        llx.DictData(nodeDetails),
			"isCancelled":        llx.BoolData(isCancelled),
			"isTerminated":       llx.BoolData(isTerminated),
			"tags":               llx.MapData(tags, types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlJ := mqlJRaw.(*mqlAwsBatchJob)
	mqlJ.cacheDependsOn = j.DependsOn
	return mqlJ, nil
}

type mqlAwsBatchJobInternal struct {
	cacheDependsOn []batch_types.JobDependency
}

func (a *mqlAwsBatchJob) dependsOn() ([]any, error) {
	res := make([]any, 0, len(a.cacheDependsOn))
	for i, dep := range a.cacheDependsOn {
		jobId := convert.ToValue(dep.JobId)
		depType := string(dep.Type)
		depId := batchChildID(a.Arn.Data+"/dep", jobId, i)
		mqlDep, err := CreateResource(a.MqlRuntime, "aws.batch.job.dependency",
			map[string]*llx.RawData{
				"__id":  llx.StringData(depId),
				"jobId": llx.StringData(jobId),
				"type":  llx.StringData(depType),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlDep)
	}
	return res, nil
}

func (a *mqlAwsBatchJobDependency) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsBatchJobDependency) job() (*mqlAwsBatchJob, error) {
	// aws.batch.job uses the job ARN as __id, and there is no initAwsBatchJob
	// yet that can resolve a resource from a bare job ID. Return StateIsNull
	// for now so queries like `job.dependsOn.job.name` fail open rather than
	// silently returning stub values. The raw `jobId` string remains available
	// for auditors and will be promotable to a typed ref once an init is added.
	a.Job.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

// timeFromBatchMillis converts an AWS Batch *int64 millisecond timestamp to
// *time.Time; returns nil when the source is nil or zero so StateIsNull is
// applied (avoids fabricating 1970 timestamps).
func timeFromBatchMillis(ms *int64) *time.Time {
	if ms == nil || *ms == 0 {
		return nil
	}
	t := time.UnixMilli(*ms)
	return &t
}

// batchChildID builds a stable __id for a child resource that lives inside a
// parent. When `name` is populated it's used as the suffix; when it's empty
// (e.g., SDK types where Name is optional) the loop index is used so that
// sibling children don't collide on the same __id. The "#" prefix on the
// index keeps the fallback visually distinct from a legitimate name.
func batchChildID(parent, name string, index int) string {
	if name == "" {
		return parent + "/#" + strconv.Itoa(index)
	}
	return parent + "/" + name
}

func (a *mqlAwsBatchJob) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsBatchJob) jobDefinition() (*mqlAwsBatchJobDefinition, error) {
	if a.JobDefinitionArn.Data == "" {
		a.JobDefinition.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.batch.jobDefinition",
		map[string]*llx.RawData{"arn": llx.StringData(a.JobDefinitionArn.Data)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBatchJobDefinition), nil
}

func (a *mqlAwsBatchJob) jobQueue() (*mqlAwsBatchJobQueue, error) {
	if a.JobQueueArn.Data == "" {
		a.JobQueue.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// aws.batch.jobQueue has neither an id() method nor an init, so without an
	// explicit "__id" every queue reached this way lands on the empty cache key
	// and each job returns the first job's queue. The ARN matches the key the
	// collection path (getJobQueues) stores under, so this also lets the lookup
	// hit the fully-populated resource instead of building a bare one.
	res, err := NewResource(a.MqlRuntime, "aws.batch.jobQueue",
		map[string]*llx.RawData{
			"__id": llx.StringData(a.JobQueueArn.Data),
			"arn":  llx.StringData(a.JobQueueArn.Data),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBatchJobQueue), nil
}
