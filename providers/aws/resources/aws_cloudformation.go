// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/cloudformation"
	cf_types "github.com/aws/aws-sdk-go-v2/service/cloudformation/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsCloudformation) id() (string, error) {
	return "aws.cloudformation", nil
}

func (a *mqlAwsCloudformation) stacks() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getStacks(conn), 5)
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

func cfnTagsToMap(in []cf_types.Tag) map[string]any {
	return tagsToMap(in, func(t cf_types.Tag) *string { return t.Key }, func(t cf_types.Tag) *string { return t.Value })
}

// stackParameterToDict converts an SDK Parameter to a dict with lowercase
// keys. ResolvedValue and UsePreviousValue are only emitted when present
// since they're context-specific (SSM-resolved params and stack updates).
func stackParameterToDict(p cf_types.Parameter) map[string]any {
	d := map[string]any{
		"key":   aws.ToString(p.ParameterKey),
		"value": aws.ToString(p.ParameterValue),
	}
	if p.ResolvedValue != nil {
		d["resolvedValue"] = *p.ResolvedValue
	}
	if p.UsePreviousValue != nil {
		d["usePreviousValue"] = *p.UsePreviousValue
	}
	return d
}

func stackOutputToDict(o cf_types.Output) map[string]any {
	d := map[string]any{
		"key":   aws.ToString(o.OutputKey),
		"value": aws.ToString(o.OutputValue),
	}
	if o.Description != nil {
		d["description"] = *o.Description
	}
	if o.ExportName != nil {
		d["exportName"] = *o.ExportName
	}
	return d
}

// normalizeDriftStatus maps the empty enum default to NOT_CHECKED so the
// field always carries one of the four documented values.
func normalizeDriftStatus(s string) string {
	if s == "" {
		return "NOT_CHECKED"
	}
	return s
}

// stackSetSummaryCacheKey builds the region-qualified __id for a stack set
// summary. Returns ok=false when StackSetId is nil so callers can skip the
// entry — synthesizing "<region>/" would collide across nil-id summaries.
func stackSetSummaryCacheKey(region string, ss cf_types.StackSetSummary) (string, bool) {
	if ss.StackSetId == nil {
		return "", false
	}
	return region + "/" + *ss.StackSetId, true
}

// managedExecutionActive returns whether the StackSet runs non-conflicting
// operations concurrently. SDK default for missing/nil is `false`, per AWS
// docs.
func managedExecutionActive(m *cf_types.ManagedExecution) bool {
	if m == nil || m.Active == nil {
		return false
	}
	return *m.Active
}

func (a *mqlAwsCloudformation) getStacks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cloudformation>getStacks>calling aws with region %s", region)

			svc := conn.CloudFormation(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeStacks(ctx, &cloudformation.DescribeStacksInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied calling cloudformation.DescribeStacks")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("CloudFormation is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, stack := range resp.Stacks {
					mqlStackRes, err := buildCloudformationStackResource(a.MqlRuntime, region, stack)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlStackRes)
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

type mqlAwsCloudformationStackInternal struct {
	cacheRoleArn          *string
	cacheParameters       []cf_types.Parameter
	cacheOutputs          []cf_types.Output
	cacheNotificationArns []string
	cacheParentId         *string
	cacheRootId           *string
}

// resolveStackById issues a targeted DescribeStacks for a single stack id in
// the given region and builds the resource. Returns (nil, nil) when the stack
// is empty/missing; callers set the field's null state before returning.
func resolveStackById(runtime *plugin.Runtime, region string, stackID *string) (*mqlAwsCloudformationStack, error) {
	if stackID == nil || *stackID == "" {
		return nil, nil
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.CloudFormation(region)
	resp, err := svc.DescribeStacks(context.Background(), &cloudformation.DescribeStacksInput{
		StackName: stackID,
	})
	if err != nil {
		if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
			return nil, nil
		}
		var oe interface{ ErrorCode() string }
		if errors.As(err, &oe) && oe.ErrorCode() == "ValidationError" {
			return nil, nil
		}
		return nil, err
	}
	if len(resp.Stacks) == 0 {
		return nil, nil
	}
	return buildCloudformationStackResource(runtime, region, resp.Stacks[0])
}

func (a *mqlAwsCloudformationStack) parentStack() (*mqlAwsCloudformationStack, error) {
	stack, err := resolveStackById(a.MqlRuntime, a.Region.Data, a.cacheParentId)
	if err != nil {
		return nil, err
	}
	if stack == nil {
		a.ParentStack.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return stack, nil
}

func (a *mqlAwsCloudformationStack) rootStack() (*mqlAwsCloudformationStack, error) {
	stack, err := resolveStackById(a.MqlRuntime, a.Region.Data, a.cacheRootId)
	if err != nil {
		return nil, err
	}
	if stack == nil {
		a.RootStack.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return stack, nil
}

func (a *mqlAwsCloudformationStack) iamRole() (*mqlAwsIamRole, error) {
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

func (a *mqlAwsCloudformationStack) parameters() ([]any, error) {
	res := make([]any, 0, len(a.cacheParameters))
	for _, p := range a.cacheParameters {
		res = append(res, stackParameterToDict(p))
	}
	return res, nil
}

func (a *mqlAwsCloudformationStack) outputs() ([]any, error) {
	res := make([]any, 0, len(a.cacheOutputs))
	for _, o := range a.cacheOutputs {
		res = append(res, stackOutputToDict(o))
	}
	return res, nil
}

func (a *mqlAwsCloudformationStack) notificationTopics() ([]any, error) {
	res := make([]any, 0, len(a.cacheNotificationArns))
	for _, arn := range a.cacheNotificationArns {
		mqlTopic, err := NewResource(a.MqlRuntime, "aws.sns.topic",
			map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTopic)
	}
	return res, nil
}

func (a *mqlAwsCloudformationStack) resources() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CloudFormation(a.Region.Data)
	ctx := context.Background()
	stackName := a.Name.Data

	res := []any{}
	paginator := cloudformation.NewListStackResourcesPaginator(svc, &cloudformation.ListStackResourcesInput{StackName: &stackName})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, r := range page.StackResourceSummaries {
			driftStatus := ""
			if r.DriftInformation != nil {
				driftStatus = string(r.DriftInformation.StackResourceDriftStatus)
			}
			mqlRes, err := CreateResource(a.MqlRuntime, "aws.cloudformation.stack.resource",
				map[string]*llx.RawData{
					"__id":          llx.StringData(a.StackId.Data + "/" + convert.ToValue(r.LogicalResourceId)),
					"logicalId":     llx.StringDataPtr(r.LogicalResourceId),
					"physicalId":    llx.StringDataPtr(r.PhysicalResourceId),
					"resourceType":  llx.StringDataPtr(r.ResourceType),
					"status":        llx.StringData(string(r.ResourceStatus)),
					"statusReason":  llx.StringDataPtr(r.ResourceStatusReason),
					"lastUpdatedAt": llx.TimeDataPtr(r.LastUpdatedTimestamp),
					"driftStatus":   llx.StringData(driftStatus),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRes)
		}
	}
	return res, nil
}

func (a *mqlAwsCloudformation) stackSets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getStackSets(conn), 5)
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

// stackSetStatusesToEnumerate are the statuses we sweep. ListStackSets
// defaults to ACTIVE only when Status is unset, so DELETED needs a
// second explicit call.
var stackSetStatusesToEnumerate = []cf_types.StackSetStatus{
	cf_types.StackSetStatusActive,
	cf_types.StackSetStatusDeleted,
}

func (a *mqlAwsCloudformation) getStackSets(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("cloudformation>getStackSets>calling aws with region %s", region)

			svc := conn.CloudFormation(region)
			ctx := context.Background()
			res := []any{}

			for _, status := range stackSetStatusesToEnumerate {
				var nextToken *string
				for {
					resp, err := svc.ListStackSets(ctx, &cloudformation.ListStackSetsInput{
						NextToken: nextToken,
						Status:    status,
					})
					if err != nil {
						if Is400AccessDeniedError(err) {
							log.Warn().Str("region", region).Msg("access denied calling cloudformation.ListStackSets")
							return res, nil
						}
						if IsServiceNotAvailableInRegionError(err) {
							log.Warn().Str("region", region).Msg("CloudFormation is not available in region")
							return res, nil
						}
						return nil, err
					}

					for _, ss := range resp.Summaries {
						id, ok := stackSetSummaryCacheKey(region, ss)
						if !ok {
							// Defensive: AWS shouldn't return a nil
							// StackSetId, but two nil-id summaries in
							// the same region would collide on __id.
							log.Debug().Str("region", region).Msg("skipping stack set summary with nil StackSetId")
							continue
						}

						mqlSs, err := CreateResource(a.MqlRuntime, "aws.cloudformation.stackSet",
							map[string]*llx.RawData{
								"__id":                    llx.StringData(id),
								"stackSetId":              llx.StringDataPtr(ss.StackSetId),
								"name":                    llx.StringDataPtr(ss.StackSetName),
								"region":                  llx.StringData(region),
								"status":                  llx.StringData(string(ss.Status)),
								"description":             llx.StringDataPtr(ss.Description),
								"permissionModel":         llx.StringData(string(ss.PermissionModel)),
								"driftStatus":             llx.StringData(normalizeDriftStatus(string(ss.DriftStatus))),
								"lastDriftCheckTimestamp": llx.TimeDataPtr(ss.LastDriftCheckTimestamp),
							})
						if err != nil {
							return nil, err
						}
						mqlSsRes := mqlSs.(*mqlAwsCloudformationStackSet)
						mqlSsRes.cacheAutoDeployment = ss.AutoDeployment
						mqlSsRes.cacheStatus = ss.Status
						res = append(res, mqlSsRes)
					}

					if resp.NextToken == nil {
						break
					}
					nextToken = resp.NextToken
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsCloudformationStackSetInternal struct {
	cacheAutoDeployment *cf_types.AutoDeployment
	cacheStatus         cf_types.StackSetStatus

	detailsLock      sync.Mutex
	detailsFetched   bool
	cacheTags        map[string]any
	cacheAdminRole   *string
	cacheExecRole    *string
	cacheOuIds       []string
	cacheManagedExec *cf_types.ManagedExecution
}

func (a *mqlAwsCloudformationStackSet) autoDeploymentEnabled() (bool, error) {
	if a.cacheAutoDeployment == nil || a.cacheAutoDeployment.Enabled == nil {
		a.AutoDeploymentEnabled.State = plugin.StateIsNull | plugin.StateIsSet
		return false, nil
	}
	return *a.cacheAutoDeployment.Enabled, nil
}

// fetchDetails calls DescribeStackSet exactly once per stack set and caches
// the fields ListStackSets doesn't return (tags, admin/exec roles, OU IDs).
// Multiple field accessors share the result via double-check locking.
// DELETED stack sets are skipped — DescribeStackSet on a deleted set returns
// StackSetNotFoundException.
func (a *mqlAwsCloudformationStackSet) fetchDetails() error {
	if a.detailsFetched {
		return nil
	}
	a.detailsLock.Lock()
	defer a.detailsLock.Unlock()
	if a.detailsFetched {
		return nil
	}
	if a.cacheStatus != cf_types.StackSetStatusActive {
		a.detailsFetched = true
		return nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.CloudFormation(a.Region.Data)
	ctx := context.Background()
	name := a.StackSetId.Data
	resp, err := svc.DescribeStackSet(ctx, &cloudformation.DescribeStackSetInput{
		StackSetName: &name,
	})
	if err != nil {
		if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
			log.Debug().Str("region", a.Region.Data).Str("stackSet", name).Msg("could not describe stack set")
			a.detailsFetched = true
			return nil
		}
		return err
	}
	if resp.StackSet != nil {
		a.cacheTags = cfnTagsToMap(resp.StackSet.Tags)
		a.cacheAdminRole = resp.StackSet.AdministrationRoleARN
		a.cacheExecRole = resp.StackSet.ExecutionRoleName
		a.cacheOuIds = resp.StackSet.OrganizationalUnitIds
		a.cacheManagedExec = resp.StackSet.ManagedExecution
	}
	a.detailsFetched = true
	return nil
}

func (a *mqlAwsCloudformationStackSet) managedExecutionActive() (bool, error) {
	if err := a.fetchDetails(); err != nil {
		return false, err
	}
	return managedExecutionActive(a.cacheManagedExec), nil
}

func (a *mqlAwsCloudformationStackSet) tags() (map[string]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheTags == nil {
		return map[string]any{}, nil
	}
	return a.cacheTags, nil
}

func (a *mqlAwsCloudformationStackSet) administrationRole() (*mqlAwsIamRole, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	if a.cacheAdminRole == nil || *a.cacheAdminRole == "" {
		a.AdministrationRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheAdminRole)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsCloudformationStackSet) executionRoleName() (string, error) {
	if err := a.fetchDetails(); err != nil {
		return "", err
	}
	if a.cacheExecRole == nil {
		a.ExecutionRoleName.State = plugin.StateIsNull | plugin.StateIsSet
		return "", nil
	}
	return *a.cacheExecRole, nil
}

func (a *mqlAwsCloudformationStackSet) organizationalUnitIds() ([]any, error) {
	if err := a.fetchDetails(); err != nil {
		return nil, err
	}
	res := make([]any, 0, len(a.cacheOuIds))
	for _, ou := range a.cacheOuIds {
		res = append(res, ou)
	}
	return res, nil
}

// managedByFromTags infers the infrastructure-management system that owns a
// resource from the provenance tags AWS injects on managed resources. It returns
// "" when no known management signal is present — the resource is unmanaged, or
// managed by a tool that leaves no recognizable tag (raw API calls, or Terraform
// without a tagging convention).
func managedByFromTags(tags map[string]any) string {
	for _, sig := range []struct {
		key   string
		owner string
	}{
		{"aws:cloudformation:stack-name", "cloudformation"},
		{"elasticbeanstalk:environment-name", "elasticbeanstalk"},
		{"eks:cluster-name", "eks"},
		{"aws:servicecatalog:provisioningPrincipalArn", "servicecatalog"},
		{"aws:autoscaling:groupName", "autoscaling"},
	} {
		if _, ok := tags[sig.key]; ok {
			return sig.owner
		}
	}
	return ""
}

// buildCloudformationStackResource maps a single CloudFormation stack from the
// API into an aws.cloudformation.stack resource, caching the fields that back
// lazy-loaded accessors. Shared by the cross-region stack listing and the
// targeted single-stack lookup.
func buildCloudformationStackResource(runtime *plugin.Runtime, region string, stack cf_types.Stack) (*mqlAwsCloudformationStack, error) {
	capabilities := make([]any, len(stack.Capabilities))
	for j, c := range stack.Capabilities {
		capabilities[j] = string(c)
	}

	driftStatus := ""
	if stack.DriftInformation != nil {
		driftStatus = string(stack.DriftInformation.StackDriftStatus)
	}

	mqlStack, err := CreateResource(runtime, "aws.cloudformation.stack",
		map[string]*llx.RawData{
			"__id":                        llx.StringDataPtr(stack.StackId),
			"stackId":                     llx.StringDataPtr(stack.StackId),
			"name":                        llx.StringDataPtr(stack.StackName),
			"region":                      llx.StringData(region),
			"status":                      llx.StringData(string(stack.StackStatus)),
			"statusReason":                llx.StringDataPtr(stack.StackStatusReason),
			"description":                 llx.StringDataPtr(stack.Description),
			"enableTerminationProtection": llx.BoolDataPtr(stack.EnableTerminationProtection),
			"capabilities":                llx.ArrayData(capabilities, types.String),
			"driftStatus":                 llx.StringData(normalizeDriftStatus(driftStatus)),
			"tags":                        llx.MapData(cfnTagsToMap(stack.Tags), types.String),
			"createdAt":                   llx.TimeDataPtr(stack.CreationTime),
			"updatedAt":                   llx.TimeDataPtr(stack.LastUpdatedTime),
			"changeSetId":                 llx.StringDataPtr(stack.ChangeSetId),
		})
	if err != nil {
		return nil, err
	}
	mqlStackRes := mqlStack.(*mqlAwsCloudformationStack)
	mqlStackRes.cacheRoleArn = stack.RoleARN
	mqlStackRes.cacheParameters = stack.Parameters
	mqlStackRes.cacheOutputs = stack.Outputs
	mqlStackRes.cacheNotificationArns = stack.NotificationARNs
	mqlStackRes.cacheParentId = stack.ParentId
	mqlStackRes.cacheRootId = stack.RootId
	return mqlStackRes, nil
}

// cloudformationStackForTags resolves the CloudFormation stack that manages a
// resource from the AWS-injected `aws:cloudformation:stack-name` tag. It issues
// a targeted DescribeStacks for that one stack in the resource's region instead
// of listing every stack across the account. Returns (nil, nil) when the
// resource is not part of a stack; callers set the field's null state before
// returning.
func cloudformationStackForTags(runtime *plugin.Runtime, region string, tags map[string]any) (*mqlAwsCloudformationStack, error) {
	raw, ok := tags["aws:cloudformation:stack-name"]
	if !ok {
		return nil, nil
	}
	name, ok := raw.(string)
	if !ok || name == "" {
		return nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.CloudFormation(region)
	resp, err := svc.DescribeStacks(context.Background(), &cloudformation.DescribeStacksInput{
		StackName: &name,
	})
	if err != nil {
		// A stale tag can reference a deleted stack; DescribeStacks returns a
		// ValidationError ("Stack with id <name> does not exist") in that case.
		// Treat any access/lookup failure as "no stack" rather than failing the
		// whole scan.
		if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
			return nil, nil
		}
		var oe interface{ ErrorCode() string }
		if errors.As(err, &oe) && oe.ErrorCode() == "ValidationError" {
			return nil, nil
		}
		return nil, err
	}
	if len(resp.Stacks) == 0 {
		return nil, nil
	}
	return buildCloudformationStackResource(runtime, region, resp.Stacks[0])
}
