// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"strings"

	"github.com/aws/aws-sdk-go-v2/service/autoscaling"
	ec2types "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsAutoscaling) id() (string, error) {
	return "aws.autoscaling", nil
}

func (a *mqlAwsAutoscalingGroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsAutoscaling) groups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getGroups(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}

	return res, nil
}

func (a *mqlAwsAutoscalingGroup) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	groupInstances := []any{}
	for _, instance := range a.groupInstances {
		mqlInstance, err := NewResource(a.MqlRuntime, "aws.ec2.instance",
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(ec2InstanceArnPattern, a.region, conn.AccountId(), convert.ToValue(instance.InstanceId))),
			})
		if err != nil {
			return nil, err
		}
		groupInstances = append(groupInstances, mqlInstance)
	}
	return groupInstances, nil
}

func (a *mqlAwsAutoscalingGroup) targetGroups() ([]any, error) {
	res := []any{}
	for _, tgArn := range a.targetGroupArns {
		mqlTg, err := NewResource(a.MqlRuntime, "aws.elb.targetgroup",
			map[string]*llx.RawData{
				"arn": llx.StringData(tgArn),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTg)
	}
	return res, nil
}

type mqlAwsAutoscalingGroupInternal struct {
	groupInstances            []ec2types.Instance
	targetGroupArns           []string
	region                    string
	cacheServiceLinkedRoleArn string
	cacheLaunchTemplateArn    string
	cacheLaunchTemplateId     string
	cacheLaunchTemplateName   string
	cacheSubnetIds            []string
}

func initAwsAutoscalingGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["region"] == nil || args["name"] == nil {
		return nil, nil, errors.New("region and name required to fetch aws autoscaling group")
	}
	region := args["region"].Value.(string)
	name := args["name"].Value.(string)
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Autoscaling(region)
	ctx := context.Background()
	ags, err := svc.DescribeAutoScalingGroups(ctx, &autoscaling.DescribeAutoScalingGroupsInput{AutoScalingGroupNames: []string{name}})
	if err != nil {
		return nil, nil, err
	}

	if len(ags.AutoScalingGroups) == 1 {
		group := ags.AutoScalingGroups[0]
		newArgs, err := autoscalingGroupArgs(runtime, group, region)
		if err != nil {
			return nil, nil, err
		}
		maps.Copy(args, newArgs)
		mqlGroup, err := CreateResource(runtime, ResourceAwsAutoscalingGroup, args)
		if err != nil {
			return args, nil, err
		}
		populateAutoscalingGroupInternals(mqlGroup.(*mqlAwsAutoscalingGroup), group, region, conn.AccountId())
		return args, mqlGroup, nil
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.autoscaling.group with name %q not found", name)
}

// autoscalingGroupArgs builds the lr-field arg map from an SDK AutoScalingGroup.
// Caller is responsible for populating internal cache fields via
// populateAutoscalingGroupInternals after the resource is created.
func autoscalingGroupArgs(runtime *plugin.Runtime, group ec2types.AutoScalingGroup, region string) (map[string]*llx.RawData, error) {
	lbNames := []any{}
	for _, name := range group.LoadBalancerNames {
		lbNames = append(lbNames, name)
	}
	availabilityZones := []any{}
	for _, zone := range group.AvailabilityZones {
		availabilityZones = append(availabilityZones, zone)
	}
	availabilityZoneIds := []any{}
	for _, id := range group.AvailabilityZoneIds {
		availabilityZoneIds = append(availabilityZoneIds, id)
	}
	terminationPolicies := []any{}
	for _, p := range group.TerminationPolicies {
		terminationPolicies = append(terminationPolicies, p)
	}

	enabledMetrics, err := convert.JsonToDictSlice(group.EnabledMetrics)
	if err != nil {
		return nil, err
	}
	suspendedProcesses, err := convert.JsonToDictSlice(group.SuspendedProcesses)
	if err != nil {
		return nil, err
	}
	trafficSources, err := convert.JsonToDictSlice(group.TrafficSources)
	if err != nil {
		return nil, err
	}
	azDistribution, err := convert.JsonToDict(group.AvailabilityZoneDistribution)
	if err != nil {
		return nil, err
	}
	azImpairmentPolicy, err := convert.JsonToDict(group.AvailabilityZoneImpairmentPolicy)
	if err != nil {
		return nil, err
	}
	capacityReservation, err := convert.JsonToDict(group.CapacityReservationSpecification)
	if err != nil {
		return nil, err
	}
	instanceLifecyclePolicy, err := convert.JsonToDict(group.InstanceLifecyclePolicy)
	if err != nil {
		return nil, err
	}
	instanceMaintenancePolicy, err := convert.JsonToDict(group.InstanceMaintenancePolicy)
	if err != nil {
		return nil, err
	}
	mixedInstancesPolicy, err := convert.JsonToDict(group.MixedInstancesPolicy)
	if err != nil {
		return nil, err
	}
	warmPoolConfiguration, err := convert.JsonToDict(group.WarmPoolConfiguration)
	if err != nil {
		return nil, err
	}

	groupArn := convert.ToValue(group.AutoScalingGroupARN)
	tagSpecs, err := createTagSpecifications(runtime, group.Tags, groupArn)
	if err != nil {
		return nil, err
	}

	launchTemplateVersion := ""
	if group.LaunchTemplate != nil {
		launchTemplateVersion = convert.ToValue(group.LaunchTemplate.Version)
	}

	operatorPrincipal := ""
	if group.Operator != nil {
		operatorPrincipal = convert.ToValue(group.Operator.Principal)
	}

	return map[string]*llx.RawData{
		"arn":                              llx.StringData(groupArn),
		"availabilityZones":                llx.ArrayData(availabilityZones, types.String),
		"availabilityZoneIds":              llx.ArrayData(availabilityZoneIds, types.String),
		"availabilityZoneDistribution":     llx.DictData(azDistribution),
		"availabilityZoneImpairmentPolicy": llx.DictData(azImpairmentPolicy),
		"capacityRebalance":                llx.BoolDataPtr(group.CapacityRebalance),
		"capacityReservationSpecification": llx.DictData(capacityReservation),
		"context":                          llx.StringDataPtr(group.Context),
		"createdAt":                        llx.TimeDataPtr(group.CreatedTime),
		"defaultCooldown":                  llx.IntDataDefault(group.DefaultCooldown, 0),
		"defaultInstanceWarmup":            llx.IntDataDefault(group.DefaultInstanceWarmup, 0),
		"deletionProtection":               llx.StringData(string(group.DeletionProtection)),
		"desiredCapacity":                  llx.IntDataDefault(group.DesiredCapacity, 0),
		"desiredCapacityType":              llx.StringDataPtr(group.DesiredCapacityType),
		"enabledMetrics":                   llx.ArrayData(enabledMetrics, types.Dict),
		"healthCheckGracePeriod":           llx.IntDataDefault(group.HealthCheckGracePeriod, 0),
		"healthCheckType":                  llx.StringDataPtr(group.HealthCheckType),
		"instanceLifecyclePolicy":          llx.DictData(instanceLifecyclePolicy),
		"instanceMaintenancePolicy":        llx.DictData(instanceMaintenancePolicy),
		"launchConfigurationName":          llx.StringDataPtr(group.LaunchConfigurationName),
		"launchTemplateVersion":            llx.StringData(launchTemplateVersion),
		"loadBalancerNames":                llx.ArrayData(lbNames, types.String),
		"maxInstanceLifetime":              llx.IntDataDefault(group.MaxInstanceLifetime, 0),
		"maxSize":                          llx.IntDataDefault(group.MaxSize, 0),
		"minSize":                          llx.IntDataDefault(group.MinSize, 0),
		"mixedInstancesPolicy":             llx.DictData(mixedInstancesPolicy),
		"name":                             llx.StringDataPtr(group.AutoScalingGroupName),
		"newInstancesProtectedFromScaleIn": llx.BoolDataPtr(group.NewInstancesProtectedFromScaleIn),
		"operatorPrincipal":                llx.StringData(operatorPrincipal),
		"placementGroup":                   llx.StringDataPtr(group.PlacementGroup),
		"predictedCapacity":                llx.IntDataDefault(group.PredictedCapacity, 0),
		"region":                           llx.StringData(region),
		"status":                           llx.StringDataPtr(group.Status),
		"suspendedProcesses":               llx.ArrayData(suspendedProcesses, types.Dict),
		"tagSpecifications":                llx.ArrayData(tagSpecs, types.Resource(ResourceAwsAutoscalingGroupTag)),
		"tags":                             llx.MapData(autoscalingTagsToMap(group.Tags), types.String),
		"terminationPolicies":              llx.ArrayData(terminationPolicies, types.String),
		"trafficSources":                   llx.ArrayData(trafficSources, types.Dict),
		"warmPoolConfiguration":            llx.DictData(warmPoolConfiguration),
		"warmPoolSize":                     llx.IntDataDefault(group.WarmPoolSize, 0),
	}, nil
}

func populateAutoscalingGroupInternals(mqlGroup *mqlAwsAutoscalingGroup, group ec2types.AutoScalingGroup, region, accountID string) {
	mqlGroup.groupInstances = group.Instances
	mqlGroup.targetGroupArns = group.TargetGroupARNs
	mqlGroup.region = region
	mqlGroup.cacheServiceLinkedRoleArn = convert.ToValue(group.ServiceLinkedRoleARN)

	if group.LaunchTemplate != nil {
		mqlGroup.cacheLaunchTemplateId = convert.ToValue(group.LaunchTemplate.LaunchTemplateId)
		mqlGroup.cacheLaunchTemplateName = convert.ToValue(group.LaunchTemplate.LaunchTemplateName)
		if mqlGroup.cacheLaunchTemplateId != "" {
			mqlGroup.cacheLaunchTemplateArn = fmt.Sprintf(launchTemplateArnPattern, region, accountID, mqlGroup.cacheLaunchTemplateId)
		}
	}

	if group.VPCZoneIdentifier != nil {
		raw := strings.TrimSpace(*group.VPCZoneIdentifier)
		if raw != "" {
			for id := range strings.SplitSeq(raw, ",") {
				id = strings.TrimSpace(id)
				if id != "" {
					mqlGroup.cacheSubnetIds = append(mqlGroup.cacheSubnetIds, id)
				}
			}
		}
	}
}

func (a *mqlAwsAutoscaling) getGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Autoscaling(region)
			ctx := context.Background()
			res := []any{}

			params := &autoscaling.DescribeAutoScalingGroupsInput{}
			paginator := autoscaling.NewDescribeAutoScalingGroupsPaginator(svc, params)
			for paginator.HasMorePages() {
				groups, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, group := range groups.AutoScalingGroups {
					args, err := autoscalingGroupArgs(a.MqlRuntime, group, region)
					if err != nil {
						return nil, err
					}
					mqlGroup, err := CreateResource(a.MqlRuntime, ResourceAwsAutoscalingGroup, args)
					if err != nil {
						return nil, err
					}
					populateAutoscalingGroupInternals(mqlGroup.(*mqlAwsAutoscalingGroup), group, region, conn.AccountId())
					res = append(res, mqlGroup)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func autoscalingTagsToMap(tags []ec2types.TagDescription) map[string]any {
	return tagsToMap(tags, func(t ec2types.TagDescription) *string { return t.Key }, func(t ec2types.TagDescription) *string { return t.Value })
}

func createTagSpecifications(runtime *plugin.Runtime, tags []ec2types.TagDescription, groupArn string) ([]any, error) {
	tagSpecs := make([]any, 0, len(tags))

	for _, tag := range tags {
		key := convert.ToValue(tag.Key)
		tagId := fmt.Sprintf("%s/tag/%s", groupArn, key)

		mqlTag, err := CreateResource(runtime, ResourceAwsAutoscalingGroupTag,
			map[string]*llx.RawData{
				"__id":              llx.StringData(tagId),
				"key":               llx.StringData(key),
				"value":             llx.StringData(convert.ToValue(tag.Value)),
				"propagateAtLaunch": llx.BoolDataPtr(tag.PropagateAtLaunch),
				"resourceId":        llx.StringData(convert.ToValue(tag.ResourceId)),
				"resourceType":      llx.StringData(convert.ToValue(tag.ResourceType)),
			})
		if err != nil {
			return nil, err
		}
		tagSpecs = append(tagSpecs, mqlTag)
	}

	return tagSpecs, nil
}

func (a *mqlAwsAutoscalingGroup) launchConfiguration() (*mqlAwsEc2Launchconfiguration, error) {
	lcName := a.LaunchConfigurationName.Data
	if lcName == "" {
		a.LaunchConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlLc, err := NewResource(a.MqlRuntime, "aws.ec2.launchconfiguration",
		map[string]*llx.RawData{
			"name":   llx.StringData(lcName),
			"region": llx.StringData(a.region),
		})
	if err != nil {
		return nil, err
	}
	return mqlLc.(*mqlAwsEc2Launchconfiguration), nil
}

func (a *mqlAwsAutoscalingGroup) launchTemplate() (*mqlAwsEc2Launchtemplate, error) {
	if a.cacheLaunchTemplateArn == "" {
		a.LaunchTemplate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlLt, err := NewResource(a.MqlRuntime, "aws.ec2.launchtemplate",
		map[string]*llx.RawData{
			"arn":    llx.StringData(a.cacheLaunchTemplateArn),
			"id":     llx.StringData(a.cacheLaunchTemplateId),
			"name":   llx.StringData(a.cacheLaunchTemplateName),
			"region": llx.StringData(a.region),
		})
	if err != nil {
		return nil, err
	}
	lt := mqlLt.(*mqlAwsEc2Launchtemplate)
	if lt.launchTemplateId == "" {
		lt.launchTemplateId = a.cacheLaunchTemplateId
		lt.region = a.region
	}
	return lt, nil
}

func (a *mqlAwsAutoscalingGroup) serviceLinkedRole() (*mqlAwsIamRole, error) {
	if a.cacheServiceLinkedRoleArn == "" {
		a.ServiceLinkedRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(a.cacheServiceLinkedRoleArn)})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsAutoscalingGroup) subnets() ([]any, error) {
	res := []any{}
	for _, id := range a.cacheSubnetIds {
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{
				"id":     llx.StringData(id),
				"region": llx.StringData(a.region),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsAutoscaling) accountSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAccountSettings(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsAutoscaling) getAccountSettings(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Autoscaling(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeAccountSettings(ctx, &autoscaling.DescribeAccountSettingsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for EC2 Auto Scaling account settings")
						return res, nil
					}
					return nil, err
				}
				for _, setting := range resp.Settings {
					mqlSetting, err := CreateResource(a.MqlRuntime, ResourceAwsAutoscalingAccountSetting,
						autoscalingAccountSettingArgs(region, setting))
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSetting)
				}
				if resp.NextToken == nil || *resp.NextToken == "" {
					break
				}
				if nextToken != nil && *nextToken == *resp.NextToken {
					// A cursor that does not advance would loop forever.
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

// autoscalingAccountSettingArgs maps one account setting. The enforcement
// values are only returned for settings with a hard or flexible enforcement
// type, so they stay null otherwise.
func autoscalingAccountSettingArgs(region string, setting ec2types.AccountSetting) map[string]*llx.RawData {
	name := convert.ToValue(setting.Name)
	return map[string]*llx.RawData{
		"__id":            llx.StringData(region + "/" + name),
		"name":            llx.StringData(name),
		"value":           llx.StringDataPtr(setting.Value),
		"region":          llx.StringData(region),
		"enforcementType": llx.StringDataPtr(setting.EnforcementType),
		"enforcementDate": llx.TimeDataPtr(setting.EnforcementDate),
		"defaultValue":    llx.StringDataPtr(setting.DefaultValue),
		"enforcedValue":   llx.StringDataPtr(setting.EnforcedValue),
	}
}
