// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/mwaa"
	mwaatypes "github.com/aws/aws-sdk-go-v2/service/mwaa/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsMwaa) id() (string, error) {
	return "aws.mwaa", nil
}

func (a *mqlAwsMwaa) environments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return perRegion(conn, "mwaa", func(ctx context.Context, region string) ([]any, error) {
		svc := conn.Mwaa(region)
		names := []string{}
		paginator := mwaa.NewListEnvironmentsPaginator(svc, &mwaa.ListEnvironmentsInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			names = append(names, page.Environments...)
		}

		res := []any{}
		for _, name := range names {
			out, err := svc.GetEnvironment(ctx, &mwaa.GetEnvironmentInput{Name: &name})
			if err != nil {
				return nil, err
			}
			if out.Environment == nil {
				continue
			}
			mqlEnv, err := newMqlMwaaEnvironment(a.MqlRuntime, conn.AccountId(), region, *out.Environment)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlEnv)
		}
		return res, nil
	})
}

// mwaaLogModule is one Airflow component's logging configuration.
type mwaaLogModule struct {
	module      string
	enabled     *bool
	logLevel    *string
	logGroupArn string
}

// mwaaLogModules flattens the per-component logging configuration in a
// fixed order, skipping components the environment reports nothing for.
func mwaaLogModules(cfg *mwaatypes.LoggingConfiguration) []mwaaLogModule {
	if cfg == nil {
		return nil
	}
	named := []struct {
		name string
		cfg  *mwaatypes.ModuleLoggingConfiguration
	}{
		{"DagProcessing", cfg.DagProcessingLogs},
		{"Scheduler", cfg.SchedulerLogs},
		{"Task", cfg.TaskLogs},
		{"WebServer", cfg.WebserverLogs},
		{"Worker", cfg.WorkerLogs},
	}
	res := []mwaaLogModule{}
	for _, n := range named {
		if n.cfg == nil {
			continue
		}
		res = append(res, mwaaLogModule{
			module:      n.name,
			enabled:     n.cfg.Enabled,
			logLevel:    nonEmptyEnum(n.cfg.LogLevel),
			logGroupArn: strings.TrimSuffix(convert.ToValue(n.cfg.CloudWatchLogGroupArn), ":*"),
		})
	}
	return res
}

// mwaaBucketName returns the bucket name of an S3 bucket ARN, or an empty
// string when the value is not one.
func mwaaBucketName(bucketArn string) string {
	parsed, err := arn.Parse(bucketArn)
	if err != nil || parsed.Service != "s3" {
		return ""
	}
	return parsed.Resource
}

func newMqlMwaaEnvironment(runtime *plugin.Runtime, accountID, region string, env mwaatypes.Environment) (*mqlAwsMwaaEnvironment, error) {
	envArn := convert.ToValue(env.Arn)

	logConfigs := []any{}
	for _, m := range mwaaLogModules(env.LoggingConfiguration) {
		mqlLog, err := CreateResource(runtime, ResourceAwsMwaaEnvironmentLogConfiguration, map[string]*llx.RawData{
			"__id":     llx.StringData(envArn + "/logging/" + m.module),
			"module":   llx.StringData(m.module),
			"enabled":  llx.BoolDataPtr(m.enabled),
			"logLevel": llx.StringDataPtr(m.logLevel),
		})
		if err != nil {
			return nil, err
		}
		mqlLog.(*mqlAwsMwaaEnvironmentLogConfiguration).cacheLogGroupArn = m.logGroupArn
		logConfigs = append(logConfigs, mqlLog)
	}

	options := make(map[string]any, len(env.AirflowConfigurationOptions))
	for k, v := range env.AirflowConfigurationOptions {
		options[k] = v
	}
	tags := make(map[string]any, len(env.Tags))
	for k, v := range env.Tags {
		tags[k] = v
	}

	res, err := CreateResource(runtime, ResourceAwsMwaaEnvironment, map[string]*llx.RawData{
		"__id":                         llx.StringData(envArn),
		"arn":                          llx.StringData(envArn),
		"name":                         llx.StringDataPtr(env.Name),
		"region":                       llx.StringData(region),
		"status":                       llx.StringDataPtr(nonEmptyEnum(env.Status)),
		"airflowVersion":               llx.StringDataPtr(env.AirflowVersion),
		"environmentClass":             llx.StringDataPtr(env.EnvironmentClass),
		"webserverAccessMode":          llx.StringDataPtr(nonEmptyEnum(env.WebserverAccessMode)),
		"webserverUrl":                 llx.StringDataPtr(env.WebserverUrl),
		"endpointManagement":           llx.StringDataPtr(nonEmptyEnum(env.EndpointManagement)),
		"dagS3Path":                    llx.StringDataPtr(env.DagS3Path),
		"pluginsS3Path":                llx.StringDataPtr(env.PluginsS3Path),
		"requirementsS3Path":           llx.StringDataPtr(env.RequirementsS3Path),
		"startupScriptS3Path":          llx.StringDataPtr(env.StartupScriptS3Path),
		"logConfigurations":            llx.ArrayData(logConfigs, types.Resource(ResourceAwsMwaaEnvironmentLogConfiguration)),
		"airflowConfigurationOptions":  llx.MapData(options, types.String),
		"minWorkers":                   llx.IntDataPtr(env.MinWorkers),
		"maxWorkers":                   llx.IntDataPtr(env.MaxWorkers),
		"minWebservers":                llx.IntDataPtr(env.MinWebservers),
		"maxWebservers":                llx.IntDataPtr(env.MaxWebservers),
		"schedulers":                   llx.IntDataPtr(env.Schedulers),
		"weeklyMaintenanceWindowStart": llx.StringDataPtr(env.WeeklyMaintenanceWindowStart),
		"webserverVpcEndpointService":  llx.StringDataPtr(env.WebserverVpcEndpointService),
		"databaseVpcEndpointService":   llx.StringDataPtr(env.DatabaseVpcEndpointService),
		"createdAt":                    llx.TimeDataPtr(env.CreatedAt),
		"tags":                         llx.MapData(tags, types.String),
	})
	if err != nil {
		return nil, err
	}
	mqlEnv := res.(*mqlAwsMwaaEnvironment)
	mqlEnv.cacheKmsKey = env.KmsKey
	mqlEnv.cacheExecutionRoleArn = convert.ToValue(env.ExecutionRoleArn)
	mqlEnv.cacheServiceRoleArn = convert.ToValue(env.ServiceRoleArn)
	mqlEnv.cacheSourceBucketArn = convert.ToValue(env.SourceBucketArn)
	if env.NetworkConfiguration != nil {
		mqlEnv.cacheSubnetIds = env.NetworkConfiguration.SubnetIds
		sgArns := make([]string, 0, len(env.NetworkConfiguration.SecurityGroupIds))
		for _, sg := range env.NetworkConfiguration.SecurityGroupIds {
			sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sg))
		}
		mqlEnv.setSecurityGroupArns(sgArns)
	}
	return mqlEnv, nil
}

type mqlAwsMwaaEnvironmentInternal struct {
	securityGroupIdHandler
	cacheKmsKey           *string
	cacheExecutionRoleArn string
	cacheServiceRoleArn   string
	cacheSourceBucketArn  string
	cacheSubnetIds        []string
}

func (a *mqlAwsMwaaEnvironment) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsMwaaEnvironment) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheKmsKey, a.Region.Data, &a.KmsKey.State)
}

func mwaaRole(runtime *plugin.Runtime, roleArn string, field *plugin.TValue[*mqlAwsIamRole]) (*mqlAwsIamRole, error) {
	if roleArn == "" {
		field.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(runtime, ResourceAwsIamRole, map[string]*llx.RawData{
		"arn": llx.StringData(roleArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsMwaaEnvironment) executionRole() (*mqlAwsIamRole, error) {
	return mwaaRole(a.MqlRuntime, a.cacheExecutionRoleArn, &a.ExecutionRole)
}

func (a *mqlAwsMwaaEnvironment) serviceRole() (*mqlAwsIamRole, error) {
	return mwaaRole(a.MqlRuntime, a.cacheServiceRoleArn, &a.ServiceRole)
}

func (a *mqlAwsMwaaEnvironment) sourceBucket() (*mqlAwsS3Bucket, error) {
	name := mwaaBucketName(a.cacheSourceBucketArn)
	if name == "" {
		a.SourceBucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsS3Bucket, map[string]*llx.RawData{
		"name": llx.StringData(name),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsMwaaEnvironment) subnets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, subnetID := range a.cacheSubnetIds {
		if subnetID == "" {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.Region.Data, conn.AccountId(), subnetID)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsMwaaEnvironment) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

type mqlAwsMwaaEnvironmentLogConfigurationInternal struct {
	cacheLogGroupArn string
}

func (a *mqlAwsMwaaEnvironmentLogConfiguration) id() (string, error) {
	return a.__id, nil
}

func (a *mqlAwsMwaaEnvironmentLogConfiguration) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	return resolveAccessLogGroup(a.MqlRuntime, a.cacheLogGroupArn, &a.LogGroup.State)
}
