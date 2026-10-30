// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk"
	ebtypes "github.com/aws/aws-sdk-go-v2/service/elasticbeanstalk/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

type mqlAwsElasticbeanstalkEnvironmentInternal struct {
	cacheLoadBalancerName string
}

func (a *mqlAwsElasticbeanstalk) id() (string, error) {
	return "aws.elasticbeanstalk", nil
}

func (a *mqlAwsElasticbeanstalk) applications() ([]any, error) {
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

func (a *mqlAwsElasticbeanstalk) getApplications(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("elasticbeanstalk>getApplications>calling aws with region %s", region)

			svc := conn.ElasticBeanstalk(region)
			ctx := context.Background()
			res := []any{}

			resp, err := svc.DescribeApplications(ctx, &elasticbeanstalk.DescribeApplicationsInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}

			for _, app := range resp.Applications {
				lifecycleEnabled, maxCount, maxAgeDays, maxCountDeleteFromS3, maxAgeDeleteFromS3, serviceRoleArn := flattenApplicationLifecycle(app.ResourceLifecycleConfig)

				mqlApp, err := CreateResource(a.MqlRuntime, "aws.elasticbeanstalk.application",
					map[string]*llx.RawData{
						"__id":                       llx.StringDataPtr(app.ApplicationArn),
						"arn":                        llx.StringDataPtr(app.ApplicationArn),
						"name":                       llx.StringDataPtr(app.ApplicationName),
						"region":                     llx.StringData(region),
						"description":                llx.StringDataPtr(app.Description),
						"createdAt":                  llx.TimeDataPtr(app.DateCreated),
						"updatedAt":                  llx.TimeDataPtr(app.DateUpdated),
						"configurationTemplates":     llx.ArrayData(convert.SliceAnyToInterface(app.ConfigurationTemplates), types.String),
						"versions":                   llx.ArrayData(convert.SliceAnyToInterface(app.Versions), types.String),
						"versionLifecycleEnabled":    llx.BoolData(lifecycleEnabled),
						"versionLifecycleMaxCount":   llx.IntData(int64(maxCount)),
						"versionLifecycleMaxAgeDays": llx.IntData(int64(maxAgeDays)),
						"versionLifecycleMaxCountDeleteSourceFromS3": llx.BoolData(maxCountDeleteFromS3),
						"versionLifecycleMaxAgeDeleteSourceFromS3":   llx.BoolData(maxAgeDeleteFromS3),
						"versionLifecycleServiceRoleArn":             llx.StringData(serviceRoleArn),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlApp)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsElasticbeanstalkApplication) tags() (map[string]any, error) {
	arn := a.Arn.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.ElasticBeanstalk(region)
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &elasticbeanstalk.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	tags := make(map[string]any)
	for _, t := range resp.ResourceTags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsElasticbeanstalk) environments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEnvironments(conn), 5)
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

func (a *mqlAwsElasticbeanstalk) getEnvironments(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("elasticbeanstalk>getEnvironments>calling aws with region %s", region)

			svc := conn.ElasticBeanstalk(region)
			ctx := context.Background()
			res := []any{}

			var nextToken *string
			for {
				resp, err := svc.DescribeEnvironments(ctx, &elasticbeanstalk.DescribeEnvironmentsInput{
					NextToken: nextToken,
				})
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, env := range resp.Environments {
					tier, err := convert.JsonToDict(env.Tier)
					if err != nil {
						return nil, err
					}

					var tierName, tierType string
					if env.Tier != nil {
						if env.Tier.Name != nil {
							tierName = *env.Tier.Name
						}
						if env.Tier.Type != nil {
							tierType = *env.Tier.Type
						}
					}

					var lbName string
					if env.Resources != nil && env.Resources.LoadBalancer != nil && env.Resources.LoadBalancer.LoadBalancerName != nil {
						lbName = *env.Resources.LoadBalancer.LoadBalancerName
					}

					var envLinks []any
					if len(env.EnvironmentLinks) > 0 {
						envLinks, err = convert.JsonToDictSlice(env.EnvironmentLinks)
						if err != nil {
							return nil, err
						}
					}

					var operationsRoleArn string
					if env.OperationsRole != nil {
						operationsRoleArn = *env.OperationsRole
					}

					mqlEnv, err := CreateResource(a.MqlRuntime, "aws.elasticbeanstalk.environment",
						map[string]*llx.RawData{
							"__id":                         llx.StringDataPtr(env.EnvironmentArn),
							"arn":                          llx.StringDataPtr(env.EnvironmentArn),
							"name":                         llx.StringDataPtr(env.EnvironmentName),
							"region":                       llx.StringData(region),
							"applicationName":              llx.StringDataPtr(env.ApplicationName),
							"description":                  llx.StringDataPtr(env.Description),
							"environmentId":                llx.StringDataPtr(env.EnvironmentId),
							"platformArn":                  llx.StringDataPtr(env.PlatformArn),
							"solutionStackName":            llx.StringDataPtr(env.SolutionStackName),
							"status":                       llx.StringData(string(env.Status)),
							"health":                       llx.StringData(string(env.Health)),
							"healthStatus":                 llx.StringData(string(env.HealthStatus)),
							"cname":                        llx.StringDataPtr(env.CNAME),
							"endpointUrl":                  llx.StringDataPtr(env.EndpointURL),
							"tier":                         llx.DictData(tier),
							"tierName":                     llx.StringData(tierName),
							"tierType":                     llx.StringData(tierType),
							"templateName":                 llx.StringDataPtr(env.TemplateName),
							"operationsRoleArn":            llx.StringData(operationsRoleArn),
							"abortableOperationInProgress": llx.BoolDataPtr(env.AbortableOperationInProgress),
							"environmentLinks":             llx.ArrayData(envLinks, types.Dict),
							"createdAt":                    llx.TimeDataPtr(env.DateCreated),
							"updatedAt":                    llx.TimeDataPtr(env.DateUpdated),
							"versionLabel":                 llx.StringDataPtr(env.VersionLabel),
						})
					if err != nil {
						return nil, err
					}
					mqlEnv.(*mqlAwsElasticbeanstalkEnvironment).cacheLoadBalancerName = lbName
					res = append(res, mqlEnv)
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

func (a *mqlAwsElasticbeanstalkEnvironment) tags() (map[string]any, error) {
	arn := a.Arn.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.ElasticBeanstalk(region)
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &elasticbeanstalk.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	tags := make(map[string]any)
	for _, t := range resp.ResourceTags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

// flattenApplicationLifecycle converts the SDK's ApplicationResourceLifecycleConfig
// into the scalar fields exposed on aws.elasticbeanstalk.application.
func flattenApplicationLifecycle(cfg *ebtypes.ApplicationResourceLifecycleConfig) (enabled bool, maxCount, maxAgeDays int, maxCountDeleteSourceFromS3, maxAgeDeleteSourceFromS3 bool, serviceRoleArn string) {
	if cfg == nil {
		return
	}
	if cfg.ServiceRole != nil {
		serviceRoleArn = *cfg.ServiceRole
	}
	vlc := cfg.VersionLifecycleConfig
	if vlc == nil {
		return
	}
	if rule := vlc.MaxCountRule; rule != nil {
		if rule.Enabled != nil && *rule.Enabled {
			enabled = true
		}
		if rule.MaxCount != nil {
			maxCount = int(*rule.MaxCount)
		}
		if rule.DeleteSourceFromS3 != nil && *rule.DeleteSourceFromS3 {
			maxCountDeleteSourceFromS3 = true
		}
	}
	if rule := vlc.MaxAgeRule; rule != nil {
		if rule.Enabled != nil && *rule.Enabled {
			enabled = true
		}
		if rule.MaxAgeInDays != nil {
			maxAgeDays = int(*rule.MaxAgeInDays)
		}
		if rule.DeleteSourceFromS3 != nil && *rule.DeleteSourceFromS3 {
			maxAgeDeleteSourceFromS3 = true
		}
	}
	return
}

func (a *mqlAwsElasticbeanstalkApplication) versionLifecycleServiceIamRole() (*mqlAwsIamRole, error) {
	arn := a.VersionLifecycleServiceRoleArn.Data
	if arn == "" {
		a.VersionLifecycleServiceIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsElasticbeanstalkApplication) applicationVersions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	appName := a.Name.Data

	svc := conn.ElasticBeanstalk(region)
	ctx := context.Background()
	res := []any{}

	var nextToken *string
	for {
		resp, err := svc.DescribeApplicationVersions(ctx, &elasticbeanstalk.DescribeApplicationVersionsInput{
			ApplicationName: &appName,
			NextToken:       nextToken,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Str("application", appName).Msg("error accessing application versions for AWS API")
				return res, nil
			}
			return nil, err
		}

		for _, v := range resp.ApplicationVersions {
			var (
				bucket, key, sourceLocation string
				sourceRepo, sourceType      string
			)
			if v.SourceBundle != nil {
				if v.SourceBundle.S3Bucket != nil {
					bucket = *v.SourceBundle.S3Bucket
				}
				if v.SourceBundle.S3Key != nil {
					key = *v.SourceBundle.S3Key
				}
			}
			if v.SourceBuildInformation != nil {
				if v.SourceBuildInformation.SourceLocation != nil {
					sourceLocation = *v.SourceBuildInformation.SourceLocation
				}
				sourceRepo = string(v.SourceBuildInformation.SourceRepository)
				sourceType = string(v.SourceBuildInformation.SourceType)
			}

			mqlVersion, err := CreateResource(a.MqlRuntime, "aws.elasticbeanstalk.applicationVersion",
				map[string]*llx.RawData{
					"__id":                 llx.StringDataPtr(v.ApplicationVersionArn),
					"arn":                  llx.StringDataPtr(v.ApplicationVersionArn),
					"applicationName":      llx.StringDataPtr(v.ApplicationName),
					"versionLabel":         llx.StringDataPtr(v.VersionLabel),
					"region":               llx.StringData(region),
					"description":          llx.StringDataPtr(v.Description),
					"status":               llx.StringData(string(v.Status)),
					"createdAt":            llx.TimeDataPtr(v.DateCreated),
					"updatedAt":            llx.TimeDataPtr(v.DateUpdated),
					"buildArn":             llx.StringDataPtr(v.BuildArn),
					"sourceBundleS3Bucket": llx.StringData(bucket),
					"sourceBundleS3Key":    llx.StringData(key),
					"sourceLocation":       llx.StringData(sourceLocation),
					"sourceRepository":     llx.StringData(sourceRepo),
					"sourceType":           llx.StringData(sourceType),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlVersion)
		}

		if resp.NextToken == nil {
			break
		}
		nextToken = resp.NextToken
	}

	return res, nil
}

func (a *mqlAwsElasticbeanstalkApplicationVersion) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElasticbeanstalkApplicationVersion) tags() (map[string]any, error) {
	arn := a.Arn.Data
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.ElasticBeanstalk(region)
	ctx := context.Background()

	resp, err := svc.ListTagsForResource(ctx, &elasticbeanstalk.ListTagsForResourceInput{
		ResourceArn: &arn,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return markTagsUnreadable(&a.Tags)
		}
		return nil, err
	}
	tags := make(map[string]any)
	for _, t := range resp.ResourceTags {
		if t.Key != nil && t.Value != nil {
			tags[*t.Key] = *t.Value
		}
	}
	return tags, nil
}

func (a *mqlAwsElasticbeanstalkEnvironment) operationsIamRole() (*mqlAwsIamRole, error) {
	arn := a.OperationsRoleArn.Data
	if arn == "" {
		a.OperationsIamRole.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsElasticbeanstalkEnvironment) resourcesSummary() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	envId := a.EnvironmentId.Data

	svc := conn.ElasticBeanstalk(region)
	ctx := context.Background()

	resp, err := svc.DescribeEnvironmentResources(ctx, &elasticbeanstalk.DescribeEnvironmentResourcesInput{
		EnvironmentId: &envId,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil
		}
		return nil, err
	}

	return convert.JsonToDict(resp.EnvironmentResources)
}

func (a *mqlAwsElasticbeanstalkEnvironment) optionSettings() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	appName := a.ApplicationName.Data
	envName := a.Name.Data

	svc := conn.ElasticBeanstalk(region)
	ctx := context.Background()

	resp, err := svc.DescribeConfigurationSettings(ctx, &elasticbeanstalk.DescribeConfigurationSettingsInput{
		ApplicationName: &appName,
		EnvironmentName: &envName,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for _, cs := range resp.ConfigurationSettings {
		for _, opt := range cs.OptionSettings {
			entry := map[string]any{
				"namespace":    convert.ToValue(opt.Namespace),
				"optionName":   convert.ToValue(opt.OptionName),
				"value":        convert.ToValue(opt.Value),
				"resourceName": convert.ToValue(opt.ResourceName),
			}
			res = append(res, entry)
		}
	}
	return res, nil
}

func (a *mqlAwsElasticbeanstalkEnvironment) loadBalancer() (*mqlAwsElbLoadbalancer, error) {
	if a.cacheLoadBalancerName == "" {
		a.LoadBalancer.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := fmt.Sprintf(elbv1LbArnPattern, a.Region.Data, conn.AccountId(), a.cacheLoadBalancerName)
	res, err := NewResource(a.MqlRuntime, "aws.elb.loadbalancer",
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsElbLoadbalancer), nil
}
