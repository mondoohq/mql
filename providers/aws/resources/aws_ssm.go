// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	mqlTypes "go.mondoo.com/mql/v13/types"
)

func (e *mqlAwsSsm) id() (string, error) {
	return "aws.ssm", nil
}

func (a *mqlAwsSsm) parameters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getParameters(conn), 5)
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

func (a *mqlAwsSsm) getParameters(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	var err error
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}} // return the error
	}
	log.Debug().Msgf("regions being called for ssm instance list are: %v", regions)
	for ri := range regions {
		region := regions[ri]
		f := func() (jobpool.JobResult, error) {
			res := []any{}
			ssmsvc := conn.Ssm(region)
			ctx := context.Background()

			input := &ssm.DescribeParametersInput{
				Filters: []types.ParametersFilter{},
			}
			paginator := ssm.NewDescribeParametersPaginator(ssmsvc, input)
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm information")
				}

				for _, param := range resp.Parameters {
					policies := make([]any, 0, len(param.Policies))
					for _, p := range param.Policies {
						policies = append(policies, map[string]any{
							"policyType":   convert.ToValue(p.PolicyType),
							"policyText":   convert.ToValue(p.PolicyText),
							"policyStatus": convert.ToValue(p.PolicyStatus),
						})
					}
					mqlParam, err := CreateResource(a.MqlRuntime, "aws.ssm.parameter",
						map[string]*llx.RawData{
							"allowedPattern":   llx.StringDataPtr(param.AllowedPattern),
							"arn":              llx.StringDataPtr(param.ARN),
							"region":           llx.StringData(region),
							"dataType":         llx.StringDataPtr(param.DataType),
							"description":      llx.StringDataPtr(param.Description),
							"lastModifiedDate": llx.TimeDataPtr(param.LastModifiedDate),
							"lastModifiedUser": llx.StringDataPtr(param.LastModifiedUser),
							"name":             llx.StringDataPtr(param.Name),
							"tier":             llx.StringData(string(param.Tier)),
							"type":             llx.StringData(string(param.Type)),
							"version":          llx.IntData(param.Version),
							"policies":         llx.ArrayData(policies, mqlTypes.Dict),
						})
					if err != nil {
						return nil, err
					}
					mqlSsmParam := mqlParam.(*mqlAwsSsmParameter)
					mqlSsmParam.parameterCache = param
					mqlSsmParam.region = region
					res = append(res, mqlParam)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsSsmParameterInternal struct {
	lazyTags
	parameterCache types.ParameterMetadata
	region         string
}

// tags reads the parameter's tags. SSM's ListTagsForResource is keyed on a
// resource id and type rather than an ARN, and for a parameter the id is the
// parameter name, including its leading path for a hierarchical parameter.
func (a *mqlAwsSsmParameter) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		name := a.Name.Data

		svc := conn.Ssm(a.region)
		resp, err := svc.ListTagsForResource(context.Background(), &ssm.ListTagsForResourceInput{
			ResourceId:   &name,
			ResourceType: types.ResourceTypeForTaggingParameter,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return nil, errTagsUnreadable
			}
			return nil, err
		}
		return tagsToMap(resp.TagList,
			func(t types.Tag) *string { return t.Key },
			func(t types.Tag) *string { return t.Value }), nil
	})
}

func (a *mqlAwsSsmParameter) kmsKey() (*mqlAwsKmsKey, error) {
	if a.parameterCache.KeyId == nil {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		kmsKeyRefArgs(a.region, conn.AccountId(), convert.ToValue(a.parameterCache.KeyId)))
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsSsm) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInstances(conn), 5)
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

func (a *mqlAwsSsm) getInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	var err error
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}} // return the error
	}
	log.Debug().Msgf("regions being called for ssm instance list are: %v", regions)
	for ri := range regions {
		region := regions[ri]
		f := func() (jobpool.JobResult, error) {
			res := []any{}
			ssmsvc := conn.Ssm(region)
			ctx := context.Background()

			input := &ssm.DescribeInstanceInformationInput{
				Filters: []types.InstanceInformationStringFilter{},
			}
			paginator := ssm.NewDescribeInstanceInformationPaginator(ssmsvc, input)
			ssminstances := make([]types.InstanceInformation, 0)
			for paginator.HasMorePages() {
				isssmresp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, errors.Wrap(err, "could not gather ssm information")
				}
				ssminstances = append(ssminstances, isssmresp.InstanceInformationList...)
			}

			log.Debug().Str("account", conn.AccountId()).Str("region", region).Int("instance count", len(ssminstances)).Msg("found ec2 ssm instances")
			for _, instance := range ssminstances {
				mqlInstance, err := CreateResource(a.MqlRuntime, "aws.ssm.instance",
					map[string]*llx.RawData{
						"instanceId":                          llx.StringDataPtr(instance.InstanceId),
						"pingStatus":                          llx.StringData(string(instance.PingStatus)),
						"ipAddress":                           llx.StringDataPtr(instance.IPAddress),
						"platformName":                        llx.StringDataPtr(instance.PlatformName),
						"platformType":                        llx.StringData(string(instance.PlatformType)),
						"platformVersion":                     llx.StringDataPtr(instance.PlatformVersion),
						"region":                              llx.StringData(region),
						"arn":                                 llx.StringData(ssmInstanceArn(conn.AccountId(), region, convert.ToValue(instance.InstanceId))),
						"agentVersion":                        llx.StringDataPtr(instance.AgentVersion),
						"lastPingedAt":                        llx.TimeDataPtr(instance.LastPingDateTime),
						"computerName":                        llx.StringDataPtr(instance.ComputerName),
						"sourceType":                          llx.StringData(string(instance.SourceType)),
						"sourceId":                            llx.StringDataPtr(instance.SourceId),
						"activationId":                        llx.StringDataPtr(instance.ActivationId),
						"resourceType":                        llx.StringData(string(instance.ResourceType)),
						"registeredAt":                        llx.TimeDataPtr(instance.RegistrationDate),
						"isLatestVersion":                     llx.BoolDataPtr(instance.IsLatestVersion),
						"associationStatus":                   llx.StringDataPtr(instance.AssociationStatus),
						"lastAssociationExecutedAt":           llx.TimeDataPtr(instance.LastAssociationExecutionDate),
						"lastSuccessfulAssociationExecutedAt": llx.TimeDataPtr(instance.LastSuccessfulAssociationExecutionDate),
						"defaultInstanceName":                 llx.StringDataPtr(instance.Name),
						"sourceLocation":                      llx.StringDataPtr(instance.SourceLocation),
					})
				if err != nil {
					return nil, err
				}
				mqlInstance.(*mqlAwsSsmInstance).iamRoleName = convert.ToValue(instance.IamRole)
				res = append(res, mqlInstance)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func ssmInstanceArn(account string, region string, id string) string {
	return fmt.Sprintf(ssmInstanceArnPattern, region, account, id)
}

func (a *mqlAwsSsmParameter) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSsmInstance) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsSsmInstance) ec2Instance() (*mqlAwsEc2Instance, error) {
	// Only EC2-registered managed nodes map to an EC2 instance; hybrid and
	// on-premises nodes (ManagedInstance) have no EC2 instance.
	if a.ResourceType.Data != "EC2Instance" || a.InstanceId.Data == "" {
		a.Ec2Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := fmt.Sprintf(ec2InstanceArnPattern, a.Region.Data, conn.AccountId(), a.InstanceId.Data)
	res, err := NewResource(a.MqlRuntime, "aws.ec2.instance",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		a.Ec2Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsEc2Instance), nil
}

type mqlAwsSsmInstanceInternal struct {
	iamRoleName string
}

// iamRole resolves the IAM role assigned to the managed instance for Systems
// Manager. It is set for hybrid and on-premises activations; standard EC2
// instances report an empty role here (their profile is on the EC2 instance).
func (a *mqlAwsSsmInstance) iamRole() (*mqlAwsIamRole, error) {
	if a.iamRoleName == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"name": llx.StringData(a.iamRoleName)})
	if err != nil {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return res.(*mqlAwsIamRole), nil
}

const ssmInstanceArnPattern = "arn:aws:ssm:%s:%s:instance/%s"

func initAwsSsmInstance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSsmInstance); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch ssm instance")
	}

	obj, err := CreateResource(runtime, "aws.ssm", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	ssm := obj.(*mqlAwsSsm)

	rawResources := ssm.GetInstances()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	arnVal := args["arn"].Value.(string)
	for _, rawResource := range rawResources.Data {
		instance := rawResource.(*mqlAwsSsmInstance)
		if instance.Arn.Data == arnVal {
			return args, instance, nil
		}
	}
	return nil, nil, errors.New("ssm instance does not exist")
}

func (a *mqlAwsSsmInstance) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	id := a.InstanceId.Data
	region := a.Region.Data
	ec2svc := conn.Ec2(region)
	tagresp, err := ec2svc.DescribeTags(context.Background(), &ec2.DescribeTagsInput{
		Filters: []ec2types.Filter{
			{
				Name:   aws.String("resource-id"),
				Values: []string{id},
			},
		},
	})
	if err != nil {
		log.Warn().Err(err).Msg("could not gather ssm instance tag information")
	} else if tagresp != nil {
		return Ec2SSMTagsToMap(tagresp.Tags), nil
	}
	return map[string]any{}, nil
}

func Ec2SSMTagsToMap(tags []ec2types.TagDescription) map[string]any {
	return tagsToMap(tags, func(t ec2types.TagDescription) *string { return t.Key }, func(t ec2types.TagDescription) *string { return t.Value })
}
