// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// newMqlVerifiedAccessSse builds the server-side encryption specification
// shared by Verified Access trust providers, groups and endpoints. A nil
// specification means the resource reports no encryption settings at all,
// which is reported as null rather than as a customer managed key being off.
func newMqlVerifiedAccessSse(runtime *plugin.Runtime, ownerID, region string, sse *ec2types.VerifiedAccessSseSpecificationResponse) (*llx.RawData, error) {
	if sse == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.verifiedaccess.sseSpecification", map[string]*llx.RawData{
		"__id":                      llx.StringData(ownerID + "/sseSpecification"),
		"customerManagedKeyEnabled": llx.BoolData(convert.ToValue(sse.CustomerManagedKeyEnabled)),
	})
	if err != nil {
		return nil, err
	}
	mqlSse := res.(*mqlAwsVerifiedaccessSseSpecification)
	mqlSse.cacheKmsKeyArn = sse.KmsKeyArn
	mqlSse.region = region
	return llx.ResourceData(mqlSse, "aws.verifiedaccess.sseSpecification"), nil
}

type mqlAwsVerifiedaccessSseSpecificationInternal struct {
	cacheKmsKeyArn *string
	region         string
}

func (a *mqlAwsVerifiedaccessSseSpecification) kmsKey() (*mqlAwsKmsKey, error) {
	return resolveKmsKeyRef(a.MqlRuntime, a.cacheKmsKeyArn, a.region, &a.KmsKey.State)
}

func (a *mqlAwsVerifiedaccess) id() (string, error) {
	return "aws.verifiedaccess", nil
}

// --- Instances ---

func (a *mqlAwsVerifiedaccess) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInstances(conn), 5)
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

func (a *mqlAwsVerifiedaccess) getInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			paginator := ec2.NewDescribeVerifiedAccessInstancesPaginator(svc, &ec2.DescribeVerifiedAccessInstancesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("verified access is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, inst := range page.VerifiedAccessInstances {
					trustProviders, _ := convert.JsonToDictSlice(inst.VerifiedAccessTrustProviders)

					mqlInst, err := CreateResource(a.MqlRuntime, "aws.verifiedaccess.instance",
						map[string]*llx.RawData{
							"__id":                     llx.StringData("aws.verifiedaccess.instance/" + region + "/" + convert.ToValue(inst.VerifiedAccessInstanceId)),
							"verifiedAccessInstanceId": llx.StringDataPtr(inst.VerifiedAccessInstanceId),
							"region":                   llx.StringData(region),
							"description":              llx.StringDataPtr(inst.Description),
							"fipsEnabled":              llx.BoolDataPtr(inst.FipsEnabled),
							"trustProviders":           llx.ArrayData(trustProviders, types.Dict),
							"createdAt":                llx.TimeDataPtr(parseAwsTimestampPtr(inst.CreationTime)),
							"lastUpdatedAt":            llx.TimeDataPtr(parseAwsTimestampPtr(inst.LastUpdatedTime)),
							"tags":                     llx.MapData(toInterfaceMap(ec2TagsToMap(inst.Tags)), types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlInstance := mqlInst.(*mqlAwsVerifiedaccessInstance)
					mqlInstance.cacheRegion = region
					res = append(res, mqlInst)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsVerifiedaccessInstanceInternal struct {
	cacheRegion string
}

func (a *mqlAwsVerifiedaccessInstance) id() (string, error) {
	return "aws.verifiedaccess.instance/" + a.Region.Data + "/" + a.VerifiedAccessInstanceId.Data, nil
}

func (a *mqlAwsVerifiedaccessInstance) loggingConfiguration() (*mqlAwsVerifiedaccessInstanceLoggingConfiguration, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.cacheRegion)
	ctx := context.Background()

	instanceId := a.VerifiedAccessInstanceId.Data
	resp, err := svc.DescribeVerifiedAccessInstanceLoggingConfigurations(ctx, &ec2.DescribeVerifiedAccessInstanceLoggingConfigurationsInput{
		VerifiedAccessInstanceIds: []string{instanceId},
	})
	if err != nil {
		return nil, classifyAwsError(err, "ec2:DescribeVerifiedAccessInstanceLoggingConfigurations")
	}

	if len(resp.LoggingConfigurations) == 0 {
		a.LoggingConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	lc := resp.LoggingConfigurations[0]
	var includeTrustContext bool
	var logVersion string
	var cwLogs, firehose, s3Config any

	if lc.AccessLogs != nil {
		if lc.AccessLogs.IncludeTrustContext != nil {
			includeTrustContext = *lc.AccessLogs.IncludeTrustContext
		}
		if lc.AccessLogs.LogVersion != nil {
			logVersion = *lc.AccessLogs.LogVersion
		}
		cwLogs, _ = convert.JsonToDict(lc.AccessLogs.CloudWatchLogs)
		firehose, _ = convert.JsonToDict(lc.AccessLogs.KinesisDataFirehose)
		s3Config, _ = convert.JsonToDict(lc.AccessLogs.S3)
	}

	mqlLC, err := CreateResource(a.MqlRuntime, "aws.verifiedaccess.instanceLoggingConfiguration",
		map[string]*llx.RawData{
			"__id":                     llx.StringData("aws.verifiedaccess.instanceLoggingConfiguration/" + a.cacheRegion + "/" + instanceId),
			"verifiedAccessInstanceId": llx.StringData(instanceId),
			"region":                   llx.StringData(a.cacheRegion),
			"includeTrustContext":      llx.BoolData(includeTrustContext),
			"logVersion":               llx.StringData(logVersion),
			"cloudWatchLogs":           llx.DictData(cwLogs),
			"kinesisDataFirehose":      llx.DictData(firehose),
			"s3":                       llx.DictData(s3Config),
		})
	if err != nil {
		return nil, err
	}
	return mqlLC.(*mqlAwsVerifiedaccessInstanceLoggingConfiguration), nil
}

func (a *mqlAwsVerifiedaccessInstanceLoggingConfiguration) id() (string, error) {
	return "aws.verifiedaccess.instanceLoggingConfiguration/" + a.Region.Data + "/" + a.VerifiedAccessInstanceId.Data, nil
}

// --- Trust Providers ---

func (a *mqlAwsVerifiedaccess) trustProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTrustProviders(conn), 5)
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

func (a *mqlAwsVerifiedaccess) getTrustProviders(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			paginator := ec2.NewDescribeVerifiedAccessTrustProvidersPaginator(svc, &ec2.DescribeVerifiedAccessTrustProvidersInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("verified access is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, tp := range page.VerifiedAccessTrustProviders {
					oidcOpts, _ := convert.JsonToDict(tp.OidcOptions)
					sseSpec, _ := convert.JsonToDict(tp.SseSpecification)
					mqlSse, err := newMqlVerifiedAccessSse(a.MqlRuntime,
						"aws.verifiedaccess.trustProvider/"+region+"/"+convert.ToValue(tp.VerifiedAccessTrustProviderId), region, tp.SseSpecification)
					if err != nil {
						return nil, err
					}

					mqlTP, err := CreateResource(a.MqlRuntime, "aws.verifiedaccess.trustProvider",
						map[string]*llx.RawData{
							"__id":                          llx.StringData("aws.verifiedaccess.trustProvider/" + region + "/" + convert.ToValue(tp.VerifiedAccessTrustProviderId)),
							"verifiedAccessTrustProviderId": llx.StringDataPtr(tp.VerifiedAccessTrustProviderId),
							"region":                        llx.StringData(region),
							"trustProviderType":             llx.StringData(string(tp.TrustProviderType)),
							"userTrustProviderType":         llx.StringData(string(tp.UserTrustProviderType)),
							"deviceTrustProviderType":       llx.StringData(string(tp.DeviceTrustProviderType)),
							"policyReferenceName":           llx.StringDataPtr(tp.PolicyReferenceName),
							"oidcOptions":                   llx.DictData(oidcOpts),
							"sseSpecification":              llx.DictData(sseSpec),
							"serverSideEncryption":          mqlSse,
							"tags":                          llx.MapData(toInterfaceMap(ec2TagsToMap(tp.Tags)), types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTP)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsVerifiedaccessTrustProvider) id() (string, error) {
	return "aws.verifiedaccess.trustProvider/" + a.Region.Data + "/" + a.VerifiedAccessTrustProviderId.Data, nil
}

// --- Groups ---

func (a *mqlAwsVerifiedaccess) groups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getGroups(conn), 5)
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

func (a *mqlAwsVerifiedaccess) getGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			paginator := ec2.NewDescribeVerifiedAccessGroupsPaginator(svc, &ec2.DescribeVerifiedAccessGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("verified access is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, grp := range page.VerifiedAccessGroups {
					sseSpec, _ := convert.JsonToDict(grp.SseSpecification)
					mqlSse, err := newMqlVerifiedAccessSse(a.MqlRuntime,
						"aws.verifiedaccess.group/"+region+"/"+convert.ToValue(grp.VerifiedAccessGroupId), region, grp.SseSpecification)
					if err != nil {
						return nil, err
					}

					mqlGrp, err := CreateResource(a.MqlRuntime, "aws.verifiedaccess.group",
						map[string]*llx.RawData{
							"__id":                     llx.StringData("aws.verifiedaccess.group/" + region + "/" + convert.ToValue(grp.VerifiedAccessGroupId)),
							"verifiedAccessGroupId":    llx.StringDataPtr(grp.VerifiedAccessGroupId),
							"verifiedAccessGroupArn":   llx.StringDataPtr(grp.VerifiedAccessGroupArn),
							"region":                   llx.StringData(region),
							"verifiedAccessInstanceId": llx.StringDataPtr(grp.VerifiedAccessInstanceId),
							"sseSpecification":         llx.DictData(sseSpec),
							"serverSideEncryption":     mqlSse,
							"owner":                    llx.StringDataPtr(grp.Owner),
							"tags":                     llx.MapData(toInterfaceMap(ec2TagsToMap(grp.Tags)), types.String),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlGrp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsVerifiedaccessGroup) id() (string, error) {
	return "aws.verifiedaccess.group/" + a.Region.Data + "/" + a.VerifiedAccessGroupId.Data, nil
}

// --- Endpoints ---

func (a *mqlAwsVerifiedaccess) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEndpoints(conn), 5)
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

func (a *mqlAwsVerifiedaccess) getEndpoints(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			paginator := ec2.NewDescribeVerifiedAccessEndpointsPaginator(svc, &ec2.DescribeVerifiedAccessEndpointsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					if IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("verified access is not available in region")
						return res, nil
					}
					return nil, err
				}

				for _, ep := range page.VerifiedAccessEndpoints {
					mqlEP, err := newMqlVerifiedAccessEndpoint(a.MqlRuntime, ep, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlEP)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlVerifiedAccessEndpoint(runtime *plugin.Runtime, ep ec2types.VerifiedAccessEndpoint, region string) (*mqlAwsVerifiedaccessEndpoint, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	sseSpec, _ := convert.JsonToDict(ep.SseSpecification)
	mqlSse, err := newMqlVerifiedAccessSse(runtime,
		"aws.verifiedaccess.endpoint/"+region+"/"+convert.ToValue(ep.VerifiedAccessEndpointId), region, ep.SseSpecification)
	if err != nil {
		return nil, err
	}
	statusDict, _ := convert.JsonToDict(ep.Status)

	res, err := CreateResource(runtime, "aws.verifiedaccess.endpoint",
		map[string]*llx.RawData{
			"__id":                     llx.StringData("aws.verifiedaccess.endpoint/" + region + "/" + convert.ToValue(ep.VerifiedAccessEndpointId)),
			"verifiedAccessEndpointId": llx.StringDataPtr(ep.VerifiedAccessEndpointId),
			"region":                   llx.StringData(region),
			"verifiedAccessGroupId":    llx.StringDataPtr(ep.VerifiedAccessGroupId),
			"verifiedAccessInstanceId": llx.StringDataPtr(ep.VerifiedAccessInstanceId),
			"applicationDomain":        llx.StringDataPtr(ep.ApplicationDomain),
			"endpointDomain":           llx.StringDataPtr(ep.EndpointDomain),
			"endpointType":             llx.StringData(string(ep.EndpointType)),
			"attachmentType":           llx.StringData(string(ep.AttachmentType)),
			"status":                   llx.DictData(statusDict),
			"sseSpecification":         llx.DictData(sseSpec),
			"serverSideEncryption":     mqlSse,
			"tags":                     llx.MapData(toInterfaceMap(ec2TagsToMap(ep.Tags)), types.String),
		})
	if err != nil {
		return nil, err
	}
	res.(*mqlAwsVerifiedaccessEndpoint).cacheDomainCertificateArn = convert.ToValue(ep.DomainCertificateArn)
	mqlEP := res.(*mqlAwsVerifiedaccessEndpoint)
	sgArns := make([]string, len(ep.SecurityGroupIds))
	for i, sgId := range ep.SecurityGroupIds {
		sgArns[i] = NewSecurityGroupArn(region, conn.AccountId(), sgId)
	}
	mqlEP.securityGroupIdHandler.setSecurityGroupArns(sgArns)
	return mqlEP, nil
}

type mqlAwsVerifiedaccessEndpointInternal struct {
	cacheDomainCertificateArn string
	securityGroupIdHandler
}

func (a *mqlAwsVerifiedaccessEndpoint) id() (string, error) {
	return "aws.verifiedaccess.endpoint/" + a.Region.Data + "/" + a.VerifiedAccessEndpointId.Data, nil
}

func (a *mqlAwsVerifiedaccessEndpoint) domainCertificate() (*mqlAwsAcmCertificate, error) {
	arnVal := a.cacheDomainCertificateArn
	if arnVal == "" {
		a.DomainCertificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsVerifiedaccessEndpoint) securityGroups() ([]any, error) {
	return a.securityGroupIdHandler.newSecurityGroupResources(a.MqlRuntime)
}
