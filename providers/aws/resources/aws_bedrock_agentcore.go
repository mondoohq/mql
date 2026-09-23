// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol"
	bacctypes "github.com/aws/aws-sdk-go-v2/service/bedrockagentcorecontrol/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// --- AgentCore namespace ---

func (a *mqlAwsBedrock) agentCore() (*mqlAwsBedrockAgentCore, error) {
	res, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore", map[string]*llx.RawData{
		"__id": llx.StringData("aws.bedrock.agentCore"),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockAgentCore), nil
}

func (a *mqlAwsBedrockAgentCore) id() (string, error) {
	return "aws.bedrock.agentCore", nil
}

// collectJobs runs a region-fanned job pool and flattens the []any results.
func (a *mqlAwsBedrockAgentCore) collectJobs(jobs []*jobpool.Job) ([]any, error) {
	poolOfJobs := jobpool.CreatePool(jobs, 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	res := []any{}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
		}
	}
	return res, nil
}

// agentCoreRegionTasks builds one job per region, invoking fn with a
// region-scoped context. Region/permission issues are logged and skipped so a
// single inaccessible region doesn't fail the whole query.
func (a *mqlAwsBedrockAgentCore) agentCoreRegionTasks(conn *connection.AwsConnection, fn func(ctx context.Context, region string) ([]any, error)) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			ctx := context.Background()
			res, err := fn(ctx, region)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS AgentCore API")
					return []any{}, nil
				}
				if IsServiceNotAvailableInRegionError(err) {
					log.Debug().Str("region", region).Msg("bedrock agentcore is not available in region")
					return []any{}, nil
				}
				return nil, err
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// --- Gateways ---

func (a *mqlAwsBedrockAgentCore) gateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListGatewaysPaginator(svc, &bedrockagentcorecontrol.ListGatewaysInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, gw := range page.Items {
				gatewayId := convert.ToValue(gw.GatewayId)
				mqlGw, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.gateway", map[string]*llx.RawData{
					"__id":           llx.StringData(region + "/" + gatewayId),
					"name":           llx.StringDataPtr(gw.Name),
					"region":         llx.StringData(region),
					"status":         llx.StringData(string(gw.Status)),
					"description":    llx.StringDataPtr(gw.Description),
					"protocolType":   llx.StringData(string(gw.ProtocolType)),
					"authorizerType": llx.StringData(string(gw.AuthorizerType)),
					"createdAt":      llx.TimeDataPtr(gw.CreatedAt),
					"updatedAt":      llx.TimeDataPtr(gw.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				mqlGwRes := mqlGw.(*mqlAwsBedrockAgentCoreGateway)
				mqlGwRes.cacheRegion = region
				mqlGwRes.cacheGatewayId = gatewayId
				res = append(res, mqlGwRes)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCoreGatewayInternal struct {
	cacheRegion    string
	cacheGatewayId string
	fetchLock      sync.Mutex
	fetched        bool
	detail         *bedrockagentcorecontrol.GetGatewayOutput
}

func (a *mqlAwsBedrockAgentCoreGateway) id() (string, error) {
	return a.Region.Data + "/" + a.cacheGatewayId, nil
}

func (a *mqlAwsBedrockAgentCoreGateway) fetchDetail() (*bedrockagentcorecontrol.GetGatewayOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	ctx := context.Background()
	gatewayId := a.cacheGatewayId
	detail, err := svc.GetGateway(ctx, &bedrockagentcorecontrol.GetGatewayInput{GatewayIdentifier: &gatewayId})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCoreGateway) arn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.GatewayArn), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) gatewayUrl() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.GatewayUrl), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) roleArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.RoleArn), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.RoleArn == nil || *detail.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.KmsKeyArn == nil || *detail.KmsKeyArn == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.KmsKeyArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) workloadIdentityArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.WorkloadIdentityDetails == nil {
		return "", nil
	}
	return convert.ToValue(detail.WorkloadIdentityDetails.WorkloadIdentityArn), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) workloadIdentity() (*mqlAwsBedrockAgentCoreWorkloadIdentity, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.WorkloadIdentityDetails == nil || detail.WorkloadIdentityDetails.WorkloadIdentityArn == nil {
		a.WorkloadIdentity.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.agentCore.workloadIdentity",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.WorkloadIdentityDetails.WorkloadIdentityArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockAgentCoreWorkloadIdentity), nil
}

func (a *mqlAwsBedrockAgentCoreGateway) targets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	ctx := context.Background()
	gatewayId := a.cacheGatewayId
	region := a.Region.Data
	res := []any{}
	paginator := bedrockagentcorecontrol.NewListGatewayTargetsPaginator(svc, &bedrockagentcorecontrol.ListGatewayTargetsInput{
		GatewayIdentifier: &gatewayId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, t := range page.Items {
			mqlTarget, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.gatewayTarget", map[string]*llx.RawData{
				"__id":        llx.StringData(region + "/" + gatewayId + "/target/" + convert.ToValue(t.TargetId)),
				"targetId":    llx.StringDataPtr(t.TargetId),
				"gatewayId":   llx.StringData(gatewayId),
				"name":        llx.StringDataPtr(t.Name),
				"region":      llx.StringData(region),
				"status":      llx.StringData(string(t.Status)),
				"description": llx.StringDataPtr(t.Description),
				"createdAt":   llx.TimeDataPtr(t.CreatedAt),
				"updatedAt":   llx.TimeDataPtr(t.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			mqlTargetRes := mqlTarget.(*mqlAwsBedrockAgentCoreGatewayTarget)
			mqlTargetRes.cacheRegion = region
			res = append(res, mqlTargetRes)
		}
	}
	return res, nil
}

// --- Gateway rate limits ---

// rateConfigsToDicts renders a rate-limit rule's rate configs as a list of
// {rate, period} maps. An absent or empty list means that dimension of traffic
// is uncapped, which is preserved as an empty list rather than a null.
func rateConfigsToDicts(configs []bacctypes.RateConfig) []any {
	res := make([]any, 0, len(configs))
	for _, c := range configs {
		res = append(res, map[string]any{
			"rate":   convert.ToValue(c.Rate),
			"period": string(c.Period),
		})
	}
	return res
}

func (a *mqlAwsBedrockAgentCoreGateway) rateLimits() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	ctx := context.Background()
	gatewayId := a.cacheGatewayId
	region := a.Region.Data
	res := []any{}
	paginator := bedrockagentcorecontrol.NewListGatewayRateLimitsPaginator(svc, &bedrockagentcorecontrol.ListGatewayRateLimitsInput{
		GatewayIdentifier: &gatewayId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, rl := range page.RateLimits {
			dimensionKeys := make([]any, 0, len(rl.DimensionKeys))
			for _, k := range rl.DimensionKeys {
				dimensionKeys = append(dimensionKeys, k)
			}

			entries := make([]any, 0, len(rl.Entries))
			for _, e := range rl.Entries {
				entries = append(entries, map[string]any{
					"dimensions":  convert.MapToInterfaceMap(e.Dimensions),
					"requests":    rateConfigsToDicts(e.Requests),
					"tokens":      rateConfigsToDicts(e.Tokens),
					"connections": rateConfigsToDicts(e.Connections),
				})
			}

			rateLimitId := convert.ToValue(rl.RateLimitId)
			mqlRl, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreGatewayRateLimit, map[string]*llx.RawData{
				"__id":          llx.StringData(region + "/" + gatewayId + "/rateLimit/" + rateLimitId),
				"id":            llx.StringData(rateLimitId),
				"gatewayId":     llx.StringData(gatewayId),
				"region":        llx.StringData(region),
				"status":        llx.StringData(string(rl.Status)),
				"description":   llx.StringDataPtr(rl.Description),
				"dimensionKeys": llx.ArrayData(dimensionKeys, types.String),
				"entries":       llx.ArrayData(entries, types.Dict),
				"createdAt":     llx.TimeDataPtr(rl.CreatedAt),
				"updatedAt":     llx.TimeDataPtr(rl.UpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRl)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayRateLimit) id() (string, error) {
	return a.Region.Data + "/" + a.GatewayId.Data + "/rateLimit/" + a.Id.Data, nil
}

// --- Capacity providers ---

func (a *mqlAwsBedrockAgentCore) capacityProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListCapacityProvidersPaginator(svc, &bedrockagentcorecontrol.ListCapacityProvidersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, cp := range page.CapacityProviders {
				mqlCp, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreCapacityProvider, map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(cp.CapacityProviderArn),
					"id":        llx.StringDataPtr(cp.CapacityProviderId),
					"arn":       llx.StringDataPtr(cp.CapacityProviderArn),
					"name":      llx.StringDataPtr(cp.Name),
					"region":    llx.StringData(region),
					"status":    llx.StringData(string(cp.Status)),
					"updatedAt": llx.TimeDataPtr(cp.LastUpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				mqlCpRes := mqlCp.(*mqlAwsBedrockAgentCoreCapacityProvider)
				mqlCpRes.cacheRegion = region
				res = append(res, mqlCpRes)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCoreCapacityProviderInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     atomic.Bool
	detail      *bedrockagentcorecontrol.GetCapacityProviderOutput
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) fetchDetail() (*bedrockagentcorecontrol.GetCapacityProviderOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	if a.Id.Error != nil {
		return nil, a.Id.Error
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	capacityProviderId := a.Id.Data
	detail, err := svc.GetCapacityProvider(context.Background(), &bedrockagentcorecontrol.GetCapacityProviderInput{
		CapacityProviderId: &capacityProviderId,
	})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched.Store(true)
	return a.detail, nil
}

// ec2Config unwraps the compute-configuration union. EC2 is the only compute
// type this SDK version models; anything else yields a nil config and leaves
// the EC2-derived fields at their zero values.
func (a *mqlAwsBedrockAgentCoreCapacityProvider) ec2Config() (*bacctypes.Ec2Configuration, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	cfg, ok := detail.ComputeConfiguration.(*bacctypes.ComputeConfigurationMemberEc2Configuration)
	if !ok {
		return nil, nil
	}
	return &cfg.Value, nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) statusCode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return string(detail.StatusCode), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) statusReason() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.StatusReason), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) description() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.Description), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) createdAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return detail.CreatedAt, nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) operatorRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.PermissionsConfiguration == nil ||
		convert.ToValue(detail.PermissionsConfiguration.CapacityProviderOperatorRoleArn) == "" {
		a.OperatorRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.PermissionsConfiguration.CapacityProviderOperatorRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) subnets() ([]any, error) {
	cfg, err := a.ec2Config()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if cfg == nil || cfg.VpcConfiguration == nil {
		return res, nil
	}
	for _, subnetId := range cfg.VpcConfiguration.Subnets {
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet", map[string]*llx.RawData{
			"id":     llx.StringData(subnetId),
			"region": llx.StringData(a.Region.Data),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) securityGroups() ([]any, error) {
	cfg, err := a.ec2Config()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if cfg == nil || cfg.VpcConfiguration == nil {
		return res, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	for _, sgId := range cfg.VpcConfiguration.SecurityGroups {
		mqlSg, err := NewResource(a.MqlRuntime, "aws.ec2.securitygroup", map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, region, conn.AccountId(), sgId)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSg)
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) idleInstanceTimeout() (int64, error) {
	cfg, err := a.ec2Config()
	if err != nil {
		return 0, err
	}
	if cfg == nil || cfg.LifecycleConfiguration == nil {
		return 0, nil
	}
	return int64(convert.ToValue(cfg.LifecycleConfiguration.IdleInstanceTimeout)), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) maxInstanceLifetime() (int64, error) {
	cfg, err := a.ec2Config()
	if err != nil {
		return 0, err
	}
	if cfg == nil || cfg.LifecycleConfiguration == nil {
		return 0, nil
	}
	return int64(convert.ToValue(cfg.LifecycleConfiguration.MaxLifetime)), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) rootVolume() (*bacctypes.RootVolumeConfiguration, error) {
	cfg, err := a.ec2Config()
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return cfg.RootVolume, nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) rootVolumeEncrypted() (bool, error) {
	rv, err := a.rootVolume()
	if err != nil || rv == nil {
		return false, err
	}
	return convert.ToValue(rv.Encrypted), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) rootVolumeFreeSpaceGiB() (int64, error) {
	rv, err := a.rootVolume()
	if err != nil || rv == nil {
		return 0, err
	}
	return int64(convert.ToValue(rv.FreeSpaceGiB)), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) rootVolumeIops() (int64, error) {
	rv, err := a.rootVolume()
	if err != nil || rv == nil {
		return 0, err
	}
	return int64(convert.ToValue(rv.Iops)), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) rootVolumeThroughput() (int64, error) {
	rv, err := a.rootVolume()
	if err != nil || rv == nil {
		return 0, err
	}
	return int64(convert.ToValue(rv.Throughput)), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) rootVolumeType() (string, error) {
	rv, err := a.rootVolume()
	if err != nil || rv == nil {
		return "", err
	}
	return string(rv.VolumeType), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) rootVolumeKmsKey() (*mqlAwsKmsKey, error) {
	rv, err := a.rootVolume()
	if err != nil {
		return nil, err
	}
	if rv == nil || convert.ToValue(rv.KmsKeyId) == "" {
		a.RootVolumeKmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key", map[string]*llx.RawData{
		"arn":    llx.StringDataPtr(rv.KmsKeyId),
		"region": llx.StringData(a.Region.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProvider) volumes() ([]any, error) {
	cfg, err := a.ec2Config()
	if err != nil {
		return nil, err
	}
	res := []any{}
	if cfg == nil {
		return res, nil
	}
	region := a.Region.Data
	for _, v := range cfg.Volumes {
		ebs, ok := v.(*bacctypes.VolumeConfigurationMemberEbsConfiguration)
		if !ok {
			// A volume type this SDK version does not model yet.
			continue
		}
		name := convert.ToValue(ebs.Value.Name)
		mqlVol, err := CreateResource(a.MqlRuntime, ResourceAwsBedrockAgentCoreCapacityProviderVolume, map[string]*llx.RawData{
			"__id":       llx.StringData(a.Arn.Data + "/volume/" + name),
			"name":       llx.StringData(name),
			"sizeGiB":    llx.IntData(int64(convert.ToValue(ebs.Value.SizeGiB))),
			"encrypted":  llx.BoolDataPtr(ebs.Value.Encrypted),
			"iops":       llx.IntData(int64(convert.ToValue(ebs.Value.Iops))),
			"throughput": llx.IntData(int64(convert.ToValue(ebs.Value.Throughput))),
			"volumeType": llx.StringData(string(ebs.Value.VolumeType)),
		})
		if err != nil {
			return nil, err
		}
		mqlVolRes := mqlVol.(*mqlAwsBedrockAgentCoreCapacityProviderVolume)
		mqlVolRes.cacheRegion = region
		mqlVolRes.cacheKmsKeyId = convert.ToValue(ebs.Value.KmsKeyId)
		mqlVolRes.cacheSnapshotId = convert.ToValue(ebs.Value.SnapshotId)
		res = append(res, mqlVolRes)
	}
	return res, nil
}

// capacityProviderIdFromArn pulls the capacity provider id out of an ARN of the
// form arn:aws:bedrock-agentcore:<region>:<account>:capacity-provider/<id>.
func capacityProviderIdFromArn(capacityProviderArn string) (string, error) {
	idx := strings.LastIndex(capacityProviderArn, "/")
	if idx < 0 || idx == len(capacityProviderArn)-1 {
		return "", fmt.Errorf("cannot derive capacity provider id from arn %q", capacityProviderArn)
	}
	return capacityProviderArn[idx+1:], nil
}

// initAwsBedrockAgentCoreCapacityProvider resolves a capacity provider from its
// ARN. It builds and returns the resource rather than only filling in args, so
// the region needed for the later detail fetch travels with it.
func initAwsBedrockAgentCoreCapacityProvider(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws bedrock agentcore capacity provider")
	}
	arnVal := args["arn"].Value.(string)

	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, nil, err
	}
	capacityProviderId, err := capacityProviderIdFromArn(arnVal)
	if err != nil {
		return nil, nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(region)
	detail, err := svc.GetCapacityProvider(context.Background(), &bedrockagentcorecontrol.GetCapacityProviderInput{
		CapacityProviderId: &capacityProviderId,
	})
	if err != nil {
		return nil, nil, err
	}

	resource, err := CreateResource(runtime, ResourceAwsBedrockAgentCoreCapacityProvider, map[string]*llx.RawData{
		"__id":      llx.StringDataPtr(detail.CapacityProviderArn),
		"id":        llx.StringDataPtr(detail.CapacityProviderId),
		"arn":       llx.StringDataPtr(detail.CapacityProviderArn),
		"name":      llx.StringDataPtr(detail.Name),
		"region":    llx.StringData(region),
		"status":    llx.StringData(string(detail.Status)),
		"updatedAt": llx.TimeDataPtr(detail.LastUpdatedAt),
	})
	if err != nil {
		return nil, nil, err
	}

	mqlCp := resource.(*mqlAwsBedrockAgentCoreCapacityProvider)
	mqlCp.cacheRegion = region
	mqlCp.detail = detail
	mqlCp.fetched.Store(true)
	return nil, mqlCp, nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) capacityProvider() (*mqlAwsBedrockAgentCoreCapacityProvider, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.CapacityProviderConfiguration == nil ||
		convert.ToValue(detail.CapacityProviderConfiguration.CapacityProviderArn) == "" {
		a.CapacityProvider.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.bedrock.agentCore.capacityProvider",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.CapacityProviderConfiguration.CapacityProviderArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsBedrockAgentCoreCapacityProvider), nil
}

type mqlAwsBedrockAgentCoreCapacityProviderVolumeInternal struct {
	cacheRegion     string
	cacheKmsKeyId   string
	cacheSnapshotId string
}

func (a *mqlAwsBedrockAgentCoreCapacityProviderVolume) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key", map[string]*llx.RawData{
		"arn":    llx.StringData(a.cacheKmsKeyId),
		"region": llx.StringData(a.cacheRegion),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsBedrockAgentCoreCapacityProviderVolume) snapshot() (*mqlAwsEc2Snapshot, error) {
	if a.cacheSnapshotId == "" {
		a.Snapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.ec2.snapshot", map[string]*llx.RawData{
		"id":     llx.StringData(a.cacheSnapshotId),
		"region": llx.StringData(a.cacheRegion),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Snapshot), nil
}

// --- Gateway targets ---

type mqlAwsBedrockAgentCoreGatewayTargetInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     bool
	detail      *bedrockagentcorecontrol.GetGatewayTargetOutput
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) id() (string, error) {
	return a.Region.Data + "/" + a.GatewayId.Data + "/target/" + a.TargetId.Data, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) fetchDetail() (*bedrockagentcorecontrol.GetGatewayTargetOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	ctx := context.Background()
	gatewayId := a.GatewayId.Data
	targetId := a.TargetId.Data
	detail, err := svc.GetGatewayTarget(ctx, &bedrockagentcorecontrol.GetGatewayTargetInput{
		GatewayIdentifier: &gatewayId,
		TargetId:          &targetId,
	})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) targetConfiguration() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return convert.JsonToDict(detail.TargetConfiguration)
}

func (a *mqlAwsBedrockAgentCoreGatewayTarget) credentialProviderConfigurations() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return convert.JsonToDictSlice(detail.CredentialProviderConfigurations)
}

// --- Agent runtimes ---

func (a *mqlAwsBedrockAgentCore) runtimes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListAgentRuntimesPaginator(svc, &bedrockagentcorecontrol.ListAgentRuntimesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, rt := range page.AgentRuntimes {
				mqlRt, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.runtime", map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(rt.AgentRuntimeArn),
					"id":          llx.StringDataPtr(rt.AgentRuntimeId),
					"arn":         llx.StringDataPtr(rt.AgentRuntimeArn),
					"name":        llx.StringDataPtr(rt.AgentRuntimeName),
					"region":      llx.StringData(region),
					"version":     llx.StringDataPtr(rt.AgentRuntimeVersion),
					"status":      llx.StringData(string(rt.Status)),
					"description": llx.StringDataPtr(rt.Description),
					"updatedAt":   llx.TimeDataPtr(rt.LastUpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				mqlRtRes := mqlRt.(*mqlAwsBedrockAgentCoreRuntime)
				mqlRtRes.cacheRegion = region
				res = append(res, mqlRtRes)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCoreRuntimeInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     bool
	detail      *bedrockagentcorecontrol.GetAgentRuntimeOutput
}

func (a *mqlAwsBedrockAgentCoreRuntime) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) fetchDetail() (*bedrockagentcorecontrol.GetAgentRuntimeOutput, error) {
	if a.fetched {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched {
		return a.detail, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	ctx := context.Background()
	runtimeId := a.Id.Data
	detail, err := svc.GetAgentRuntime(ctx, &bedrockagentcorecontrol.GetAgentRuntimeInput{AgentRuntimeId: &runtimeId})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched = true
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) roleArn() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return convert.ToValue(detail.RoleArn), nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) iamRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.RoleArn == nil || *detail.RoleArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(detail.RoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) networkMode() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.NetworkConfiguration == nil {
		return "", nil
	}
	return string(detail.NetworkConfiguration.NetworkMode), nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) authorizerType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.AuthorizerConfiguration == nil {
		return "", nil
	}
	// AuthorizerConfiguration is a union; a custom JWT authorizer is the only
	// inbound authorizer type currently expressible on a runtime.
	if _, ok := detail.AuthorizerConfiguration.(*bacctypes.AuthorizerConfigurationMemberCustomJWTAuthorizer); ok {
		return "CUSTOM_JWT", nil
	}
	return "", nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) platformVersion() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	v := agentRuntimePlatformVersion(detail)
	if v == nil {
		a.PlatformVersion.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return *v, nil
}

// agentRuntimePlatformVersion returns the runtime platform version reported by
// GetAgentRuntime, or nil when the response or the value is absent.
func agentRuntimePlatformVersion(detail *bedrockagentcorecontrol.GetAgentRuntimeOutput) *string {
	if detail == nil || detail.PlatformVersion == nil || *detail.PlatformVersion == "" {
		return nil
	}
	return detail.PlatformVersion
}

func (a *mqlAwsBedrockAgentCoreRuntime) environmentVariables() (map[string]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return convert.MapToInterfaceMap(detail.EnvironmentVariables), nil
}

func (a *mqlAwsBedrockAgentCoreRuntime) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	ctx := context.Background()
	runtimeId := a.Id.Data
	region := a.Region.Data
	res := []any{}
	paginator := bedrockagentcorecontrol.NewListAgentRuntimeEndpointsPaginator(svc, &bedrockagentcorecontrol.ListAgentRuntimeEndpointsInput{
		AgentRuntimeId: &runtimeId,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			return nil, err
		}
		for _, ep := range page.RuntimeEndpoints {
			mqlEp, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.runtimeEndpoint", map[string]*llx.RawData{
				"__id":            llx.StringDataPtr(ep.AgentRuntimeEndpointArn),
				"id":              llx.StringDataPtr(ep.Id),
				"arn":             llx.StringDataPtr(ep.AgentRuntimeEndpointArn),
				"agentRuntimeArn": llx.StringDataPtr(ep.AgentRuntimeArn),
				"name":            llx.StringDataPtr(ep.Name),
				"region":          llx.StringData(region),
				"status":          llx.StringData(string(ep.Status)),
				"description":     llx.StringDataPtr(ep.Description),
				"liveVersion":     llx.StringDataPtr(ep.LiveVersion),
				"targetVersion":   llx.StringDataPtr(ep.TargetVersion),
				"createdAt":       llx.TimeDataPtr(ep.CreatedAt),
				"updatedAt":       llx.TimeDataPtr(ep.LastUpdatedAt),
			})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlEp)
		}
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreRuntimeEndpoint) id() (string, error) {
	return a.Arn.Data, nil
}

// --- Memory ---

func (a *mqlAwsBedrockAgentCore) memories() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListMemoriesPaginator(svc, &bedrockagentcorecontrol.ListMemoriesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, m := range page.Memories {
				mqlMem, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.memory", map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(m.Arn),
					"id":        llx.StringDataPtr(m.Id),
					"arn":       llx.StringDataPtr(m.Arn),
					"region":    llx.StringData(region),
					"status":    llx.StringData(string(m.Status)),
					"createdAt": llx.TimeDataPtr(m.CreatedAt),
					"updatedAt": llx.TimeDataPtr(m.UpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				mqlMem.(*mqlAwsBedrockAgentCoreMemory).cacheRegion = region
				res = append(res, mqlMem)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCoreMemoryInternal struct {
	cacheRegion string
	fetchLock   sync.Mutex
	fetched     atomic.Bool
	detail      *bedrockagentcorecontrol.GetMemoryOutput
}

func (a *mqlAwsBedrockAgentCoreMemory) id() (string, error) {
	return a.Arn.Data, nil
}

// fetchDetail reads the full memory store. ListMemories returns a summary that
// omits the namespace keys, so they need a per-store call.
func (a *mqlAwsBedrockAgentCoreMemory) fetchDetail() (*bedrockagentcorecontrol.GetMemoryOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	if a.Id.Error != nil {
		return nil, a.Id.Error
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.cacheRegion)
	memoryId := a.Id.Data
	detail, err := svc.GetMemory(context.Background(), &bedrockagentcorecontrol.GetMemoryInput{
		MemoryId: &memoryId,
	})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched.Store(true)
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCoreMemory) namespaceKeys() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.Memory == nil {
		return []any{}, nil
	}

	res := make([]any, 0, len(detail.Memory.NamespaceKeys))
	for _, entry := range detail.Memory.NamespaceKeys {
		if entry.Key == nil {
			continue
		}

		// A key with no validation accepts any value. Reporting an empty
		// allowed-value list and an empty pattern is the honest rendering of
		// that: neither constraint is in force.
		allowed := []any{}
		regexPattern := ""
		if entry.Validation != nil {
			for _, v := range entry.Validation.AllowedValues {
				allowed = append(allowed, v)
			}
			if entry.Validation.RegexPattern != nil {
				regexPattern = *entry.Validation.RegexPattern
			}
		}

		mqlKey, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.memory.namespaceKey",
			map[string]*llx.RawData{
				"__id":          llx.StringData(a.Arn.Data + "/namespaceKey/" + *entry.Key),
				"key":           llx.StringDataPtr(entry.Key),
				"allowedValues": llx.ArrayData(allowed, types.String),
				"regexPattern":  llx.StringData(regexPattern),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlKey)
	}
	return res, nil
}

// --- Browsers ---

func (a *mqlAwsBedrockAgentCore) browsers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListBrowsersPaginator(svc, &bedrockagentcorecontrol.ListBrowsersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, b := range page.BrowserSummaries {
				mqlBrowser, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.browser", map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(b.BrowserArn),
					"id":          llx.StringDataPtr(b.BrowserId),
					"arn":         llx.StringDataPtr(b.BrowserArn),
					"name":        llx.StringDataPtr(b.Name),
					"region":      llx.StringData(region),
					"status":      llx.StringData(string(b.Status)),
					"description": llx.StringDataPtr(b.Description),
					"createdAt":   llx.TimeDataPtr(b.CreatedAt),
					"updatedAt":   llx.TimeDataPtr(b.LastUpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlBrowser)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCoreBrowserInternal struct {
	fetchLock sync.Mutex
	fetched   atomic.Bool
	detail    *bedrockagentcorecontrol.GetBrowserOutput
}

func (a *mqlAwsBedrockAgentCoreBrowser) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBedrockAgentCoreBrowser) fetchDetail() (*bedrockagentcorecontrol.GetBrowserOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	if a.Id.Error != nil {
		return nil, a.Id.Error
	}
	if a.Region.Error != nil {
		return nil, a.Region.Error
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.Region.Data)
	browserId := a.Id.Data
	detail, err := svc.GetBrowser(context.Background(), &bedrockagentcorecontrol.GetBrowserInput{BrowserId: &browserId})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched.Store(true)
	return a.detail, nil
}

type mqlAwsBedrockAgentCoreFilesystemConfigurationInternal struct {
	cacheEfsFilesystemArn string
}

func (a *mqlAwsBedrockAgentCoreFilesystemConfiguration) fileSystem() (*mqlAwsEfsFilesystem, error) {
	if a.cacheEfsFilesystemArn == "" {
		a.FileSystem.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.efs.filesystem", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheEfsFilesystemArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEfsFilesystem), nil
}

// newAgentCoreFilesystemConfigurations flattens the EFS / S3 Files union that
// AgentCore returns for a sandbox's mounts into one resource per mount.
func newAgentCoreFilesystemConfigurations(runtime *plugin.Runtime, parentArn string, configs []bacctypes.ToolsFileSystemConfiguration) ([]any, error) {
	res := []any{}
	for _, cfg := range configs {
		var kind, accessPointArn, fileSystemArn, mountPath string
		switch v := cfg.(type) {
		case *bacctypes.ToolsFileSystemConfigurationMemberEfsConfiguration:
			kind = "EFS"
			accessPointArn = convert.ToValue(v.Value.AccessPointArn)
			fileSystemArn = convert.ToValue(v.Value.FileSystemArn)
			mountPath = convert.ToValue(v.Value.MountPath)
		case *bacctypes.ToolsFileSystemConfigurationMemberS3FilesConfiguration:
			kind = "S3_FILES"
			accessPointArn = convert.ToValue(v.Value.AccessPointArn)
			fileSystemArn = convert.ToValue(v.Value.FileSystemArn)
			mountPath = convert.ToValue(v.Value.MountPath)
		default:
			// A mount type this SDK version does not model yet.
			continue
		}

		mqlCfg, err := CreateResource(runtime, "aws.bedrock.agentCore.filesystemConfiguration", map[string]*llx.RawData{
			"__id":           llx.StringData(parentArn + "/filesystemConfigurations/" + mountPath),
			"type":           llx.StringData(kind),
			"accessPointArn": llx.StringData(accessPointArn),
			"fileSystemArn":  llx.StringData(fileSystemArn),
			"mountPath":      llx.StringData(mountPath),
		})
		if err != nil {
			return nil, err
		}
		if kind == "EFS" {
			mqlCfg.(*mqlAwsBedrockAgentCoreFilesystemConfiguration).cacheEfsFilesystemArn = fileSystemArn
		}
		res = append(res, mqlCfg)
	}
	return res, nil
}

func (a *mqlAwsBedrockAgentCoreBrowser) filesystemConfigurations() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return []any{}, nil
	}
	return newAgentCoreFilesystemConfigurations(a.MqlRuntime, a.Arn.Data, detail.FilesystemConfigurations)
}

// --- Code interpreters ---

func (a *mqlAwsBedrockAgentCore) codeInterpreters() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListCodeInterpretersPaginator(svc, &bedrockagentcorecontrol.ListCodeInterpretersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, ci := range page.CodeInterpreterSummaries {
				mqlCi, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.codeInterpreter", map[string]*llx.RawData{
					"__id":        llx.StringDataPtr(ci.CodeInterpreterArn),
					"id":          llx.StringDataPtr(ci.CodeInterpreterId),
					"arn":         llx.StringDataPtr(ci.CodeInterpreterArn),
					"name":        llx.StringDataPtr(ci.Name),
					"region":      llx.StringData(region),
					"status":      llx.StringData(string(ci.Status)),
					"description": llx.StringDataPtr(ci.Description),
					"createdAt":   llx.TimeDataPtr(ci.CreatedAt),
					"updatedAt":   llx.TimeDataPtr(ci.LastUpdatedAt),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlCi)
			}
		}
		return res, nil
	}))
}

type mqlAwsBedrockAgentCoreCodeInterpreterInternal struct {
	fetchLock sync.Mutex
	fetched   atomic.Bool
	detail    *bedrockagentcorecontrol.GetCodeInterpreterOutput
}

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) fetchDetail() (*bedrockagentcorecontrol.GetCodeInterpreterOutput, error) {
	if a.fetched.Load() {
		return a.detail, nil
	}
	a.fetchLock.Lock()
	defer a.fetchLock.Unlock()
	if a.fetched.Load() {
		return a.detail, nil
	}
	if a.Id.Error != nil {
		return nil, a.Id.Error
	}
	if a.Region.Error != nil {
		return nil, a.Region.Error
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.BedrockAgentCoreControl(a.Region.Data)
	codeInterpreterId := a.Id.Data
	detail, err := svc.GetCodeInterpreter(context.Background(), &bedrockagentcorecontrol.GetCodeInterpreterInput{
		CodeInterpreterId: &codeInterpreterId,
	})
	if err != nil {
		return nil, err
	}
	a.detail = detail
	a.fetched.Store(true)
	return a.detail, nil
}

func (a *mqlAwsBedrockAgentCoreCodeInterpreter) filesystemConfigurations() ([]any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return []any{}, nil
	}
	return newAgentCoreFilesystemConfigurations(a.MqlRuntime, a.Arn.Data, detail.FilesystemConfigurations)
}

// --- Identity: OAuth2 credential providers ---

func (a *mqlAwsBedrockAgentCore) oauth2CredentialProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		var nextToken *string
		for {
			page, err := svc.ListOauth2CredentialProviders(ctx, &bedrockagentcorecontrol.ListOauth2CredentialProvidersInput{
				NextToken: nextToken,
			})
			if err != nil {
				return nil, err
			}
			for _, p := range page.CredentialProviders {
				mqlProvider, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.oauth2CredentialProvider", map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(p.CredentialProviderArn),
					"arn":       llx.StringDataPtr(p.CredentialProviderArn),
					"name":      llx.StringDataPtr(p.Name),
					"region":    llx.StringData(region),
					"vendor":    llx.StringData(string(p.CredentialProviderVendor)),
					"createdAt": llx.TimeDataPtr(p.CreatedTime),
					"updatedAt": llx.TimeDataPtr(p.LastUpdatedTime),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlProvider)
			}
			if page.NextToken == nil {
				break
			}
			nextToken = page.NextToken
		}
		return res, nil
	}))
}

func (a *mqlAwsBedrockAgentCoreOauth2CredentialProvider) id() (string, error) {
	return a.Arn.Data, nil
}

// --- Identity: API-key credential providers ---

func (a *mqlAwsBedrockAgentCore) apiKeyCredentialProviders() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListApiKeyCredentialProvidersPaginator(svc, &bedrockagentcorecontrol.ListApiKeyCredentialProvidersInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, p := range page.CredentialProviders {
				mqlProvider, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.apiKeyCredentialProvider", map[string]*llx.RawData{
					"__id":      llx.StringDataPtr(p.CredentialProviderArn),
					"arn":       llx.StringDataPtr(p.CredentialProviderArn),
					"name":      llx.StringDataPtr(p.Name),
					"region":    llx.StringData(region),
					"createdAt": llx.TimeDataPtr(p.CreatedTime),
					"updatedAt": llx.TimeDataPtr(p.LastUpdatedTime),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlProvider)
			}
		}
		return res, nil
	}))
}

func (a *mqlAwsBedrockAgentCoreApiKeyCredentialProvider) id() (string, error) {
	return a.Arn.Data, nil
}

// --- Identity: workload identities ---

func (a *mqlAwsBedrockAgentCore) workloadIdentities() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return a.collectJobs(a.agentCoreRegionTasks(conn, func(ctx context.Context, region string) ([]any, error) {
		svc := conn.BedrockAgentCoreControl(region)
		res := []any{}
		paginator := bedrockagentcorecontrol.NewListWorkloadIdentitiesPaginator(svc, &bedrockagentcorecontrol.ListWorkloadIdentitiesInput{})
		for paginator.HasMorePages() {
			page, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, w := range page.WorkloadIdentities {
				mqlIdentity, err := CreateResource(a.MqlRuntime, "aws.bedrock.agentCore.workloadIdentity", map[string]*llx.RawData{
					"__id":   llx.StringDataPtr(w.WorkloadIdentityArn),
					"arn":    llx.StringDataPtr(w.WorkloadIdentityArn),
					"name":   llx.StringDataPtr(w.Name),
					"region": llx.StringData(region),
				})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlIdentity)
			}
		}
		return res, nil
	}))
}

// initAwsBedrockAgentCoreWorkloadIdentity resolves a workload identity from its
// ARN. The region and name are both encoded in the ARN
// (arn:aws:bedrock-agentcore:<region>:<account>:workload-identity-directory/default/workload-identity/<name>),
// so a single ARN is enough to populate the resource without an API call.
func initAwsBedrockAgentCoreWorkloadIdentity(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to resolve aws.bedrock.agentCore.workloadIdentity")
	}
	arnVal := args["arn"].Value.(string)

	if args["region"] == nil {
		if region, err := GetRegionFromArn(arnVal); err == nil && region != "" {
			args["region"] = llx.StringData(region)
		}
	}
	if args["name"] == nil {
		if idx := strings.LastIndex(arnVal, "/"); idx >= 0 && idx < len(arnVal)-1 {
			args["name"] = llx.StringData(arnVal[idx+1:])
		}
	}
	return args, nil, nil
}

func (a *mqlAwsBedrockAgentCoreWorkloadIdentity) id() (string, error) {
	return a.Arn.Data, nil
}
