// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apprunner"
	apprunnertypes "github.com/aws/aws-sdk-go-v2/service/apprunner/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsApprunner) id() (string, error) {
	return "aws.apprunner", nil
}

// Services

func (a *mqlAwsApprunner) services() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getServices(conn), 5)
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

func (a *mqlAwsApprunner) getServices(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apprunner>getServices>calling aws with region %s", region)
			svc := conn.AppRunner(region)
			res := []any{}
			ctx := context.Background()

			var nextToken *string
			for {
				resp, err := svc.ListServices(ctx, &apprunner.ListServicesInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for App Runner ListServices")
						return res, nil
					}
					return nil, err
				}

				for i := range resp.ServiceSummaryList {
					summary := resp.ServiceSummaryList[i]
					mqlService, err := newMqlAwsApprunnerServiceFromSummary(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlService)
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

// newMqlAwsApprunnerServiceFromSummary maps a ServiceSummary into the MQL
// resource using only the fields the list API returns. Detail fields populated
// by DescribeService are loaded lazily through the Internal struct.
func newMqlAwsApprunnerServiceFromSummary(runtime *plugin.Runtime, region string, summary apprunnertypes.ServiceSummary) (*mqlAwsApprunnerService, error) {
	resource, err := CreateResource(runtime, "aws.apprunner.service",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(summary.ServiceArn),
			"arn":         llx.StringDataPtr(summary.ServiceArn),
			"serviceId":   llx.StringDataPtr(summary.ServiceId),
			"serviceName": llx.StringDataPtr(summary.ServiceName),
			"serviceUrl":  llx.StringDataPtr(summary.ServiceUrl),
			"status":      llx.StringData(string(summary.Status)),
			"createdAt":   llx.TimeDataPtr(summary.CreatedAt),
			"updatedAt":   llx.TimeDataPtr(summary.UpdatedAt),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsApprunnerService), nil
}

func (a *mqlAwsApprunnerService) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsApprunnerServiceInternal struct {
	detailFetched bool
	detailErr     error
	detail        *apprunnertypes.Service
	lock          sync.Mutex
}

// fetchDetail caches the result of DescribeService so that the various
// computed fields (source, instance config, network config, observability,
// kms) share a single API call. The double-check locking guards against the
// runtime invoking multiple field accessors concurrently on the same resource.
func (a *mqlAwsApprunnerService) fetchDetail() (*apprunnertypes.Service, error) {
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: &arn})
	if err != nil {
		a.detailFetched = true
		a.detailErr = classifyAwsError(err, "apprunner:DescribeService")
		return nil, a.detailErr
	}
	a.detailFetched = true
	a.detail = resp.Service
	return a.detail, nil
}

func (a *mqlAwsApprunnerService) deletedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return detail.DeletedAt, nil
}

func (a *mqlAwsApprunnerService) sourceConfiguration() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.SourceConfiguration == nil {
		return nil, nil
	}
	dict, err := convert.JsonToDict(detail.SourceConfiguration)
	if err != nil {
		return nil, err
	}
	return dict, nil
}

func (a *mqlAwsApprunnerService) instanceCpu() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.InstanceConfiguration == nil || detail.InstanceConfiguration.Cpu == nil {
		return "", nil
	}
	return *detail.InstanceConfiguration.Cpu, nil
}

func (a *mqlAwsApprunnerService) instanceMemory() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.InstanceConfiguration == nil || detail.InstanceConfiguration.Memory == nil {
		return "", nil
	}
	return *detail.InstanceConfiguration.Memory, nil
}

func (a *mqlAwsApprunnerService) instanceRole() (*mqlAwsIamRole, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.InstanceConfiguration == nil || detail.InstanceConfiguration.InstanceRoleArn == nil || *detail.InstanceConfiguration.InstanceRoleArn == "" {
		a.InstanceRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{"arn": llx.StringData(*detail.InstanceConfiguration.InstanceRoleArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsIamRole), nil
}

func (a *mqlAwsApprunnerService) healthCheckConfiguration() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.HealthCheckConfiguration == nil {
		return nil, nil
	}
	hc := detail.HealthCheckConfiguration
	out := map[string]any{
		"protocol": string(hc.Protocol),
	}
	if hc.Path != nil {
		out["path"] = *hc.Path
	}
	if hc.Interval != nil {
		out["interval"] = int64(*hc.Interval)
	}
	if hc.Timeout != nil {
		out["timeout"] = int64(*hc.Timeout)
	}
	if hc.HealthyThreshold != nil {
		out["healthyThreshold"] = int64(*hc.HealthyThreshold)
	}
	if hc.UnhealthyThreshold != nil {
		out["unhealthyThreshold"] = int64(*hc.UnhealthyThreshold)
	}
	return out, nil
}

func (a *mqlAwsApprunnerService) egressType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.NetworkConfiguration == nil || detail.NetworkConfiguration.EgressConfiguration == nil {
		return "", nil
	}
	return string(detail.NetworkConfiguration.EgressConfiguration.EgressType), nil
}

func (a *mqlAwsApprunnerService) vpcConnector() (*mqlAwsApprunnerVpcConnector, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil ||
		detail.NetworkConfiguration == nil ||
		detail.NetworkConfiguration.EgressConfiguration == nil ||
		detail.NetworkConfiguration.EgressConfiguration.VpcConnectorArn == nil ||
		*detail.NetworkConfiguration.EgressConfiguration.VpcConnectorArn == "" {
		a.VpcConnector.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.apprunner.vpcConnector",
		map[string]*llx.RawData{"arn": llx.StringData(*detail.NetworkConfiguration.EgressConfiguration.VpcConnectorArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApprunnerVpcConnector), nil
}

func (a *mqlAwsApprunnerService) isPubliclyAccessible() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	// Default to false when the detail call returned no data (e.g., access
	// denied or transient error swallowed by fetchDetail). Reporting "publicly
	// accessible" without proof would create false positives across the
	// inventory — the trade-off is a possible false negative on a truly
	// public service the caller couldn't read.
	if detail == nil || detail.NetworkConfiguration == nil || detail.NetworkConfiguration.IngressConfiguration == nil {
		return false, nil
	}
	return detail.NetworkConfiguration.IngressConfiguration.IsPubliclyAccessible, nil
}

func (a *mqlAwsApprunnerService) ipAddressType() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.NetworkConfiguration == nil {
		return "", nil
	}
	return string(detail.NetworkConfiguration.IpAddressType), nil
}

func (a *mqlAwsApprunnerService) observabilityConfiguration() (*mqlAwsApprunnerObservabilityConfiguration, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil ||
		detail.ObservabilityConfiguration == nil ||
		!detail.ObservabilityConfiguration.ObservabilityEnabled ||
		detail.ObservabilityConfiguration.ObservabilityConfigurationArn == nil ||
		*detail.ObservabilityConfiguration.ObservabilityConfigurationArn == "" {
		a.ObservabilityConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.apprunner.observabilityConfiguration",
		map[string]*llx.RawData{"arn": llx.StringData(*detail.ObservabilityConfiguration.ObservabilityConfigurationArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApprunnerObservabilityConfiguration), nil
}

func (a *mqlAwsApprunnerService) autoScalingConfiguration() (*mqlAwsApprunnerAutoScalingConfiguration, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil ||
		detail.AutoScalingConfigurationSummary == nil ||
		detail.AutoScalingConfigurationSummary.AutoScalingConfigurationArn == nil ||
		*detail.AutoScalingConfigurationSummary.AutoScalingConfigurationArn == "" {
		a.AutoScalingConfiguration.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.apprunner.autoScalingConfiguration",
		map[string]*llx.RawData{"arn": llx.StringData(*detail.AutoScalingConfigurationSummary.AutoScalingConfigurationArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApprunnerAutoScalingConfiguration), nil
}

func (a *mqlAwsApprunnerService) kmsKey() (*mqlAwsKmsKey, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.EncryptionConfiguration == nil || detail.EncryptionConfiguration.KmsKey == nil || *detail.EncryptionConfiguration.KmsKey == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringData(*detail.EncryptionConfiguration.KmsKey)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsApprunnerService) tags() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(a.Region.Data)
	ctx := context.Background()
	resp, err := svc.ListTagsForResource(ctx, &apprunner.ListTagsForResourceInput{ResourceArn: aws.String(a.Arn.Data)})
	if err != nil {
		return nil, classifyAwsError(err, "apprunner:ListTagsForResource")
	}
	out := map[string]any{}
	for _, tag := range resp.Tags {
		if tag.Key != nil && tag.Value != nil {
			out[*tag.Key] = *tag.Value
		}
	}
	return out, nil
}

func initAwsApprunnerService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	arnArg, ok := args["arn"]
	if !ok || arnArg == nil || arnArg.Value == nil {
		return args, nil, nil
	}
	arnVal, ok := arnArg.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}
	region, err := regionFromApprunnerArn(arnVal)
	if err != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(region)
	ctx := context.Background()
	resp, err := svc.DescribeService(ctx, &apprunner.DescribeServiceInput{ServiceArn: &arnVal})
	if err != nil {
		return nil, nil, classifyAwsError(err, "apprunner:DescribeService")
	}
	if resp.Service == nil {
		return args, nil, nil
	}
	s := resp.Service
	mqlService, err := CreateResource(runtime, "aws.apprunner.service",
		map[string]*llx.RawData{
			"__id":        llx.StringDataPtr(s.ServiceArn),
			"arn":         llx.StringDataPtr(s.ServiceArn),
			"serviceId":   llx.StringDataPtr(s.ServiceId),
			"serviceName": llx.StringDataPtr(s.ServiceName),
			"serviceUrl":  llx.StringDataPtr(s.ServiceUrl),
			"status":      llx.StringData(string(s.Status)),
			"createdAt":   llx.TimeDataPtr(s.CreatedAt),
			"updatedAt":   llx.TimeDataPtr(s.UpdatedAt),
			"region":      llx.StringData(region),
		})
	if err != nil {
		return nil, nil, err
	}
	svcRes := mqlService.(*mqlAwsApprunnerService)
	svcRes.detail = s
	svcRes.detailFetched = true
	return args, svcRes, nil
}

// regionFromApprunnerArn parses the region segment out of an App Runner ARN
// (arn:aws:apprunner:<region>:<account>:<type>/<name>...). Returns an error
// when the ARN is malformed; callers treat that as "skip" rather than fail.
func regionFromApprunnerArn(arnVal string) (string, error) {
	parts := strings.SplitN(arnVal, ":", 6)
	if len(parts) < 4 {
		return "", errors.New("invalid apprunner arn")
	}
	if parts[2] != "apprunner" {
		return "", errors.New("not an apprunner arn")
	}
	region := parts[3]
	if region == "" {
		return "", errors.New("apprunner arn missing region")
	}
	return region, nil
}

// AutoScalingConfigurations

func (a *mqlAwsApprunner) autoScalingConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getAutoScalingConfigurations(conn), 5)
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

func (a *mqlAwsApprunner) getAutoScalingConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apprunner>getAutoScalingConfigurations>calling aws with region %s", region)
			svc := conn.AppRunner(region)
			res := []any{}
			ctx := context.Background()

			var nextToken *string
			for {
				// LatestOnly defaults to true server-side when the field is
				// omitted, which hid every non-latest revision -- including
				// revisions that services are actively pinned to.
				resp, err := svc.ListAutoScalingConfigurations(ctx, &apprunner.ListAutoScalingConfigurationsInput{
					NextToken:  nextToken,
					LatestOnly: false,
				})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for App Runner ListAutoScalingConfigurations")
						return res, nil
					}
					return nil, err
				}

				for i := range resp.AutoScalingConfigurationSummaryList {
					summary := resp.AutoScalingConfigurationSummaryList[i]
					mqlCfg, err := newMqlAwsApprunnerAutoScalingFromSummary(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCfg)
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

func newMqlAwsApprunnerAutoScalingFromSummary(runtime *plugin.Runtime, region string, summary apprunnertypes.AutoScalingConfigurationSummary) (*mqlAwsApprunnerAutoScalingConfiguration, error) {
	resource, err := CreateResource(runtime, "aws.apprunner.autoScalingConfiguration",
		map[string]*llx.RawData{
			"__id":                 llx.StringDataPtr(summary.AutoScalingConfigurationArn),
			"arn":                  llx.StringDataPtr(summary.AutoScalingConfigurationArn),
			"region":               llx.StringData(region),
			"name":                 llx.StringDataPtr(summary.AutoScalingConfigurationName),
			"revision":             llx.IntData(int64(summary.AutoScalingConfigurationRevision)),
			"createdAt":            llx.TimeDataPtr(summary.CreatedAt),
			"hasAssociatedService": llx.BoolDataPtr(summary.HasAssociatedService),
			"status":               llx.StringData(string(summary.Status)),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsApprunnerAutoScalingConfiguration), nil
}

func (a *mqlAwsApprunnerAutoScalingConfiguration) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsApprunnerAutoScalingConfigurationInternal struct {
	detailFetched bool
	detailErr     error
	detail        *apprunnertypes.AutoScalingConfiguration
	lock          sync.Mutex
}

func (a *mqlAwsApprunnerAutoScalingConfiguration) fetchDetail() (*apprunnertypes.AutoScalingConfiguration, error) {
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.DescribeAutoScalingConfiguration(ctx, &apprunner.DescribeAutoScalingConfigurationInput{AutoScalingConfigurationArn: &arn})
	if err != nil {
		a.detailFetched = true
		a.detailErr = classifyAwsError(err, "apprunner:DescribeAutoScalingConfiguration")
		return nil, a.detailErr
	}
	a.detailFetched = true
	a.detail = resp.AutoScalingConfiguration
	return a.detail, nil
}

func (a *mqlAwsApprunnerAutoScalingConfiguration) latest() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if detail == nil || detail.Latest == nil {
		return false, nil
	}
	return *detail.Latest, nil
}

func (a *mqlAwsApprunnerAutoScalingConfiguration) deletedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return detail.DeletedAt, nil
}

func (a *mqlAwsApprunnerAutoScalingConfiguration) maxConcurrency() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail == nil || detail.MaxConcurrency == nil {
		return 0, nil
	}
	return int64(*detail.MaxConcurrency), nil
}

func (a *mqlAwsApprunnerAutoScalingConfiguration) minSize() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail == nil || detail.MinSize == nil {
		return 0, nil
	}
	return int64(*detail.MinSize), nil
}

func (a *mqlAwsApprunnerAutoScalingConfiguration) maxSize() (int64, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return 0, err
	}
	if detail == nil || detail.MaxSize == nil {
		return 0, nil
	}
	return int64(*detail.MaxSize), nil
}

func initAwsApprunnerAutoScalingConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	arnArg, ok := args["arn"]
	if !ok || arnArg == nil || arnArg.Value == nil {
		return args, nil, nil
	}
	arnVal, ok := arnArg.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}
	region, err := regionFromApprunnerArn(arnVal)
	if err != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(region)
	ctx := context.Background()
	resp, err := svc.DescribeAutoScalingConfiguration(ctx, &apprunner.DescribeAutoScalingConfigurationInput{AutoScalingConfigurationArn: &arnVal})
	if err != nil {
		return nil, nil, classifyAwsError(err, "apprunner:DescribeAutoScalingConfiguration")
	}
	if resp.AutoScalingConfiguration == nil {
		return args, nil, nil
	}
	c := resp.AutoScalingConfiguration
	revision := int32(0)
	if c.AutoScalingConfigurationRevision != nil {
		revision = *c.AutoScalingConfigurationRevision
	}
	mqlCfg, err := CreateResource(runtime, "aws.apprunner.autoScalingConfiguration",
		map[string]*llx.RawData{
			"__id":                 llx.StringDataPtr(c.AutoScalingConfigurationArn),
			"arn":                  llx.StringDataPtr(c.AutoScalingConfigurationArn),
			"region":               llx.StringData(region),
			"name":                 llx.StringDataPtr(c.AutoScalingConfigurationName),
			"revision":             llx.IntData(int64(revision)),
			"createdAt":            llx.TimeDataPtr(c.CreatedAt),
			"hasAssociatedService": llx.BoolDataPtr(c.HasAssociatedService),
			"status":               llx.StringData(string(c.Status)),
		})
	if err != nil {
		return nil, nil, err
	}
	cfgRes := mqlCfg.(*mqlAwsApprunnerAutoScalingConfiguration)
	cfgRes.detail = c
	cfgRes.detailFetched = true
	return args, cfgRes, nil
}

// Connections

func (a *mqlAwsApprunner) connections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getConnections(conn), 5)
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

func (a *mqlAwsApprunner) getConnections(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apprunner>getConnections>calling aws with region %s", region)
			svc := conn.AppRunner(region)
			res := []any{}
			ctx := context.Background()

			var nextToken *string
			for {
				resp, err := svc.ListConnections(ctx, &apprunner.ListConnectionsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for App Runner ListConnections")
						return res, nil
					}
					return nil, err
				}

				for i := range resp.ConnectionSummaryList {
					summary := resp.ConnectionSummaryList[i]
					resource, err := CreateResource(a.MqlRuntime, "aws.apprunner.connection",
						map[string]*llx.RawData{
							"__id":         llx.StringDataPtr(summary.ConnectionArn),
							"arn":          llx.StringDataPtr(summary.ConnectionArn),
							"name":         llx.StringDataPtr(summary.ConnectionName),
							"providerType": llx.StringData(string(summary.ProviderType)),
							"status":       llx.StringData(string(summary.Status)),
							"createdAt":    llx.TimeDataPtr(summary.CreatedAt),
							"region":       llx.StringData(region),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, resource)
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

func (a *mqlAwsApprunnerConnection) id() (string, error) {
	return a.Arn.Data, nil
}

// VPC connectors

func (a *mqlAwsApprunner) vpcConnectors() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVpcConnectors(conn), 5)
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

func (a *mqlAwsApprunner) getVpcConnectors(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	accountID := conn.AccountId()

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apprunner>getVpcConnectors>calling aws with region %s", region)
			svc := conn.AppRunner(region)
			res := []any{}
			ctx := context.Background()

			var nextToken *string
			for {
				resp, err := svc.ListVpcConnectors(ctx, &apprunner.ListVpcConnectorsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for App Runner ListVpcConnectors")
						return res, nil
					}
					return nil, err
				}

				for i := range resp.VpcConnectors {
					vc := resp.VpcConnectors[i]
					mqlVc, err := newMqlAwsApprunnerVpcConnector(a.MqlRuntime, region, accountID, vc)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlVc)
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

func newMqlAwsApprunnerVpcConnector(runtime *plugin.Runtime, region, accountID string, vc apprunnertypes.VpcConnector) (*mqlAwsApprunnerVpcConnector, error) {
	resource, err := CreateResource(runtime, "aws.apprunner.vpcConnector",
		map[string]*llx.RawData{
			"__id":      llx.StringDataPtr(vc.VpcConnectorArn),
			"arn":       llx.StringDataPtr(vc.VpcConnectorArn),
			"name":      llx.StringDataPtr(vc.VpcConnectorName),
			"revision":  llx.IntData(int64(vc.VpcConnectorRevision)),
			"status":    llx.StringData(string(vc.Status)),
			"createdAt": llx.TimeDataPtr(vc.CreatedAt),
			"deletedAt": llx.TimeDataPtr(vc.DeletedAt),
			"region":    llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlVc := resource.(*mqlAwsApprunnerVpcConnector)
	mqlVc.region = region
	mqlVc.accountID = accountID
	mqlVc.cacheSubnetIds = vc.Subnets
	sgArns := make([]string, 0, len(vc.SecurityGroups))
	for _, sgId := range vc.SecurityGroups {
		sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sgId))
	}
	mqlVc.setSecurityGroupArns(sgArns)
	return mqlVc, nil
}

func (a *mqlAwsApprunnerVpcConnector) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsApprunnerVpcConnectorInternal struct {
	securityGroupIdHandler
	region         string
	accountID      string
	cacheSubnetIds []string
}

func (a *mqlAwsApprunnerVpcConnector) subnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return []any{}, nil
	}
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		subnetArn := fmt.Sprintf(subnetArnPattern, a.region, a.accountID, subnetId)
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"arn": llx.StringData(subnetArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsApprunnerVpcConnector) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func initAwsApprunnerVpcConnector(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	arnArg, ok := args["arn"]
	if !ok || arnArg == nil || arnArg.Value == nil {
		return args, nil, nil
	}
	arnVal, ok := arnArg.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}
	region, err := regionFromApprunnerArn(arnVal)
	if err != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(region)
	ctx := context.Background()
	resp, err := svc.DescribeVpcConnector(ctx, &apprunner.DescribeVpcConnectorInput{VpcConnectorArn: &arnVal})
	if err != nil {
		return nil, nil, classifyAwsError(err, "apprunner:DescribeVpcConnector")
	}
	if resp.VpcConnector == nil {
		return args, nil, nil
	}
	mqlVc, err := newMqlAwsApprunnerVpcConnector(runtime, region, conn.AccountId(), *resp.VpcConnector)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlVc, nil
}

// Observability configurations

func (a *mqlAwsApprunner) observabilityConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getObservabilityConfigurations(conn), 5)
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

func (a *mqlAwsApprunner) getObservabilityConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apprunner>getObservabilityConfigurations>calling aws with region %s", region)
			svc := conn.AppRunner(region)
			res := []any{}
			ctx := context.Background()

			var nextToken *string
			for {
				// See the note on ListAutoScalingConfigurations: LatestOnly defaults to
				// true when omitted.
				resp, err := svc.ListObservabilityConfigurations(ctx, &apprunner.ListObservabilityConfigurationsInput{
					NextToken:  nextToken,
					LatestOnly: false,
				})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for App Runner ListObservabilityConfigurations")
						return res, nil
					}
					return nil, err
				}

				for i := range resp.ObservabilityConfigurationSummaryList {
					summary := resp.ObservabilityConfigurationSummaryList[i]
					mqlCfg, err := newMqlAwsApprunnerObservabilityFromSummary(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlCfg)
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

func newMqlAwsApprunnerObservabilityFromSummary(runtime *plugin.Runtime, region string, summary apprunnertypes.ObservabilityConfigurationSummary) (*mqlAwsApprunnerObservabilityConfiguration, error) {
	resource, err := CreateResource(runtime, "aws.apprunner.observabilityConfiguration",
		map[string]*llx.RawData{
			"__id":     llx.StringDataPtr(summary.ObservabilityConfigurationArn),
			"arn":      llx.StringDataPtr(summary.ObservabilityConfigurationArn),
			"name":     llx.StringDataPtr(summary.ObservabilityConfigurationName),
			"revision": llx.IntData(int64(summary.ObservabilityConfigurationRevision)),
			"region":   llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsApprunnerObservabilityConfiguration), nil
}

func (a *mqlAwsApprunnerObservabilityConfiguration) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsApprunnerObservabilityConfigurationInternal struct {
	detailFetched bool
	detailErr     error
	detail        *apprunnertypes.ObservabilityConfiguration
	lock          sync.Mutex
}

func (a *mqlAwsApprunnerObservabilityConfiguration) fetchDetail() (*apprunnertypes.ObservabilityConfiguration, error) {
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.DescribeObservabilityConfiguration(ctx, &apprunner.DescribeObservabilityConfigurationInput{ObservabilityConfigurationArn: &arn})
	if err != nil {
		a.detailFetched = true
		a.detailErr = classifyAwsError(err, "apprunner:DescribeObservabilityConfiguration")
		return nil, a.detailErr
	}
	a.detailFetched = true
	a.detail = resp.ObservabilityConfiguration
	return a.detail, nil
}

func (a *mqlAwsApprunnerObservabilityConfiguration) latest() (bool, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return false, err
	}
	if detail == nil {
		return false, nil
	}
	return detail.Latest, nil
}

func (a *mqlAwsApprunnerObservabilityConfiguration) status() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return string(detail.Status), nil
}

func (a *mqlAwsApprunnerObservabilityConfiguration) createdAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return detail.CreatedAt, nil
}

func (a *mqlAwsApprunnerObservabilityConfiguration) deletedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return detail.DeletedAt, nil
}

func (a *mqlAwsApprunnerObservabilityConfiguration) traceConfigurationVendor() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.TraceConfiguration == nil {
		return "", nil
	}
	return string(detail.TraceConfiguration.Vendor), nil
}

func initAwsApprunnerObservabilityConfiguration(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	arnArg, ok := args["arn"]
	if !ok || arnArg == nil || arnArg.Value == nil {
		return args, nil, nil
	}
	arnVal, ok := arnArg.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}
	region, err := regionFromApprunnerArn(arnVal)
	if err != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(region)
	ctx := context.Background()
	resp, err := svc.DescribeObservabilityConfiguration(ctx, &apprunner.DescribeObservabilityConfigurationInput{ObservabilityConfigurationArn: &arnVal})
	if err != nil {
		return nil, nil, classifyAwsError(err, "apprunner:DescribeObservabilityConfiguration")
	}
	if resp.ObservabilityConfiguration == nil {
		return args, nil, nil
	}
	c := resp.ObservabilityConfiguration
	mqlCfg, err := CreateResource(runtime, "aws.apprunner.observabilityConfiguration",
		map[string]*llx.RawData{
			"__id":     llx.StringDataPtr(c.ObservabilityConfigurationArn),
			"arn":      llx.StringDataPtr(c.ObservabilityConfigurationArn),
			"name":     llx.StringDataPtr(c.ObservabilityConfigurationName),
			"revision": llx.IntData(int64(c.ObservabilityConfigurationRevision)),
			"region":   llx.StringData(region),
		})
	if err != nil {
		return nil, nil, err
	}
	cfgRes := mqlCfg.(*mqlAwsApprunnerObservabilityConfiguration)
	cfgRes.detail = c
	cfgRes.detailFetched = true
	return args, cfgRes, nil
}

// VPC ingress connections

func (a *mqlAwsApprunner) vpcIngressConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVpcIngressConnections(conn), 5)
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

func (a *mqlAwsApprunner) getVpcIngressConnections(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("apprunner>getVpcIngressConnections>calling aws with region %s", region)
			svc := conn.AppRunner(region)
			res := []any{}
			ctx := context.Background()

			var nextToken *string
			for {
				resp, err := svc.ListVpcIngressConnections(ctx, &apprunner.ListVpcIngressConnectionsInput{NextToken: nextToken})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Debug().Str("region", region).Msg("error accessing region for App Runner ListVpcIngressConnections")
						return res, nil
					}
					return nil, err
				}

				for i := range resp.VpcIngressConnectionSummaryList {
					summary := resp.VpcIngressConnectionSummaryList[i]
					mqlIngress, err := newMqlAwsApprunnerVpcIngressFromSummary(a.MqlRuntime, region, summary)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlIngress)
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

func newMqlAwsApprunnerVpcIngressFromSummary(runtime *plugin.Runtime, region string, summary apprunnertypes.VpcIngressConnectionSummary) (*mqlAwsApprunnerVpcIngressConnection, error) {
	resource, err := CreateResource(runtime, "aws.apprunner.vpcIngressConnection",
		map[string]*llx.RawData{
			"__id":   llx.StringDataPtr(summary.VpcIngressConnectionArn),
			"arn":    llx.StringDataPtr(summary.VpcIngressConnectionArn),
			"region": llx.StringData(region),
		})
	if err != nil {
		return nil, err
	}
	mqlIngress := resource.(*mqlAwsApprunnerVpcIngressConnection)
	mqlIngress.cacheServiceArn = summary.ServiceArn
	return mqlIngress, nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsApprunnerVpcIngressConnectionInternal struct {
	cacheServiceArn *string
	detailFetched   bool
	detailErr       error
	detail          *apprunnertypes.VpcIngressConnection
	lock            sync.Mutex
}

func (a *mqlAwsApprunnerVpcIngressConnection) fetchDetail() (*apprunnertypes.VpcIngressConnection, error) {
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	a.lock.Lock()
	defer a.lock.Unlock()
	if a.detailFetched {
		return a.detail, a.detailErr
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(a.Region.Data)
	ctx := context.Background()
	arn := a.Arn.Data
	resp, err := svc.DescribeVpcIngressConnection(ctx, &apprunner.DescribeVpcIngressConnectionInput{VpcIngressConnectionArn: &arn})
	if err != nil {
		a.detailFetched = true
		a.detailErr = classifyAwsError(err, "apprunner:DescribeVpcIngressConnection")
		return nil, a.detailErr
	}
	a.detailFetched = true
	a.detail = resp.VpcIngressConnection
	if a.detail != nil && a.detail.ServiceArn != nil {
		a.cacheServiceArn = a.detail.ServiceArn
	}
	return a.detail, nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) name() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.VpcIngressConnectionName == nil {
		return "", nil
	}
	return *detail.VpcIngressConnectionName, nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) status() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil {
		return "", nil
	}
	return string(detail.Status), nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) createdAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return detail.CreatedAt, nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) deletedAt() (*time.Time, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil {
		return nil, nil
	}
	return detail.DeletedAt, nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) domainName() (string, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return "", err
	}
	if detail == nil || detail.DomainName == nil {
		return "", nil
	}
	return *detail.DomainName, nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) ingressVpcConfiguration() (any, error) {
	detail, err := a.fetchDetail()
	if err != nil {
		return nil, err
	}
	if detail == nil || detail.IngressVpcConfiguration == nil {
		return nil, nil
	}
	cfg := detail.IngressVpcConfiguration
	out := map[string]any{}
	if cfg.VpcId != nil {
		out["vpcId"] = *cfg.VpcId
	}
	if cfg.VpcEndpointId != nil {
		out["vpcEndpointId"] = *cfg.VpcEndpointId
	}
	return out, nil
}

func (a *mqlAwsApprunnerVpcIngressConnection) service() (*mqlAwsApprunnerService, error) {
	if a.cacheServiceArn == nil || *a.cacheServiceArn == "" {
		// Try to populate from detail call before giving up.
		if _, err := a.fetchDetail(); err != nil {
			return nil, err
		}
	}
	if a.cacheServiceArn == nil || *a.cacheServiceArn == "" {
		a.Service.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.apprunner.service",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheServiceArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsApprunnerService), nil
}

func initAwsApprunnerVpcIngressConnection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 1 {
		return args, nil, nil
	}
	arnArg, ok := args["arn"]
	if !ok || arnArg == nil || arnArg.Value == nil {
		return args, nil, nil
	}
	arnVal, ok := arnArg.Value.(string)
	if !ok || arnVal == "" {
		return args, nil, nil
	}
	region, err := regionFromApprunnerArn(arnVal)
	if err != nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.AppRunner(region)
	ctx := context.Background()
	resp, err := svc.DescribeVpcIngressConnection(ctx, &apprunner.DescribeVpcIngressConnectionInput{VpcIngressConnectionArn: &arnVal})
	if err != nil {
		return nil, nil, classifyAwsError(err, "apprunner:DescribeVpcIngressConnection")
	}
	if resp.VpcIngressConnection == nil {
		return args, nil, nil
	}
	v := resp.VpcIngressConnection
	mqlIngress, err := CreateResource(runtime, "aws.apprunner.vpcIngressConnection",
		map[string]*llx.RawData{
			"__id":   llx.StringDataPtr(v.VpcIngressConnectionArn),
			"arn":    llx.StringDataPtr(v.VpcIngressConnectionArn),
			"region": llx.StringData(region),
		})
	if err != nil {
		return nil, nil, err
	}
	mqlIngressRes := mqlIngress.(*mqlAwsApprunnerVpcIngressConnection)
	mqlIngressRes.detail = v
	mqlIngressRes.detailFetched = true
	mqlIngressRes.cacheServiceArn = v.ServiceArn
	return args, mqlIngressRes, nil
}
