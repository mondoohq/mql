// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/route53resolver"
	resolvertypes "github.com/aws/aws-sdk-go-v2/service/route53resolver/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// aws.route53.resolver

func (a *mqlAwsRoute53Resolver) id() (string, error) {
	return "aws.route53.resolver", nil
}

// resolver() returns the typed Resolver namespace from the Route 53 root.
func (a *mqlAwsRoute53) resolver() (*mqlAwsRoute53Resolver, error) {
	r, err := CreateResource(a.MqlRuntime, "aws.route53.resolver", map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	return r.(*mqlAwsRoute53Resolver), nil
}

// ----- Resolver endpoints -----

type mqlAwsRoute53ResolverEndpointInternal struct {
	securityGroupIdHandler
	region    string
	accountID string
}

func (a *mqlAwsRoute53ResolverEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.endpointTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) endpointTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	accountID := conn.AccountId()

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>endpoints>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListResolverEndpointsPaginator(svc, &route53resolver.ListResolverEndpointsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 resolver endpoints")
						return res, nil
					}
					return nil, err
				}
				for _, endpoint := range page.ResolverEndpoints {
					endpoint := endpoint
					mqlEndpoint, err := newMqlAwsRoute53ResolverEndpoint(a.MqlRuntime, region, accountID, &endpoint)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlEndpoint)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsRoute53ResolverEndpoint(runtime *plugin.Runtime, region, accountID string, endpoint *resolvertypes.ResolverEndpoint) (*mqlAwsRoute53ResolverEndpoint, error) {
	id := convert.ToValue(endpoint.Id)
	ipAddrCount := int64(0)
	if endpoint.IpAddressCount != nil {
		ipAddrCount = int64(*endpoint.IpAddressCount)
	}
	resource, err := CreateResource(runtime, "aws.route53.resolver.endpoint", map[string]*llx.RawData{
		"__id":                 llx.StringData(region + "/" + id),
		"id":                   llx.StringData(id),
		"arn":                  llx.StringData(convert.ToValue(endpoint.Arn)),
		"name":                 llx.StringData(convert.ToValue(endpoint.Name)),
		"region":               llx.StringData(region),
		"direction":            llx.StringData(string(endpoint.Direction)),
		"status":               llx.StringData(string(endpoint.Status)),
		"statusMessage":        llx.StringData(convert.ToValue(endpoint.StatusMessage)),
		"hostVpcId":            llx.StringData(convert.ToValue(endpoint.HostVPCId)),
		"resolverEndpointType": llx.StringData(string(endpoint.ResolverEndpointType)),
		"ipAddressCount":       llx.IntData(ipAddrCount),
		"creationTime":         llx.StringData(convert.ToValue(endpoint.CreationTime)),
		"modificationTime":     llx.StringData(convert.ToValue(endpoint.ModificationTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlEndpoint := resource.(*mqlAwsRoute53ResolverEndpoint)
	mqlEndpoint.region = region
	mqlEndpoint.accountID = accountID

	sgArns := make([]string, 0, len(endpoint.SecurityGroupIds))
	for _, sg := range endpoint.SecurityGroupIds {
		sgArns = append(sgArns, NewSecurityGroupArn(region, accountID, sg))
	}
	mqlEndpoint.setSecurityGroupArns(sgArns)

	return mqlEndpoint, nil
}

func (a *mqlAwsRoute53ResolverEndpoint) hostVpc() (*mqlAwsVpc, error) {
	vpcId := a.HostVpcId.Data
	if vpcId == "" {
		a.HostVpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"id": llx.StringData(vpcId),
	})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsRoute53ResolverEndpoint) securityGroups() ([]any, error) {
	return a.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsRoute53ResolverEndpoint) ipAddresses() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Route53Resolver(a.region)
	ctx := context.Background()
	id := a.Id.Data

	res := []any{}
	paginator := route53resolver.NewListResolverEndpointIpAddressesPaginator(svc, &route53resolver.ListResolverEndpointIpAddressesInput{
		ResolverEndpointId: &id,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "route53resolver:ListResolverEndpointIpAddresses")
		}
		for _, ip := range page.IpAddresses {
			res = append(res, map[string]any{
				"ipId":             convert.ToValue(ip.IpId),
				"subnetId":         convert.ToValue(ip.SubnetId),
				"ip":               convert.ToValue(ip.Ip),
				"ipv6":             convert.ToValue(ip.Ipv6),
				"status":           string(ip.Status),
				"statusMessage":    convert.ToValue(ip.StatusMessage),
				"creationTime":     convert.ToValue(ip.CreationTime),
				"modificationTime": convert.ToValue(ip.ModificationTime),
			})
		}
	}
	return res, nil
}

// ----- Resolver rules -----

type mqlAwsRoute53ResolverRuleInternal struct {
	region string
}

func (a *mqlAwsRoute53ResolverRule) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) rules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.ruleTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) ruleTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>rules>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListResolverRulesPaginator(svc, &route53resolver.ListResolverRulesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 resolver rules")
						return res, nil
					}
					return nil, err
				}
				for _, rule := range page.ResolverRules {
					rule := rule
					mqlRule, err := newMqlAwsRoute53ResolverRule(a.MqlRuntime, region, &rule)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRule)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func newMqlAwsRoute53ResolverRule(runtime *plugin.Runtime, region string, rule *resolvertypes.ResolverRule) (*mqlAwsRoute53ResolverRule, error) {
	id := convert.ToValue(rule.Id)
	targetIps := make([]any, 0, len(rule.TargetIps))
	for _, t := range rule.TargetIps {
		entry := map[string]any{
			"ip":       convert.ToValue(t.Ip),
			"ipv6":     convert.ToValue(t.Ipv6),
			"protocol": string(t.Protocol),
		}
		if t.Port != nil {
			entry["port"] = int64(*t.Port)
		}
		targetIps = append(targetIps, entry)
	}
	resource, err := CreateResource(runtime, "aws.route53.resolver.rule", map[string]*llx.RawData{
		"__id":               llx.StringData(region + "/" + id),
		"id":                 llx.StringData(id),
		"arn":                llx.StringData(convert.ToValue(rule.Arn)),
		"name":               llx.StringData(convert.ToValue(rule.Name)),
		"region":             llx.StringData(region),
		"status":             llx.StringData(string(rule.Status)),
		"statusMessage":      llx.StringData(convert.ToValue(rule.StatusMessage)),
		"domainName":         llx.StringData(convert.ToValue(rule.DomainName)),
		"ruleType":           llx.StringData(string(rule.RuleType)),
		"resolverEndpointId": llx.StringData(convert.ToValue(rule.ResolverEndpointId)),
		"targetIps":          llx.ArrayData(targetIps, types.Dict),
		"shareStatus":        llx.StringData(string(rule.ShareStatus)),
		"ownerId":            llx.StringData(convert.ToValue(rule.OwnerId)),
		"creationTime":       llx.StringData(convert.ToValue(rule.CreationTime)),
		"modificationTime":   llx.StringData(convert.ToValue(rule.ModificationTime)),
	})
	if err != nil {
		return nil, err
	}
	mqlRule := resource.(*mqlAwsRoute53ResolverRule)
	mqlRule.region = region
	return mqlRule, nil
}

func (a *mqlAwsRoute53ResolverRule) resolverEndpoint() (*mqlAwsRoute53ResolverEndpoint, error) {
	endpointId := a.ResolverEndpointId.Data
	if endpointId == "" {
		a.ResolverEndpoint.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// Endpoints are regional; reuse the rule's region as the cache key prefix
	// so the runtime can satisfy this from the listing in aws.route53.resolver.endpoints().
	res, err := NewResource(a.MqlRuntime, "aws.route53.resolver.endpoint", map[string]*llx.RawData{
		"id": llx.StringData(endpointId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRoute53ResolverEndpoint), nil
}

// ----- Resolver rule associations -----

func (a *mqlAwsRoute53ResolverRuleAssociation) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) ruleAssociations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.ruleAssociationTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) ruleAssociationTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>ruleAssociations>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListResolverRuleAssociationsPaginator(svc, &route53resolver.ListResolverRuleAssociationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 resolver rule associations")
						return res, nil
					}
					return nil, err
				}
				for _, assoc := range page.ResolverRuleAssociations {
					id := convert.ToValue(assoc.Id)
					resource, err := CreateResource(a.MqlRuntime, "aws.route53.resolver.ruleAssociation", map[string]*llx.RawData{
						"__id":           llx.StringData(region + "/" + id),
						"id":             llx.StringData(id),
						"name":           llx.StringData(convert.ToValue(assoc.Name)),
						"region":         llx.StringData(region),
						"resolverRuleId": llx.StringData(convert.ToValue(assoc.ResolverRuleId)),
						"status":         llx.StringData(string(assoc.Status)),
						"statusMessage":  llx.StringData(convert.ToValue(assoc.StatusMessage)),
					})
					if err != nil {
						return nil, err
					}
					resource.(*mqlAwsRoute53ResolverRuleAssociation).cacheVpcId = convert.ToValue(assoc.VPCId)
					res = append(res, resource)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRoute53ResolverRuleAssociation) resolverRule() (*mqlAwsRoute53ResolverRule, error) {
	ruleId := a.ResolverRuleId.Data
	if ruleId == "" {
		a.ResolverRule.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.route53.resolver.rule", map[string]*llx.RawData{
		"id": llx.StringData(ruleId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRoute53ResolverRule), nil
}

func (a *mqlAwsRoute53ResolverRuleAssociation) vpc() (*mqlAwsVpc, error) {
	vpcId := a.cacheVpcId
	if vpcId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"id": llx.StringData(vpcId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// ----- Resolver query log configs -----

func (a *mqlAwsRoute53ResolverQueryLogConfig) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) queryLogConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.queryLogConfigTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) queryLogConfigTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>queryLogConfigs>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListResolverQueryLogConfigsPaginator(svc, &route53resolver.ListResolverQueryLogConfigsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 resolver query log configs")
						return res, nil
					}
					return nil, err
				}
				for _, cfg := range page.ResolverQueryLogConfigs {
					id := convert.ToValue(cfg.Id)
					resource, err := CreateResource(a.MqlRuntime, "aws.route53.resolver.queryLogConfig", map[string]*llx.RawData{
						"__id":             llx.StringData(region + "/" + id),
						"id":               llx.StringData(id),
						"arn":              llx.StringData(convert.ToValue(cfg.Arn)),
						"name":             llx.StringData(convert.ToValue(cfg.Name)),
						"region":           llx.StringData(region),
						"ownerId":          llx.StringData(convert.ToValue(cfg.OwnerId)),
						"status":           llx.StringData(string(cfg.Status)),
						"shareStatus":      llx.StringData(string(cfg.ShareStatus)),
						"associationCount": llx.IntData(int64(cfg.AssociationCount)),
						"destinationArn":   llx.StringData(convert.ToValue(cfg.DestinationArn)),
						"creationTime":     llx.StringData(convert.ToValue(cfg.CreationTime)),
						"creatorRequestId": llx.StringData(convert.ToValue(cfg.CreatorRequestId)),
					})
					if err != nil {
						return nil, err
					}
					res = append(res, resource)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// destinationService extracts the AWS service portion of a destination ARN.
// Returns "" if the ARN cannot be parsed or is empty.
func destinationService(arnVal string) string {
	if arnVal == "" {
		return ""
	}
	parsed, err := arn.Parse(arnVal)
	if err != nil {
		return ""
	}
	return parsed.Service
}

func (a *mqlAwsRoute53ResolverQueryLogConfig) s3Bucket() (*mqlAwsS3Bucket, error) {
	arnVal := a.DestinationArn.Data
	if destinationService(arnVal) != "s3" {
		a.S3Bucket.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.s3.bucket", map[string]*llx.RawData{
		"arn": llx.StringData(arnVal),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsS3Bucket), nil
}

func (a *mqlAwsRoute53ResolverQueryLogConfig) cloudwatchLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	arnVal := a.DestinationArn.Data
	if destinationService(arnVal) != "logs" {
		a.CloudwatchLogGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup", map[string]*llx.RawData{
		"arn": llx.StringData(arnVal),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsRoute53ResolverQueryLogConfig) firehoseDeliveryStream() (*mqlAwsKinesisFirehoseDeliveryStream, error) {
	arnVal := a.DestinationArn.Data
	if destinationService(arnVal) != "firehose" {
		a.FirehoseDeliveryStream.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.kinesis.firehoseDeliveryStream", map[string]*llx.RawData{
		"arn": llx.StringData(arnVal),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsKinesisFirehoseDeliveryStream), nil
}

// ----- Resolver query log config associations -----

func (a *mqlAwsRoute53ResolverQueryLogConfigAssociation) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) queryLogConfigAssociations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.queryLogConfigAssociationTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) queryLogConfigAssociationTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>queryLogConfigAssociations>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListResolverQueryLogConfigAssociationsPaginator(svc, &route53resolver.ListResolverQueryLogConfigAssociationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 resolver query log config associations")
						return res, nil
					}
					return nil, err
				}
				for _, assoc := range page.ResolverQueryLogConfigAssociations {
					id := convert.ToValue(assoc.Id)
					resource, err := CreateResource(a.MqlRuntime, "aws.route53.resolver.queryLogConfigAssociation", map[string]*llx.RawData{
						"__id":                     llx.StringData(region + "/" + id),
						"id":                       llx.StringData(id),
						"region":                   llx.StringData(region),
						"resolverQueryLogConfigId": llx.StringData(convert.ToValue(assoc.ResolverQueryLogConfigId)),
						"resourceId":               llx.StringData(convert.ToValue(assoc.ResourceId)),
						"status":                   llx.StringData(string(assoc.Status)),
						"error":                    llx.StringData(string(assoc.Error)),
						"errorMessage":             llx.StringData(convert.ToValue(assoc.ErrorMessage)),
						"creationTime":             llx.StringData(convert.ToValue(assoc.CreationTime)),
					})
					if err != nil {
						return nil, err
					}
					res = append(res, resource)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRoute53ResolverQueryLogConfigAssociation) resolverQueryLogConfig() (*mqlAwsRoute53ResolverQueryLogConfig, error) {
	cfgId := a.ResolverQueryLogConfigId.Data
	if cfgId == "" {
		a.ResolverQueryLogConfig.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.route53.resolver.queryLogConfig", map[string]*llx.RawData{
		"id": llx.StringData(cfgId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRoute53ResolverQueryLogConfig), nil
}

func (a *mqlAwsRoute53ResolverQueryLogConfigAssociation) vpc() (*mqlAwsVpc, error) {
	resourceId := a.ResourceId.Data
	if resourceId == "" || !strings.HasPrefix(resourceId, "vpc-") {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"id": llx.StringData(resourceId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// ----- DNS Firewall rule groups -----

type mqlAwsRoute53ResolverFirewallRuleGroupInternal struct {
	region string
}

func (a *mqlAwsRoute53ResolverFirewallRuleGroup) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) firewallRuleGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.firewallRuleGroupTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) firewallRuleGroupTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>firewallRuleGroups>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListFirewallRuleGroupsPaginator(svc, &route53resolver.ListFirewallRuleGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 firewall rule groups")
						return res, nil
					}
					return nil, err
				}
				for _, meta := range page.FirewallRuleGroups {
					meta := meta
					mqlGroup, err := fetchAndCreateFirewallRuleGroup(a.MqlRuntime, conn, region, &meta)
					if err != nil {
						return nil, err
					}
					if mqlGroup != nil {
						res = append(res, mqlGroup)
					}
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// fetchAndCreateFirewallRuleGroup calls GetFirewallRuleGroup to fill in
// rule count, status, and timestamps that the List API leaves out, then
// constructs the MQL resource.
func fetchAndCreateFirewallRuleGroup(runtime *plugin.Runtime, conn *connection.AwsConnection, region string, meta *resolvertypes.FirewallRuleGroupMetadata) (*mqlAwsRoute53ResolverFirewallRuleGroup, error) {
	svc := conn.Route53Resolver(region)
	resp, err := svc.GetFirewallRuleGroup(context.TODO(), &route53resolver.GetFirewallRuleGroupInput{
		FirewallRuleGroupId: meta.Id,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return newMqlAwsRoute53ResolverFirewallRuleGroupFromMeta(runtime, region, meta)
		}
		return nil, err
	}
	if resp == nil || resp.FirewallRuleGroup == nil {
		return newMqlAwsRoute53ResolverFirewallRuleGroupFromMeta(runtime, region, meta)
	}
	return newMqlAwsRoute53ResolverFirewallRuleGroup(runtime, region, resp.FirewallRuleGroup)
}

func newMqlAwsRoute53ResolverFirewallRuleGroupFromMeta(runtime *plugin.Runtime, region string, meta *resolvertypes.FirewallRuleGroupMetadata) (*mqlAwsRoute53ResolverFirewallRuleGroup, error) {
	id := convert.ToValue(meta.Id)
	resource, err := CreateResource(runtime, "aws.route53.resolver.firewallRuleGroup", map[string]*llx.RawData{
		"__id":             llx.StringData(region + "/" + id),
		"id":               llx.StringData(id),
		"arn":              llx.StringData(convert.ToValue(meta.Arn)),
		"name":             llx.StringData(convert.ToValue(meta.Name)),
		"region":           llx.StringData(region),
		"ruleCount":        llx.IntData(0),
		"status":           llx.StringData(""),
		"statusMessage":    llx.StringData(""),
		"ownerId":          llx.StringData(convert.ToValue(meta.OwnerId)),
		"shareStatus":      llx.StringData(string(meta.ShareStatus)),
		"creationTime":     llx.StringData(""),
		"modificationTime": llx.StringData(""),
		"creatorRequestId": llx.StringData(convert.ToValue(meta.CreatorRequestId)),
	})
	if err != nil {
		return nil, err
	}
	mqlGroup := resource.(*mqlAwsRoute53ResolverFirewallRuleGroup)
	mqlGroup.region = region
	return mqlGroup, nil
}

func newMqlAwsRoute53ResolverFirewallRuleGroup(runtime *plugin.Runtime, region string, group *resolvertypes.FirewallRuleGroup) (*mqlAwsRoute53ResolverFirewallRuleGroup, error) {
	id := convert.ToValue(group.Id)
	ruleCount := int64(0)
	if group.RuleCount != nil {
		ruleCount = int64(*group.RuleCount)
	}
	resource, err := CreateResource(runtime, "aws.route53.resolver.firewallRuleGroup", map[string]*llx.RawData{
		"__id":             llx.StringData(region + "/" + id),
		"id":               llx.StringData(id),
		"arn":              llx.StringData(convert.ToValue(group.Arn)),
		"name":             llx.StringData(convert.ToValue(group.Name)),
		"region":           llx.StringData(region),
		"ruleCount":        llx.IntData(ruleCount),
		"status":           llx.StringData(string(group.Status)),
		"statusMessage":    llx.StringData(convert.ToValue(group.StatusMessage)),
		"ownerId":          llx.StringData(convert.ToValue(group.OwnerId)),
		"shareStatus":      llx.StringData(string(group.ShareStatus)),
		"creationTime":     llx.StringData(convert.ToValue(group.CreationTime)),
		"modificationTime": llx.StringData(convert.ToValue(group.ModificationTime)),
		"creatorRequestId": llx.StringData(convert.ToValue(group.CreatorRequestId)),
	})
	if err != nil {
		return nil, err
	}
	mqlGroup := resource.(*mqlAwsRoute53ResolverFirewallRuleGroup)
	mqlGroup.region = region
	return mqlGroup, nil
}

type mqlAwsRoute53ResolverFirewallRuleInternal struct {
	region string
}

func (a *mqlAwsRoute53ResolverFirewallRuleGroup) firewallRules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Route53Resolver(a.region)
	ctx := context.Background()
	id := a.Id.Data

	res := []any{}
	paginator := route53resolver.NewListFirewallRulesPaginator(svc, &route53resolver.ListFirewallRulesInput{
		FirewallRuleGroupId: &id,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "route53resolver:ListFirewallRules")
		}
		for i := range page.FirewallRules {
			mqlRule, err := newMqlAwsRoute53ResolverFirewallRule(a.MqlRuntime, a.region, &page.FirewallRules[i])
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

func newMqlAwsRoute53ResolverFirewallRule(runtime *plugin.Runtime, region string, rule *resolvertypes.FirewallRule) (*mqlAwsRoute53ResolverFirewallRule, error) {
	groupID := convert.ToValue(rule.FirewallRuleGroupId)
	// Priority is unique within a rule group, so it makes a stable key.
	priority := int64(0)
	if rule.Priority != nil {
		priority = int64(*rule.Priority)
	}
	resource, err := CreateResource(runtime, "aws.route53.resolver.firewallRule", map[string]*llx.RawData{
		"__id":                            llx.StringData(fmt.Sprintf("%s/%s/%d", region, groupID, priority)),
		"name":                            llx.StringData(convert.ToValue(rule.Name)),
		"firewallRuleGroupId":             llx.StringData(groupID),
		"priority":                        llx.IntData(priority),
		"action":                          llx.StringData(string(rule.Action)),
		"blockResponse":                   llx.StringData(string(rule.BlockResponse)),
		"blockOverrideDomain":             llx.StringData(convert.ToValue(rule.BlockOverrideDomain)),
		"blockOverrideDnsType":            llx.StringData(string(rule.BlockOverrideDnsType)),
		"blockOverrideTtl":                llx.IntData(int64(convert.ToValue(rule.BlockOverrideTtl))),
		"firewallDomainListId":            llx.StringData(convert.ToValue(rule.FirewallDomainListId)),
		"firewallDomainRedirectionAction": llx.StringData(string(rule.FirewallDomainRedirectionAction)),
		"qtype":                           llx.StringData(convert.ToValue(rule.Qtype)),
		"dnsThreatProtection":             llx.StringData(string(rule.DnsThreatProtection)),
		"confidenceThreshold":             llx.StringData(string(rule.ConfidenceThreshold)),
		"firewallRuleType":                llx.DictData(firewallRuleTypeToDict(rule.FirewallRuleType)),
		"firewallThreatProtectionId":      llx.StringData(convert.ToValue(rule.FirewallThreatProtectionId)),
		"creationTime":                    llx.StringData(convert.ToValue(rule.CreationTime)),
		"modificationTime":                llx.StringData(convert.ToValue(rule.ModificationTime)),
		"creatorRequestId":                llx.StringData(convert.ToValue(rule.CreatorRequestId)),
	})
	if err != nil {
		return nil, err
	}
	mqlRule := resource.(*mqlAwsRoute53ResolverFirewallRule)
	mqlRule.region = region
	return mqlRule, nil
}

// firewallRuleTypeToDict flattens the FirewallRuleType union into a dict
// keyed by the populated member. Returns nil when no member is set.
func firewallRuleTypeToDict(rt *resolvertypes.FirewallRuleType) any {
	if rt == nil {
		return nil
	}
	out := map[string]any{}
	if rt.DnsThreatProtection != nil {
		out["dnsThreatProtection"] = map[string]any{
			"confidenceThreshold": string(rt.DnsThreatProtection.ConfidenceThreshold),
			"value":               convert.ToValue(rt.DnsThreatProtection.Value),
		}
	}
	if rt.FirewallAdvancedContentCategory != nil {
		out["firewallAdvancedContentCategory"] = map[string]any{
			"category": convert.ToValue(rt.FirewallAdvancedContentCategory.Category),
		}
	}
	if rt.FirewallAdvancedThreatCategory != nil {
		out["firewallAdvancedThreatCategory"] = map[string]any{
			"category": convert.ToValue(rt.FirewallAdvancedThreatCategory.Category),
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (a *mqlAwsRoute53ResolverFirewallRule) firewallDomainList() (*mqlAwsRoute53ResolverFirewallDomainList, error) {
	domainListID := a.FirewallDomainListId.Data
	if domainListID == "" {
		a.FirewallDomainList.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	resp, err := conn.Route53Resolver(a.region).GetFirewallDomainList(context.TODO(), &route53resolver.GetFirewallDomainListInput{
		FirewallDomainListId: &domainListID,
	})
	if err != nil {
		return nil, classifyAwsError(err, "route53resolver:GetFirewallDomainList")
	}
	if resp == nil || resp.FirewallDomainList == nil {
		return newMqlAwsRoute53ResolverFirewallDomainListFromMeta(a.MqlRuntime, a.region, &resolvertypes.FirewallDomainListMetadata{Id: &domainListID})
	}
	return newMqlAwsRoute53ResolverFirewallDomainList(a.MqlRuntime, a.region, resp.FirewallDomainList)
}

// ----- DNS Firewall rule group associations -----

func (a *mqlAwsRoute53ResolverFirewallRuleGroupAssociation) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) firewallRuleGroupAssociations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.firewallRuleGroupAssociationTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) firewallRuleGroupAssociationTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>firewallRuleGroupAssociations>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListFirewallRuleGroupAssociationsPaginator(svc, &route53resolver.ListFirewallRuleGroupAssociationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 firewall rule group associations")
						return res, nil
					}
					return nil, err
				}
				for _, assoc := range page.FirewallRuleGroupAssociations {
					id := convert.ToValue(assoc.Id)
					priority := int64(0)
					if assoc.Priority != nil {
						priority = int64(*assoc.Priority)
					}
					resource, err := CreateResource(a.MqlRuntime, "aws.route53.resolver.firewallRuleGroupAssociation", map[string]*llx.RawData{
						"__id":                llx.StringData(region + "/" + id),
						"id":                  llx.StringData(id),
						"arn":                 llx.StringData(convert.ToValue(assoc.Arn)),
						"name":                llx.StringData(convert.ToValue(assoc.Name)),
						"region":              llx.StringData(region),
						"firewallRuleGroupId": llx.StringData(convert.ToValue(assoc.FirewallRuleGroupId)),
						"priority":            llx.IntData(priority),
						"mutationProtection":  llx.StringData(string(assoc.MutationProtection)),
						"managedOwnerName":    llx.StringData(convert.ToValue(assoc.ManagedOwnerName)),
						"status":              llx.StringData(string(assoc.Status)),
						"statusMessage":       llx.StringData(convert.ToValue(assoc.StatusMessage)),
						"creationTime":        llx.StringData(convert.ToValue(assoc.CreationTime)),
						"modificationTime":    llx.StringData(convert.ToValue(assoc.ModificationTime)),
						"creatorRequestId":    llx.StringData(convert.ToValue(assoc.CreatorRequestId)),
					})
					if err != nil {
						return nil, err
					}
					resource.(*mqlAwsRoute53ResolverFirewallRuleGroupAssociation).cacheVpcId = convert.ToValue(assoc.VpcId)
					res = append(res, resource)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRoute53ResolverFirewallRuleGroupAssociation) firewallRuleGroup() (*mqlAwsRoute53ResolverFirewallRuleGroup, error) {
	groupId := a.FirewallRuleGroupId.Data
	if groupId == "" {
		a.FirewallRuleGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.route53.resolver.firewallRuleGroup", map[string]*llx.RawData{
		"id": llx.StringData(groupId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsRoute53ResolverFirewallRuleGroup), nil
}

func (a *mqlAwsRoute53ResolverFirewallRuleGroupAssociation) vpc() (*mqlAwsVpc, error) {
	vpcId := a.cacheVpcId
	if vpcId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"id": llx.StringData(vpcId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// ----- DNS Firewall domain lists -----

func (a *mqlAwsRoute53ResolverFirewallDomainList) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) firewallDomainLists() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.firewallDomainListTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) firewallDomainListTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>firewallDomainLists>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListFirewallDomainListsPaginator(svc, &route53resolver.ListFirewallDomainListsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 firewall domain lists")
						return res, nil
					}
					return nil, err
				}
				for _, meta := range page.FirewallDomainLists {
					meta := meta
					mqlList, err := fetchAndCreateFirewallDomainList(a.MqlRuntime, conn, region, &meta)
					if err != nil {
						return nil, err
					}
					if mqlList != nil {
						res = append(res, mqlList)
					}
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// fetchAndCreateFirewallDomainList calls GetFirewallDomainList to enrich
// the list metadata with status, domain count, and timestamps.
func fetchAndCreateFirewallDomainList(runtime *plugin.Runtime, conn *connection.AwsConnection, region string, meta *resolvertypes.FirewallDomainListMetadata) (*mqlAwsRoute53ResolverFirewallDomainList, error) {
	svc := conn.Route53Resolver(region)
	resp, err := svc.GetFirewallDomainList(context.TODO(), &route53resolver.GetFirewallDomainListInput{
		FirewallDomainListId: meta.Id,
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return newMqlAwsRoute53ResolverFirewallDomainListFromMeta(runtime, region, meta)
		}
		return nil, err
	}
	if resp == nil || resp.FirewallDomainList == nil {
		return newMqlAwsRoute53ResolverFirewallDomainListFromMeta(runtime, region, meta)
	}
	return newMqlAwsRoute53ResolverFirewallDomainList(runtime, region, resp.FirewallDomainList)
}

func newMqlAwsRoute53ResolverFirewallDomainListFromMeta(runtime *plugin.Runtime, region string, meta *resolvertypes.FirewallDomainListMetadata) (*mqlAwsRoute53ResolverFirewallDomainList, error) {
	id := convert.ToValue(meta.Id)
	resource, err := CreateResource(runtime, "aws.route53.resolver.firewallDomainList", map[string]*llx.RawData{
		"__id":             llx.StringData(region + "/" + id),
		"id":               llx.StringData(id),
		"arn":              llx.StringData(convert.ToValue(meta.Arn)),
		"name":             llx.StringData(convert.ToValue(meta.Name)),
		"region":           llx.StringData(region),
		"domainCount":      llx.IntData(0),
		"category":         llx.StringData(convert.ToValue(meta.Category)),
		"managedListType":  llx.StringData(string(meta.ManagedListType)),
		"status":           llx.StringData(""),
		"statusMessage":    llx.StringData(""),
		"managedOwnerName": llx.StringData(convert.ToValue(meta.ManagedOwnerName)),
		"creationTime":     llx.StringData(""),
		"modificationTime": llx.StringData(""),
		"creatorRequestId": llx.StringData(convert.ToValue(meta.CreatorRequestId)),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsRoute53ResolverFirewallDomainList), nil
}

func newMqlAwsRoute53ResolverFirewallDomainList(runtime *plugin.Runtime, region string, list *resolvertypes.FirewallDomainList) (*mqlAwsRoute53ResolverFirewallDomainList, error) {
	id := convert.ToValue(list.Id)
	domainCount := int64(0)
	if list.DomainCount != nil {
		domainCount = int64(*list.DomainCount)
	}
	resource, err := CreateResource(runtime, "aws.route53.resolver.firewallDomainList", map[string]*llx.RawData{
		"__id":             llx.StringData(region + "/" + id),
		"id":               llx.StringData(id),
		"arn":              llx.StringData(convert.ToValue(list.Arn)),
		"name":             llx.StringData(convert.ToValue(list.Name)),
		"region":           llx.StringData(region),
		"domainCount":      llx.IntData(domainCount),
		"category":         llx.StringData(convert.ToValue(list.Category)),
		"managedListType":  llx.StringData(string(list.ManagedListType)),
		"status":           llx.StringData(string(list.Status)),
		"statusMessage":    llx.StringData(convert.ToValue(list.StatusMessage)),
		"managedOwnerName": llx.StringData(convert.ToValue(list.ManagedOwnerName)),
		"creationTime":     llx.StringData(convert.ToValue(list.CreationTime)),
		"modificationTime": llx.StringData(convert.ToValue(list.ModificationTime)),
		"creatorRequestId": llx.StringData(convert.ToValue(list.CreatorRequestId)),
	})
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsRoute53ResolverFirewallDomainList), nil
}

func (a *mqlAwsRoute53ResolverFirewallDomainList) domains() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Route53Resolver(a.Region.Data)
	ctx := context.Background()
	id := a.Id.Data

	res := []any{}
	paginator := route53resolver.NewListFirewallDomainsPaginator(svc, &route53resolver.ListFirewallDomainsInput{
		FirewallDomainListId: &id,
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, classifyAwsError(err, "route53resolver:ListFirewallDomains")
		}
		for _, domain := range page.Domains {
			res = append(res, domain)
		}
	}
	return res, nil
}

// ----- DNS Firewall configs -----

func (a *mqlAwsRoute53ResolverFirewallConfig) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsRoute53Resolver) firewallConfigs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.firewallConfigTasks(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		entries, ok := poolOfJobs.Jobs[i].Result.([]any)
		if !ok {
			continue
		}
		res = append(res, entries...)
	}
	return res, nil
}

func (a *mqlAwsRoute53Resolver) firewallConfigTasks(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		region := region
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msg("route53resolver>firewallConfigs>list")
			svc := conn.Route53Resolver(region)
			res := []any{}
			paginator := route53resolver.NewListFirewallConfigsPaginator(svc, &route53resolver.ListFirewallConfigsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(context.TODO())
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("access denied listing Route 53 firewall configs")
						return res, nil
					}
					return nil, err
				}
				for _, cfg := range page.FirewallConfigs {
					id := convert.ToValue(cfg.Id)
					resourceId := convert.ToValue(cfg.ResourceId)
					resource, err := CreateResource(a.MqlRuntime, "aws.route53.resolver.firewallConfig", map[string]*llx.RawData{
						"__id":             llx.StringData(region + "/" + resourceId),
						"id":               llx.StringData(id),
						"region":           llx.StringData(region),
						"resourceId":       llx.StringData(resourceId),
						"ownerId":          llx.StringData(convert.ToValue(cfg.OwnerId)),
						"firewallFailOpen": llx.StringData(string(cfg.FirewallFailOpen)),
					})
					if err != nil {
						return nil, err
					}
					res = append(res, resource)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsRoute53ResolverFirewallConfig) vpc() (*mqlAwsVpc, error) {
	resourceId := a.ResourceId.Data
	if resourceId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{
		"id": llx.StringData(resourceId),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// ----- init functions -----

func initAwsRoute53ResolverEndpoint(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	idVal := args["id"].Value.(string)

	obj, err := CreateResource(runtime, "aws.route53.resolver", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	r := obj.(*mqlAwsRoute53Resolver)

	rawResources := r.GetEndpoints()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, raw := range rawResources.Data {
		endpoint := raw.(*mqlAwsRoute53ResolverEndpoint)
		if endpoint.Id.Data == idVal {
			return args, endpoint, nil
		}
	}
	return nil, nil, errors.New("aws route53 resolver endpoint not found: " + idVal)
}

func initAwsRoute53ResolverRule(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	idVal := args["id"].Value.(string)

	obj, err := CreateResource(runtime, "aws.route53.resolver", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	r := obj.(*mqlAwsRoute53Resolver)

	rawResources := r.GetRules()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, raw := range rawResources.Data {
		rule := raw.(*mqlAwsRoute53ResolverRule)
		if rule.Id.Data == idVal {
			return args, rule, nil
		}
	}
	return nil, nil, errors.New("aws route53 resolver rule not found: " + idVal)
}

func initAwsRoute53ResolverQueryLogConfig(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	idVal := args["id"].Value.(string)

	obj, err := CreateResource(runtime, "aws.route53.resolver", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	r := obj.(*mqlAwsRoute53Resolver)

	rawResources := r.GetQueryLogConfigs()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, raw := range rawResources.Data {
		cfg := raw.(*mqlAwsRoute53ResolverQueryLogConfig)
		if cfg.Id.Data == idVal {
			return args, cfg, nil
		}
	}
	return nil, nil, errors.New("aws route53 resolver query log config not found: " + idVal)
}

func initAwsRoute53ResolverFirewallRuleGroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil {
		return args, nil, nil
	}
	idVal := args["id"].Value.(string)

	obj, err := CreateResource(runtime, "aws.route53.resolver", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	r := obj.(*mqlAwsRoute53Resolver)

	rawResources := r.GetFirewallRuleGroups()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, raw := range rawResources.Data {
		group := raw.(*mqlAwsRoute53ResolverFirewallRuleGroup)
		if group.Id.Data == idVal {
			return args, group, nil
		}
	}
	return nil, nil, fmt.Errorf("aws route53 resolver firewall rule group not found: %s", idVal)
}

type mqlAwsRoute53ResolverRuleAssociationInternal struct {
	cacheVpcId string
}

type mqlAwsRoute53ResolverFirewallRuleGroupAssociationInternal struct {
	cacheVpcId string
}
