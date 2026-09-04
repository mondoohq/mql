// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	elbv1types "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing/types"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	elbtypes "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

func (a *mqlAwsElb) id() (string, error) {
	return ResourceAwsElb, nil
}

type mqlAwsElbInternal struct {
	dnsIndexMu    sync.Mutex
	dnsIndexBuilt bool
	dnsIndex      map[string]*mqlAwsElbLoadbalancer
}

// loadBalancerByDNSName returns the load balancer whose DNS name matches the
// given already-normalized DNS name, or nil when none matches. It builds a
// normalized-DNS-name index across all load balancers on first call and reuses
// it afterwards. The index lives on the aws.elb list resource, which the runtime
// caches, so many callers (for example every Route 53 alias record resolving its
// target) share one index instead of each rescanning every load balancer.
func (a *mqlAwsElb) loadBalancerByDNSName(normalized string) (*mqlAwsElbLoadbalancer, error) {
	a.dnsIndexMu.Lock()
	defer a.dnsIndexMu.Unlock()

	if !a.dnsIndexBuilt {
		// Index both v2 (application/network/gateway) and classic load balancers:
		// a Route 53 alias record can point at either, and each carries its own
		// DNS name.
		lbs := a.GetLoadBalancers()
		if lbs.Error != nil {
			return nil, lbs.Error
		}
		classic := a.GetClassicLoadBalancers()
		if classic.Error != nil {
			return nil, classic.Error
		}
		idx, err := buildLoadBalancerDNSIndex(lbs.Data, classic.Data)
		if err != nil {
			return nil, err
		}
		a.dnsIndex = idx
		a.dnsIndexBuilt = true
	}
	return a.dnsIndex[normalized], nil
}

// buildLoadBalancerDNSIndex maps each load balancer's normalized DNS name to the
// load balancer, across every provided list (v2 and classic). DNS names are
// unique across load balancer types, so the lists share one index without
// collision.
func buildLoadBalancerDNSIndex(lbLists ...[]any) (map[string]*mqlAwsElbLoadbalancer, error) {
	idx := map[string]*mqlAwsElbLoadbalancer{}
	for _, lbs := range lbLists {
		for _, l := range lbs {
			lb, ok := l.(*mqlAwsElbLoadbalancer)
			if !ok {
				continue
			}
			dnsName := lb.GetDnsName()
			if dnsName.Error != nil {
				return nil, dnsName.Error
			}
			if dnsName.Data != "" {
				idx[normalizeAliasDNSName(dnsName.Data)] = lb
			}
		}
	}
	return idx, nil
}

func (a *mqlAwsElb) classicLoadBalancers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClassicLoadBalancers(conn), 5)
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

func (a *mqlAwsElb) getClassicLoadBalancers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elb(region)
			ctx := context.Background()
			res := []any{}

			params := &elasticloadbalancing.DescribeLoadBalancersInput{}
			paginator := elasticloadbalancing.NewDescribeLoadBalancersPaginator(svc, params)
			for paginator.HasMorePages() {
				lbs, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, lb := range lbs.LoadBalancerDescriptions {
					mqlLb, err := buildElbClassicLoadBalancerResource(a.MqlRuntime, region, conn.AccountId(), lb)
					if err != nil {
						return nil, err
					}
					// keeps the tags lazy unless the filters need to be evaluated
					if conn.Filters.General.HasTags() {
						tags, err := mqlLb.tags()
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
					}

					res = append(res, mqlLb)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func buildElbClassicLoadBalancerResource(runtime *plugin.Runtime, region, accountID string, lb elbv1types.LoadBalancerDescription) (*mqlAwsElbLoadbalancer, error) {
	jsonListeners, err := convert.JsonToDictSlice(lb.ListenerDescriptions)
	if err != nil {
		return nil, err
	}
	healthCheck, err := convert.JsonToDict(lb.HealthCheck)
	if err != nil {
		return nil, err
	}
	lbName := convert.ToValue(lb.LoadBalancerName)

	availabilityZones := []any{}
	for _, zone := range lb.AvailabilityZones {
		availabilityZones = append(availabilityZones, zone)
	}

	sgs := []any{}
	for _, sg := range lb.SecurityGroups {
		mqlSg, err := NewResource(runtime, ResourceAwsEc2Securitygroup,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, region, accountID, sg)),
			})
		if err != nil {
			// When tag filters are active, the security group may not be in the
			// filtered list. Log and continue rather than failing the entire LB.
			log.Debug().Str("sg", sg).Err(err).Msg("could not resolve security group for classic ELB")
			continue
		}
		sgs = append(sgs, mqlSg)
	}

	args := map[string]*llx.RawData{
		"arn":                  llx.StringData(fmt.Sprintf(elbv1LbArnPattern, region, accountID, lbName)),
		"availabilityZones":    llx.ArrayData(availabilityZones, types.String),
		"createdAt":            llx.TimeDataPtr(lb.CreatedTime),
		"dnsName":              llx.StringDataPtr(lb.DNSName),
		"elbType":              llx.StringData("classic"),
		"hostedZoneId":         llx.StringDataPtr(lb.CanonicalHostedZoneNameID),
		"healthCheck":          llx.DictData(healthCheck),
		"listenerDescriptions": llx.AnyData(jsonListeners),
		"name":                 llx.StringDataPtr(lb.LoadBalancerName),
		"region":               llx.StringData(region),
		"scheme":               llx.StringDataPtr(lb.Scheme),
		"securityGroups":       llx.ArrayData(sgs, types.Resource(ResourceAwsEc2Securitygroup)),
		"state":                llx.NilData, // classic load balancers have no provisioning state
		"vpc":                  llx.NilData,
	}

	if lb.VPCId != nil {
		mqlVpc, err := NewResource(runtime, ResourceAwsVpc,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, region, accountID, convert.ToValue(lb.VPCId))),
			})
		if err != nil {
			// When tag filters are active, the VPC may not be in the filtered list.
			log.Debug().Str("vpcId", convert.ToValue(lb.VPCId)).Err(err).Msg("could not resolve VPC for classic ELB")
		} else {
			args["vpc"] = llx.ResourceData(mqlVpc, mqlVpc.MqlName())
		}
	}

	mqlLb, err := CreateResource(runtime, ResourceAwsElbLoadbalancer, args)
	if err != nil {
		return nil, err
	}
	res := mqlLb.(*mqlAwsElbLoadbalancer)
	res.cacheSubnetIds = lb.Subnets
	return res, nil
}

func (a *mqlAwsElbLoadbalancer) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElbLoadbalancer) subnets() ([]any, error) {
	if len(a.cacheSubnetIds) == 0 {
		return []any{}, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, region, conn.AccountId(), subnetId)),
			})
		if err != nil {
			// When tag filters are active, the subnet may not be in the filtered
			// list. Log and continue rather than failing the entire LB.
			log.Debug().Str("subnet", subnetId).Err(err).Msg("could not resolve subnet for ELB")
			continue
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

type mqlAwsElbLoadbalancerInternal struct {
	// Subnet IDs the load balancer is attached to, resolved lazily by subnets().
	cacheSubnetIds []string

	// Cached v2 DescribeLoadBalancerAttributes response, shared between attributes() and attribute().
	cachedV2Attrs  []elbtypes.LoadBalancerAttribute
	v2AttrsFetched bool
	v2AttrsLock    sync.Mutex

	// Tag caching for the filter guard pattern during listing.
	cacheTags   map[string]any
	tagsFetched bool
	tagsLock    sync.Mutex
}

// fetchV2Attrs fetches and caches v2 load balancer attributes with double-check locking.
func (a *mqlAwsElbLoadbalancer) fetchV2Attrs() ([]elbtypes.LoadBalancerAttribute, error) {
	if a.v2AttrsFetched {
		return a.cachedV2Attrs, nil
	}
	a.v2AttrsLock.Lock()
	defer a.v2AttrsLock.Unlock()
	if a.v2AttrsFetched {
		return a.cachedV2Attrs, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := a.Arn.Data
	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, err
	}
	svc := conn.Elbv2(region)
	ctx := context.Background()

	resp, err := svc.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancingv2.DescribeLoadBalancerAttributesInput{
		LoadBalancerArn: &arnVal,
	})
	if err != nil {
		return nil, err
	}

	a.cachedV2Attrs = resp.Attributes
	a.v2AttrsFetched = true
	return a.cachedV2Attrs, nil
}

func (a *mqlAwsElb) loadBalancers() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLoadBalancers(conn), 5)
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

func (a *mqlAwsElb) getLoadBalancers(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elbv2(region)
			ctx := context.Background()
			res := []any{}

			params := &elasticloadbalancingv2.DescribeLoadBalancersInput{}
			paginator := elasticloadbalancingv2.NewDescribeLoadBalancersPaginator(svc, params)
			for paginator.HasMorePages() {
				lbs, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, lb := range lbs.LoadBalancers {
					mqlLb, err := buildElbV2LoadBalancerResource(a.MqlRuntime, region, conn.AccountId(), lb)
					if err != nil {
						return nil, err
					}
					// keeps the tags lazy unless the filters need to be evaluated
					if conn.Filters.General.HasTags() {
						tags, err := mqlLb.tags()
						if err != nil {
							return nil, err
						}
						if conn.Filters.General.IsFilteredOutByTags(mapStringInterfaceToStringString(tags)) {
							continue
						}
					}

					res = append(res, mqlLb)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func buildElbV2LoadBalancerResource(runtime *plugin.Runtime, region, accountID string, lb elbtypes.LoadBalancer) (*mqlAwsElbLoadbalancer, error) {
	availabilityZones := []any{}
	subnetIds := []string{}
	for _, zone := range lb.AvailabilityZones {
		availabilityZones = append(availabilityZones, convert.ToValue(zone.ZoneName))
		if zone.SubnetId != nil {
			subnetIds = append(subnetIds, *zone.SubnetId)
		}
	}

	state := ""
	if lb.State != nil {
		state = string(lb.State.Code)
	}

	sgs := []any{}
	for _, sg := range lb.SecurityGroups {
		mqlSg, err := NewResource(runtime, ResourceAwsEc2Securitygroup,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, region, accountID, sg)),
			})
		if err != nil {
			// When tag filters are active, the security group may not be in the
			// filtered list. Log and continue rather than failing the entire LB.
			log.Debug().Str("sg", sg).Err(err).Msg("could not resolve security group for ELB")
			continue
		}
		sgs = append(sgs, mqlSg)
	}

	args := map[string]*llx.RawData{
		"arn":               llx.StringDataPtr(lb.LoadBalancerArn),
		"availabilityZones": llx.ArrayData(availabilityZones, types.String),
		"createdAt":         llx.TimeDataPtr(lb.CreatedTime),
		"dnsName":           llx.StringDataPtr(lb.DNSName),
		"hostedZoneId":      llx.StringDataPtr(lb.CanonicalHostedZoneId),
		"name":              llx.StringDataPtr(lb.LoadBalancerName),
		"scheme":            llx.StringData(string(lb.Scheme)),
		"securityGroups":    llx.ArrayData(sgs, types.Resource(ResourceAwsEc2Securitygroup)),
		"state":             llx.StringData(state),
		"elbType":           llx.StringData(string(lb.Type)),
		"ipAddressType":     llx.StringData(string(lb.IpAddressType)),
		"enforceSecurityGroupInboundRulesOnPrivateLinkTraffic": llx.StringData(convert.ToValue(lb.EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic)),
		"region":      llx.StringData(region),
		"vpc":         llx.NilData, // set vpc to nil as default, if vpc is not set
		"healthCheck": llx.NilData, // classic ELB only; ALB/NLB have no LB-level health check
	}

	if lb.VpcId != nil {
		mqlVpc, err := NewResource(runtime, ResourceAwsVpc,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, region, accountID, convert.ToValue(lb.VpcId))),
			})
		if err != nil {
			// When tag filters are active, the VPC may not be in the filtered list.
			log.Debug().Str("vpcId", convert.ToValue(lb.VpcId)).Err(err).Msg("could not resolve VPC for ELB")
		} else {
			// update the vpc setting
			args["vpc"] = llx.ResourceData(mqlVpc, mqlVpc.MqlName())
		}
	}

	mqlLb, err := CreateResource(runtime, ResourceAwsElbLoadbalancer, args)
	if err != nil {
		return nil, err
	}
	res := mqlLb.(*mqlAwsElbLoadbalancer)
	res.cacheSubnetIds = subnetIds
	return res, nil
}

func initAwsElbLoadbalancer(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformElbLoadbalancer); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch elb loadbalancer")
	}

	arnVal := args["arn"].Value.(string)

	// Quick check: if the ARN doesn't belong to elasticloadbalancing, this asset
	// is not an ELB. This happens when the query runs against non-ELB discovered
	// assets (e.g., DynamoDB tables, IAM users, S3 buckets).
	if arnVal == "" || !strings.Contains(arnVal, ":elasticloadbalancing:") {
		return nil, nil, errors.New("elb load balancer does not exist")
	}

	if cached := cachedByArn(runtime, ResourceAwsElbLoadbalancer, arnVal); cached != nil {
		return args, cached, nil
	}

	// Issue a single targeted Describe against the ARN's region instead of
	// listing every load balancer in every region. ELBv2 (app/net/gateway) and
	// classic ELB live in different APIs; discriminate by the ARN form.
	region, err := GetRegionFromArn(arnVal)
	if err == nil && region != "" {
		conn := runtime.Connection.(*connection.AwsConnection)
		if isV1LoadBalancerArn(arnVal) {
			// Classic ELB: the synthetic ARN encodes the name as
			// loadbalancer/classic/<name>.
			name := ""
			if args["name"] != nil {
				if n, ok := args["name"].Value.(string); ok {
					name = n
				}
			}
			if name == "" {
				if parsed, perr := arn.Parse(arnVal); perr == nil {
					name = strings.TrimPrefix(parsed.Resource, "loadbalancer/classic/")
				}
			}
			if name != "" {
				svc := conn.Elb(region)
				resp, err := svc.DescribeLoadBalancers(context.Background(), &elasticloadbalancing.DescribeLoadBalancersInput{
					LoadBalancerNames: []string{name},
				})
				if err != nil {
					// Surface unexpected errors; on access-denied or a stale ARN
					// (deleted LB) fall through to the list-scan fallback below.
					if !Is400AccessDeniedError(err) && !isResourceNotFoundError(err) {
						return nil, nil, err
					}
				} else if len(resp.LoadBalancerDescriptions) > 0 {
					lb, err := buildElbClassicLoadBalancerResource(runtime, region, conn.AccountId(), resp.LoadBalancerDescriptions[0])
					if err != nil {
						return nil, nil, err
					}
					return args, lb, nil
				}
			}
		} else {
			svc := conn.Elbv2(region)
			resp, err := svc.DescribeLoadBalancers(context.Background(), &elasticloadbalancingv2.DescribeLoadBalancersInput{
				LoadBalancerArns: []string{arnVal},
			})
			if err != nil {
				// Surface unexpected errors; on access-denied or a stale ARN
				// (deleted LB) fall through to the list-scan fallback below.
				if !Is400AccessDeniedError(err) && !isResourceNotFoundError(err) {
					return nil, nil, err
				}
			} else if len(resp.LoadBalancers) > 0 {
				lb, err := buildElbV2LoadBalancerResource(runtime, region, conn.AccountId(), resp.LoadBalancers[0])
				if err != nil {
					return nil, nil, err
				}
				return args, lb, nil
			}
		}
	}

	// Fallback: no region hint (or the targeted lookup was denied/not found),
	// scan the cached lists.
	obj, err := CreateResource(runtime, ResourceAwsElb, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	elb := obj.(*mqlAwsElb)

	rawResources := elb.GetLoadBalancers()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, rawResource := range rawResources.Data {
		lb := rawResource.(*mqlAwsElbLoadbalancer)
		if lb.Arn.Data == arnVal {
			return args, lb, nil
		}
	}

	classicResources := elb.GetClassicLoadBalancers()
	if classicResources.Error != nil {
		return nil, nil, classicResources.Error
	}
	for _, rawResource := range classicResources.Data {
		lb := rawResource.(*mqlAwsElbLoadbalancer)
		if lb.Arn.Data == arnVal {
			return args, lb, nil
		}
	}

	return nil, nil, errors.New("elb load balancer does not exist")
}

func (a *mqlAwsElbLoadbalancer) listenerDescriptions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := a.Arn.Data

	region, err := GetRegionFromArn(arn)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	if isV1LoadBalancerArn(arn) {
		return a.ListenerDescriptions.Data, nil
	}
	svc := conn.Elbv2(region)
	listeners, err := svc.DescribeListeners(ctx, &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: &arn})
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(listeners.Listeners)
}

func (a *mqlAwsElbLoadbalancer) attributes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := a.Arn.Data
	name := a.Name.Data

	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, err
	}

	if isV1LoadBalancerArn(arnVal) {
		svc := conn.Elb(region)
		ctx := context.Background()
		attributes, err := svc.DescribeLoadBalancerAttributes(ctx, &elasticloadbalancing.DescribeLoadBalancerAttributesInput{LoadBalancerName: &name})
		if err != nil {
			return nil, err
		}
		j, err := convert.JsonToDict(attributes.LoadBalancerAttributes)
		if err != nil {
			return nil, err
		}
		return []any{j}, nil
	}
	attrs, err := a.fetchV2Attrs()
	if err != nil {
		return nil, err
	}
	return convert.JsonToDictSlice(attrs)
}

func (a *mqlAwsElbListener) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElbListener) loadBalancer() (*mqlAwsElbLoadbalancer, error) {
	arnVal := a.cacheLoadBalancerArn
	if arnVal == "" {
		a.LoadBalancer.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.elb.loadbalancer",
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsElbLoadbalancer), nil
}

func (a *mqlAwsElbLoadbalancer) listeners() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := a.Arn.Data

	if isV1LoadBalancerArn(arnVal) {
		return []any{}, nil
	}

	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc := conn.Elbv2(region)

	res := []any{}
	params := &elasticloadbalancingv2.DescribeListenersInput{LoadBalancerArn: &arnVal}
	paginator := elasticloadbalancingv2.NewDescribeListenersPaginator(svc, params)
	for paginator.HasMorePages() {
		listenersResp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, l := range listenersResp.Listeners {
			defaultActions, err := convert.JsonToDictSlice(l.DefaultActions)
			if err != nil {
				return nil, err
			}
			certificates, err := convert.JsonToDictSlice(l.Certificates)
			if err != nil {
				return nil, err
			}

			var mutualAuth any
			mutualAuthTrustStoreArn := ""
			if l.MutualAuthentication != nil {
				mutualAuth, err = convert.JsonToDict(l.MutualAuthentication)
				if err != nil {
					return nil, err
				}
				mutualAuthTrustStoreArn = convert.ToValue(l.MutualAuthentication.TrustStoreArn)
			}
			mqlMutualAuth, err := newMqlElbMutualAuthentication(a.MqlRuntime, convert.ToValue(l.ListenerArn), l.MutualAuthentication)
			if err != nil {
				return nil, err
			}

			args := map[string]*llx.RawData{
				"__id":                 llx.StringDataPtr(l.ListenerArn),
				"arn":                  llx.StringDataPtr(l.ListenerArn),
				"port":                 llx.IntDataPtr(l.Port),
				"protocol":             llx.StringData(string(l.Protocol)),
				"sslPolicy":            llx.StringDataPtr(l.SslPolicy),
				"defaultActions":       llx.ArrayData(defaultActions, types.Dict),
				"certificates":         llx.ArrayData(certificates, types.Dict),
				"alpnPolicy":           llx.ArrayData(llx.TArr2Raw(l.AlpnPolicy), types.String),
				"mutualAuthentication": llx.DictData(mutualAuth),
				"mutualTls":            mqlMutualAuth,
			}

			mqlListener, err := CreateResource(a.MqlRuntime, "aws.elb.listener", args)
			if err != nil {
				return nil, err
			}
			mqlListener.(*mqlAwsElbListener).cacheLoadBalancerArn = convert.ToValue(l.LoadBalancerArn)
			mqlListener.(*mqlAwsElbListener).defaultActionsCache = l.DefaultActions
			mqlListener.(*mqlAwsElbListener).mutualAuthTrustStoreArn = mutualAuthTrustStoreArn
			res = append(res, mqlListener)
		}
	}
	return res, nil
}

type mqlAwsElbListenerInternal struct {
	lazyTags
	cacheLoadBalancerArn    string
	defaultActionsCache     []elbtypes.Action
	mutualAuthTrustStoreArn string
}

// sniCertificates returns every certificate installed on the listener.
// DescribeListeners reports only the default certificate, so the certificates
// served for the other SNI host names need a separate call.
func (a *mqlAwsElbListener) sniCertificates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	listenerArn := a.Arn.Data

	region, err := GetRegionFromArn(listenerArn)
	if err != nil {
		return nil, err
	}
	svc := conn.Elbv2(region)
	ctx := context.Background()

	res := []any{}
	paginator := elasticloadbalancingv2.NewDescribeListenerCertificatesPaginator(svc,
		&elasticloadbalancingv2.DescribeListenerCertificatesInput{ListenerArn: &listenerArn})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return res, nil
			}
			// A listener that terminates no TLS has no certificate list at all.
			var notFound *elbtypes.ListenerNotFoundException
			if errors.As(err, &notFound) {
				return res, nil
			}
			return nil, err
		}
		for _, cert := range page.Certificates {
			certArn := convert.ToValue(cert.CertificateArn)
			if certArn == "" {
				continue
			}
			mqlCert, err := CreateResource(a.MqlRuntime, "aws.elb.listener.certificate",
				map[string]*llx.RawData{
					// The same certificate can be installed on many listeners,
					// so the key has to name the listener as well.
					"__id":      llx.StringData(listenerArn + "/certificate/" + certArn),
					"arn":       llx.StringData(certArn),
					"isDefault": llx.BoolData(convert.ToValue(cert.IsDefault)),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlCert)
		}
	}
	return res, nil
}

func (a *mqlAwsElbListenerCertificate) id() (string, error) {
	return a.__id, nil
}

// acmCertificate resolves the listener certificate to its ACM record. A
// listener can also present an IAM server certificate, which ACM does not know
// about, so those resolve to null rather than to a blank certificate.
func (a *mqlAwsElbListenerCertificate) acmCertificate() (*mqlAwsAcmCertificate, error) {
	certArn := a.Arn.Data
	if !strings.Contains(certArn, ":acm:") {
		a.AcmCertificate.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.acm.certificate",
		map[string]*llx.RawData{"arn": llx.StringData(certArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

// mqlAwsElbListenerRuleInternal and mqlAwsElbTruststoreInternal exist only to
// carry the tag cache; neither resource had per-instance state before.
type mqlAwsElbListenerRuleInternal struct {
	lazyTags
}

type mqlAwsElbTruststoreInternal struct {
	lazyTags
}

func (a *mqlAwsElbListener) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elbv2TagsForArn(a.MqlRuntime, a.Arn.Data)
	})
}

func (a *mqlAwsElbListenerRule) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elbv2TagsForArn(a.MqlRuntime, a.Arn.Data)
	})
}

func (a *mqlAwsElbTruststore) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elbv2TagsForArn(a.MqlRuntime, a.Arn.Data)
	})
}

func (a *mqlAwsElb) sslPolicies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSSLPolicies(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for _, job := range poolOfJobs.Jobs {
		if job.Result != nil {
			res = append(res, job.Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsElb) getSSLPolicies(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elbv2(region)
			ctx := context.Background()
			res := []any{}
			var marker *string
			for {
				resp, err := svc.DescribeSSLPolicies(ctx, &elasticloadbalancingv2.DescribeSSLPoliciesInput{Marker: marker})
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, p := range resp.SslPolicies {
					mqlP, err := buildElbSSLPolicyResource(a.MqlRuntime, region, p)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlP)
				}
				if resp.NextMarker == nil {
					break
				}
				marker = resp.NextMarker
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func buildElbSSLPolicyResource(runtime *plugin.Runtime, region string, p elbtypes.SslPolicy) (*mqlAwsElbSslPolicy, error) {
	ciphers := []any{}
	for _, c := range p.Ciphers {
		ciphers = append(ciphers, map[string]any{
			"Name":     convert.ToValue(c.Name),
			"Priority": int64(convert.ToValue(c.Priority)),
		})
	}
	res, err := CreateResource(runtime, "aws.elb.sslPolicy",
		map[string]*llx.RawData{
			"__id":                       llx.StringData(region + "/" + convert.ToValue(p.Name)),
			"name":                       llx.StringDataPtr(p.Name),
			"region":                     llx.StringData(region),
			"sslProtocols":               llx.ArrayData(llx.TArr2Raw(p.SslProtocols), types.String),
			"ciphers":                    llx.ArrayData(ciphers, types.Dict),
			"supportedLoadBalancerTypes": llx.ArrayData(llx.TArr2Raw(p.SupportedLoadBalancerTypes), types.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsElbSslPolicy), nil
}

func (a *mqlAwsElbSslPolicy) id() (string, error) {
	return a.Region.Data + "/" + a.Name.Data, nil
}

func (a *mqlAwsElb) trustStores() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTrustStores(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for _, job := range poolOfJobs.Jobs {
		if job.Result != nil {
			res = append(res, job.Result.([]any)...)
		}
	}
	return res, nil
}

func (a *mqlAwsElb) getTrustStores(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Elbv2(region)
			ctx := context.Background()
			res := []any{}
			paginator := elasticloadbalancingv2.NewDescribeTrustStoresPaginator(svc, &elasticloadbalancingv2.DescribeTrustStoresInput{})
			for paginator.HasMorePages() {
				resp, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, ts := range resp.TrustStores {
					mqlTs, err := buildElbTrustStoreResource(a.MqlRuntime, region, ts)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTs)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func buildElbTrustStoreResource(runtime *plugin.Runtime, region string, ts elbtypes.TrustStore) (*mqlAwsElbTruststore, error) {
	res, err := CreateResource(runtime, "aws.elb.truststore",
		map[string]*llx.RawData{
			"__id":                   llx.StringDataPtr(ts.TrustStoreArn),
			"arn":                    llx.StringDataPtr(ts.TrustStoreArn),
			"name":                   llx.StringDataPtr(ts.Name),
			"region":                 llx.StringData(region),
			"status":                 llx.StringData(string(ts.Status)),
			"numberOfCaCertificates": llx.IntDataPtr(ts.NumberOfCaCertificates),
			"totalRevokedEntries":    llx.IntDataPtr(ts.TotalRevokedEntries),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsElbTruststore), nil
}

func (a *mqlAwsElbTruststore) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElbListener) sslPolicyRef() (*mqlAwsElbSslPolicy, error) {
	name := a.SslPolicy.Data
	if name == "" {
		a.SslPolicyRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	region, err := GetRegionFromArn(a.Arn.Data)
	if err != nil {
		return nil, err
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Elbv2(region)
	ctx := context.Background()
	resp, err := svc.DescribeSSLPolicies(ctx, &elasticloadbalancingv2.DescribeSSLPoliciesInput{Names: []string{name}})
	if err != nil {
		if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
			a.SslPolicyRef.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if len(resp.SslPolicies) == 0 {
		a.SslPolicyRef.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return buildElbSSLPolicyResource(a.MqlRuntime, region, resp.SslPolicies[0])
}

func (a *mqlAwsElbListener) trustStore() (*mqlAwsElbTruststore, error) {
	return resolveElbTrustStore(a.MqlRuntime, a.Arn.Data, a.mutualAuthTrustStoreArn, &a.TrustStore.State)
}

// newMqlElbMutualAuthentication builds the listener's mutual TLS settings. A
// nil MutualAuthentication means the load balancer reports no mutual TLS
// settings for the listener at all, which is reported as null rather than as
// the off mode.
func newMqlElbMutualAuthentication(runtime *plugin.Runtime, listenerArn string, ma *elbtypes.MutualAuthenticationAttributes) (*llx.RawData, error) {
	if ma == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.elb.mutualAuthentication", map[string]*llx.RawData{
		"__id":                          llx.StringData(listenerArn + "/mutualAuthentication"),
		"mode":                          llx.StringData(convert.ToValue(ma.Mode)),
		"ignoreClientCertificateExpiry": llx.BoolData(convert.ToValue(ma.IgnoreClientCertificateExpiry)),
		"advertiseTrustStoreCaNames":    llx.StringData(string(ma.AdvertiseTrustStoreCaNames)),
		"trustStoreAssociationStatus":   llx.StringData(string(ma.TrustStoreAssociationStatus)),
	})
	if err != nil {
		return nil, err
	}
	mqlMa := res.(*mqlAwsElbMutualAuthentication)
	mqlMa.cacheListenerArn = listenerArn
	mqlMa.cacheTrustStoreArn = convert.ToValue(ma.TrustStoreArn)
	return llx.ResourceData(mqlMa, "aws.elb.mutualAuthentication"), nil
}

type mqlAwsElbMutualAuthenticationInternal struct {
	cacheListenerArn   string
	cacheTrustStoreArn string
}

func (a *mqlAwsElbMutualAuthentication) trustStore() (*mqlAwsElbTruststore, error) {
	return resolveElbTrustStore(a.MqlRuntime, a.cacheListenerArn, a.cacheTrustStoreArn, &a.TrustStore.State)
}

// resolveElbTrustStore looks up the trust store a listener verifies client
// certificates against. An empty ARN, an access-denied read, or a trust store
// that no longer exists all leave the field null: the listener names no store
// this scan can see, which is not the same as it naming one.
func resolveElbTrustStore(runtime *plugin.Runtime, listenerArn, trustStoreArn string, state *plugin.State) (*mqlAwsElbTruststore, error) {
	if trustStoreArn == "" {
		*state = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	region, err := GetRegionFromArn(listenerArn)
	if err != nil {
		return nil, err
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Elbv2(region)
	ctx := context.Background()
	resp, err := svc.DescribeTrustStores(ctx, &elasticloadbalancingv2.DescribeTrustStoresInput{TrustStoreArns: []string{trustStoreArn}})
	if err != nil {
		if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
			*state = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}
	if len(resp.TrustStores) == 0 {
		*state = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return buildElbTrustStoreResource(runtime, region, resp.TrustStores[0])
}

func (a *mqlAwsElbListener) rules() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := a.Arn.Data
	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc := conn.Elbv2(region)
	res := []any{}
	paginator := elasticloadbalancingv2.NewDescribeRulesPaginator(svc, &elasticloadbalancingv2.DescribeRulesInput{ListenerArn: &arnVal})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
				log.Warn().Str("listener", arnVal).Msg("access denied listing listener rules")
				return res, nil
			}
			return nil, err
		}
		for _, r := range resp.Rules {
			conditions, err := convert.JsonToDictSlice(r.Conditions)
			if err != nil {
				return nil, err
			}
			actions, err := convert.JsonToDictSlice(r.Actions)
			if err != nil {
				return nil, err
			}
			mqlRule, err := CreateResource(a.MqlRuntime, "aws.elb.listener.rule",
				map[string]*llx.RawData{
					"__id":       llx.StringDataPtr(r.RuleArn),
					"arn":        llx.StringDataPtr(r.RuleArn),
					"priority":   llx.StringDataPtr(r.Priority),
					"isDefault":  llx.BoolDataPtr(r.IsDefault),
					"conditions": llx.ArrayData(conditions, types.Dict),
					"actions":    llx.ArrayData(actions, types.Dict),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRule)
		}
	}
	return res, nil
}

func (a *mqlAwsElbListenerRule) id() (string, error) {
	return a.Arn.Data, nil
}

// forwardTargetGroups resolves the target groups named by the listener's default
// forward action to typed resources, matched against the parent load balancer's
// target groups. It completes the internet -> load balancer -> listener ->
// target group hop of the ingress path.
func (a *mqlAwsElbListener) forwardTargetGroups() ([]any, error) {
	// Collect the target group ARNs referenced by forward actions, both the
	// single-target shorthand and the weighted ForwardConfig form.
	wanted := map[string]struct{}{}
	for _, act := range a.defaultActionsCache {
		if act.TargetGroupArn != nil && *act.TargetGroupArn != "" {
			wanted[*act.TargetGroupArn] = struct{}{}
		}
		if act.ForwardConfig != nil {
			for _, tg := range act.ForwardConfig.TargetGroups {
				if tg.TargetGroupArn != nil && *tg.TargetGroupArn != "" {
					wanted[*tg.TargetGroupArn] = struct{}{}
				}
			}
		}
	}
	if len(wanted) == 0 {
		return []any{}, nil
	}

	lb := a.GetLoadBalancer()
	if lb.Error != nil {
		return nil, lb.Error
	}
	if lb.Data == nil {
		return []any{}, nil
	}
	tgs := lb.Data.GetTargetGroups()
	if tgs.Error != nil {
		return nil, tgs.Error
	}

	res := []any{}
	for _, t := range tgs.Data {
		tg, ok := t.(*mqlAwsElbTargetgroup)
		if !ok {
			continue
		}
		if _, found := wanted[tg.Arn.Data]; found {
			res = append(res, tg)
		}
	}
	return res, nil
}

func isV1LoadBalancerArn(a string) bool {
	arnVal, err := arn.Parse(a)
	if err != nil {
		return false
	}
	// Must be a prefix match on the synthesized classic path. A substring match
	// also caught ALB/NLB ARNs whose *name* contains "classic"
	// (loadbalancer/app/prod-classic-api/...), dispatching them to the v1 API:
	// listeners() then returned [] and enforcesTls() passed vacuously.
	return strings.HasPrefix(arnVal.Resource, "loadbalancer/classic/")
}

func elbv2TagsToMap(tags []elbtypes.Tag) map[string]any {
	return tagsToMap(tags, func(t elbtypes.Tag) *string { return t.Key }, func(t elbtypes.Tag) *string { return t.Value })
}

func elbv1TagsToMap(tags []elbv1types.Tag) map[string]any {
	return tagsToMap(tags, func(t elbv1types.Tag) *string { return t.Key }, func(t elbv1types.Tag) *string { return t.Value })
}

func (a *mqlAwsElbLoadbalancer) tags() (map[string]any, error) {
	if a.tagsFetched {
		return a.cacheTags, nil
	}
	a.tagsLock.Lock()
	defer a.tagsLock.Unlock()
	if a.tagsFetched {
		return a.cacheTags, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	lbArn := a.Arn.Data
	name := a.Name.Data

	region, err := GetRegionFromArn(lbArn)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()

	var tags map[string]any
	if isV1LoadBalancerArn(lbArn) {
		svc := conn.Elb(region)
		resp, err := svc.DescribeTags(ctx, &elasticloadbalancing.DescribeTagsInput{LoadBalancerNames: []string{name}})
		if err != nil {
			return nil, err
		}
		for _, desc := range resp.TagDescriptions {
			if convert.ToValue(desc.LoadBalancerName) == name {
				tags = elbv1TagsToMap(desc.Tags)
				break
			}
		}
	} else {
		svc := conn.Elbv2(region)
		resp, err := svc.DescribeTags(ctx, &elasticloadbalancingv2.DescribeTagsInput{ResourceArns: []string{lbArn}})
		if err != nil {
			return nil, err
		}
		for _, desc := range resp.TagDescriptions {
			if convert.ToValue(desc.ResourceArn) == lbArn {
				tags = elbv2TagsToMap(desc.Tags)
				break
			}
		}
	}
	if tags == nil {
		tags = map[string]any{}
	}

	a.cacheTags = tags
	a.tagsFetched = true
	return tags, nil
}

// elbv2TagsForArn reads the tags of one ELBv2 resource. DescribeTags accepts up
// to 20 ARNs per request, but each resource resolves only its own: tags are a
// computed field, and listing a load balancer's target groups must not pay for
// tags nobody asked for. Batching would need the ARNs of sibling resources that
// a single resource cannot see.
//
// An ARN the API returns no tag description for yields an empty map rather than
// an error, since DescribeTags omits resources that carry no tags.
func elbv2TagsForArn(runtime *plugin.Runtime, resourceArn string) (map[string]any, error) {
	region, err := GetRegionFromArn(resourceArn)
	if err != nil {
		return nil, err
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Elbv2(region)
	resp, err := svc.DescribeTags(context.Background(), &elasticloadbalancingv2.DescribeTagsInput{
		ResourceArns: []string{resourceArn},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, errTagsUnreadable
		}
		return nil, err
	}

	for _, desc := range resp.TagDescriptions {
		if convert.ToValue(desc.ResourceArn) == resourceArn {
			return elbv2TagsToMap(desc.Tags), nil
		}
	}
	return map[string]any{}, nil
}

func (a *mqlAwsElbTargetgroup) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsElbTargetgroup) tags() (map[string]any, error) {
	return a.resolveTags(&a.Tags, func() (map[string]any, error) {
		return elbv2TagsForArn(a.MqlRuntime, a.Arn.Data)
	})
}

func (a *mqlAwsElbLoadbalancer) targetGroups() ([]any, error) {
	// Classic load balancers don't have target groups
	if isV1LoadBalancerArn(a.Arn.Data) {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	regionVal := a.Region.Data
	svc := conn.Elbv2(regionVal)
	ctx := context.Background()
	res := []any{}

	params := &elasticloadbalancingv2.DescribeTargetGroupsInput{LoadBalancerArn: aws.String(a.Arn.Data)}
	paginator := elasticloadbalancingv2.NewDescribeTargetGroupsPaginator(svc, params)
	for paginator.HasMorePages() {
		tgs, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", regionVal).Msg("error accessing region for AWS API")
				return res, nil
			}
			return nil, err
		}
		for _, tg := range tgs.TargetGroups {
			args := map[string]*llx.RawData{
				"arn":                        llx.StringDataPtr(tg.TargetGroupArn),
				"name":                       llx.StringDataPtr(tg.TargetGroupName),
				"port":                       llx.IntDataPtr(tg.Port),
				"protocol":                   llx.StringData(string(tg.Protocol)),
				"protocolVersion":            llx.StringDataPtr(tg.ProtocolVersion),
				"ipAddressType":              llx.StringData(string(tg.IpAddressType)),
				"healthCheckEnabled":         llx.BoolDataPtr(tg.HealthCheckEnabled),
				"healthCheckIntervalSeconds": llx.IntDataPtr(tg.HealthCheckIntervalSeconds),
				"healthCheckPath":            llx.StringDataPtr(tg.HealthCheckPath),
				"healthCheckPort":            llx.StringDataPtr(tg.HealthCheckPort),
				"healthCheckProtocol":        llx.StringData(string(tg.HealthCheckProtocol)),
				"healthCheckTimeoutSeconds":  llx.IntDataPtr(tg.HealthCheckTimeoutSeconds),
				"targetType":                 llx.StringData(string(tg.TargetType)),
				"unhealthyThresholdCount":    llx.IntDataPtr(tg.UnhealthyThresholdCount),
				"healthyThresholdCount":      llx.IntDataPtr(tg.HealthyThresholdCount),
				"region":                     llx.StringData(regionVal),
			}

			mqlLb, err := CreateResource(a.MqlRuntime, ResourceAwsElbTargetgroup, args)
			if err != nil {
				return nil, err
			}
			mqlLb.(*mqlAwsElbTargetgroup).targetGroup = tg
			mqlLb.(*mqlAwsElbTargetgroup).region = regionVal
			res = append(res, mqlLb)
		}
	}
	return res, nil
}

type mqlAwsElbTargetgroupInternal struct {
	lazyTags
	targetGroup elbtypes.TargetGroup
	region      string
}

func (a *mqlAwsElbTargetgroup) vpc() (*mqlAwsVpc, error) {
	if a.targetGroup.VpcId == nil {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlVpc, err := NewResource(a.MqlRuntime, ResourceAwsVpc,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, conn.AccountId(), *a.targetGroup.VpcId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsElbTargetgroup) attributes() (*mqlAwsElbTargetgroupAttributes, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	tgArn := a.Arn.Data

	region := a.region
	svc := conn.Elbv2(region)
	ctx := context.Background()

	resp, err := svc.DescribeTargetGroupAttributes(ctx, &elasticloadbalancingv2.DescribeTargetGroupAttributesInput{
		TargetGroupArn: &tgArn,
	})
	if err != nil {
		return nil, err
	}

	// Build a lookup map from the key/value attributes
	attrMap := make(map[string]string)
	for _, attr := range resp.Attributes {
		if attr.Key != nil && attr.Value != nil {
			attrMap[*attr.Key] = *attr.Value
		}
	}

	args := map[string]*llx.RawData{
		"__id":                                         llx.StringData(tgArn + "/attributes"),
		"targetGroupArn":                               llx.StringData(tgArn),
		"deregistrationDelayTimeoutSeconds":            llx.IntData(attrMapInt(attrMap, "deregistration_delay.timeout_seconds")),
		"stickinessEnabled":                            llx.BoolData(attrMapBool(attrMap, "stickiness.enabled")),
		"stickinessType":                               llx.StringData(attrMap["stickiness.type"]),
		"loadBalancingAlgorithmType":                   llx.StringData(attrMap["load_balancing.algorithm.type"]),
		"loadBalancingAlgorithmAnomalyMitigation":      llx.StringData(attrMap["load_balancing.algorithm.anomaly_mitigation"]),
		"slowStartDurationSeconds":                     llx.IntData(attrMapInt(attrMap, "slow_start.duration_seconds")),
		"crossZoneEnabled":                             llx.StringData(attrMap["load_balancing.cross_zone.enabled"]),
		"proxyProtocolV2Enabled":                       llx.BoolData(attrMapBool(attrMap, "proxy_protocol_v2.enabled")),
		"preserveClientIpEnabled":                      llx.BoolData(attrMapBool(attrMap, "preserve_client_ip.enabled")),
		"connectionTerminationOnDeregistrationEnabled": llx.BoolData(attrMapBool(attrMap, "deregistration_delay.connection_termination.enabled")),
		"connectionTerminationOnUnhealthyEnabled":      llx.BoolData(attrMapBool(attrMap, "target_health_state.unhealthy.connection_termination.enabled")),
		"lambdaMultiValueHeadersEnabled":               llx.BoolData(attrMapBool(attrMap, "lambda.multi_value_headers.enabled")),
		"targetFailoverOnDeregistration":               llx.StringData(attrMap["target_failover.on_deregistration"]),
		"targetFailoverOnUnhealthy":                    llx.StringData(attrMap["target_failover.on_unhealthy"]),
	}

	res, err := CreateResource(a.MqlRuntime, ResourceAwsElbTargetgroupAttributes, args)
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsElbTargetgroupAttributes), nil
}

func (a *mqlAwsElbTargetgroupAttributes) id() (string, error) {
	return a.TargetGroupArn.Data + "/attributes", nil
}

// attrMapBool parses a string value from the attribute map as a boolean.
func attrMapBool(m map[string]string, key string) bool {
	return m[key] == "true"
}

// attrMapInt parses a string value from the attribute map as an integer.
// Returns 0 if the key is missing or the value is not a valid integer.
func attrMapInt(m map[string]string, key string) int64 {
	v, ok := m[key]
	if !ok {
		return 0
	}
	var i int64
	if _, err := fmt.Sscanf(v, "%d", &i); err != nil {
		return 0
	}
	return i
}

func (a *mqlAwsElbLoadbalancerAttribute) id() (string, error) {
	return a.LoadBalancerArn.Data + "/attributes", nil
}

func (a *mqlAwsElbLoadbalancer) attribute() (*mqlAwsElbLoadbalancerAttribute, error) {
	arnVal := a.Arn.Data

	if isV1LoadBalancerArn(arnVal) {
		a.Attribute.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	attrs, err := a.fetchV2Attrs()
	if err != nil {
		return nil, err
	}

	attrMap := make(map[string]string)
	for _, attr := range attrs {
		if attr.Key != nil && attr.Value != nil {
			attrMap[*attr.Key] = *attr.Value
		}
	}

	args := map[string]*llx.RawData{
		"__id":                      llx.StringData(arnVal + "/attributes"),
		"loadBalancerArn":           llx.StringData(arnVal),
		"deletionProtectionEnabled": llx.BoolData(attrMapBool(attrMap, "deletion_protection.enabled")),
		"crossZoneEnabled":          llx.StringData(attrMap["load_balancing.cross_zone.enabled"]),
		"accessLogsEnabled":         llx.BoolData(attrMapBool(attrMap, "access_logs.s3.enabled")),
		"accessLogsBucket":          llx.StringData(attrMap["access_logs.s3.bucket"]),
		"accessLogsPrefix":          llx.StringData(attrMap["access_logs.s3.prefix"]),
		"idleTimeoutSeconds":        llx.IntData(attrMapInt(attrMap, "idle_timeout.timeout_seconds")),
		"desyncMitigationMode":      llx.StringData(attrMap["routing.http.desync_mitigation_mode"]),
		"dropInvalidHeaderFields":   llx.BoolData(attrMapBool(attrMap, "routing.http.drop_invalid_header_fields.enabled")),
		"preserveHostHeader":        llx.BoolData(attrMapBool(attrMap, "routing.http.preserve_host_header.enabled")),
		"http2Enabled":              llx.BoolData(attrMapBool(attrMap, "routing.http2.enabled")),
		"wafFailOpenEnabled":        llx.BoolData(attrMapBool(attrMap, "waf.fail_open.enabled")),
		"zonalShiftEnabled":         llx.BoolData(attrMapBool(attrMap, "zonal_shift.config.enabled")),
		"connectionLogsEnabled":     llx.BoolData(attrMapBool(attrMap, "connection_logs.s3.enabled")),
		"connectionLogsBucket":      llx.StringData(attrMap["connection_logs.s3.bucket"]),
	}

	resource, err := CreateResource(a.MqlRuntime, "aws.elb.loadbalancer.attribute", args)
	if err != nil {
		return nil, err
	}
	return resource.(*mqlAwsElbLoadbalancerAttribute), nil
}

func (a *mqlAwsElbLoadbalancer) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnVal := a.Arn.Data

	if !isV1LoadBalancerArn(arnVal) {
		// ALB/NLB/GLB don't have direct instances; use target groups instead
		return []any{}, nil
	}

	region, err := GetRegionFromArn(arnVal)
	if err != nil {
		return nil, err
	}

	name := a.Name.Data
	svc := conn.Elb(region)
	ctx := context.Background()

	resp, err := svc.DescribeLoadBalancers(ctx, &elasticloadbalancing.DescribeLoadBalancersInput{
		LoadBalancerNames: []string{name},
	})
	if err != nil {
		return nil, err
	}

	res := []any{}
	if len(resp.LoadBalancerDescriptions) == 0 {
		return res, nil
	}

	for _, inst := range resp.LoadBalancerDescriptions[0].Instances {
		if inst.InstanceId == nil {
			continue
		}
		mqlInst, err := NewResource(a.MqlRuntime, ResourceAwsEc2Instance,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(ec2InstanceArnPattern, region, conn.AccountId(), *inst.InstanceId)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInst)
	}
	return res, nil
}

func (a *mqlAwsElbTargetgroup) ec2Targets() ([]any, error) {
	// Only instance-type target groups register EC2 instances; ip and lambda
	// target groups resolve to other resource kinds, so there is nothing to do.
	if a.targetGroup.TargetType != "" && a.targetGroup.TargetType != elbtypes.TargetTypeEnumInstance {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	region := a.region
	svc := conn.Elbv2(region)
	ctx := context.Background()

	resp, err := svc.DescribeTargetHealth(ctx, &elasticloadbalancingv2.DescribeTargetHealthInput{
		TargetGroupArn: aws.String(a.Arn.Data),
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for _, desc := range resp.TargetHealthDescriptions {
		if desc.Target == nil || desc.Target.Id == nil {
			continue
		}
		// instance-type targets register the instance ID (i-...); ip-type
		// targets register an IP address, which is not an EC2 instance.
		instanceID := *desc.Target.Id
		if !strings.HasPrefix(instanceID, "i-") {
			continue
		}
		mqlInst, err := NewResource(a.MqlRuntime, ResourceAwsEc2Instance,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(ec2InstanceArnPattern, region, conn.AccountId(), instanceID)),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlInst)
	}
	return res, nil
}

func (a *mqlAwsElbTargetgroup) lambdaTargets() ([]any, error) {
	// Only lambda-type target groups register Lambda functions.
	if a.targetGroup.TargetType != elbtypes.TargetTypeEnumLambda {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Elbv2(a.region)
	resp, err := svc.DescribeTargetHealth(context.Background(), &elasticloadbalancingv2.DescribeTargetHealthInput{
		TargetGroupArn: aws.String(a.Arn.Data),
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for _, desc := range resp.TargetHealthDescriptions {
		if desc.Target == nil || desc.Target.Id == nil {
			continue
		}
		// lambda-type targets register the function ARN as the target id.
		mqlFn, err := NewResource(a.MqlRuntime, ResourceAwsLambdaFunction,
			map[string]*llx.RawData{"arn": llx.StringData(*desc.Target.Id)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlFn)
	}
	return res, nil
}

// ipTargets returns the IP addresses registered with an ip-type target group.
// These backends (containers, Kubernetes pods, on-premises hosts) are not EC2
// instances, so they do not appear in ec2Targets.
func (a *mqlAwsElbTargetgroup) ipTargets() ([]any, error) {
	if a.targetGroup.TargetType != elbtypes.TargetTypeEnumIp {
		return []any{}, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Elbv2(a.region)
	resp, err := svc.DescribeTargetHealth(context.Background(), &elasticloadbalancingv2.DescribeTargetHealthInput{
		TargetGroupArn: aws.String(a.Arn.Data),
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := []any{}
	for _, desc := range resp.TargetHealthDescriptions {
		if desc.Target == nil || desc.Target.Id == nil {
			continue
		}
		res = append(res, *desc.Target.Id)
	}
	return res, nil
}

// enforcesTls reports whether every listener terminates an encrypted protocol —
// HTTPS or TLS on an ALB/NLB, SSL on a classic load balancer. Any other
// protocol counts as plaintext, including GENEVE and a listener whose protocol
// could not be read, so an unrecognized listener never reads as secure. It reads
// listenerDescriptions, which covers both classic ELBs (where the protocol is
// nested under "Listener") and ALB/NLB load balancers (top-level "Protocol"), so
// a classic HTTP load balancer is not missed. A load balancer with no listeners
// vacuously enforces TLS (nothing accepts plaintext).
func (a *mqlAwsElbLoadbalancer) enforcesTls() (bool, error) {
	descriptions := a.GetListenerDescriptions()
	if descriptions.Error != nil {
		return false, descriptions.Error
	}
	for _, d := range descriptions.Data {
		desc, ok := d.(map[string]any)
		if !ok {
			continue
		}
		if listenerProtocolIsPlaintext(listenerDescriptionProtocol(desc)) {
			return false, nil
		}
	}
	return true, nil
}
