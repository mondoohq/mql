// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"strings"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// cloudFrontAliasHostedZoneID is the fixed hosted zone AWS assigns to every
// CloudFront distribution alias target, so an alias record pointing at a
// distribution always carries this value in aliasTargetHostedZoneId.
const cloudFrontAliasHostedZoneID = "Z2FDTNDATAQYW2"

// normalizeAliasDNSName canonicalizes a Route 53 alias target DNS name for
// comparison against a resource's own DNS name: it lowercases, drops the
// trailing dot of the fully qualified name, and strips the "dualstack." prefix
// that Route 53 prepends to load balancer alias targets.
func normalizeAliasDNSName(name string) string {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	return strings.TrimPrefix(n, "dualstack.")
}

// aliasLoadBalancer resolves the load balancer an A/AAAA alias record points to
// by matching the alias target DNS name against the load balancer DNS-name index
// on the (runtime-cached) aws.elb list resource.
func (a *mqlAwsRoute53Record) aliasLoadBalancer() (*mqlAwsElbLoadbalancer, error) {
	target := normalizeAliasDNSName(a.AliasTargetDnsName.Data)
	if target == "" {
		a.AliasLoadBalancer.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	obj, err := CreateResource(a.MqlRuntime, ResourceAwsElb, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	lb, err := obj.(*mqlAwsElb).loadBalancerByDNSName(target)
	if err != nil {
		return nil, err
	}
	if lb == nil {
		a.AliasLoadBalancer.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return lb, nil
}

// aliasCloudFrontDistribution resolves the CloudFront distribution an A/AAAA
// alias record points to. A distribution alias always uses the fixed CloudFront
// hosted zone, so records with any other alias zone short-circuit to null.
func (a *mqlAwsRoute53Record) aliasCloudFrontDistribution() (*mqlAwsCloudfrontDistribution, error) {
	if a.AliasTargetHostedZoneId.Data != cloudFrontAliasHostedZoneID {
		a.AliasCloudFrontDistribution.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	target := normalizeAliasDNSName(a.AliasTargetDnsName.Data)
	if target == "" {
		a.AliasCloudFrontDistribution.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	obj, err := CreateResource(a.MqlRuntime, ResourceAwsCloudfront, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	dist, err := obj.(*mqlAwsCloudfront).distributionByDomainName(target)
	if err != nil {
		return nil, err
	}
	if dist == nil {
		a.AliasCloudFrontDistribution.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return dist, nil
}
