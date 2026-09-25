// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"sync"

	"golang.org/x/sync/errgroup"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/networkfirewall"
	nftypes "github.com/aws/aws-sdk-go-v2/service/networkfirewall/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
)

func (a *mqlAwsNetworkfirewall) id() (string, error) {
	return "aws.networkfirewall", nil
}

func (a *mqlAwsNetworkfirewall) firewalls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getFirewalls(conn), 5)
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

func (a *mqlAwsNetworkfirewall) getFirewalls(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.NetworkFirewall(region)
			ctx := context.Background()

			res := []any{}
			paginator := networkfirewall.NewListFirewallsPaginator(svc, &networkfirewall.ListFirewallsInput{})
			var fwArns []*string
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, fw := range page.Firewalls {
					if fw.FirewallArn != nil {
						fwArns = append(fwArns, fw.FirewallArn)
					}
				}
			}

			details := make([]*networkfirewall.DescribeFirewallOutput, len(fwArns))
			g, gctx := errgroup.WithContext(ctx)
			g.SetLimit(10)
			for i, arn := range fwArns {
				g.Go(func() error {
					resp, err := svc.DescribeFirewall(gctx, &networkfirewall.DescribeFirewallInput{FirewallArn: arn})
					if err != nil {
						if Is400AccessDeniedError(err) {
							return nil
						}
						return err
					}
					details[i] = resp
					return nil
				})
			}
			if err := g.Wait(); err != nil {
				return nil, err
			}

			for _, detail := range details {
				if detail == nil || detail.Firewall == nil {
					continue
				}
				f := detail.Firewall
				subnetMappings := make([]any, 0, len(f.SubnetMappings))
				subnetIds := make([]string, 0, len(f.SubnetMappings))
				for _, sm := range f.SubnetMappings {
					d, err := convert.JsonToDict(sm)
					if err != nil {
						log.Warn().Err(err).Msg("failed to convert subnet mapping")
						continue
					}
					subnetMappings = append(subnetMappings, d)
					if sm.SubnetId != nil {
						subnetIds = append(subnetIds, *sm.SubnetId)
					}
				}
				var encryptionType string
				var kmsKeyId *string
				if f.EncryptionConfiguration != nil {
					encryptionType = string(f.EncryptionConfiguration.Type)
					kmsKeyId = f.EncryptionConfiguration.KeyId
				}
				tags := nfTagsToMap(f.Tags)

				proxyListeners := []any{}
				if f.ProxySettings != nil {
					for _, lp := range f.ProxySettings.ListenerProperties {
						d, derr := convert.JsonToDict(lp)
						if derr != nil {
							log.Warn().Err(derr).Msg("failed to convert proxy listener property")
							continue
						}
						proxyListeners = append(proxyListeners, d)
					}
				}
				natGatewayIds := make([]string, 0, len(f.NatGatewayMappings))
				for _, ngm := range f.NatGatewayMappings {
					if ngm.NatGatewayId != nil {
						natGatewayIds = append(natGatewayIds, *ngm.NatGatewayId)
					}
				}

				mqlFirewall, err := CreateResource(a.MqlRuntime, "aws.networkfirewall.firewall",
					map[string]*llx.RawData{
						"arn":                            llx.StringDataPtr(f.FirewallArn),
						"name":                           llx.StringDataPtr(f.FirewallName),
						"description":                    llx.StringDataPtr(f.Description),
						"region":                         llx.StringData(region),
						"deleteProtection":               llx.BoolData(f.DeleteProtection),
						"subnetChangeProtection":         llx.BoolData(f.SubnetChangeProtection),
						"firewallPolicyChangeProtection": llx.BoolData(f.FirewallPolicyChangeProtection),
						"firewallPolicyArn":              llx.StringDataPtr(f.FirewallPolicyArn),
						"subnetMappings":                 llx.ArrayData(subnetMappings, "dict"),
						"encryptionType":                 llx.StringData(encryptionType),
						"noSourcePreservation":           llx.BoolData(f.NoSourcePreservation),
						"proxyListeners":                 llx.ArrayData(proxyListeners, "dict"),
						"tags":                           llx.MapData(tags, "string"),
					})
				if err != nil {
					return nil, err
				}
				mqlFw := mqlFirewall.(*mqlAwsNetworkfirewallFirewall)
				mqlFw.cacheVpcId = f.VpcId
				mqlFw.cacheSubnetIds = subnetIds
				mqlFw.cacheKmsKeyId = kmsKeyId
				mqlFw.cacheStatusVal = detail.FirewallStatus
				mqlFw.cacheNatGatewayIds = natGatewayIds
				res = append(res, mqlFirewall)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsNetworkfirewallFirewallInternal struct {
	cacheVpcId         *string
	cacheSubnetIds     []string
	cacheKmsKeyId      *string
	cacheNatGatewayIds []string
	cacheStatusVal     *nftypes.FirewallStatus
	cacheLogConfig     *nftypes.LoggingConfiguration
	cacheLogFetched    bool
	cacheLogLock       sync.Mutex
}

type mqlAwsNetworkfirewallPolicyInternal struct {
	cacheStatelessRuleGroupArns []string
	cacheStatefulRuleGroupArns  []string
	cacheKmsKeyId               *string
}

type mqlAwsNetworkfirewallRulegroupInternal struct {
	cacheKmsKeyId *string
	cacheSnsTopic *string
}

func (a *mqlAwsNetworkfirewallFirewall) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func (a *mqlAwsNetworkfirewallFirewall) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcArn := fmt.Sprintf(vpcArnPattern, a.Region.Data, conn.AccountId(), *a.cacheVpcId)
	mqlVpc, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsNetworkfirewallFirewall) natGateways() ([]any, error) {
	res := []any{}
	for _, natGatewayId := range a.cacheNatGatewayIds {
		if natGatewayId == "" {
			continue
		}
		// The NAT gateway id does not encode a region, so the init needs the
		// firewall's region alongside it to run a targeted lookup.
		mqlNat, err := NewResource(a.MqlRuntime, "aws.vpc.natgateway",
			map[string]*llx.RawData{
				"natGatewayId": llx.StringData(natGatewayId),
				"region":       llx.StringData(a.Region.Data),
			})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlNat)
	}
	return res, nil
}

func (a *mqlAwsNetworkfirewallFirewall) subnets() ([]any, error) {
	res := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		if subnetId == "" {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, "aws.vpc.subnet",
			map[string]*llx.RawData{"id": llx.StringData(subnetId)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlSubnet)
	}
	return res, nil
}

func (a *mqlAwsNetworkfirewallFirewall) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsNetworkfirewallFirewall) status() (string, error) {
	if a.cacheStatusVal == nil {
		return "", nil
	}
	return string(a.cacheStatusVal.Status), nil
}

func (a *mqlAwsNetworkfirewallFirewall) configurationSyncStateSummary() (string, error) {
	if a.cacheStatusVal == nil {
		return "", nil
	}
	return string(a.cacheStatusVal.ConfigurationSyncStateSummary), nil
}

func (a *mqlAwsNetworkfirewallFirewall) syncStates() ([]any, error) {
	res := []any{}
	if a.cacheStatusVal == nil {
		return res, nil
	}
	for az, ss := range a.cacheStatusVal.SyncStates {
		entry := map[string]any{
			"availabilityZone": az,
		}
		if ss.Attachment != nil {
			if ss.Attachment.SubnetId != nil {
				entry["subnetId"] = *ss.Attachment.SubnetId
			}
			if ss.Attachment.EndpointId != nil {
				entry["endpointId"] = *ss.Attachment.EndpointId
			}
			entry["status"] = string(ss.Attachment.Status)
			if ss.Attachment.StatusMessage != nil {
				entry["statusMessage"] = *ss.Attachment.StatusMessage
			}
		}
		if len(ss.Config) > 0 {
			cfg := make(map[string]any, len(ss.Config))
			for k, v := range ss.Config {
				cfgEntry := map[string]any{
					"syncStatus": string(v.SyncStatus),
				}
				if v.UpdateToken != nil {
					cfgEntry["updateToken"] = *v.UpdateToken
				}
				cfg[k] = cfgEntry
			}
			entry["config"] = cfg
		}
		res = append(res, entry)
	}
	return res, nil
}

func (a *mqlAwsNetworkfirewallFirewall) loggingDestinations() ([]any, error) {
	res := []any{}
	logCfg, err := a.fetchLoggingConfig()
	if err != nil {
		return nil, err
	}
	if logCfg == nil {
		return res, nil
	}
	for _, ld := range logCfg.LogDestinationConfigs {
		entry := map[string]any{
			"logDestinationType": string(ld.LogDestinationType),
			"logType":            string(ld.LogType),
		}
		if len(ld.LogDestination) > 0 {
			dest := make(map[string]any, len(ld.LogDestination))
			for k, v := range ld.LogDestination {
				dest[k] = v
			}
			entry["logDestination"] = dest
		}
		res = append(res, entry)
	}
	return res, nil
}

func (a *mqlAwsNetworkfirewallFirewall) loggingConfiguration() (any, error) {
	logCfg, err := a.fetchLoggingConfig()
	if err != nil {
		return nil, err
	}
	if logCfg == nil {
		return nil, nil
	}
	cfgs := make([]any, 0, len(logCfg.LogDestinationConfigs))
	for _, ld := range logCfg.LogDestinationConfigs {
		entry := map[string]any{
			"logDestinationType": string(ld.LogDestinationType),
			"logType":            string(ld.LogType),
		}
		if len(ld.LogDestination) > 0 {
			dest := make(map[string]any, len(ld.LogDestination))
			for k, v := range ld.LogDestination {
				dest[k] = v
			}
			entry["logDestination"] = dest
		}
		cfgs = append(cfgs, entry)
	}
	return map[string]any{
		"logDestinationConfigs": cfgs,
	}, nil
}

func (a *mqlAwsNetworkfirewallFirewall) fetchLoggingConfig() (*nftypes.LoggingConfiguration, error) {
	if a.cacheLogFetched {
		return a.cacheLogConfig, nil
	}
	a.cacheLogLock.Lock()
	defer a.cacheLogLock.Unlock()
	if a.cacheLogFetched {
		return a.cacheLogConfig, nil
	}
	if a.Arn.Error != nil {
		return nil, a.Arn.Error
	}
	arn := a.Arn.Data
	if arn == "" {
		a.cacheLogFetched = true
		return nil, nil
	}
	if a.Region.Error != nil {
		return nil, a.Region.Error
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.NetworkFirewall(a.Region.Data)
	ctx := context.Background()
	resp, err := svc.DescribeLoggingConfiguration(ctx, &networkfirewall.DescribeLoggingConfigurationInput{
		FirewallArn: &arn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "network-firewall:DescribeLoggingConfiguration")
	}
	a.cacheLogConfig = resp.LoggingConfiguration
	a.cacheLogFetched = true
	return a.cacheLogConfig, nil
}

func (a *mqlAwsNetworkfirewallFirewall) policy() (*mqlAwsNetworkfirewallPolicy, error) {
	if a.FirewallPolicyArn.Error != nil {
		return nil, a.FirewallPolicyArn.Error
	}
	policyArn := a.FirewallPolicyArn.Data
	if policyArn == "" {
		a.Policy.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	if a.Region.Error != nil {
		return nil, a.Region.Error
	}
	region := a.Region.Data
	svc := conn.NetworkFirewall(region)
	ctx := context.Background()

	resp, err := svc.DescribeFirewallPolicy(ctx, &networkfirewall.DescribeFirewallPolicyInput{
		FirewallPolicyArn: &policyArn,
	})
	if err != nil {
		return nil, err
	}

	return networkfirewallPolicyToMql(a.MqlRuntime, resp.FirewallPolicyResponse, resp.FirewallPolicy, region)
}

func (a *mqlAwsNetworkfirewall) policies() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getPolicies(conn), 5)
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

func (a *mqlAwsNetworkfirewall) getPolicies(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.NetworkFirewall(region)
			ctx := context.Background()

			res := []any{}
			paginator := networkfirewall.NewListFirewallPoliciesPaginator(svc, &networkfirewall.ListFirewallPoliciesInput{})
			var policyArns []*string
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, pm := range page.FirewallPolicies {
					if pm.Arn != nil {
						policyArns = append(policyArns, pm.Arn)
					}
				}
			}

			details := make([]*networkfirewall.DescribeFirewallPolicyOutput, len(policyArns))
			g, gctx := errgroup.WithContext(ctx)
			g.SetLimit(10)
			for i, arn := range policyArns {
				g.Go(func() error {
					resp, err := svc.DescribeFirewallPolicy(gctx, &networkfirewall.DescribeFirewallPolicyInput{FirewallPolicyArn: arn})
					if err != nil {
						if Is400AccessDeniedError(err) {
							return nil
						}
						return err
					}
					details[i] = resp
					return nil
				})
			}
			if err := g.Wait(); err != nil {
				return nil, err
			}

			for _, detail := range details {
				if detail == nil {
					continue
				}
				mqlPolicy, err := networkfirewallPolicyToMql(a.MqlRuntime, detail.FirewallPolicyResponse, detail.FirewallPolicy, region)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlPolicy)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func networkfirewallPolicyToMql(runtime *plugin.Runtime, policyResp *nftypes.FirewallPolicyResponse, policy *nftypes.FirewallPolicy, region string) (*mqlAwsNetworkfirewallPolicy, error) {
	statelessRuleGroupRefs, err := convert.JsonToDictSlice(policy.StatelessRuleGroupReferences)
	if err != nil {
		log.Warn().Err(err).Msg("failed to convert stateless rule group references")
	}
	statefulRuleGroupRefs, err := convert.JsonToDictSlice(policy.StatefulRuleGroupReferences)
	if err != nil {
		log.Warn().Err(err).Msg("failed to convert stateful rule group references")
	}
	statelessCustomActions, err := convert.JsonToDictSlice(policy.StatelessCustomActions)
	if err != nil {
		log.Warn().Err(err).Msg("failed to convert stateless custom actions")
	}
	var statefulEngineOpts any
	var statefulEngineRuleOrder string
	var streamExceptionPolicy string
	if policy.StatefulEngineOptions != nil {
		var optErr error
		statefulEngineOpts, optErr = convert.JsonToDict(policy.StatefulEngineOptions)
		if optErr != nil {
			log.Warn().Err(optErr).Msg("failed to convert stateful engine options")
		}
		statefulEngineRuleOrder = string(policy.StatefulEngineOptions.RuleOrder)
		streamExceptionPolicy = string(policy.StatefulEngineOptions.StreamExceptionPolicy)
	}
	policyVariables := []any{}
	if policy.PolicyVariables != nil && len(policy.PolicyVariables.RuleVariables) > 0 {
		for name, ipSet := range policy.PolicyVariables.RuleVariables {
			entry := map[string]any{
				"name":       name,
				"definition": llx.TArr2Raw(ipSet.Definition),
			}
			policyVariables = append(policyVariables, entry)
		}
	}
	tags := nfTagsToMap(policyResp.Tags)

	var consumedStatefulDomain int64
	if policyResp.ConsumedStatefulDomainCapacity != nil {
		consumedStatefulDomain = int64(*policyResp.ConsumedStatefulDomainCapacity)
	}
	var consumedStatelessRule int64
	if policyResp.ConsumedStatelessRuleCapacity != nil {
		consumedStatelessRule = int64(*policyResp.ConsumedStatelessRuleCapacity)
	}
	var consumedStatefulRule int64
	if policyResp.ConsumedStatefulRuleCapacity != nil {
		consumedStatefulRule = int64(*policyResp.ConsumedStatefulRuleCapacity)
	}
	var numberOfAssociations int64
	if policyResp.NumberOfAssociations != nil {
		numberOfAssociations = int64(*policyResp.NumberOfAssociations)
	}

	statelessArns := make([]string, 0, len(policy.StatelessRuleGroupReferences))
	for _, ref := range policy.StatelessRuleGroupReferences {
		if ref.ResourceArn != nil {
			statelessArns = append(statelessArns, *ref.ResourceArn)
		}
	}
	statefulArns := make([]string, 0, len(policy.StatefulRuleGroupReferences))
	for _, ref := range policy.StatefulRuleGroupReferences {
		if ref.ResourceArn != nil {
			statefulArns = append(statefulArns, *ref.ResourceArn)
		}
	}

	var encryptionType string
	var kmsKeyId *string
	if policyResp.EncryptionConfiguration != nil {
		encryptionType = string(policyResp.EncryptionConfiguration.Type)
		kmsKeyId = policyResp.EncryptionConfiguration.KeyId
	}

	mqlPolicy, err := CreateResource(runtime, "aws.networkfirewall.policy",
		map[string]*llx.RawData{
			"arn":                                 llx.StringDataPtr(policyResp.FirewallPolicyArn),
			"firewallPolicyId":                    llx.StringDataPtr(policyResp.FirewallPolicyId),
			"name":                                llx.StringDataPtr(policyResp.FirewallPolicyName),
			"description":                         llx.StringDataPtr(policyResp.Description),
			"region":                              llx.StringData(region),
			"firewallPolicyStatus":                llx.StringData(string(policyResp.FirewallPolicyStatus)),
			"numberOfAssociations":                llx.IntData(numberOfAssociations),
			"consumedStatelessRuleCapacity":       llx.IntData(consumedStatelessRule),
			"consumedStatefulRuleCapacity":        llx.IntData(consumedStatefulRule),
			"lastModifiedTime":                    llx.TimeDataPtr(policyResp.LastModifiedTime),
			"statelessDefaultActions":             llx.ArrayData(llx.TArr2Raw(policy.StatelessDefaultActions), "string"),
			"statelessFragmentDefaultActions":     llx.ArrayData(llx.TArr2Raw(policy.StatelessFragmentDefaultActions), "string"),
			"statelessCustomActions":              llx.ArrayData(statelessCustomActions, "dict"),
			"statelessRuleGroupReferences":        llx.ArrayData(statelessRuleGroupRefs, "dict"),
			"statefulDefaultActions":              llx.ArrayData(llx.TArr2Raw(policy.StatefulDefaultActions), "string"),
			"statefulRuleGroupReferences":         llx.ArrayData(statefulRuleGroupRefs, "dict"),
			"statefulEngineOptions":               llx.DictData(statefulEngineOpts),
			"statefulEngineRuleOrder":             llx.StringData(statefulEngineRuleOrder),
			"statefulEngineStreamExceptionPolicy": llx.StringData(streamExceptionPolicy),
			"policyVariables":                     llx.ArrayData(policyVariables, "dict"),
			"tlsInspectionConfigurationArn":       llx.StringDataPtr(policy.TLSInspectionConfigurationArn),
			"consumedStatefulDomainCapacity":      llx.IntData(consumedStatefulDomain),
			"encryptionType":                      llx.StringData(encryptionType),
			"tags":                                llx.MapData(tags, "string"),
		})
	if err != nil {
		return nil, err
	}
	mp := mqlPolicy.(*mqlAwsNetworkfirewallPolicy)
	mp.cacheStatelessRuleGroupArns = statelessArns
	mp.cacheStatefulRuleGroupArns = statefulArns
	mp.cacheKmsKeyId = kmsKeyId
	return mp, nil
}

func (a *mqlAwsNetworkfirewallPolicy) statelessRuleGroups() ([]any, error) {
	return ruleGroupsFromArns(a.MqlRuntime, a.cacheStatelessRuleGroupArns)
}

func (a *mqlAwsNetworkfirewallPolicy) statefulRuleGroups() ([]any, error) {
	return ruleGroupsFromArns(a.MqlRuntime, a.cacheStatefulRuleGroupArns)
}

func (a *mqlAwsNetworkfirewallPolicy) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsNetworkfirewallPolicy) tlsInspectionConfiguration() (*mqlAwsNetworkfirewallTlsInspectionConfiguration, error) {
	if a.TlsInspectionConfigurationArn.Error != nil {
		return nil, a.TlsInspectionConfigurationArn.Error
	}
	tlsArn := a.TlsInspectionConfigurationArn.Data
	if tlsArn == "" {
		a.TlsInspectionConfiguration.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	if a.Region.Error != nil {
		return nil, a.Region.Error
	}
	region := a.Region.Data

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.NetworkFirewall(region)
	ctx := context.Background()
	resp, err := svc.DescribeTLSInspectionConfiguration(ctx, &networkfirewall.DescribeTLSInspectionConfigurationInput{
		TLSInspectionConfigurationArn: &tlsArn,
	})
	if err != nil {
		return nil, classifyAwsError(err, "network-firewall:DescribeTLSInspectionConfiguration")
	}
	return networkfirewallTLSInspectionConfigToMql(a.MqlRuntime, resp.TLSInspectionConfigurationResponse, resp.TLSInspectionConfiguration, region)
}

func ruleGroupsFromArns(runtime *plugin.Runtime, arns []string) ([]any, error) {
	res := []any{}
	for _, arn := range arns {
		if arn == "" {
			continue
		}
		mqlRG, err := NewResource(runtime, "aws.networkfirewall.rulegroup",
			map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRG)
	}
	return res, nil
}

func (a *mqlAwsNetworkfirewallPolicy) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func (a *mqlAwsNetworkfirewall) ruleGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getRuleGroups(conn), 5)
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

func (a *mqlAwsNetworkfirewall) getRuleGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.NetworkFirewall(region)
			ctx := context.Background()

			res := []any{}
			paginator := networkfirewall.NewListRuleGroupsPaginator(svc, &networkfirewall.ListRuleGroupsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, rg := range page.RuleGroups {
					detail, err := svc.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{
						RuleGroupArn: rg.Arn,
					})
					if err != nil {
						if Is400AccessDeniedError(err) {
							continue
						}
						return nil, err
					}
					mqlRuleGroup, err := networkfirewallRuleGroupToMql(a.MqlRuntime, detail.RuleGroupResponse, detail.RuleGroup, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlRuleGroup)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsNetworkfirewallRulegroup) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func (a *mqlAwsNetworkfirewallRulegroup) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func initAwsNetworkfirewallRulegroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args["arn"] == nil {
		return args, nil, nil
	}
	arnValue, ok := args["arn"].Value.(string)
	if !ok || arnValue == "" {
		return args, nil, nil
	}
	parsed, err := arn.Parse(arnValue)
	if err != nil {
		return args, nil, nil
	}
	region := parsed.Region
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.NetworkFirewall(region)
	ctx := context.Background()
	resp, err := svc.DescribeRuleGroup(ctx, &networkfirewall.DescribeRuleGroupInput{
		RuleGroupArn: &arnValue,
	})
	if err != nil {
		return nil, nil, classifyAwsError(fmt.Errorf("fetching aws.networkfirewall.rulegroup with arn %q: %w", arnValue, err), "network-firewall:DescribeRuleGroup")
	}
	mqlRG, err := networkfirewallRuleGroupToMql(runtime, resp.RuleGroupResponse, resp.RuleGroup, region)
	if err != nil {
		return nil, nil, err
	}
	return args, mqlRG, nil
}

func networkfirewallRuleGroupToMql(runtime *plugin.Runtime, resp *nftypes.RuleGroupResponse, ruleGroup *nftypes.RuleGroup, region string) (*mqlAwsNetworkfirewallRulegroup, error) {
	var rules any
	var rulesString string
	var statefulRuleOrder string
	referenceSets := []any{}
	ruleVariables := []any{}
	if ruleGroup != nil {
		var rulesErr error
		rules, rulesErr = convert.JsonToDict(ruleGroup)
		if rulesErr != nil {
			log.Warn().Err(rulesErr).Msg("failed to convert rule group")
		}
		if ruleGroup.RulesSource != nil && ruleGroup.RulesSource.RulesString != nil {
			rulesString = *ruleGroup.RulesSource.RulesString
		}
		if ruleGroup.StatefulRuleOptions != nil {
			statefulRuleOrder = string(ruleGroup.StatefulRuleOptions.RuleOrder)
		}
		if ruleGroup.ReferenceSets != nil && len(ruleGroup.ReferenceSets.IPSetReferences) > 0 {
			for name, ref := range ruleGroup.ReferenceSets.IPSetReferences {
				entry := map[string]any{"name": name}
				if ref.ReferenceArn != nil {
					entry["referenceArn"] = *ref.ReferenceArn
				}
				referenceSets = append(referenceSets, entry)
			}
		}
		if ruleGroup.RuleVariables != nil {
			for name, ipSet := range ruleGroup.RuleVariables.IPSets {
				ruleVariables = append(ruleVariables, map[string]any{
					"name":       name,
					"kind":       "ipSet",
					"definition": llx.TArr2Raw(ipSet.Definition),
				})
			}
			for name, portSet := range ruleGroup.RuleVariables.PortSets {
				ruleVariables = append(ruleVariables, map[string]any{
					"name":       name,
					"kind":       "portSet",
					"definition": llx.TArr2Raw(portSet.Definition),
				})
			}
		}
	}

	sourceMetadata := []any{}
	if resp.SourceMetadata != nil {
		entry := map[string]any{}
		if resp.SourceMetadata.SourceArn != nil {
			entry["sourceArn"] = *resp.SourceMetadata.SourceArn
		}
		if resp.SourceMetadata.SourceUpdateToken != nil {
			entry["sourceUpdateToken"] = *resp.SourceMetadata.SourceUpdateToken
		}
		if len(entry) > 0 {
			sourceMetadata = append(sourceMetadata, entry)
		}
	}

	var encryptionType string
	var kmsKeyId *string
	if resp.EncryptionConfiguration != nil {
		encryptionType = string(resp.EncryptionConfiguration.Type)
		kmsKeyId = resp.EncryptionConfiguration.KeyId
	}

	tags := nfTagsToMap(resp.Tags)

	var consumedCapacity int64
	if resp.ConsumedCapacity != nil {
		consumedCapacity = int64(*resp.ConsumedCapacity)
	}
	var numberOfAssociations int64
	if resp.NumberOfAssociations != nil {
		numberOfAssociations = int64(*resp.NumberOfAssociations)
	}

	mqlRG, err := CreateResource(runtime, "aws.networkfirewall.rulegroup",
		map[string]*llx.RawData{
			"arn":                  llx.StringDataPtr(resp.RuleGroupArn),
			"ruleGroupId":          llx.StringDataPtr(resp.RuleGroupId),
			"name":                 llx.StringDataPtr(resp.RuleGroupName),
			"description":          llx.StringDataPtr(resp.Description),
			"region":               llx.StringData(region),
			"lastModifiedTime":     llx.TimeDataPtr(resp.LastModifiedTime),
			"capacity":             llx.IntDataDefault(resp.Capacity, 0),
			"consumedCapacity":     llx.IntData(consumedCapacity),
			"numberOfAssociations": llx.IntData(numberOfAssociations),
			"type":                 llx.StringData(string(resp.Type)),
			"ruleGroupStatus":      llx.StringData(string(resp.RuleGroupStatus)),
			"rules":                llx.DictData(rules),
			"rulesString":          llx.StringData(rulesString),
			"referenceSets":        llx.ArrayData(referenceSets, "dict"),
			"ruleVariables":        llx.ArrayData(ruleVariables, "dict"),
			"statefulRuleOrder":    llx.StringData(statefulRuleOrder),
			"sourceMetadata":       llx.ArrayData(sourceMetadata, "dict"),
			"encryptionType":       llx.StringData(encryptionType),
			"tags":                 llx.MapData(tags, "string"),
		})
	if err != nil {
		return nil, err
	}
	mrg := mqlRG.(*mqlAwsNetworkfirewallRulegroup)
	mrg.cacheKmsKeyId = kmsKeyId
	mrg.cacheSnsTopic = resp.SnsTopic
	return mrg, nil
}

func (a *mqlAwsNetworkfirewallRulegroup) snsTopic() (*mqlAwsSnsTopic, error) {
	if a.cacheSnsTopic == nil || *a.cacheSnsTopic == "" {
		a.SnsTopic.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlTopic, err := NewResource(a.MqlRuntime, "aws.sns.topic",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheSnsTopic)})
	if err != nil {
		return nil, err
	}
	return mqlTopic.(*mqlAwsSnsTopic), nil
}

func nfTagsToMap(tags []nftypes.Tag) map[string]any {
	return tagsToMap(tags, func(t nftypes.Tag) *string { return t.Key }, func(t nftypes.Tag) *string { return t.Value })
}

type mqlAwsNetworkfirewallTlsInspectionConfigurationInternal struct {
	cacheKmsKeyId          *string
	cacheCertAuthorityArns []string
}

func (a *mqlAwsNetworkfirewallTlsInspectionConfiguration) id() (string, error) {
	return a.Arn.Data, a.Arn.Error
}

func (a *mqlAwsNetworkfirewallTlsInspectionConfiguration) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, "aws.kms.key",
		map[string]*llx.RawData{"arn": llx.StringDataPtr(a.cacheKmsKeyId)})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsNetworkfirewallTlsInspectionConfiguration) certificateAuthorities() ([]any, error) {
	res := make([]any, 0, len(a.cacheCertAuthorityArns))
	for _, arn := range a.cacheCertAuthorityArns {
		if arn == "" {
			continue
		}
		arnVal := arn
		mqlCert, err := NewResource(a.MqlRuntime, "aws.acm.certificate",
			map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCert.(*mqlAwsAcmCertificate))
	}
	return res, nil
}

func (a *mqlAwsNetworkfirewall) tlsInspectionConfigurations() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTLSInspectionConfigurations(conn), 5)
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

func (a *mqlAwsNetworkfirewall) getTLSInspectionConfigurations(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.NetworkFirewall(region)
			ctx := context.Background()

			res := []any{}
			paginator := networkfirewall.NewListTLSInspectionConfigurationsPaginator(svc, &networkfirewall.ListTLSInspectionConfigurationsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, tlsMeta := range page.TLSInspectionConfigurations {
					detail, err := svc.DescribeTLSInspectionConfiguration(ctx, &networkfirewall.DescribeTLSInspectionConfigurationInput{
						TLSInspectionConfigurationArn: tlsMeta.Arn,
					})
					if err != nil {
						if Is400AccessDeniedError(err) {
							continue
						}
						return nil, err
					}
					mqlTLS, err := networkfirewallTLSInspectionConfigToMql(a.MqlRuntime, detail.TLSInspectionConfigurationResponse, detail.TLSInspectionConfiguration, region)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTLS)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func networkfirewallTLSInspectionConfigToMql(runtime *plugin.Runtime, resp *nftypes.TLSInspectionConfigurationResponse, tlsConfig *nftypes.TLSInspectionConfiguration, region string) (*mqlAwsNetworkfirewallTlsInspectionConfiguration, error) {
	serverCertConfigs := []any{}
	scopes := []any{}
	caArns := []string{}
	if tlsConfig != nil {
		for _, scc := range tlsConfig.ServerCertificateConfigurations {
			d, err := convert.JsonToDict(scc)
			if err != nil {
				log.Warn().Err(err).Msg("failed to convert server certificate configuration")
			} else {
				serverCertConfigs = append(serverCertConfigs, d)
			}
			if scc.CertificateAuthorityArn != nil && *scc.CertificateAuthorityArn != "" {
				caArns = append(caArns, *scc.CertificateAuthorityArn)
			}
			for _, scope := range scc.Scopes {
				sd, sErr := convert.JsonToDict(scope)
				if sErr != nil {
					log.Warn().Err(sErr).Msg("failed to convert tls inspection scope")
					continue
				}
				scopes = append(scopes, sd)
			}
		}
	}

	var encryptionType string
	var kmsKeyId *string
	if resp.EncryptionConfiguration != nil {
		encryptionType = string(resp.EncryptionConfiguration.Type)
		kmsKeyId = resp.EncryptionConfiguration.KeyId
	}

	var numberOfAssociations int64
	if resp.NumberOfAssociations != nil {
		numberOfAssociations = int64(*resp.NumberOfAssociations)
	}

	caArnsAny := make([]any, 0, len(caArns))
	for _, a := range caArns {
		caArnsAny = append(caArnsAny, a)
	}

	tags := nfTagsToMap(resp.Tags)

	mqlTLS, err := CreateResource(runtime, "aws.networkfirewall.tlsInspectionConfiguration",
		map[string]*llx.RawData{
			"arn":                             llx.StringDataPtr(resp.TLSInspectionConfigurationArn),
			"tlsInspectionConfigurationId":    llx.StringDataPtr(resp.TLSInspectionConfigurationId),
			"name":                            llx.StringDataPtr(resp.TLSInspectionConfigurationName),
			"description":                     llx.StringDataPtr(resp.Description),
			"region":                          llx.StringData(region),
			"status":                          llx.StringData(string(resp.TLSInspectionConfigurationStatus)),
			"numberOfAssociations":            llx.IntData(numberOfAssociations),
			"lastModifiedTime":                llx.TimeDataPtr(resp.LastModifiedTime),
			"serverCertificateConfigurations": llx.ArrayData(serverCertConfigs, "dict"),
			"scopes":                          llx.ArrayData(scopes, "dict"),
			"certificateAuthorityArns":        llx.ArrayData(caArnsAny, "string"),
			"encryptionType":                  llx.StringData(encryptionType),
			"tags":                            llx.MapData(tags, "string"),
		})
	if err != nil {
		return nil, err
	}
	mt := mqlTLS.(*mqlAwsNetworkfirewallTlsInspectionConfiguration)
	mt.cacheKmsKeyId = kmsKeyId
	mt.cacheCertAuthorityArns = caArns
	return mt, nil
}
