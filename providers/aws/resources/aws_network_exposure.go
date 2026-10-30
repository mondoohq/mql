// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws/arn"
	elasticache_types "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

// openIngressRulesFromSecurityGroups returns the ingress rules across the given
// security groups that permit inbound traffic from the internet.
func openIngressRulesFromSecurityGroups(sgs *plugin.TValue[[]any]) ([]any, error) {
	if sgs == nil {
		return []any{}, nil
	}
	if sgs.Error != nil {
		return nil, sgs.Error
	}
	rules := []any{}
	for _, s := range sgs.Data {
		sg, ok := s.(*mqlAwsEc2Securitygroup)
		if !ok {
			continue
		}
		perms := sg.GetIpPermissions()
		if perms.Error != nil {
			return nil, perms.Error
		}
		for _, p := range perms.Data {
			perm, ok := p.(*mqlAwsEc2SecuritygroupIppermission)
			if !ok {
				continue
			}
			public := perm.GetIncludesPublicSource()
			if public.Error != nil {
				return nil, public.Error
			}
			if public.Data {
				rules = append(rules, perm)
			}
		}
	}
	return rules, nil
}

// securityGroupCount reports how many security groups are attached, and is used
// to tell "no security group opens this" apart from "security groups do not
// constrain this resource at all".
func securityGroupCount(sgs *plugin.TValue[[]any]) int {
	if sgs == nil {
		return 0
	}
	return len(sgs.Data)
}

// knownPublicAccess carries a public-access verdict a caller derived itself --
// from a load balancer scheme, a task network configuration, or the absence of
// any public endpoint at all -- rather than reading it off a resource field.
// The value is known, so it is never null.
func knownPublicAccess(publiclyAccessible bool) *plugin.TValue[bool] {
	return &plugin.TValue[bool]{Data: publiclyAccessible, State: plugin.StateIsSet}
}

// publicAccessIsUnknown reports whether a resource's public-access toggle was
// never read: the field does not exist for this resource shape (Aurora clusters
// do not carry PubliclyAccessible) or the call that would have answered it was
// denied.
func publicAccessIsUnknown(publiclyAccessible *plugin.TValue[bool]) bool {
	return publiclyAccessible == nil || publiclyAccessible.State&plugin.StateIsNull != 0
}

// buildNetworkExposure creates a shared aws.network.exposure from a resource's
// public-access toggle and its attached security groups.
//
// internetReachable requires the resource to be publicly accessible, and -- when
// security groups apply to it -- for one of them to open it. When no security
// group is attached, security groups are not what stands between the resource
// and the internet, so publiclyAccessible alone decides.
//
// That distinction matters most for load balancers: Network Load Balancers only
// support security groups when one was attached at creation (they cannot be
// added later) and Gateway Load Balancers never support them, so most NLBs
// report an empty list. Requiring sgAllows there made every internet-facing NLB
// -- including one with a world-open listener -- report internetReachable:false.
// It is also the safe direction when the group list could not be enumerated.
//
// A null public-access toggle stays null on the exposure, for both
// publiclyAccessible and internetReachable. Reading false out of a value nobody
// ever read would report the resource as shielded from the internet on evidence
// that does not exist, which silently passes an audit.
func buildNetworkExposure(runtime *plugin.Runtime, id string, publiclyAccessible *plugin.TValue[bool], sgs *plugin.TValue[[]any]) (*mqlAwsNetworkExposure, error) {
	openRules, err := openIngressRulesFromSecurityGroups(sgs)
	if err != nil {
		return nil, err
	}
	sgAllows := len(openRules) > 0
	sgsApply := securityGroupCount(sgs) > 0

	publiclyAccessibleData := llx.NilData
	internetReachableData := llx.NilData
	if !publicAccessIsUnknown(publiclyAccessible) {
		internetReachable := publiclyAccessible.Data
		if sgsApply {
			internetReachable = publiclyAccessible.Data && sgAllows
		}
		publiclyAccessibleData = llx.BoolData(publiclyAccessible.Data)
		internetReachableData = llx.BoolData(internetReachable)
	}

	res, err := CreateResource(runtime, "aws.network.exposure", map[string]*llx.RawData{
		"__id":                       llx.StringData(id),
		"internetReachable":          internetReachableData,
		"publiclyAccessible":         publiclyAccessibleData,
		"securityGroupAllowsIngress": llx.BoolData(sgAllows),
		"openIngressRules":           llx.ArrayData(openRules, types.Resource("aws.ec2.securitygroup.ippermission")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsNetworkExposure), nil
}

// buildNetworkExposureFromGroups is buildNetworkExposure for callers holding
// already-resolved security groups rather than a lazily-fetched field.
func buildNetworkExposureFromGroups(runtime *plugin.Runtime, id string, publiclyAccessible *plugin.TValue[bool], sgs []any) (*mqlAwsNetworkExposure, error) {
	return buildNetworkExposure(runtime, id, publiclyAccessible, &plugin.TValue[[]any]{
		Data:  sgs,
		State: plugin.StateIsSet,
	})
}

func (a *mqlAwsRdsDbinstance) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, a.GetSecurityGroups())
}

func (a *mqlAwsDocumentdbInstance) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, a.GetSecurityGroups())
}

func (a *mqlAwsElbLoadbalancer) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	scheme := a.GetScheme()
	if scheme.Error != nil {
		return nil, scheme.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", knownPublicAccess(scheme.Data == "internet-facing"), a.GetSecurityGroups())
}

func (a *mqlAwsRdsDbcluster) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, a.GetSecurityGroups())
}

func (a *mqlAwsRedshiftCluster) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, a.GetSecurityGroups())
}

func (a *mqlAwsMqBroker) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, a.GetSecurityGroups())
}

func (a *mqlAwsDmsReplicationInstance) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, a.GetSecurityGroups())
}

func (a *mqlAwsMskCluster) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publicAccess := a.GetPublicAccess()
	if publicAccess.Error != nil {
		return nil, publicAccess.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publicAccess, a.GetSecurityGroups())
}

// buildVpcOnlyExposure builds a network exposure for a service that has no
// public endpoint (it is only reachable inside its VPC). publiclyAccessible and
// internetReachable are therefore always false; the value is in surfacing any
// attached security group that opens the resource to a public source.
func buildVpcOnlyExposure(a interface {
	GetArn() *plugin.TValue[string]
	GetSecurityGroups() *plugin.TValue[[]any]
}, runtime *plugin.Runtime) (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	return buildNetworkExposure(runtime, arn.Data+"/exposure", knownPublicAccess(false), a.GetSecurityGroups())
}

func (a *mqlAwsDocumentdbCluster) exposure() (*mqlAwsNetworkExposure, error) {
	return buildVpcOnlyExposure(a, a.MqlRuntime)
}

// exposure reports the internet exposure of the cluster's Kubernetes API server
// endpoint. publicAccessCidrs can narrow a public endpoint to specific source
// ranges; it is left on the cluster rather than folded in here, so a caller sees
// both the verdict and the allow-list.
func (a *mqlAwsEksCluster) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publicAccess := a.GetEndpointPublicAccess()
	if publicAccess.Error != nil {
		return nil, publicAccess.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publicAccess, a.GetClusterSecurityGroups())
}

// exposure reports the internet exposure of tasks the service runs.
//
// Only awsvpc networking carries a public-IP assignment and task-level security
// groups. A service using host or bridge networking has neither, and its
// reachability is decided by the container instance, so exposure is null rather
// than a verdict about the wrong thing.
func (a *mqlAwsEcsService) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}

	netConfig := a.GetNetworkConfiguration()
	if netConfig.Error != nil {
		return nil, netConfig.Error
	}
	if netConfig.Data == nil {
		a.Exposure.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	vpcConfig := netConfig.Data.GetAwsVpcConfiguration()
	if vpcConfig.Error != nil {
		return nil, vpcConfig.Error
	}
	if vpcConfig.Data == nil {
		a.Exposure.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	assignPublicIp := vpcConfig.Data.GetAssignPublicIp()
	if assignPublicIp.Error != nil {
		return nil, assignPublicIp.Error
	}
	sgIds := vpcConfig.Data.GetSecurityGroups()
	if sgIds.Error != nil {
		return nil, sgIds.Error
	}

	sgs, err := resolveSecurityGroupsByIdInArnScope(a.MqlRuntime, arn.Data, sgIds.Data)
	if err != nil {
		return nil, err
	}
	return buildNetworkExposureFromGroups(a.MqlRuntime, arn.Data+"/exposure",
		knownPublicAccess(strings.EqualFold(assignPublicIp.Data, "ENABLED")), sgs)
}

// resolveSecurityGroupsByIdInArnScope turns bare security group IDs into typed
// resources, taking the region and account from a sibling ARN. Services that
// store group IDs rather than ARNs have no other way to name the scope.
func resolveSecurityGroupsByIdInArnScope(runtime *plugin.Runtime, scopeArn string, sgIds []any) ([]any, error) {
	parsed, err := arn.Parse(scopeArn)
	if err != nil {
		return nil, err
	}
	handler := securityGroupIdHandler{}
	arns := make([]string, 0, len(sgIds))
	for _, raw := range sgIds {
		sgId, ok := raw.(string)
		if !ok || sgId == "" {
			continue
		}
		arns = append(arns, fmt.Sprintf(securityGroupArnPattern, parsed.Region, parsed.AccountID, sgId))
	}
	handler.setSecurityGroupArns(arns)
	return handler.newSecurityGroupResources(runtime)
}

// exposure reports the internet exposure of the App Runner service endpoint.
// App Runner does not gate inbound traffic with security groups, so the
// public-accessibility setting alone decides.
func (a *mqlAwsApprunnerService) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	publiclyAccessible := a.GetIsPubliclyAccessible()
	if publiclyAccessible.Error != nil {
		return nil, publiclyAccessible.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publiclyAccessible, nil)
}

// exposure reports the internet exposure of the notebook instance. Both inputs
// live on the details sub-resource, which is a separate API call, so this is the
// one exposure accessor that can cost a fetch.
func (a *mqlAwsSagemakerNotebookinstance) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	details := a.GetDetails()
	if details.Error != nil {
		return nil, details.Error
	}
	if details.Data == nil {
		a.Exposure.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	directInternetAccess := details.Data.GetDirectInternetAccess()
	if directInternetAccess.Error != nil {
		return nil, directInternetAccess.Error
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure",
		directInternetAccess, details.Data.GetSecurityGroups())
}

func (a *mqlAwsElasticacheCluster) exposure() (*mqlAwsNetworkExposure, error) {
	return buildVpcOnlyExposure(a, a.MqlRuntime)
}

// serverlessCacheExposureInputs decides the public-access toggle for a
// serverless cache from its connectionType, and whether its security groups
// stand between the cache and the internet.
//
// A public cache is reached over the internet directly; its security groups
// only authorize traffic to the VPC endpoint, so they are not consulted. A vpc
// cache, and one that reports no connection type (ElastiCache's default is
// vpc), is reachable only through its VPC endpoint. A value this SDK does not
// know leaves public access unknown rather than guessing.
func serverlessCacheExposureInputs(connectionType string) (publicAccess *plugin.TValue[bool], securityGroupsApply bool) {
	switch elasticache_types.ConnectionType(connectionType) {
	case elasticache_types.ConnectionTypePublic:
		return knownPublicAccess(true), false
	case elasticache_types.ConnectionTypeVpc, "":
		return knownPublicAccess(false), true
	default:
		return &plugin.TValue[bool]{State: plugin.StateIsSet | plugin.StateIsNull}, true
	}
}

func (a *mqlAwsElasticacheServerlessCache) exposure() (*mqlAwsNetworkExposure, error) {
	arn := a.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}
	connectionType := a.GetConnectionType()
	if connectionType.Error != nil {
		return nil, connectionType.Error
	}
	publicAccess, securityGroupsApply := serverlessCacheExposureInputs(connectionType.Data)
	var sgs *plugin.TValue[[]any]
	if securityGroupsApply {
		sgs = a.GetSecurityGroups()
	}
	return buildNetworkExposure(a.MqlRuntime, arn.Data+"/exposure", publicAccess, sgs)
}

func (a *mqlAwsMemorydbCluster) exposure() (*mqlAwsNetworkExposure, error) {
	return buildVpcOnlyExposure(a, a.MqlRuntime)
}

func (a *mqlAwsNeptuneCluster) exposure() (*mqlAwsNetworkExposure, error) {
	return buildVpcOnlyExposure(a, a.MqlRuntime)
}
