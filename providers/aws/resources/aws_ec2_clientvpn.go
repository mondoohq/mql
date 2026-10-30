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

	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/smithy-go"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

const clientVpnEndpointArnPattern = "arn:aws:ec2:%s:%s:client-vpn-endpoint/%s"

func parseTimeOrZero(s *string) time.Time {
	if s == nil || *s == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, *s)
	if err != nil {
		// Try alternate format
		t, err = time.Parse("2006-01-02T15:04:05", *s)
		if err != nil {
			return time.Time{}
		}
	}
	return t
}

func (a *mqlAwsEc2ClientVpnEndpoint) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsEc2ClientVpnEndpointInternal struct {
	cacheServerCertificateArn string
	securityGroupIdHandler
	cacheVpcId            *string
	cacheTransitGatewayId *string
	region                string
	accountID             string

	authzPolicyLock    sync.Mutex
	authzPolicyFetched bool
	authzPolicy        *clientVpnAuthorizationPolicy
}

func (a *mqlAwsEc2) clientVpnEndpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getClientVpnEndpoints(conn), 5)
	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEc2) getClientVpnEndpoints(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ec2.NewDescribeClientVpnEndpointsPaginator(svc, &ec2.DescribeClientVpnEndpointsInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, ep := range page.ClientVpnEndpoints {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(ep.Tags)) {
						continue
					}

					var status string
					if ep.Status != nil {
						status = string(ep.Status.Code)
					}

					var dnsServers []any
					for _, dns := range ep.DnsServers {
						dnsServers = append(dnsServers, dns)
					}

					endpointID := convert.ToValue(ep.ClientVpnEndpointId)
					mqlConnectionLogging, err := newMqlClientVpnConnectionLogOptions(a.MqlRuntime, endpointID, region, conn.AccountId(), ep.ConnectionLogOptions)
					if err != nil {
						return nil, err
					}
					mqlLoginBanner, err := newMqlClientVpnLoginBannerOptions(a.MqlRuntime, endpointID, ep.ClientLoginBannerOptions)
					if err != nil {
						return nil, err
					}
					mqlClientConnect, err := newMqlClientVpnConnectOptions(a.MqlRuntime, endpointID, ep.ClientConnectOptions)
					if err != nil {
						return nil, err
					}

					clientConnectOpts, _ := convert.JsonToDict(ep.ClientConnectOptions)
					clientBannerOpts, _ := convert.JsonToDict(ep.ClientLoginBannerOptions)
					connectionLogOpts, _ := convert.JsonToDict(ep.ConnectionLogOptions)
					authOpts, _ := convert.JsonToDictSlice(ep.AuthenticationOptions)

					var vpnPort int64
					if ep.VpnPort != nil {
						vpnPort = int64(*ep.VpnPort)
					}
					var sessionTimeout int64
					if ep.SessionTimeoutHours != nil {
						sessionTimeout = int64(*ep.SessionTimeoutHours)
					}

					tgwAZs := []any{}
					var tgwIdPtr *string
					if ep.TransitGatewayConfiguration != nil {
						tgwIdPtr = ep.TransitGatewayConfiguration.TransitGatewayId
						for _, az := range ep.TransitGatewayConfiguration.AvailabilityZones {
							tgwAZs = append(tgwAZs, az)
						}
					}

					mqlEp, err := CreateResource(a.MqlRuntime, ResourceAwsEc2ClientVpnEndpoint,
						map[string]*llx.RawData{
							"id":                              llx.StringData(convert.ToValue(ep.ClientVpnEndpointId)),
							"arn":                             llx.StringData(fmt.Sprintf(clientVpnEndpointArnPattern, region, conn.AccountId(), convert.ToValue(ep.ClientVpnEndpointId))),
							"region":                          llx.StringData(region),
							"description":                     llx.StringData(convert.ToValue(ep.Description)),
							"status":                          llx.StringData(status),
							"createdAt":                       llx.TimeData(parseTimeOrZero(ep.CreationTime)),
							"transportProtocol":               llx.StringData(string(ep.TransportProtocol)),
							"vpnProtocol":                     llx.StringData(string(ep.VpnProtocol)),
							"splitTunnel":                     llx.BoolData(convert.ToValue(ep.SplitTunnel)),
							"vpnPort":                         llx.IntData(vpnPort),
							"selfServicePortalUrl":            llx.StringData(convert.ToValue(ep.SelfServicePortalUrl)),
							"dnsServers":                      llx.ArrayData(dnsServers, types.String),
							"sessionTimeoutHours":             llx.IntData(sessionTimeout),
							"clientConnectOptions":            llx.DictData(clientConnectOpts),
							"clientLoginBannerOptions":        llx.DictData(clientBannerOpts),
							"connectionLogOptions":            llx.DictData(connectionLogOpts),
							"connectionLogging":               mqlConnectionLogging,
							"loginBanner":                     mqlLoginBanner,
							"clientConnect":                   mqlClientConnect,
							"authenticationOptions":           llx.ArrayData(authOpts, types.Any),
							"transitGatewayAvailabilityZones": llx.ArrayData(tgwAZs, types.String),
							"deviceTrustProviders":            llx.ArrayData(clientVpnDeviceTrustProviders(ep.DevicePostureOptions), types.Dict),
							"tags":                            llx.MapData(toInterfaceMap(ec2TagsToMap(ep.Tags)), types.String),
						})
					if err != nil {
						return nil, err
					}
					mqlEp.(*mqlAwsEc2ClientVpnEndpoint).cacheServerCertificateArn = convert.ToValue(ep.ServerCertificateArn)

					mqlCvpn := mqlEp.(*mqlAwsEc2ClientVpnEndpoint)
					mqlCvpn.cacheVpcId = ep.VpcId
					mqlCvpn.cacheTransitGatewayId = tgwIdPtr
					mqlCvpn.region = region
					mqlCvpn.accountID = conn.AccountId()

					// Cache security group ARNs
					sgArns := make([]string, len(ep.SecurityGroupIds))
					for i, sgId := range ep.SecurityGroupIds {
						sgArns[i] = fmt.Sprintf(securityGroupArnPattern, region, conn.AccountId(), sgId)
					}
					mqlCvpn.setSecurityGroupArns(sgArns)

					res = append(res, mqlEp)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// newMqlClientVpnConnectionLogOptions builds the endpoint's connection logging
// configuration. A nil ConnectionLogOptions means EC2 reports no connection
// log options at all, which is reported as null rather than as logging being
// off.
func newMqlClientVpnConnectionLogOptions(runtime *plugin.Runtime, endpointID, region, accountID string, opts *ec2types.ConnectionLogResponseOptions) (*llx.RawData, error) {
	if opts == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.ec2.clientVpnConnectionLogOptions", map[string]*llx.RawData{
		"__id":                              llx.StringData(endpointID + "/connectionLogOptions"),
		"enabled":                           llx.BoolData(convert.ToValue(opts.Enabled)),
		"cloudWatchLogStream":               llx.StringData(convert.ToValue(opts.CloudwatchLogStream)),
		"includeAuthorizationPolicyContext": llx.BoolDataPtr(opts.IncludeAuthorizationPolicyContext),
	})
	if err != nil {
		return nil, err
	}
	mqlOpts := res.(*mqlAwsEc2ClientVpnConnectionLogOptions)
	mqlOpts.cacheLogGroupName = convert.ToValue(opts.CloudwatchLogGroup)
	mqlOpts.region = region
	mqlOpts.accountID = accountID
	return llx.ResourceData(mqlOpts, "aws.ec2.clientVpnConnectionLogOptions"), nil
}

type mqlAwsEc2ClientVpnConnectionLogOptionsInternal struct {
	cacheLogGroupName string
	region            string
	accountID         string
}

func (a *mqlAwsEc2ClientVpnConnectionLogOptions) cloudWatchLogGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.cacheLogGroupName == "" {
		a.CloudWatchLogGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	// EC2 reports the log group by name; the log group init only accepts an
	// ARN, so build one from the endpoint's own region and account.
	res, err := NewResource(a.MqlRuntime, "aws.cloudwatch.loggroup", map[string]*llx.RawData{
		"arn": llx.StringData(fmt.Sprintf(logGroupArnPattern, a.region, a.accountID, a.cacheLogGroupName)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsCloudwatchLoggroup), nil
}

// newMqlClientVpnLoginBannerOptions builds the endpoint's login banner. A nil
// ClientLoginBannerOptions means EC2 reports no banner options at all.
func newMqlClientVpnLoginBannerOptions(runtime *plugin.Runtime, endpointID string, opts *ec2types.ClientLoginBannerResponseOptions) (*llx.RawData, error) {
	if opts == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.ec2.clientVpnLoginBannerOptions", map[string]*llx.RawData{
		"__id":       llx.StringData(endpointID + "/clientLoginBannerOptions"),
		"enabled":    llx.BoolData(convert.ToValue(opts.Enabled)),
		"bannerText": llx.StringData(convert.ToValue(opts.BannerText)),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "aws.ec2.clientVpnLoginBannerOptions"), nil
}

// newMqlClientVpnConnectOptions builds the endpoint's client connect handling.
// A nil ClientConnectOptions means EC2 reports no client connect options at
// all.
func newMqlClientVpnConnectOptions(runtime *plugin.Runtime, endpointID string, opts *ec2types.ClientConnectResponseOptions) (*llx.RawData, error) {
	if opts == nil {
		return llx.NilData, nil
	}
	statusCode, statusMessage := "", ""
	if opts.Status != nil {
		statusCode = string(opts.Status.Code)
		statusMessage = convert.ToValue(opts.Status.Message)
	}
	res, err := CreateResource(runtime, "aws.ec2.clientVpnConnectOptions", map[string]*llx.RawData{
		"__id":          llx.StringData(endpointID + "/clientConnectOptions"),
		"enabled":       llx.BoolData(convert.ToValue(opts.Enabled)),
		"statusCode":    llx.StringData(statusCode),
		"statusMessage": llx.StringData(statusMessage),
	})
	if err != nil {
		return nil, err
	}
	mqlOpts := res.(*mqlAwsEc2ClientVpnConnectOptions)
	mqlOpts.cacheLambdaFunctionArn = convert.ToValue(opts.LambdaFunctionArn)
	return llx.ResourceData(mqlOpts, "aws.ec2.clientVpnConnectOptions"), nil
}

type mqlAwsEc2ClientVpnConnectOptionsInternal struct {
	cacheLambdaFunctionArn string
}

func (a *mqlAwsEc2ClientVpnConnectOptions) lambdaFunction() (*mqlAwsLambdaFunction, error) {
	if a.cacheLambdaFunctionArn == "" {
		a.LambdaFunction.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.lambda.function", map[string]*llx.RawData{
		"arn": llx.StringData(a.cacheLambdaFunctionArn),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsLambdaFunction), nil
}

func (a *mqlAwsEc2ClientVpnEndpoint) securityGroups() ([]any, error) {
	return a.securityGroupIdHandler.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsEc2ClientVpnEndpoint) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == nil || *a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlVpc, err := NewResource(a.MqlRuntime, ResourceAwsVpc,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, a.accountID, *a.cacheVpcId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsEc2ClientVpnEndpoint) serverCertificate() (*mqlAwsAcmCertificate, error) {
	arnVal := a.cacheServerCertificateArn
	if arnVal == "" {
		a.ServerCertificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

func (a *mqlAwsEc2ClientVpnEndpoint) transitGateway() (*mqlAwsEc2Transitgateway, error) {
	if a.cacheTransitGatewayId == nil || *a.cacheTransitGatewayId == "" {
		a.TransitGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	tgwArn := fmt.Sprintf(transitGatewayArnPattern, a.region, a.accountID, *a.cacheTransitGatewayId)
	mqlTgw, err := NewResource(a.MqlRuntime, ResourceAwsEc2Transitgateway,
		map[string]*llx.RawData{"arn": llx.StringData(tgwArn)})
	if err != nil {
		return nil, err
	}
	return mqlTgw.(*mqlAwsEc2Transitgateway), nil
}

// clientVpnDeviceTrustProviders flattens the endpoint's device trust providers.
// A nil DevicePostureOptions means the endpoint has no device posture
// evaluation configured, which is reported as an empty list: the describe call
// succeeded and says there are none.
func clientVpnDeviceTrustProviders(opts *ec2types.DevicePostureResponseOptions) []any {
	res := []any{}
	if opts == nil {
		return res
	}
	for _, p := range opts.TrustProviders {
		res = append(res, map[string]any{
			"trustProviderType":   string(p.TrustProviderType),
			"tenantId":            convert.ToValue(p.TenantId),
			"publicSigningKeyUrl": convert.ToValue(p.PublicSigningKeyUrl),
		})
	}
	return res
}

// clientVpnAuthorizationPolicy is the part of an endpoint's Cedar
// authorization policy the schema exposes.
type clientVpnAuthorizationPolicy struct {
	document string
	status   string
	// inShadowMode is nil when EC2 reports no shadow mode or a value this
	// provider does not know.
	inShadowMode *bool
}

// newClientVpnAuthorizationPolicy converts the GetClientVpnEndpointAuthorizationPolicy
// answer. It returns nil when the answer carries neither a policy document nor
// a status, which is how an endpoint without an authorization policy reads.
func newClientVpnAuthorizationPolicy(out *ec2.GetClientVpnEndpointAuthorizationPolicyOutput) *clientVpnAuthorizationPolicy {
	if out == nil || (convert.ToValue(out.PolicyDocument) == "" && out.Status == "") {
		return nil
	}
	return &clientVpnAuthorizationPolicy{
		document:     convert.ToValue(out.PolicyDocument),
		status:       string(out.Status),
		inShadowMode: clientVpnShadowModeEnabled(out.ShadowMode),
	}
}

// clientVpnShadowModeEnabled maps the two-state shadow mode enum to a bool.
// An empty or unknown value is nil rather than a guess.
func clientVpnShadowModeEnabled(mode ec2types.ClientVpnAuthorizationPolicyShadowMode) *bool {
	var v bool
	switch mode {
	case ec2types.ClientVpnAuthorizationPolicyShadowModeEnabled:
		v = true
	case ec2types.ClientVpnAuthorizationPolicyShadowModeDisabled:
		v = false
	default:
		return nil
	}
	return &v
}

// isClientVpnAuthorizationPolicyNotFound reports the error EC2 answers with
// when the endpoint has no authorization policy. The error code is not
// documented, so this matches any NotFound code that names the authorization
// policy. InvalidClientVpnEndpointId.NotFound (the endpoint itself is gone) is
// deliberately not matched: that leaves the policy unknown, it does not
// establish that there is none.
func isClientVpnAuthorizationPolicyNotFound(err error) bool {
	var apiErr smithy.APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	code := apiErr.ErrorCode()
	return strings.Contains(code, "AuthorizationPolicy") && strings.Contains(code, "NotFound")
}

// fetchAuthorizationPolicy loads the endpoint's authorization policy once and
// shares it between the authorizationPolicy* fields. A nil policy with a nil
// error means the endpoint has no authorization policy.
func (a *mqlAwsEc2ClientVpnEndpoint) fetchAuthorizationPolicy() (*clientVpnAuthorizationPolicy, error) {
	a.authzPolicyLock.Lock()
	defer a.authzPolicyLock.Unlock()
	if a.authzPolicyFetched {
		return a.authzPolicy, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	endpointID := a.Id.Data
	out, err := svc.GetClientVpnEndpointAuthorizationPolicy(context.Background(), &ec2.GetClientVpnEndpointAuthorizationPolicyInput{
		ClientVpnEndpointId: &endpointID,
	})
	if err != nil {
		if isClientVpnAuthorizationPolicyNotFound(err) {
			a.authzPolicyFetched = true
			return nil, nil
		}
		if Is400AccessDeniedError(err) {
			if !plugin.StructuredErrors() {
				a.authzPolicyFetched = true
				return nil, nil
			}
			return nil, llx.Forbidden(err, llx.WithPermissions("ec2:GetClientVpnEndpointAuthorizationPolicy"))
		}
		return nil, err
	}
	a.authzPolicy = newClientVpnAuthorizationPolicy(out)
	a.authzPolicyFetched = true
	return a.authzPolicy, nil
}

func (a *mqlAwsEc2ClientVpnEndpoint) authorizationPolicyDocument() (string, error) {
	policy, err := a.fetchAuthorizationPolicy()
	if err != nil {
		return "", err
	}
	if policy == nil {
		a.AuthorizationPolicyDocument.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return policy.document, nil
}

func (a *mqlAwsEc2ClientVpnEndpoint) authorizationPolicyStatus() (string, error) {
	policy, err := a.fetchAuthorizationPolicy()
	if err != nil {
		return "", err
	}
	if policy == nil || policy.status == "" {
		a.AuthorizationPolicyStatus.State = plugin.StateIsSet | plugin.StateIsNull
		return "", nil
	}
	return policy.status, nil
}

func (a *mqlAwsEc2ClientVpnEndpoint) authorizationPolicyInShadowMode() (bool, error) {
	policy, err := a.fetchAuthorizationPolicy()
	if err != nil {
		return false, err
	}
	if policy == nil || policy.inShadowMode == nil {
		a.AuthorizationPolicyInShadowMode.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *policy.inShadowMode, nil
}
