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
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	vpctypes "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/v13/providers/aws/connection"
	"go.mondoo.com/mql/v13/types"
)

func (a *mqlAwsVpc) id() (string, error) {
	return a.Arn.Data, nil
}

// initAwsVpcEncryptionControl resolves the encryption control through the
// scanned VPC asset. Without this init, the static path
// `aws.vpc.encryptionControl` used by policy checks instantiates the
// sub-resource standalone (empty id, no fields set), so per-asset checks
// scored fail even for VPCs with an enforce-mode encryption control.
func initAwsVpcEncryptionControl(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// Fully-built resources (from the accessor) always carry an __id.
	if args["__id"] != nil {
		return args, nil, nil
	}
	if len(args) > 0 {
		return nil, nil, errors.New("aws.vpc.encryptionControl cannot be initialized from partial arguments; query it without arguments or through aws.vpc")
	}
	vpcRes, err := NewResource(runtime, "aws.vpc", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	vpc := vpcRes.(*mqlAwsVpc)
	ec := vpc.GetEncryptionControl()
	if ec.Error != nil {
		return nil, nil, ec.Error
	}
	if vpc.encryptionControlAccessDenied {
		// Do NOT fabricate an "absent" control here: that would score
		// security checks as "no encryption" when the truth is unknown.
		return nil, nil, errors.New("access denied reading the VPC encryption control")
	}
	if ec.Data == nil {
		// No encryption control on this VPC: represent it explicitly so
		// checks fail (instead of erroring) on the absent case.
		res, err := CreateResource(runtime, "aws.vpc.encryptionControl",
			map[string]*llx.RawData{
				"__id":               llx.StringData(vpc.Arn.Data + "/encryptionControl"),
				"id":                 llx.StringData(""),
				"mode":               llx.StringData(""),
				"state":              llx.StringData(""),
				"stateMessage":       llx.StringData(""),
				"resourceExclusions": llx.MapData(map[string]any{}, types.String),
				"tags":               llx.MapData(map[string]any{}, types.String),
			})
		if err != nil {
			return nil, nil, err
		}
		return args, res, nil
	}
	return args, ec.Data, nil
}

func (a *mqlAwsVpc) encryptionControl() (*mqlAwsVpcEncryptionControl, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeVpcEncryptionControls(ctx, &ec2.DescribeVpcEncryptionControlsInput{
		VpcIds: []string{a.Id.Data},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			a.encryptionControlAccessDenied = true
			a.EncryptionControl.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}
	if resp == nil || len(resp.VpcEncryptionControls) == 0 {
		a.EncryptionControl.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return newMqlAwsVpcEncryptionControl(a.MqlRuntime, resp.VpcEncryptionControls[0])
}

func newMqlAwsVpcEncryptionControl(runtime *plugin.Runtime, ec vpctypes.VpcEncryptionControl) (*mqlAwsVpcEncryptionControl, error) {
	res, err := CreateResource(runtime, ResourceAwsVpcEncryptionControl,
		map[string]*llx.RawData{
			"__id":               llx.StringData(convert.ToValue(ec.VpcEncryptionControlId)),
			"id":                 llx.StringDataPtr(ec.VpcEncryptionControlId),
			"mode":               llx.StringData(string(ec.Mode)),
			"state":              llx.StringData(string(ec.State)),
			"stateMessage":       llx.StringDataPtr(ec.StateMessage),
			"resourceExclusions": llx.MapData(vpcEncryptionControlExclusionsToMap(ec.ResourceExclusions), types.String),
			"tags":               llx.MapData(toInterfaceMap(ec2TagsToMap(ec.Tags)), types.String),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcEncryptionControl), nil
}

// vpcEncryptionControlExclusionsToMap flattens the per-traffic-type exclusion
// configuration into a map of traffic type to exclusion state. Traffic types
// that carry no exclusion configuration are omitted.
func vpcEncryptionControlExclusionsToMap(ex *vpctypes.VpcEncryptionControlExclusions) map[string]any {
	m := map[string]any{}
	if ex == nil {
		return m
	}
	add := func(key string, e *vpctypes.VpcEncryptionControlExclusion) {
		if e != nil {
			m[key] = string(e.State)
		}
	}
	add("internetGateway", ex.InternetGateway)
	add("egressOnlyInternetGateway", ex.EgressOnlyInternetGateway)
	add("natGateway", ex.NatGateway)
	add("lambda", ex.Lambda)
	add("elasticFileSystem", ex.ElasticFileSystem)
	add("virtualPrivateGateway", ex.VirtualPrivateGateway)
	add("vpcLattice", ex.VpcLattice)
	add("vpcPeering", ex.VpcPeering)
	return m
}

func buildVpcResource(runtime *plugin.Runtime, region, accountID string, vpc vpctypes.Vpc) (*mqlAwsVpc, error) {
	tagsMap := ec2TagsToMap(vpc.Tags)
	name := tagsMap["Name"]
	mqlVpc, err := CreateResource(runtime, ResourceAwsVpc,
		map[string]*llx.RawData{
			"arn":             llx.StringData(fmt.Sprintf(vpcArnPattern, region, accountID, convert.ToValue(vpc.VpcId))),
			"cidrBlock":       llx.StringDataPtr(vpc.CidrBlock),
			"dhcpOptionsId":   llx.StringDataPtr(vpc.DhcpOptionsId),
			"id":              llx.StringDataPtr(vpc.VpcId),
			"instanceTenancy": llx.StringData(string(vpc.InstanceTenancy)),
			"isDefault":       llx.BoolData(convert.ToValue(vpc.IsDefault)),
			"name":            llx.StringData(name),
			"ownerId":         llx.StringDataPtr(vpc.OwnerId),
			"region":          llx.StringData(region),
			"state":           llx.StringData(string(vpc.State)),
			"tags":            llx.MapData(toInterfaceMap(tagsMap), types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlVpcRes := mqlVpc.(*mqlAwsVpc)
	if vpc.BlockPublicAccessStates != nil {
		mqlVpcRes.InternetGatewayBlockMode = plugin.TValue[string]{Data: string(vpc.BlockPublicAccessStates.InternetGatewayBlockMode), State: plugin.StateIsSet}
	}
	mqlVpcRes.cacheCidrBlockAssociations = vpc.CidrBlockAssociationSet
	mqlVpcRes.cacheIpv6CidrBlockAssociations = vpc.Ipv6CidrBlockAssociationSet
	return mqlVpcRes, nil
}

func (a *mqlAws) vpcs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVpcs(conn), 5)
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

func (a *mqlAws) getVpcs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("vpc>getVpcs>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			params := &ec2.DescribeVpcsInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			}
			paginator := ec2.NewDescribeVpcsPaginator(svc, params)
			for paginator.HasMorePages() {
				vpcs, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, vpc := range vpcs.Vpcs {
					tagsMap := ec2TagsToMap(vpc.Tags)
					if conn.Filters.General.MatchesExcludeTags(tagsMap) {
						log.Debug().Interface("vpc", vpc.VpcId).Msg("excluding vpc due to filters")
						continue
					}

					mqlVpc, err := buildVpcResource(a.MqlRuntime, region, conn.AccountId(), vpc)
					if err != nil {
						log.Error().Msg(err.Error())
						continue
					}
					res = append(res, mqlVpc)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsVpcInternal struct {
	cacheCidrBlockAssociations     []vpctypes.VpcCidrBlockAssociation
	cacheIpv6CidrBlockAssociations []vpctypes.VpcIpv6CidrBlockAssociation
	// set when DescribeVpcEncryptionControls was denied, so callers can tell
	// "unknown" apart from "no encryption control" (both yield a null field)
	encryptionControlAccessDenied bool
}

func (a *mqlAwsVpc) cidrBlockAssociations() ([]any, error) {
	res := []any{}
	for _, assoc := range a.cacheCidrBlockAssociations {
		d, err := convert.JsonToDict(assoc)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func (a *mqlAwsVpc) ipv6CidrBlockAssociations() ([]any, error) {
	res := []any{}
	for _, assoc := range a.cacheIpv6CidrBlockAssociations {
		d, err := convert.JsonToDict(assoc)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

// natgatewayAddressCacheKey builds a stable, unique cache key for a NAT gateway
// address. Private NAT gateways have no AllocationId, so the allocation ID alone
// collapses every private address onto the same key; the ENI plus private IP are
// always present and uniquely identify the address.
func natgatewayAddressCacheKey(networkInterfaceId, privateIp string) string {
	return networkInterfaceId + "/" + privateIp
}

func (a *mqlAwsVpcNatgatewayAddress) id() (string, error) {
	return natgatewayAddressCacheKey(a.NetworkInterfaceId.Data, a.PrivateIp.Data), nil
}

func (a *mqlAwsVpcNatgateway) id() (string, error) {
	return a.NatGatewayId.Data, nil
}

func (a *mqlAwsVpcNatgateway) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(natGatewayArnPattern, a.region, conn.AccountId(), a.NatGatewayId.Data), nil
}

type mqlAwsVpcNatgatewayInternal struct {
	natGatewayCache vpctypes.NatGateway
	region          string
}

type mqlAwsVpcNatgatewayAddressInternal struct {
	natGatewayAddressCache vpctypes.NatGatewayAddress
	region                 string
}

func (a *mqlAwsVpcNatgateway) vpc() (*mqlAwsVpc, error) {
	if a.natGatewayCache.VpcId != nil {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		res, err := NewResource(a.MqlRuntime, ResourceAwsVpc, map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, conn.AccountId(), convert.ToValue(a.natGatewayCache.VpcId)))})
		if err != nil {
			return nil, err
		}
		return res.(*mqlAwsVpc), nil
	}
	a.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsVpcNatgateway) subnet() (*mqlAwsVpcSubnet, error) {
	if a.natGatewayCache.SubnetId != nil {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		res, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), convert.ToValue(a.natGatewayCache.SubnetId)))})
		if err != nil {
			return nil, err
		}
		return res.(*mqlAwsVpcSubnet), nil
	}
	a.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsVpcNatgatewayAddress) publicIp() (*mqlAwsEc2Eip, error) {
	if a.natGatewayAddressCache.PublicIp != nil {
		res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Eip, map[string]*llx.RawData{"publicIp": llx.StringDataPtr(a.natGatewayAddressCache.PublicIp), "region": llx.StringData(a.region)})
		if err != nil {
			return nil, err
		}
		return res.(*mqlAwsEc2Eip), nil
	}
	a.PublicIp.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsVpcNatgatewayAddress) networkInterface() (*mqlAwsEc2Networkinterface, error) {
	eniId := a.NetworkInterfaceId.Data
	if eniId == "" {
		a.NetworkInterface.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkinterface,
		map[string]*llx.RawData{"id": llx.StringData(eniId), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Networkinterface), nil
}

func (a *mqlAwsVpc) natGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcId := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	endpoints := []any{}

	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, vpcFilter(vpcId))
	params := &ec2.DescribeNatGatewaysInput{Filter: filters}
	paginator := ec2.NewDescribeNatGatewaysPaginator(svc, params)
	for paginator.HasMorePages() {
		natgateways, err := paginator.NextPage(ctx)
		if err != nil {
			a.NatGateways.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, err
		}

		for _, gw := range natgateways.NatGateways {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(gw.Tags)) {
				log.Debug().Interface("nat_gateway", gw.NatGatewayId).Msg("excluding nat gateway due to filters")
				continue
			}

			mqlNatGat, err := newMqlAwsVpcNatgateway(a.MqlRuntime, a.Region.Data, gw)
			if err != nil {
				return nil, err
			}
			endpoints = append(endpoints, mqlNatGat)
		}
	}
	return endpoints, nil
}

// newMqlAwsVpcNatgateway builds an aws.vpc.natgateway resource (and its
// address sub-resources) from a DescribeNatGateways result.
func newMqlAwsVpcNatgateway(runtime *plugin.Runtime, region string, gw vpctypes.NatGateway) (*mqlAwsVpcNatgateway, error) {
	addresses := []any{}
	for _, address := range gw.NatGatewayAddresses {
		mqlAddr, err := CreateResource(runtime, ResourceAwsVpcNatgatewayAddress,
			map[string]*llx.RawData{
				"allocationId":       llx.StringDataPtr(address.AllocationId),
				"networkInterfaceId": llx.StringDataPtr(address.NetworkInterfaceId),
				"privateIp":          llx.StringDataPtr(address.PrivateIp),
				"isPrimary":          llx.BoolDataPtr(address.IsPrimary),
			})
		if err != nil {
			log.Error().Err(err).Msg("cannot create vpc natgateway address resource")
			continue
		}
		mqlAddr.(*mqlAwsVpcNatgatewayAddress).natGatewayAddressCache = address
		mqlAddr.(*mqlAwsVpcNatgatewayAddress).region = region
		addresses = append(addresses, mqlAddr)
	}

	mqlNat, err := CreateResource(runtime, ResourceAwsVpcNatgateway,
		map[string]*llx.RawData{
			"createdAt":        llx.TimeDataPtr(gw.CreateTime),
			"natGatewayId":     llx.StringDataPtr(gw.NatGatewayId),
			"state":            llx.StringData(string(gw.State)),
			"connectivityType": llx.StringData(string(gw.ConnectivityType)),
			"tags":             llx.MapData(toInterfaceMap(ec2TagsToMap(gw.Tags)), types.String),
			"addresses":        llx.ArrayData(addresses, types.Type(ResourceAwsVpcNatgatewayAddress)),
		})
	if err != nil {
		return nil, err
	}
	mqlNat.(*mqlAwsVpcNatgateway).natGatewayCache = gw
	mqlNat.(*mqlAwsVpcNatgateway).region = region
	return mqlNat.(*mqlAwsVpcNatgateway), nil
}

func initAwsVpcNatgateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// region is a lookup hint, not a schema field on aws.vpc.natgateway. Pull it
	// out of args before any fallthrough so SetAllData never tries to apply it.
	var region string
	if r := args["region"]; r != nil {
		region, _ = r.Value.(string)
		delete(args, "region")
	}

	if len(args) > 2 {
		return args, nil, nil
	}
	// A targeted lookup needs both the NAT gateway id and its region (the id
	// does not encode a region). Without them, hand back a bare resource.
	if args["natGatewayId"] == nil || region == "" {
		return args, nil, nil
	}
	natID, _ := args["natGatewayId"].Value.(string)
	if natID == "" {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	resp, err := svc.DescribeNatGateways(context.Background(), &ec2.DescribeNatGatewaysInput{
		NatGatewayIds: []string{natID},
	})
	if err != nil {
		return nil, nil, err
	}
	if len(resp.NatGateways) == 0 {
		return nil, nil, fmt.Errorf("aws.vpc.natgateway with id %q not found", natID)
	}
	mqlNat, err := newMqlAwsVpcNatgateway(runtime, region, resp.NatGateways[0])
	if err != nil {
		return nil, nil, err
	}
	return args, mqlNat, nil
}

func (a *mqlAwsVpcEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsVpcEndpoint) arn() (string, error) {
	account := a.OwnerId.Data
	if account == "" {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		account = conn.AccountId()
	}
	return fmt.Sprintf(vpcEndpointArnPattern, a.Region.Data, account, a.cacheEndpointId), nil
}

type mqlAwsVpcEndpointInternal struct {
	securityGroupIdHandler
	cacheRouteTableIds       []string
	cacheNetworkInterfaceIds []string
	cacheSubnetIds           []string
	cacheEndpointId          string
	region                   string
	accountID                string
}

func (a *mqlAwsVpc) endpoints() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcId := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	endpoints := []any{}

	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, vpcFilter(vpcId))
	params := &ec2.DescribeVpcEndpointsInput{Filters: filters}
	paginator := ec2.NewDescribeVpcEndpointsPaginator(svc, params)
	for paginator.HasMorePages() {
		endpointsRes, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, endpoint := range endpointsRes.VpcEndpoints {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(endpoint.Tags)) {
				log.Debug().Interface("vpc_endpoint", endpoint.VpcEndpointId).Msg("excluding vpc endpoint due to filters")
				continue
			}

			subnetIds := make([]any, 0, len(endpoint.SubnetIds))
			for _, subnet := range endpoint.SubnetIds {
				subnetIds = append(subnetIds, subnet)
			}

			dnsEntries := make([]any, 0, len(endpoint.DnsEntries))
			for _, entry := range endpoint.DnsEntries {
				dnsEntries = append(dnsEntries, map[string]any{
					"dnsName":      convert.ToValue(entry.DnsName),
					"hostedZoneId": convert.ToValue(entry.HostedZoneId),
				})
			}

			mqlEndpoint, err := CreateResource(a.MqlRuntime, ResourceAwsVpcEndpoint,
				map[string]*llx.RawData{
					"id":                llx.StringData(fmt.Sprintf("%s/%s", a.Region.Data, *endpoint.VpcEndpointId)),
					"policyDocument":    llx.StringDataPtr(endpoint.PolicyDocument),
					"privateDnsEnabled": llx.BoolDataPtr(endpoint.PrivateDnsEnabled),
					"region":            llx.StringData(a.Region.Data),
					"serviceName":       llx.StringDataPtr(endpoint.ServiceName),
					"state":             llx.StringData(string(endpoint.State)),
					"subnets":           llx.ArrayData(subnetIds, types.String),
					"type":              llx.StringData(string(endpoint.VpcEndpointType)),
					"vpc":               llx.StringDataPtr(endpoint.VpcId),
					"createdAt":         llx.TimeDataPtr(endpoint.CreationTimestamp),
					"dnsEntries":        llx.ArrayData(dnsEntries, types.Any),
					"tags":              llx.MapData(toInterfaceMap(ec2TagsToMap(endpoint.Tags)), types.String),
					"ipAddressType":     llx.StringData(string(endpoint.IpAddressType)),
					"ownerId":           llx.StringDataPtr(endpoint.OwnerId),
					"requesterManaged":  llx.BoolDataPtr(endpoint.RequesterManaged),
				},
			)
			if err != nil {
				return nil, err
			}

			ep := mqlEndpoint.(*mqlAwsVpcEndpoint)
			ep.region = a.Region.Data
			ep.accountID = conn.AccountId()
			ep.cacheEndpointId = convert.ToValue(endpoint.VpcEndpointId)
			// Cached separately from the deprecated subnets field so subnetRefs
			// does not depend on a field that is due for removal.
			ep.cacheSubnetIds = endpoint.SubnetIds

			// Cache security group ARNs
			sgArns := make([]string, len(endpoint.Groups))
			for i, sg := range endpoint.Groups {
				sgArns[i] = fmt.Sprintf(securityGroupArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(sg.GroupId))
			}
			ep.setSecurityGroupArns(sgArns)

			// Cache route table IDs
			ep.cacheRouteTableIds = endpoint.RouteTableIds

			// Cache network interface IDs
			ep.cacheNetworkInterfaceIds = endpoint.NetworkInterfaceIds

			endpoints = append(endpoints, mqlEndpoint)
		}
	}
	return endpoints, nil
}

func (a *mqlAwsVpcServiceEndpoint) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsVpc) serviceEndpoints() ([]any, error) {
	var (
		conn      = a.MqlRuntime.Connection.(*connection.AwsConnection)
		vpcID     = a.Id.Data
		svc       = conn.Ec2(a.Region.Data)
		ctx       = context.Background()
		endpoints = []any{}
	)

	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, vpcFilter(vpcID))
	paginator := ec2.NewDescribeVpcEndpointsPaginator(svc, &ec2.DescribeVpcEndpointsInput{Filters: filters})
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return endpoints, err
		}

		for _, endpoint := range resp.VpcEndpoints {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(endpoint.Tags)) {
				log.Debug().Interface("vpc_endpoint", endpoint.VpcEndpointId).Msg("excluding vpc endpoint due to filters")
				continue
			}

			dnsNames := convert.Into(endpoint.DnsEntries,
				func(d vpctypes.DnsEntry) any { return convert.ToValue(d.DnsName) },
			)
			mqlEndpoint, err := CreateResource(a.MqlRuntime, ResourceAwsVpcServiceEndpoint,
				map[string]*llx.RawData{
					"id":       llx.StringDataPtr(endpoint.VpcEndpointId),
					"name":     llx.StringDataPtr(endpoint.ServiceName),
					"type":     llx.StringData(string(endpoint.VpcEndpointType)),
					"tags":     llx.MapData(toInterfaceMap(ec2TagsToMap(endpoint.Tags)), types.String),
					"dnsNames": llx.ArrayData(dnsNames, types.String),
					"owner":    llx.StringDataPtr(endpoint.OwnerId),
				},
			)
			if err != nil {
				return nil, err
			}

			endpoints = append(endpoints, mqlEndpoint)

			// store the region for further endpoint info
			cast := mqlEndpoint.(*mqlAwsVpcServiceEndpoint)
			cast.region = a.Region.Data
		}
	}

	return endpoints, nil
}

type mqlAwsVpcServiceEndpointInternal struct {
	region  string
	infoErr error
	lock    sync.Mutex
}

func (a *mqlAwsVpcServiceEndpoint) gatherVpcServiceEndpointInfo() error {
	a.lock.Lock()
	defer a.lock.Unlock()

	if a.infoErr != nil {
		return a.infoErr
	}

	var (
		conn = a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc  = conn.Ec2(a.region)
		ctx  = context.Background()

		// https: //docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DescribeVpcEndpointServices.html
		params = &ec2.DescribeVpcEndpointServicesInput{
			Filters: []vpctypes.Filter{
				{
					Name:   aws.String("service-name"),
					Values: []string{a.Name.Data},
				},
				{
					Name:   aws.String("service-type"),
					Values: []string{a.Type.Data},
				},
			},
		}
	)

	endpointsRes, err := svc.DescribeVpcEndpointServices(ctx, params)
	if err != nil {
		return err
	}

	if len(endpointsRes.ServiceDetails) == 0 {
		a.infoErr = fmt.Errorf("no vpc service endpoint information found for %s", a.Name.Data)
		return a.infoErr
	}

	service := endpointsRes.ServiceDetails[0]

	dnsNames := convert.Into(service.PrivateDnsNames,
		func(d vpctypes.PrivateDnsDetails) any {
			return convert.ToValue(d.PrivateDnsName)
		},
	)

	a.AcceptanceRequired = plugin.TValue[bool]{Data: convert.ToValue(service.AcceptanceRequired), State: plugin.StateIsSet}
	a.ManagesVpcEndpoints = plugin.TValue[bool]{Data: convert.ToValue(service.ManagesVpcEndpoints), State: plugin.StateIsSet}
	a.VpcEndpointPolicySupported = plugin.TValue[bool]{Data: convert.ToValue(service.VpcEndpointPolicySupported), State: plugin.StateIsSet}
	a.PayerResponsibility = plugin.TValue[string]{Data: string(service.PayerResponsibility), State: plugin.StateIsSet}
	a.PrivateDnsNameVerificationState = plugin.TValue[string]{Data: string(service.PrivateDnsNameVerificationState), State: plugin.StateIsSet}
	a.AvailabilityZones = plugin.TValue[[]any]{Data: convert.SliceAnyToInterface(service.AvailabilityZones), State: plugin.StateIsSet}
	a.PrivateDnsNames = plugin.TValue[[]any]{Data: dnsNames, State: plugin.StateIsSet}

	return nil
}

func (a *mqlAwsVpcServiceEndpoint) acceptanceRequired() (bool, error) {
	return false, a.gatherVpcServiceEndpointInfo()
}

func (a *mqlAwsVpcServiceEndpoint) managesVpcEndpoints() (bool, error) {
	return false, a.gatherVpcServiceEndpointInfo()
}

func (a *mqlAwsVpcServiceEndpoint) vpcEndpointPolicySupported() (bool, error) {
	return false, a.gatherVpcServiceEndpointInfo()
}

func (a *mqlAwsVpcServiceEndpoint) privateDnsNameVerificationState() (string, error) {
	return "", a.gatherVpcServiceEndpointInfo()
}

func (a *mqlAwsVpcServiceEndpoint) payerResponsibility() (string, error) {
	return "", a.gatherVpcServiceEndpointInfo()
}

func (a *mqlAwsVpcServiceEndpoint) availabilityZones() ([]any, error) {
	return nil, a.gatherVpcServiceEndpointInfo()
}

func (a *mqlAwsVpcServiceEndpoint) privateDnsNames() ([]any, error) {
	return nil, a.gatherVpcServiceEndpointInfo()
}

func (a *mqlAwsVpcPeeringConnection) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsVpc) peeringConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpc := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	pcs := []any{}
	seen := map[string]struct{}{}

	// A peering connection records this VPC in exactly one of requester-vpc-info
	// or accepter-vpc-info, never both. AWS ANDs multiple Filters entries, so a
	// single request filtering on both keys would require this VPC to be both
	// ends of the same connection (impossible) and always returns nothing.
	// Query each side separately and union the results, de-duplicating by id.
	for _, filterKey := range []string{"requester-vpc-info.vpc-id", "accepter-vpc-info.vpc-id"} {
		params := &ec2.DescribeVpcPeeringConnectionsInput{Filters: []vpctypes.Filter{{Name: &filterKey, Values: []string{vpc}}}}
		paginator := ec2.NewDescribeVpcPeeringConnectionsPaginator(svc, params)
		for paginator.HasMorePages() {
			res, err := paginator.NextPage(ctx)
			if err != nil {
				return nil, err
			}

			for _, peerconn := range res.VpcPeeringConnections {
				id := convert.ToValue(peerconn.VpcPeeringConnectionId)
				if _, ok := seen[id]; ok {
					continue
				}
				seen[id] = struct{}{}

				mqlPeerConn, err := newMqlAwsVpcPeeringConnection(a.MqlRuntime, a.Region.Data, peerconn)
				if err != nil {
					return nil, err
				}
				pcs = append(pcs, mqlPeerConn)
			}
		}
	}
	return pcs, nil
}

func (a *mqlAwsVpcPeeringConnectionPeeringVpc) id() (string, error) {
	return fmt.Sprintf("aws.vpc.peeringConnection.peeringVpc/%s/%s", a.Region.Data, a.VpcId.Data), nil
}

type mqlAwsVpcPeeringConnectionInternal struct {
	peeringConnectionCache vpctypes.VpcPeeringConnection
	region                 string
}

// newMqlAwsVpcPeeringConnection builds an aws.vpc.peeringConnection from an SDK
// VpcPeeringConnection. Shared by the per-VPC list and the by-id init. The
// acceptor/requestor VPC sub-resources are resolved lazily from the cached SDK
// struct by their own accessors, so only the scalar fields are set here.
func newMqlAwsVpcPeeringConnection(runtime *plugin.Runtime, region string, peerconn vpctypes.VpcPeeringConnection) (plugin.Resource, error) {
	status := ""
	if peerconn.Status != nil {
		status = convert.ToValue(peerconn.Status.Message)
	}
	// Determine DNS resolution status from peering options
	dnsResolution := false
	if peerconn.RequesterVpcInfo != nil && peerconn.RequesterVpcInfo.PeeringOptions != nil &&
		peerconn.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil {
		dnsResolution = *peerconn.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc
	}
	if !dnsResolution && peerconn.AccepterVpcInfo != nil && peerconn.AccepterVpcInfo.PeeringOptions != nil &&
		peerconn.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil {
		dnsResolution = *peerconn.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc
	}

	var requesterAccountId, accepterAccountId string
	if peerconn.RequesterVpcInfo != nil {
		requesterAccountId = convert.ToValue(peerconn.RequesterVpcInfo.OwnerId)
	}
	if peerconn.AccepterVpcInfo != nil {
		accepterAccountId = convert.ToValue(peerconn.AccepterVpcInfo.OwnerId)
	}

	mqlPeerConn, err := CreateResource(runtime, ResourceAwsVpcPeeringConnection,
		map[string]*llx.RawData{
			"expirationTime":       llx.TimeDataPtr(peerconn.ExpirationTime),
			"id":                   llx.StringDataPtr(peerconn.VpcPeeringConnectionId),
			"status":               llx.StringData(status),
			"tags":                 llx.MapData(toInterfaceMap(ec2TagsToMap(peerconn.Tags)), types.String),
			"requesterAccountId":   llx.StringData(requesterAccountId),
			"accepterAccountId":    llx.StringData(accepterAccountId),
			"dnsResolutionEnabled": llx.BoolData(dnsResolution),
		},
	)
	if err != nil {
		return nil, err
	}
	mqlPeerConn.(*mqlAwsVpcPeeringConnection).peeringConnectionCache = peerconn
	mqlPeerConn.(*mqlAwsVpcPeeringConnection).region = region
	return mqlPeerConn, nil
}

func initAwsVpcPeeringConnection(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	// region is a lookup hint, not a schema field on aws.vpc.peeringConnection.
	var region string
	if r := args["region"]; r != nil {
		region, _ = r.Value.(string)
		delete(args, "region")
	}

	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil || region == "" {
		return args, nil, nil
	}
	pcxID, _ := args["id"].Value.(string)
	if pcxID == "" {
		return args, nil, nil
	}

	// Reuse a peering connection already listed before spending an API call.
	cacheID := ResourceAwsVpcPeeringConnection + "\x00" + pcxID
	if cached, ok := runtime.Resources.Get(cacheID); ok {
		return args, cached, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	resp, err := svc.DescribeVpcPeeringConnections(context.Background(), &ec2.DescribeVpcPeeringConnectionsInput{
		VpcPeeringConnectionIds: []string{pcxID},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil, fmt.Errorf("access denied fetching aws.vpc.peeringConnection with id %q in region %s", pcxID, region)
		}
		return nil, nil, err
	}
	if len(resp.VpcPeeringConnections) == 0 {
		return nil, nil, fmt.Errorf("aws.vpc.peeringConnection with id %q not found", pcxID)
	}
	res, err := newMqlAwsVpcPeeringConnection(runtime, region, resp.VpcPeeringConnections[0])
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

// peeringVpcCacheKey names one side of one peering connection.
//
// The connection and the side both have to appear in the key. Keying on the
// region and the VPC id alone gave a VPC one entry per region however many
// connections it takes part in, so a hub VPC peered to several spokes reported
// the first connection's CIDRs for all of them.
func peeringVpcCacheKey(peeringConnectionID, side string) string {
	return "aws.vpc.peeringConnection.peeringVpc/" + peeringConnectionID + "/" + side
}

// peeringVpcSide builds the accepter or the requester side of this peering
// connection from the DescribeVpcPeeringConnections result.
func (a *mqlAwsVpcPeeringConnection) peeringVpcSide(side string, info *vpctypes.VpcPeeringConnectionVpcInfo) (*mqlAwsVpcPeeringConnectionPeeringVpc, error) {
	ipv4 := []any{}
	for i := range info.CidrBlockSet {
		ipv4 = append(ipv4, convert.ToValue(info.CidrBlockSet[i].CidrBlock))
	}
	ipv6 := []any{}
	for i := range info.Ipv6CidrBlockSet {
		ipv6 = append(ipv6, convert.ToValue(info.Ipv6CidrBlockSet[i].Ipv6CidrBlock))
	}
	var allowDns *bool
	if info.PeeringOptions != nil {
		allowDns = info.PeeringOptions.AllowDnsResolutionFromRemoteVpc
	}
	mql, err := CreateResource(a.MqlRuntime, ResourceAwsVpcPeeringConnectionPeeringVpc,
		map[string]*llx.RawData{
			"__id":                            llx.StringData(peeringVpcCacheKey(a.Id.Data, side)),
			"allowDnsResolutionFromRemoteVpc": llx.BoolDataPtr(allowDns),
			"ipv4CiderBlocks":                 llx.ArrayData(ipv4, types.String),
			"ipv6CiderBlocks":                 llx.ArrayData(ipv6, types.String),
			"ownerID":                         llx.StringDataPtr(info.OwnerId),
			"region":                          llx.StringData(a.region),
			"vpcId":                           llx.StringDataPtr(info.VpcId),
		},
	)
	if err != nil {
		return nil, err
	}
	return mql.(*mqlAwsVpcPeeringConnectionPeeringVpc), nil
}

func (a *mqlAwsVpcPeeringConnection) acceptorVpc() (*mqlAwsVpcPeeringConnectionPeeringVpc, error) {
	acceptor := a.peeringConnectionCache.AccepterVpcInfo
	if acceptor == nil {
		a.AcceptorVpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.peeringVpcSide("accepter", acceptor)
}

func (a *mqlAwsVpcPeeringConnectionPeeringVpc) vpc() (*mqlAwsVpc, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpc, map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.Region.Data, conn.AccountId(), a.VpcId.Data))})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsVpcPeeringConnection) requestorVpc() (*mqlAwsVpcPeeringConnectionPeeringVpc, error) {
	requestor := a.peeringConnectionCache.RequesterVpcInfo
	if requestor == nil {
		a.RequestorVpc.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return a.peeringVpcSide("requester", requestor)
}

func (a *mqlAwsVpc) flowLogs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpc := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	flowLogs := []any{}
	filterKeyVal := "resource-id"
	params := &ec2.DescribeFlowLogsInput{Filter: []vpctypes.Filter{{Name: &filterKeyVal, Values: []string{vpc}}}}
	paginator := ec2.NewDescribeFlowLogsPaginator(svc, params)
	for paginator.HasMorePages() {
		flowLogsRes, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, flowLog := range flowLogsRes.FlowLogs {
			mqlFlowLog, err := CreateResource(a.MqlRuntime, ResourceAwsVpcFlowlog,
				map[string]*llx.RawData{
					"__id":                   llx.StringData(vpcFlowLogCacheKey(a.Region.Data, convert.ToValue(flowLog.FlowLogId))),
					"createdAt":              llx.TimeDataPtr(flowLog.CreationTime),
					"destination":            llx.StringDataPtr(flowLog.LogDestination),
					"destinationType":        llx.StringData(string(flowLog.LogDestinationType)),
					"deliverLogsStatus":      llx.StringDataPtr(flowLog.DeliverLogsStatus),
					"id":                     llx.StringDataPtr(flowLog.FlowLogId),
					"logFormat":              llx.StringDataPtr(flowLog.LogFormat),
					"maxAggregationInterval": llx.IntDataDefault(flowLog.MaxAggregationInterval, 0),
					"region":                 llx.StringData(a.Region.Data),
					"status":                 llx.StringDataPtr(flowLog.FlowLogStatus),
					"tags":                   llx.MapData(toInterfaceMap(ec2TagsToMap(flowLog.Tags)), types.String),
					"trafficType":            llx.StringData(string(flowLog.TrafficType)),
					"vpc":                    llx.StringData(vpc),
				},
			)
			if err != nil {
				return nil, err
			}
			fl := mqlFlowLog.(*mqlAwsVpcFlowlog)
			fl.cacheDeliverLogsPermissionArn = flowLog.DeliverLogsPermissionArn
			fl.cacheLogGroupName = flowLog.LogGroupName
			fl.cacheLogDestination = flowLog.LogDestination
			fl.cacheLogDestinationType = string(flowLog.LogDestinationType)
			fl.region = a.Region.Data
			flowLogs = append(flowLogs, mqlFlowLog)
		}
	}
	return flowLogs, nil
}

func (a *mqlAwsVpcRoutetable) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsVpc) routeTables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcVal := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	res := []any{}

	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, vpcFilter(vpcVal))
	params := &ec2.DescribeRouteTablesInput{Filters: filters}
	paginator := ec2.NewDescribeRouteTablesPaginator(svc, params)
	for paginator.HasMorePages() {
		routeTables, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, routeTable := range routeTables.RouteTables {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(routeTable.Tags)) {
				log.Debug().Interface("route_table", routeTable.RouteTableId).Msg("excluding route table due to filters")
				continue
			}

			dictRoutes, err := convert.JsonToDictSlice(routeTable.Routes)
			if err != nil {
				return nil, err
			}
			mqlRouteTable, err := CreateResource(a.MqlRuntime, ResourceAwsVpcRoutetable,
				map[string]*llx.RawData{
					"arn":    llx.StringData(fmt.Sprintf(routeTableArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(routeTable.RouteTableId))),
					"id":     llx.StringDataPtr(routeTable.RouteTableId),
					"region": llx.StringData(a.Region.Data),
					"routes": llx.ArrayData(dictRoutes, types.Any),
					"tags":   llx.MapData(toInterfaceMap(ec2TagsToMap(routeTable.Tags)), types.String),
				})
			if err != nil {
				return nil, err
			}
			res = append(res, mqlRouteTable)
			mqlRouteTable.(*mqlAwsVpcRoutetable).cacheAssociations = routeTable.Associations
			mqlRouteTable.(*mqlAwsVpcRoutetable).cacheRoutes = routeTable.Routes
		}
	}
	return res, nil
}

type mqlAwsVpcRoutetableInternal struct {
	cacheAssociations []vpctypes.RouteTableAssociation
	cacheRoutes       []vpctypes.Route
}

type mqlAwsVpcRoutetableRouteInternal struct {
	region string
}

func (a *mqlAwsVpcRoutetableRoute) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsVpcRoutetableRoute) networkInterface() (*mqlAwsEc2Networkinterface, error) {
	eniId := a.NetworkInterfaceId.Data
	if eniId == "" {
		a.NetworkInterface.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkinterface,
		map[string]*llx.RawData{"id": llx.StringData(eniId), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Networkinterface), nil
}

func (a *mqlAwsVpcRoutetableRoute) natGateway() (*mqlAwsVpcNatgateway, error) {
	natID := a.NatGatewayId.Data
	if natID == "" {
		a.NatGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpcNatgateway,
		map[string]*llx.RawData{"natGatewayId": llx.StringData(natID), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcNatgateway), nil
}

func (a *mqlAwsVpcRoutetableRoute) instance() (*mqlAwsEc2Instance, error) {
	instanceID := a.InstanceId.Data
	if instanceID == "" {
		a.Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(ec2InstanceArnPattern, a.region, conn.AccountId(), instanceID)
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Instance,
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Instance), nil
}

func (a *mqlAwsVpcRoutetableRoute) internetGateway() (*mqlAwsEc2Internetgateway, error) {
	gwID := a.GatewayId.Data
	if !strings.HasPrefix(gwID, "igw-") {
		a.InternetGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Internetgateway,
		map[string]*llx.RawData{"id": llx.StringData(gwID), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Internetgateway), nil
}

func (a *mqlAwsVpcRoutetableRoute) vpnGateway() (*mqlAwsVpcVpnGateway, error) {
	gwID := a.GatewayId.Data
	if !strings.HasPrefix(gwID, "vgw-") {
		a.VpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpcVpnGateway,
		map[string]*llx.RawData{"id": llx.StringData(gwID), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcVpnGateway), nil
}

func (a *mqlAwsVpcRoutetableRoute) transitGateway() (*mqlAwsEc2Transitgateway, error) {
	tgwID := a.TransitGatewayId.Data
	if tgwID == "" {
		a.TransitGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Transitgateway,
		map[string]*llx.RawData{"id": llx.StringData(tgwID), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Transitgateway), nil
}

func (a *mqlAwsVpcRoutetableRoute) peeringConnection() (*mqlAwsVpcPeeringConnection, error) {
	pcxID := a.VpcPeeringConnectionId.Data
	if pcxID == "" {
		a.PeeringConnection.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsVpcPeeringConnection,
		map[string]*llx.RawData{"id": llx.StringData(pcxID), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcPeeringConnection), nil
}

func (a *mqlAwsVpcRoutetableRoute) egressOnlyInternetGateway() (*mqlAwsEc2EgressOnlyInternetGateway, error) {
	eigwID := a.EgressOnlyInternetGatewayId.Data
	if eigwID == "" {
		a.EgressOnlyInternetGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2EgressOnlyInternetGateway,
		map[string]*llx.RawData{"id": llx.StringData(eigwID), "region": llx.StringData(a.region)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2EgressOnlyInternetGateway), nil
}

func (a *mqlAwsVpcRoutetableRoute) managedPrefixList() (*mqlAwsEc2ManagedPrefixList, error) {
	plID := a.DestinationPrefixListId.Data
	if plID == "" {
		a.ManagedPrefixList.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(prefixListArnPattern, a.region, conn.AccountId(), plID)
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2ManagedPrefixList,
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2ManagedPrefixList), nil
}

func (a *mqlAwsVpcRoutetable) routeEntries() ([]any, error) {
	routeTableId := a.Id.Data
	res := []any{}
	for _, route := range a.cacheRoutes {
		destCidr := convert.ToValue(route.DestinationCidrBlock)
		destIpv6 := convert.ToValue(route.DestinationIpv6CidrBlock)
		destPrefix := convert.ToValue(route.DestinationPrefixListId)

		// Build a unique ID from route table + destination
		dest := destCidr
		if dest == "" {
			dest = destIpv6
		}
		if dest == "" {
			dest = destPrefix
		}
		if dest == "" {
			dest = "unknown"
		}
		routeId := routeTableId + "/" + dest

		args := map[string]*llx.RawData{
			"id":                          llx.StringData(routeId),
			"destinationCidrBlock":        llx.StringData(destCidr),
			"destinationIpv6CidrBlock":    llx.StringData(destIpv6),
			"destinationPrefixListId":     llx.StringData(destPrefix),
			"gatewayId":                   llx.StringData(convert.ToValue(route.GatewayId)),
			"instanceId":                  llx.StringData(convert.ToValue(route.InstanceId)),
			"instanceOwnerId":             llx.StringData(convert.ToValue(route.InstanceOwnerId)),
			"networkInterfaceId":          llx.StringData(convert.ToValue(route.NetworkInterfaceId)),
			"natGatewayId":                llx.StringData(convert.ToValue(route.NatGatewayId)),
			"transitGatewayId":            llx.StringData(convert.ToValue(route.TransitGatewayId)),
			"vpcPeeringConnectionId":      llx.StringData(convert.ToValue(route.VpcPeeringConnectionId)),
			"egressOnlyInternetGatewayId": llx.StringData(convert.ToValue(route.EgressOnlyInternetGatewayId)),
			"localGatewayId":              llx.StringData(convert.ToValue(route.LocalGatewayId)),
			"carrierGatewayId":            llx.StringData(convert.ToValue(route.CarrierGatewayId)),
			"coreNetworkArn":              llx.StringData(convert.ToValue(route.CoreNetworkArn)),
			"origin":                      llx.StringData(string(route.Origin)),
			"state":                       llx.StringData(string(route.State)),
		}

		mqlRoute, err := CreateResource(a.MqlRuntime, "aws.vpc.routetable.route", args)
		if err != nil {
			return nil, err
		}
		mqlRoute.(*mqlAwsVpcRoutetableRoute).region = a.Region.Data
		res = append(res, mqlRoute)
	}
	return res, nil
}

func (a *mqlAwsVpcRoutetable) associations() ([]any, error) {
	res := []any{}
	for _, assoc := range a.cacheAssociations {
		state, err := convert.JsonToDict(assoc.AssociationState)
		if err != nil {
			return nil, err
		}
		mqlAssoc, err := CreateResource(a.MqlRuntime, ResourceAwsVpcRoutetableAssociation, map[string]*llx.RawData{
			"__id":                    llx.StringDataPtr(assoc.RouteTableAssociationId),
			"routeTableAssociationId": llx.StringDataPtr(assoc.RouteTableAssociationId),
			"associationsState":       llx.DictData(state),
			"gatewayId":               llx.StringDataPtr(assoc.GatewayId),
			"main":                    llx.BoolDataPtr(assoc.Main),
			"routeTableId":            llx.StringDataPtr(assoc.RouteTableId),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlAssoc)
		mqlAssoc.(*mqlAwsVpcRoutetableAssociation).cacheSubnetId = assoc.SubnetId
		mqlAssoc.(*mqlAwsVpcRoutetableAssociation).region = a.Region.Data
	}
	return res, nil
}

type mqlAwsVpcRoutetableAssociationInternal struct {
	cacheSubnetId *string
	region        string
}

func (a *mqlAwsVpcRoutetableAssociation) subnet() (*mqlAwsVpcSubnet, error) {
	if a.cacheSubnetId != nil {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		res, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), convert.ToValue(a.cacheSubnetId)))})
		if err != nil {
			return nil, err
		}
		return res.(*mqlAwsVpcSubnet), nil
	}
	a.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsVpcSubnet) id() (string, error) {
	return a.Arn.Data, nil
}

type mqlAwsVpcSubnetInternal struct {
	cacheVpcId string
}

// vpc resolves the VPC that contains this subnet. DescribeSubnets returns
// VpcId on every subnet, so both paths that build a subnet already seed
// cacheVpcId and this costs no extra call once the VPC has been listed.
func (a *mqlAwsVpcSubnet) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpcId == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlVpc, err := NewResource(a.MqlRuntime, ResourceAwsVpc,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.Region.Data, conn.AccountId(), a.cacheVpcId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlVpc.(*mqlAwsVpc), nil
}

func (a *mqlAwsVpcSubnet) routeTable() (*mqlAwsVpcRoutetable, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data
	subnetId := a.Id.Data
	vpcId := a.cacheVpcId

	svc := conn.Ec2(region)
	ctx := context.Background()

	// If we don't have the VPC ID cached, we need to look it up
	if vpcId == "" {
		subnets, err := svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{
			SubnetIds: []string{subnetId},
		})
		if err != nil {
			return nil, err
		}
		if len(subnets.Subnets) > 0 {
			vpcId = convert.ToValue(subnets.Subnets[0].VpcId)
		}
	}

	if vpcId == "" {
		a.RouteTable.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	// Get all route tables for this VPC
	params := &ec2.DescribeRouteTablesInput{
		Filters: []vpctypes.Filter{{Name: aws.String("vpc-id"), Values: []string{vpcId}}},
	}

	paginator := ec2.NewDescribeRouteTablesPaginator(svc, params)
	var mainRouteTable *vpctypes.RouteTable
	var explicitRouteTable *vpctypes.RouteTable

	for paginator.HasMorePages() {
		routeTables, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for i := range routeTables.RouteTables {
			rt := routeTables.RouteTables[i]
			for _, assoc := range rt.Associations {
				// Check if this is the main route table
				if assoc.Main != nil && *assoc.Main {
					mainRouteTable = &rt
				}
				// Check if this route table has an explicit association with our subnet
				if assoc.SubnetId != nil && *assoc.SubnetId == subnetId {
					explicitRouteTable = &rt
				}
			}
		}
	}

	// Use explicit association if exists, otherwise fall back to main route table
	var routeTableToReturn *vpctypes.RouteTable
	if explicitRouteTable != nil {
		routeTableToReturn = explicitRouteTable
	} else if mainRouteTable != nil {
		routeTableToReturn = mainRouteTable
	}

	if routeTableToReturn == nil {
		a.RouteTable.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	dictRoutes, err := convert.JsonToDictSlice(routeTableToReturn.Routes)
	if err != nil {
		return nil, err
	}
	mqlRouteTable, err := CreateResource(a.MqlRuntime, ResourceAwsVpcRoutetable,
		map[string]*llx.RawData{
			"arn":    llx.StringData(fmt.Sprintf(routeTableArnPattern, region, conn.AccountId(), convert.ToValue(routeTableToReturn.RouteTableId))),
			"id":     llx.StringDataPtr(routeTableToReturn.RouteTableId),
			"region": llx.StringData(region),
			"routes": llx.ArrayData(dictRoutes, types.Any),
			"tags":   llx.MapData(toInterfaceMap(ec2TagsToMap(routeTableToReturn.Tags)), types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlRouteTable.(*mqlAwsVpcRoutetable).cacheAssociations = routeTableToReturn.Associations
	mqlRouteTable.(*mqlAwsVpcRoutetable).cacheRoutes = routeTableToReturn.Routes
	return mqlRouteTable.(*mqlAwsVpcRoutetable), nil
}

func (a *mqlAwsVpc) subnets() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcVal := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	res := []any{}

	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, vpcFilter(vpcVal))
	params := &ec2.DescribeSubnetsInput{Filters: filters}
	paginator := ec2.NewDescribeSubnetsPaginator(svc, params)
	for paginator.HasMorePages() {
		subnets, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, subnet := range subnets.Subnets {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(subnet.Tags)) {
				log.Debug().Interface("subnet", subnet.SubnetId).Msg("excluding subnet due to filters")
				continue
			}

			tagsMap := ec2TagsToMap(subnet.Tags)
			var ipv6CidrBlock string
			if len(subnet.Ipv6CidrBlockAssociationSet) > 0 && subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock != nil {
				ipv6CidrBlock = *subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock
			}

			subnetResource, err := CreateResource(a.MqlRuntime, ResourceAwsVpcSubnet,
				map[string]*llx.RawData{
					"arn":                         llx.StringData(fmt.Sprintf(subnetArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(subnet.SubnetId))),
					"assignIpv6AddressOnCreation": llx.BoolDataPtr(subnet.AssignIpv6AddressOnCreation),
					"availabilityZone":            llx.StringDataPtr(subnet.AvailabilityZone),
					"availableIpAddressCount":     llx.IntDataPtr(subnet.AvailableIpAddressCount),
					"cidrs":                       llx.StringDataPtr(subnet.CidrBlock),
					"defaultForAvailabilityZone":  llx.BoolDataPtr(subnet.DefaultForAz),
					"id":                          llx.StringDataPtr(subnet.SubnetId),
					"ipv6CidrBlock":               llx.StringData(ipv6CidrBlock),
					"mapPublicIpOnLaunch":         llx.BoolDataPtr(subnet.MapPublicIpOnLaunch),
					"name":                        llx.StringData(tagsMap["Name"]),
					"ownerId":                     llx.StringDataPtr(subnet.OwnerId),
					"region":                      llx.StringData(a.Region.Data),
					"state":                       llx.StringData(string(subnet.State)),
					"tags":                        llx.MapData(toInterfaceMap(tagsMap), types.String),
				})
			if err != nil {
				return nil, err
			}
			if subnet.BlockPublicAccessStates != nil {
				subnetResource.(*mqlAwsVpcSubnet).InternetGatewayBlockMode = plugin.TValue[string]{Data: string(subnet.BlockPublicAccessStates.InternetGatewayBlockMode), State: plugin.StateIsSet}
			}
			subnetResource.(*mqlAwsVpcSubnet).cacheVpcId = vpcVal
			res = append(res, subnetResource)
		}
	}
	return res, nil
}

func initAwsVpcSubnet(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if args["arn"] == nil && args["id"] == nil {
		return nil, nil, errors.New("id or arn required to fetch aws vpc subnet")
	}

	var arnValue, id, region, subnetId string
	if args["arn"] != nil {
		arnValue = args["arn"].Value.(string)
	}
	if args["region"] != nil {
		region = args["region"].Value.(string)
	}
	if args["id"] != nil {
		id = args["id"].Value.(string)
	}
	if id != "" {
		subnetId = id
	} else if arnValue != "" {
		parsed, err := arn.Parse(arnValue)
		if err == nil {
			split := strings.Split(parsed.Resource, "/")
			if len(split) == 2 {
				subnetId = split[1]
				region = parsed.Region
			}
		}
	}
	if subnetId == "" {
		return nil, nil, errors.New("no subnet id specified")
	}

	conn := runtime.Connection.(*connection.AwsConnection)

	// Reuse a subnet already listed before spending a DescribeSubnets call. The
	// subnet ARN is its cache key, so resolving several references to subnets in
	// one VPC costs one API call rather than one per reference.
	cacheArn := arnValue
	if cacheArn == "" && region != "" {
		cacheArn = fmt.Sprintf(subnetArnPattern, region, conn.AccountId(), subnetId)
	}
	if cacheArn != "" {
		if cached, ok := runtime.Resources.Get(ResourceAwsVpcSubnet + "\x00" + cacheArn); ok {
			return args, cached, nil
		}
	}

	svc := conn.Ec2(region)
	ctx := context.Background()
	subnets, err := svc.DescribeSubnets(ctx, &ec2.DescribeSubnetsInput{Filters: []vpctypes.Filter{{Name: aws.String("subnet-id"), Values: []string{subnetId}}}})
	if err != nil {
		return nil, nil, err
	}

	if len(subnets.Subnets) > 0 {
		subnet := subnets.Subnets[0]
		tagsMap := ec2TagsToMap(subnet.Tags)
		if arnValue != "" {
			args["arn"] = llx.StringData(arnValue)
		} else {
			args["arn"] = llx.StringData(fmt.Sprintf(subnetArnPattern, region, conn.AccountId(), convert.ToValue(subnet.SubnetId)))
		}
		args["assignIpv6AddressOnCreation"] = llx.BoolDataPtr(subnet.AssignIpv6AddressOnCreation)
		args["availabilityZone"] = llx.StringDataPtr(subnet.AvailabilityZone)
		args["availableIpAddressCount"] = llx.IntDataPtr(subnet.AvailableIpAddressCount)
		args["cidrs"] = llx.StringDataPtr(subnet.CidrBlock)
		args["defaultForAvailabilityZone"] = llx.BoolDataPtr(subnet.DefaultForAz)
		args["id"] = llx.StringDataPtr(subnet.SubnetId)
		var ipv6CidrBlock string
		if len(subnet.Ipv6CidrBlockAssociationSet) > 0 && subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock != nil {
			ipv6CidrBlock = *subnet.Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock
		}
		args["ipv6CidrBlock"] = llx.StringData(ipv6CidrBlock)
		if subnet.BlockPublicAccessStates != nil {
			args["internetGatewayBlockMode"] = llx.StringData(string(subnet.BlockPublicAccessStates.InternetGatewayBlockMode))
		}
		args["mapPublicIpOnLaunch"] = llx.BoolDataPtr(subnet.MapPublicIpOnLaunch)
		args["name"] = llx.StringData(tagsMap["Name"])
		args["ownerId"] = llx.StringDataPtr(subnet.OwnerId)
		args["region"] = llx.StringData(region)
		args["state"] = llx.StringData(string(subnet.State))
		args["tags"] = llx.MapData(toInterfaceMap(tagsMap), types.String)

		res, err := CreateResource(runtime, ResourceAwsVpcSubnet, args)
		if err != nil {
			return nil, nil, err
		}
		mqlSubnet := res.(*mqlAwsVpcSubnet)
		mqlSubnet.cacheVpcId = convert.ToValue(subnet.VpcId)
		return nil, mqlSubnet, nil
	}
	return nil, nil, errors.New("subnet not found")
}

// deriveVpcTarget resolves the region and VPC id to look up. It pulls the ARN
// from the asset identifier when args are empty, then derives the id from the
// ARN's resource segment or an explicit "id" arg — never from the asset name
// (which may be a "Name" tag, not the vpc-id), keeping asset-name-vs-id
// resolution correct. It may populate args["arn"] from the asset identifier.
func deriveVpcTarget(runtime *plugin.Runtime, args map[string]*llx.RawData) (region, vpcId string) {
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformVpc); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}
	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		// The VPC ARN uses a custom shape, vpcArnPattern =
		// "arn:aws:vpc:<region>:<acct>:id/<vpc-id>", so the id lives behind an
		// "id/" prefix (not the standard "vpc/").
		if parsed, err := arn.Parse(arnVal); err == nil && strings.HasPrefix(parsed.Resource, "id/") {
			region = parsed.Region
			vpcId = strings.TrimPrefix(parsed.Resource, "id/")
		}
	}
	if args["id"] != nil && vpcId == "" {
		vpcId = args["id"].Value.(string)
	}
	if args["region"] != nil {
		if r, ok := args["region"].Value.(string); ok && r != "" {
			region = r
		}
	}
	return region, vpcId
}

func initAwsVpc(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// Already materialized by an earlier reference or by the list that
	// built it: NewResource consults the cache only after this init
	// returns, so without this the same target is fetched once per
	// referring resource and the result thrown away.
	if cached := cachedArgByArn(runtime, ResourceAwsVpc, args); cached != nil {
		return args, cached, nil
	}

	// Derive region + vpcId for a single targeted DescribeVpcs call instead of
	// listing every VPC in every region. This also pulls the ARN from the asset
	// identifier when args are empty.
	region, vpcId := deriveVpcTarget(runtime, args)

	if args["arn"] == nil && args["id"] == nil {
		return nil, nil, errors.New("arn or id required to fetch aws vpc")
	}

	if region != "" && vpcId != "" {
		conn := runtime.Connection.(*connection.AwsConnection)

		// Check again now the ARN can be derived. The check above only fires
		// for a caller that passed one, and callers passing an id instead are
		// the ones that repeat.
		if cached := cachedByArn(runtime, ResourceAwsVpc,
			fmt.Sprintf(vpcArnPattern, region, conn.AccountId(), vpcId)); cached != nil {
			return args, cached, nil
		}

		svc := conn.Ec2(region)
		resp, err := svc.DescribeVpcs(context.Background(), &ec2.DescribeVpcsInput{
			VpcIds: []string{vpcId},
		})
		if err != nil {
			return nil, nil, err
		}
		if len(resp.Vpcs) > 0 {
			vpc, err := buildVpcResource(runtime, region, conn.AccountId(), resp.Vpcs[0])
			if err != nil {
				return nil, nil, err
			}
			return args, vpc, nil
		}
		return nil, nil, errors.New("vpc does not exist")
	}

	// Fallback: scan the cached list (e.g. when called with just an opaque id
	// and no region hint).
	obj, err := CreateResource(runtime, "aws", map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	a := obj.(*mqlAws)

	rawResources := a.GetVpcs()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	var match func(vpc *mqlAwsVpc) bool

	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		match = func(vpc *mqlAwsVpc) bool {
			return vpc.Arn.Data == arnVal
		}
	} else if args["id"] != nil {
		idVal := args["id"].Value.(string)
		match = func(vpc *mqlAwsVpc) bool {
			return vpc.Id.Data == idVal
		}
	}

	for _, rawResource := range rawResources.Data {
		vpc := rawResource.(*mqlAwsVpc)
		if match(vpc) {
			return args, vpc, nil
		}
	}

	return nil, nil, errors.New("vpc does not exist")
}

func vpcFilter(vpcId string) vpctypes.Filter {
	return vpctypes.Filter{
		Name:   aws.String("vpc-id"),
		Values: []string{vpcId},
	}
}

// Internet Gateway implementation

func (a *mqlAwsVpc) internetGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcId := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	igws := []any{}

	filterKeyVal := "attachment.vpc-id"
	params := &ec2.DescribeInternetGatewaysInput{
		Filters: []vpctypes.Filter{{Name: &filterKeyVal, Values: []string{vpcId}}},
	}

	paginator := ec2.NewDescribeInternetGatewaysPaginator(svc, params)

	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, igw := range resp.InternetGateways {
			attachments, err := convert.JsonToDictSlice(igw.Attachments)
			if err != nil {
				return nil, err
			}

			mqlIgw, err := CreateResource(a.MqlRuntime, ResourceAwsEc2Internetgateway,
				map[string]*llx.RawData{
					"arn":         llx.StringData(fmt.Sprintf(internetGwArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(igw.InternetGatewayId))),
					"id":          llx.StringDataPtr(igw.InternetGatewayId),
					"region":      llx.StringData(a.Region.Data),
					"attachments": llx.ArrayData(attachments, types.Any),
					"tags":        llx.MapData(toInterfaceMap(ec2TagsToMap(igw.Tags)), types.String),
				})
			if err != nil {
				return nil, err
			}
			igws = append(igws, mqlIgw)
		}
	}
	return igws, nil
}

// Security Groups link implementation

func (a *mqlAwsVpc) securityGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcId := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	sgs := []any{}

	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, vpcFilter(vpcId))
	params := &ec2.DescribeSecurityGroupsInput{Filters: filters}
	paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, params)

	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, sg := range resp.SecurityGroups {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(sg.Tags)) {
				log.Debug().Interface("security_group", sg.GroupId).Msg("excluding security group due to filters")
				continue
			}

			mqlSg, err := NewResource(a.MqlRuntime, ResourceAwsEc2Securitygroup,
				map[string]*llx.RawData{
					"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(sg.GroupId))),
				})
			if err != nil {
				return nil, err
			}
			sgs = append(sgs, mqlSg)
		}
	}
	return sgs, nil
}

// Network ACLs link implementation

func (a *mqlAwsVpc) networkAcls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcId := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	acls := []any{}

	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, vpcFilter(vpcId))
	params := &ec2.DescribeNetworkAclsInput{Filters: filters}
	paginator := ec2.NewDescribeNetworkAclsPaginator(svc, params)

	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, acl := range resp.NetworkAcls {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(acl.Tags)) {
				log.Debug().Interface("network_acl", acl.NetworkAclId).Msg("excluding network acl due to filters")
				continue
			}

			mqlAcl, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkacl,
				map[string]*llx.RawData{
					"arn": llx.StringData(fmt.Sprintf(networkAclArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(acl.NetworkAclId))),
				})
			if err != nil {
				return nil, err
			}
			acls = append(acls, mqlAcl)
		}
	}
	return acls, nil
}

func (a *mqlAwsVpc) defaultSecurityGroup() (*mqlAwsEc2Securitygroup, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeSecurityGroups(ctx, &ec2.DescribeSecurityGroupsInput{
		Filters: []vpctypes.Filter{
			vpcFilter(a.Id.Data),
			{Name: aws.String("group-name"), Values: []string{"default"}},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.SecurityGroups) == 0 {
		a.DefaultSecurityGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	mqlSg, err := NewResource(a.MqlRuntime, ResourceAwsEc2Securitygroup,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(resp.SecurityGroups[0].GroupId))),
		})
	if err != nil {
		return nil, err
	}
	return mqlSg.(*mqlAwsEc2Securitygroup), nil
}

func (a *mqlAwsVpc) defaultNetworkAcl() (*mqlAwsEc2Networkacl, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
		Filters: []vpctypes.Filter{
			vpcFilter(a.Id.Data),
			{Name: aws.String("default"), Values: []string{"true"}},
		},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.NetworkAcls) == 0 {
		a.DefaultNetworkAcl.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	mqlAcl, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkacl,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(networkAclArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(resp.NetworkAcls[0].NetworkAclId))),
		})
	if err != nil {
		return nil, err
	}
	return mqlAcl.(*mqlAwsEc2Networkacl), nil
}

func (a *mqlAwsVpc) blockPublicAccessOptions() (any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	region := a.Region.Data

	// VPC Block Public Access is account/region-scoped, so every VPC in a
	// region returns identical data — cache it per region on the connection.
	cacheKey := "_vpc_bpa_" + region
	if cached, ok := conn.GetCachedValue(cacheKey); ok {
		return cached, nil
	}

	svc := conn.Ec2(region)
	ctx := context.Background()

	resp, err := svc.DescribeVpcBlockPublicAccessOptions(ctx, &ec2.DescribeVpcBlockPublicAccessOptionsInput{})
	if err != nil {
		if Is400AccessDeniedError(err) {
			conn.SetCachedValue(cacheKey, nil)
			return nil, nil
		}
		return nil, err
	}
	opts := resp.VpcBlockPublicAccessOptions
	if opts == nil {
		conn.SetCachedValue(cacheKey, nil)
		return nil, nil
	}
	lastUpdate := ""
	if opts.LastUpdateTimestamp != nil {
		lastUpdate = opts.LastUpdateTimestamp.Format(time.RFC3339)
	}
	result := map[string]any{
		"internetGatewayBlockMode": string(opts.InternetGatewayBlockMode),
		"state":                    string(opts.State),
		"exclusionsAllowed":        string(opts.ExclusionsAllowed),
		"managedBy":                string(opts.ManagedBy),
		"reason":                   convert.ToValue(opts.Reason),
		"lastUpdateTimestamp":      lastUpdate,
	}
	conn.SetCachedValue(cacheKey, result)
	return result, nil
}

// VPN Gateway implementation

func (a *mqlAwsVpcVpnGateway) id() (string, error) {
	return a.Arn.Data, nil
}

const vpnGatewayArnPattern = "arn:aws:ec2:%s:%s:vpn-gateway/%s"

func initAwsVpcVpnGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil && args["id"] == nil {
		return nil, nil, errors.New("arn or id required to fetch aws vpn gateway")
	}

	var vgwId, region string
	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		parsed, err := arn.Parse(arnVal)
		if err == nil {
			parts := strings.Split(parsed.Resource, "/")
			if len(parts) == 2 {
				vgwId = parts[1]
				region = parsed.Region
			}
		}
	}
	if args["id"] != nil {
		vgwId = args["id"].Value.(string)
	}
	if args["region"] != nil {
		region = args["region"].Value.(string)
	}
	if vgwId == "" {
		return nil, nil, errors.New("no vpn gateway id specified")
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	ctx := context.Background()

	if region == "" {
		regions, err := conn.Regions()
		if err != nil {
			return nil, nil, err
		}
		for _, r := range regions {
			svc := conn.Ec2(r)
			resp, err := svc.DescribeVpnGateways(ctx, &ec2.DescribeVpnGatewaysInput{
				VpnGatewayIds: []string{vgwId},
			})
			if err != nil {
				continue
			}
			if len(resp.VpnGateways) > 0 {
				region = r
				return buildVpnGatewayResource(runtime, region, conn, resp.VpnGateways[0])
			}
		}
		return nil, nil, errors.New("vpn gateway not found")
	}

	svc := conn.Ec2(region)
	resp, err := svc.DescribeVpnGateways(ctx, &ec2.DescribeVpnGatewaysInput{
		VpnGatewayIds: []string{vgwId},
	})
	if err != nil {
		return nil, nil, err
	}
	if len(resp.VpnGateways) == 0 {
		return nil, nil, errors.New("vpn gateway not found")
	}
	return buildVpnGatewayResource(runtime, region, conn, resp.VpnGateways[0])
}

func buildVpnGatewayResource(runtime *plugin.Runtime, region string, conn *connection.AwsConnection, vgw vpctypes.VpnGateway) (map[string]*llx.RawData, plugin.Resource, error) {
	attachments, _ := convert.JsonToDictSlice(vgw.VpcAttachments)

	var availabilityZone string
	if vgw.AvailabilityZone != nil {
		availabilityZone = *vgw.AvailabilityZone
	}
	var amazonSideAsn int64
	if vgw.AmazonSideAsn != nil {
		amazonSideAsn = *vgw.AmazonSideAsn
	}

	args := map[string]*llx.RawData{
		"id":               llx.StringDataPtr(vgw.VpnGatewayId),
		"arn":              llx.StringData(fmt.Sprintf(vpnGatewayArnPattern, region, conn.AccountId(), convert.ToValue(vgw.VpnGatewayId))),
		"region":           llx.StringData(region),
		"state":            llx.StringData(string(vgw.State)),
		"type":             llx.StringData(string(vgw.Type)),
		"amazonSideAsn":    llx.IntData(amazonSideAsn),
		"availabilityZone": llx.StringData(availabilityZone),
		"attachments":      llx.ArrayData(attachments, types.Any),
		"tags":             llx.MapData(toInterfaceMap(ec2TagsToMap(vgw.Tags)), types.String),
	}

	res, err := CreateResource(runtime, ResourceAwsVpcVpnGateway, args)
	if err != nil {
		return nil, nil, err
	}
	res.(*mqlAwsVpcVpnGateway).region = region
	return nil, res, nil
}

func (a *mqlAwsVpc) vpnGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	vpcId := a.Id.Data

	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()
	vgws := []any{}

	filterKeyVal := "attachment.vpc-id"
	params := &ec2.DescribeVpnGatewaysInput{
		Filters: []vpctypes.Filter{{Name: &filterKeyVal, Values: []string{vpcId}}},
	}

	resp, err := svc.DescribeVpnGateways(ctx, params)
	if err != nil {
		return nil, err
	}

	for _, vgw := range resp.VpnGateways {
		attachments, err := convert.JsonToDictSlice(vgw.VpcAttachments)
		if err != nil {
			return nil, err
		}

		var availabilityZone string
		if vgw.AvailabilityZone != nil {
			availabilityZone = *vgw.AvailabilityZone
		}

		var amazonSideAsn int64
		if vgw.AmazonSideAsn != nil {
			amazonSideAsn = *vgw.AmazonSideAsn
		}

		mqlVgw, err := CreateResource(a.MqlRuntime, ResourceAwsVpcVpnGateway,
			map[string]*llx.RawData{
				"id":               llx.StringDataPtr(vgw.VpnGatewayId),
				"arn":              llx.StringData(fmt.Sprintf(vpnGatewayArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(vgw.VpnGatewayId))),
				"region":           llx.StringData(a.Region.Data),
				"state":            llx.StringData(string(vgw.State)),
				"type":             llx.StringData(string(vgw.Type)),
				"amazonSideAsn":    llx.IntData(amazonSideAsn),
				"availabilityZone": llx.StringData(availabilityZone),
				"attachments":      llx.ArrayData(attachments, types.Any),
				"tags":             llx.MapData(toInterfaceMap(ec2TagsToMap(vgw.Tags)), types.String),
			})
		if err != nil {
			return nil, err
		}
		mqlVgw.(*mqlAwsVpcVpnGateway).region = a.Region.Data
		vgws = append(vgws, mqlVgw)
	}
	return vgws, nil
}

// VPC DNS attributes (#14, #15)

func (a *mqlAwsVpc) enableDnsSupport() (bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		VpcId:     aws.String(a.Id.Data),
		Attribute: vpctypes.VpcAttributeNameEnableDnsSupport,
	})
	if err != nil {
		return false, err
	}
	if resp.EnableDnsSupport != nil && resp.EnableDnsSupport.Value != nil {
		return *resp.EnableDnsSupport.Value, nil
	}
	return false, nil
}

func (a *mqlAwsVpc) enableDnsHostnames() (bool, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeVpcAttribute(ctx, &ec2.DescribeVpcAttributeInput{
		VpcId:     aws.String(a.Id.Data),
		Attribute: vpctypes.VpcAttributeNameEnableDnsHostnames,
	})
	if err != nil {
		return false, err
	}
	if resp.EnableDnsHostnames != nil && resp.EnableDnsHostnames.Value != nil {
		return *resp.EnableDnsHostnames.Value, nil
	}
	return false, nil
}

// DHCP Options (#13)

func (a *mqlAwsEc2DhcpOptions) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsEc2DhcpOptions) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(dhcpOptionsArnPattern, a.Region.Data, conn.AccountId(), a.Id.Data), nil
}

func (a *mqlAwsVpc) dhcpOptions() (*mqlAwsEc2DhcpOptions, error) {
	dhcpOptionsId := a.DhcpOptionsId.Data
	if dhcpOptionsId == "" {
		a.DhcpOptions.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	resp, err := svc.DescribeDhcpOptions(ctx, &ec2.DescribeDhcpOptionsInput{
		DhcpOptionsIds: []string{dhcpOptionsId},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.DhcpOptions) == 0 {
		a.DhcpOptions.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	opts := resp.DhcpOptions[0]
	configs, _ := convert.JsonToDictSlice(opts.DhcpConfigurations)

	mqlDhcp, err := CreateResource(a.MqlRuntime, ResourceAwsEc2DhcpOptions,
		map[string]*llx.RawData{
			"id":             llx.StringDataPtr(opts.DhcpOptionsId),
			"region":         llx.StringData(a.Region.Data),
			"tags":           llx.MapData(toInterfaceMap(ec2TagsToMap(opts.Tags)), types.String),
			"configurations": llx.ArrayData(configs, types.Any),
		})
	if err != nil {
		return nil, err
	}
	return mqlDhcp.(*mqlAwsEc2DhcpOptions), nil
}

// VPC Endpoint methods (#16-19)

func (a *mqlAwsVpcEndpoint) securityGroups() ([]any, error) {
	return a.securityGroupIdHandler.newSecurityGroupResources(a.MqlRuntime)
}

func (a *mqlAwsVpcEndpoint) routeTables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	rts := []any{}
	for _, rtId := range a.cacheRouteTableIds {
		mqlRt, err := NewResource(a.MqlRuntime, ResourceAwsVpcRoutetable,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(routeTableArnPattern, a.region, conn.AccountId(), rtId)),
			})
		if err != nil {
			return nil, err
		}
		rts = append(rts, mqlRt)
	}
	return rts, nil
}

// subnetRefs resolves the endpoint's subnet IDs to typed subnet resources.
func (a *mqlAwsVpcEndpoint) subnetRefs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	subnets := []any{}
	for _, subnetId := range a.cacheSubnetIds {
		if subnetId == "" {
			continue
		}
		mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, conn.AccountId(), subnetId)),
			})
		if err != nil {
			return nil, err
		}
		subnets = append(subnets, mqlSubnet)
	}
	return subnets, nil
}

// hasWildcardPolicy reports whether the endpoint policy leaves access
// unrestricted, which is what the default policy AWS attaches does.
func (a *mqlAwsVpcEndpoint) hasWildcardPolicy() (bool, error) {
	statements := a.GetPolicyStatements()
	if statements.Error != nil {
		return false, statements.Error
	}
	return statementsAllowWildcard(statements.Data)
}

func (a *mqlAwsVpcEndpoint) networkInterfaces() ([]any, error) {
	enis := []any{}
	for _, eniId := range a.cacheNetworkInterfaceIds {
		mqlEni, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkinterface,
			map[string]*llx.RawData{
				"id": llx.StringData(eniId),
			})
		if err != nil {
			return nil, err
		}
		enis = append(enis, mqlEni)
	}
	return enis, nil
}

// Flow log methods (#20-22)

type mqlAwsVpcFlowlogInternal struct {
	cacheDeliverLogsPermissionArn *string
	cacheLogGroupName             *string
	cacheLogDestination           *string
	cacheLogDestinationType       string
	region                        string
}

// vpcFlowLogCacheKey builds the cache key for an aws.vpc.flowlog.
//
// The resource has no id() method, so without an explicit "__id" every flow
// log in the account keys on the empty string and CreateResource hands back
// whichever one was built first. A VPC logging ALL traffic and a VPC logging
// REJECT then report identical rows, and a check asking whether rejected
// traffic is captured reads an unrelated flow log's trafficType.
//
// Flow log ids are unique per account; the region keeps the key aligned with
// the rest of the provider and with the ARN the arn() accessor builds.
func vpcFlowLogCacheKey(region, flowLogID string) string {
	return region + "/" + flowLogID
}

func (a *mqlAwsVpcFlowlog) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(vpcFlowLogArnPattern, a.Region.Data, conn.AccountId(), a.Id.Data), nil
}

func (a *mqlAwsVpcFlowlog) iamRole() (*mqlAwsIamRole, error) {
	if a.cacheDeliverLogsPermissionArn == nil || *a.cacheDeliverLogsPermissionArn == "" {
		a.IamRole.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlRole, err := NewResource(a.MqlRuntime, "aws.iam.role",
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheDeliverLogsPermissionArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlRole.(*mqlAwsIamRole), nil
}

func (a *mqlAwsVpcFlowlog) logGroup() (*mqlAwsCloudwatchLoggroup, error) {
	if a.cacheLogGroupName == nil || *a.cacheLogGroupName == "" || a.cacheLogDestinationType != "cloud-watch-logs" {
		a.LogGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	logGroupArn := fmt.Sprintf("arn:aws:logs:%s:%s:log-group:%s", a.region, conn.AccountId(), *a.cacheLogGroupName)
	mqlLogGroup, err := NewResource(a.MqlRuntime, ResourceAwsCloudwatchLoggroup,
		map[string]*llx.RawData{
			"arn": llx.StringData(logGroupArn),
		})
	if err != nil {
		return nil, err
	}
	return mqlLogGroup.(*mqlAwsCloudwatchLoggroup), nil
}

func (a *mqlAwsVpcFlowlog) s3Bucket() (*mqlAwsS3Bucket, error) {
	if a.cacheLogDestination == nil || *a.cacheLogDestination == "" || a.cacheLogDestinationType != "s3" {
		a.S3Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// Parse bucket name from ARN: arn:aws:s3:::bucket-name or arn:aws:s3:::bucket-name/prefix
	dest := *a.cacheLogDestination
	parsed, err := arn.Parse(dest)
	if err != nil {
		a.S3Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	bucketName := strings.Split(parsed.Resource, "/")[0]
	if bucketName == "" {
		a.S3Bucket.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	mqlBucket, err := NewResource(a.MqlRuntime, "aws.s3.bucket",
		map[string]*llx.RawData{
			"name": llx.StringData(bucketName),
		})
	if err != nil {
		return nil, err
	}
	return mqlBucket.(*mqlAwsS3Bucket), nil
}

// Subnet methods (#24-26)

func (a *mqlAwsVpcSubnet) networkAcl() (*mqlAwsEc2Networkacl, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	subnetFilter := "association.subnet-id"
	resp, err := svc.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{
		Filters: []vpctypes.Filter{{Name: &subnetFilter, Values: []string{a.Id.Data}}},
	})
	if err != nil {
		return nil, err
	}
	if len(resp.NetworkAcls) == 0 {
		a.NetworkAcl.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	acl := resp.NetworkAcls[0]
	mqlAcl, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkacl,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(networkAclArnPattern, a.Region.Data, conn.AccountId(), convert.ToValue(acl.NetworkAclId))),
		})
	if err != nil {
		return nil, err
	}
	return mqlAcl.(*mqlAwsEc2Networkacl), nil
}

func (a *mqlAwsVpcSubnet) natGateway() (*mqlAwsVpcNatgateway, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	subnetFilter := "subnet-id"
	resp, err := svc.DescribeNatGateways(ctx, &ec2.DescribeNatGatewaysInput{
		Filter: []vpctypes.Filter{{Name: &subnetFilter, Values: []string{a.Id.Data}}},
	})
	if err != nil {
		return nil, err
	}

	// Find an active NAT gateway
	for _, gw := range resp.NatGateways {
		if gw.State == vpctypes.NatGatewayStateAvailable || gw.State == vpctypes.NatGatewayStatePending {
			return newMqlAwsVpcNatgateway(a.MqlRuntime, a.Region.Data, gw)
		}
	}
	a.NatGateway.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsVpcSubnet) flowLogs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.Region.Data)
	ctx := context.Background()

	filterKeyVal := "resource-id"
	params := &ec2.DescribeFlowLogsInput{
		Filter: []vpctypes.Filter{{Name: &filterKeyVal, Values: []string{a.Id.Data}}},
	}
	paginator := ec2.NewDescribeFlowLogsPaginator(svc, params)
	flowLogs := []any{}
	for paginator.HasMorePages() {
		resp, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, flowLog := range resp.FlowLogs {
			mqlFlowLog, err := CreateResource(a.MqlRuntime, ResourceAwsVpcFlowlog,
				map[string]*llx.RawData{
					"__id":                   llx.StringData(vpcFlowLogCacheKey(a.Region.Data, convert.ToValue(flowLog.FlowLogId))),
					"createdAt":              llx.TimeDataPtr(flowLog.CreationTime),
					"destination":            llx.StringDataPtr(flowLog.LogDestination),
					"destinationType":        llx.StringData(string(flowLog.LogDestinationType)),
					"deliverLogsStatus":      llx.StringDataPtr(flowLog.DeliverLogsStatus),
					"id":                     llx.StringDataPtr(flowLog.FlowLogId),
					"logFormat":              llx.StringDataPtr(flowLog.LogFormat),
					"maxAggregationInterval": llx.IntDataDefault(flowLog.MaxAggregationInterval, 0),
					"region":                 llx.StringData(a.Region.Data),
					"status":                 llx.StringDataPtr(flowLog.FlowLogStatus),
					"tags":                   llx.MapData(toInterfaceMap(ec2TagsToMap(flowLog.Tags)), types.String),
					"trafficType":            llx.StringData(string(flowLog.TrafficType)),
					"vpc":                    llx.StringData(a.cacheVpcId),
				})
			if err != nil {
				return nil, err
			}
			fl := mqlFlowLog.(*mqlAwsVpcFlowlog)
			fl.cacheDeliverLogsPermissionArn = flowLog.DeliverLogsPermissionArn
			fl.cacheLogGroupName = flowLog.LogGroupName
			fl.cacheLogDestination = flowLog.LogDestination
			fl.cacheLogDestinationType = string(flowLog.LogDestinationType)
			fl.region = a.Region.Data
			flowLogs = append(flowLogs, mqlFlowLog)
		}
	}
	return flowLogs, nil
}

func (a *mqlAwsVpcSubnet) networkInterfaces() ([]any, error) {
	return networkInterfacesByFilter(a.MqlRuntime, a.Region.Data, "subnet-id", a.Id.Data)
}

func (a *mqlAwsVpcSubnet) instances() ([]any, error) {
	nis := a.GetNetworkInterfaces()
	if nis.Error != nil {
		return nil, nis.Error
	}
	return instancesFromNetworkInterfaces(nis.Data)
}

// VPN Gateway methods (#40)

type mqlAwsVpcVpnGatewayInternal struct {
	region string
}

func (a *mqlAwsVpcVpnGateway) vpnConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.region)
	ctx := context.Background()

	filterKeyVal := "vpn-gateway-id"
	resp, err := svc.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{
		Filters: []vpctypes.Filter{{Name: &filterKeyVal, Values: []string{a.Id.Data}}},
	})
	if err != nil {
		return nil, err
	}

	vpnConns := []any{}
	for _, vpnConn := range resp.VpnConnections {
		mqlVpnConn, err := newMqlVpnConnection(a.MqlRuntime, a.region, conn.AccountId(), vpnConn)
		if err != nil {
			return nil, err
		}
		vpnConns = append(vpnConns, mqlVpnConn)
	}
	return vpnConns, nil
}

func (a *mqlAwsVpc) cloudformationStack() (*mqlAwsCloudformationStack, error) {
	stack, err := cloudformationStackForTags(a.MqlRuntime, a.Region.Data, a.Tags.Data)
	if err != nil {
		return nil, err
	}
	if stack == nil {
		a.CloudformationStack.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return stack, nil
}

func (a *mqlAwsVpc) managedBy() (string, error) {
	return managedByFromTags(a.Tags.Data), nil
}
