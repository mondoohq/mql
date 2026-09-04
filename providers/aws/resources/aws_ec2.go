// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/base64"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/aws/smithy-go"
	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/aws/connection"
	"go.mondoo.com/mql/types"
)

// imdsSupport returns a human-readable IMDS support value. The AWS API only
// returns a value ("v2.0") when IMDSv2 is explicitly configured on the AMI.
// For all other images the field is empty, so we default to "none".
func imdsSupport(v ec2types.ImdsSupportValues) string {
	if v == "" {
		return "none"
	}
	return string(v)
}

func bootMode(v string) string {
	if v == "" {
		return "undefined"
	}
	return v
}

func (e *mqlAwsEc2) id() (string, error) {
	return ResourceAwsEc2, nil
}

func initAwsEc2Eip(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["publicIp"] == nil {
		return nil, nil, errors.New("publicIp required to fetch aws ec2 eip")
	}
	p := args["publicIp"].Value.(string)

	if args["region"] == nil {
		return nil, nil, errors.New("region required to fetch aws ec2 eip")
	}
	r := args["region"].Value.(string)

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(r)
	ctx := context.Background()
	address, err := svc.DescribeAddresses(ctx, &ec2.DescribeAddressesInput{Filters: []ec2types.Filter{{Name: aws.String("public-ip"), Values: []string{p}}}})
	if err != nil {
		return nil, nil, err
	}

	if len(address.Addresses) > 0 {
		add := address.Addresses[0]
		// AssociationId, not AllocationId: AllocationId is the allocation handle
		// present on every VPC Elastic IP whether or not it is associated (it was
		// only absent for EC2-Classic, retired in 2022), so keying on it made
		// `attached` unconditionally true and `where(attached == false)` empty.
		attached := add.AssociationId != nil
		args["publicIp"] = llx.StringDataPtr(add.PublicIp)
		args["allocationId"] = llx.StringDataPtr(add.AllocationId)
		args["attached"] = llx.BoolData(attached) // this is false if allocationId is null and true otherwise
		args["networkInterfaceId"] = llx.StringDataPtr(add.NetworkInterfaceId)
		args["networkInterfaceOwnerId"] = llx.StringDataPtr(add.NetworkInterfaceOwnerId)
		args["privateIpAddress"] = llx.StringDataPtr(add.PrivateIpAddress)
		args["publicIpv4Pool"] = llx.StringDataPtr(add.PublicIpv4Pool)
		args["tags"] = llx.MapData(toInterfaceMap(ec2TagsToMap(add.Tags)), types.String)
		args["region"] = llx.StringData(r)

		res, err := CreateResource(runtime, ResourceAwsEc2Eip, args)
		if err != nil {
			return nil, nil, err
		}
		res.(*mqlAwsEc2Eip).eipCache = add
		return nil, res, nil
	}
	// Returning (args, nil, nil) here would let the runtime create a resource
	// whose fields are all unset, which surfaces as malformed nil data when
	// those fields are queried.
	return nil, nil, fmt.Errorf("aws.ec2.eip with publicIp %q not found", p)
}

func (a *mqlAwsEc2Eip) id() (string, error) {
	// publicIp is always present and globally unique for an Elastic IP, whereas
	// networkInterfaceId is empty for unattached EIPs (which would collide them
	// all to a single cache entry). region+publicIp also matches the key used
	// when EIPs are resolved by cross-references (nat gateway, network interface).
	return "aws.ec2.eip/" + a.Region.Data + "/" + a.PublicIp.Data, nil
}

type mqlAwsEc2EipInternal struct {
	eipCache ec2types.Address
}

func (a *mqlAwsEc2Eip) instance() (*mqlAwsEc2Instance, error) {
	regionVal := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	if a.eipCache.InstanceId != nil {
		instanceId := a.eipCache.InstanceId
		mqlEc2Instance, err := NewResource(a.MqlRuntime, ResourceAwsEc2Instance,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(ec2InstanceArnPattern, regionVal, conn.AccountId(), convert.ToValue(instanceId))),
			})
		if err != nil {
			return nil, err
		}
		return mqlEc2Instance.(*mqlAwsEc2Instance), err
	}
	a.Instance.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (a *mqlAwsEc2Eip) networkInterface() (*mqlAwsEc2Networkinterface, error) {
	if a.eipCache.NetworkInterfaceId == nil || *a.eipCache.NetworkInterfaceId == "" {
		a.NetworkInterface.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlEni, err := NewResource(a.MqlRuntime, ResourceAwsEc2Networkinterface,
		map[string]*llx.RawData{
			"id": llx.StringDataPtr(a.eipCache.NetworkInterfaceId),
		})
	if err != nil {
		return nil, err
	}
	return mqlEni.(*mqlAwsEc2Networkinterface), nil
}

func (a *mqlAwsEc2) eips() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEIPs(conn), 5)
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

func (a *mqlAwsEc2) getEIPs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ec2>getEIPs>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			params := &ec2.DescribeAddressesInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			} // no pagination
			addresses, err := svc.DescribeAddresses(ctx, params)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}

			for _, add := range addresses.Addresses {
				if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(add.Tags)) {
					log.Debug().Interface("acl", add.AllocationId).Msg("excluding elastic ip address due to filters")
					continue
				}

				// AssociationId, not AllocationId: AllocationId is the allocation handle
				// present on every VPC Elastic IP whether or not it is associated (it was
				// only absent for EC2-Classic, retired in 2022), so keying on it made
				// `attached` unconditionally true and `where(attached == false)` empty.
				attached := add.AssociationId != nil
				args := map[string]*llx.RawData{
					"publicIp":                llx.StringDataPtr(add.PublicIp),
					"allocationId":            llx.StringDataPtr(add.AllocationId),
					"attached":                llx.BoolData(attached), // this is false if allocationId is null and true otherwise
					"networkInterfaceId":      llx.StringDataPtr(add.NetworkInterfaceId),
					"networkInterfaceOwnerId": llx.StringDataPtr(add.NetworkInterfaceOwnerId),
					"privateIpAddress":        llx.StringDataPtr(add.PrivateIpAddress),
					"publicIpv4Pool":          llx.StringDataPtr(add.PublicIpv4Pool),
					"tags":                    llx.MapData(toInterfaceMap(ec2TagsToMap(add.Tags)), types.String),
					"region":                  llx.StringData(region),
				}
				mqlAddress, err := CreateResource(a.MqlRuntime, ResourceAwsEc2Eip, args)
				if err != nil {
					return nil, err
				}
				mqlAddress.(*mqlAwsEc2Eip).eipCache = add

				res = append(res, mqlAddress)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2Networkacl) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2) networkAcls() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getNetworkACLs(conn), 5)
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

func (a *mqlAwsEc2) getNetworkACLs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ec2>getNetworkACLs>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			params := &ec2.DescribeNetworkAclsInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			}
			paginator := ec2.NewDescribeNetworkAclsPaginator(svc, params)
			for paginator.HasMorePages() {
				networkAcls, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, acl := range networkAcls.NetworkAcls {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(acl.Tags)) {
						log.Debug().Interface("acl", acl.NetworkAclId).Msg("excluding network acl due to filters")
						continue
					}
					assoc := []any{}
					for _, association := range acl.Associations {
						mqlNetworkAclAssoc, err := CreateResource(a.MqlRuntime, ResourceAwsEc2NetworkaclAssociation,
							map[string]*llx.RawData{
								"__id":          llx.StringData("aws.ec2.networkacl.association/" + convert.ToValue(association.NetworkAclAssociationId)),
								"associationId": llx.StringDataPtr(association.NetworkAclAssociationId),
								"networkAclId":  llx.StringDataPtr(association.NetworkAclId),
							})
						if err == nil {
							assocRes := mqlNetworkAclAssoc.(*mqlAwsEc2NetworkaclAssociation)
							assocRes.cacheSubnetId = association.SubnetId
							assocRes.region = region
							assocRes.accountID = conn.AccountId()
							assoc = append(assoc, mqlNetworkAclAssoc)
						}
					}

					mqlNetworkAcl, err := CreateResource(a.MqlRuntime, ResourceAwsEc2Networkacl,
						map[string]*llx.RawData{
							"arn":          llx.StringData(fmt.Sprintf(networkAclArnPattern, region, conn.AccountId(), convert.ToValue(acl.NetworkAclId))),
							"id":           llx.StringDataPtr(acl.NetworkAclId),
							"region":       llx.StringData(region),
							"isDefault":    llx.BoolDataPtr(acl.IsDefault),
							"tags":         llx.MapData(toInterfaceMap(ec2TagsToMap(acl.Tags)), types.String),
							"associations": llx.ArrayData(assoc, types.Type(ResourceAwsEc2NetworkaclAssociation)),
						})
					if err != nil {
						return nil, err
					}

					res = append(res, mqlNetworkAcl)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2NetworkaclEntry) id() (string, error) {
	return a.Id.Data, nil
}

// cidrEntryIsPublic reports whether a network ACL entry opens traffic to the
// entire internet, matching every IPv4 address (0.0.0.0/0) or every IPv6
// address (::/0).
func cidrEntryIsPublic(cidrBlock, ipv6CidrBlock string) bool {
	return cidrIsPublic(cidrBlock) || cidrIsPublic(ipv6CidrBlock)
}

// isPublic reports whether the entry opens traffic to the entire internet.
func (a *mqlAwsEc2NetworkaclEntry) isPublic() (bool, error) {
	return cidrEntryIsPublic(a.CidrBlock.Data, a.Ipv6CidrBlock.Data), nil
}

func initAwsEc2Networkacl(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil && args["id"] == nil {
		return nil, nil, errors.New("arn or id required to fetch aws network acl")
	}

	// load all network acls
	obj, err := CreateResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	awsEc2 := obj.(*mqlAwsEc2)

	rawResources := awsEc2.GetNetworkAcls()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	var match func(acl *mqlAwsEc2Networkacl) bool

	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		match = func(acl *mqlAwsEc2Networkacl) bool {
			return acl.Arn.Data == arnVal
		}
	} else if args["id"] != nil {
		idVal := args["id"].Value.(string)
		match = func(acl *mqlAwsEc2Networkacl) bool {
			return acl.Id.Data == idVal
		}
	}

	for _, rawResource := range rawResources.Data {
		acl := rawResource.(*mqlAwsEc2Networkacl)
		if match(acl) {
			return args, acl, nil
		}
	}

	return nil, nil, errors.New("network acl not found")
}

// NACL association subnet (#31)

type mqlAwsEc2NetworkaclAssociationInternal struct {
	cacheSubnetId *string
	region        string
	accountID     string
}

func (a *mqlAwsEc2NetworkaclAssociation) subnet() (*mqlAwsVpcSubnet, error) {
	if a.cacheSubnetId == nil || *a.cacheSubnetId == "" {
		a.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlSubnet, err := NewResource(a.MqlRuntime, ResourceAwsVpcSubnet,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(subnetArnPattern, a.region, a.accountID, *a.cacheSubnetId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlSubnet.(*mqlAwsVpcSubnet), nil
}

func (a *mqlAwsEc2NetworkaclEntryPortrange) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsEc2Networkacl) entries() ([]any, error) {
	id := a.Id.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	ctx := context.Background()
	networkacls, err := svc.DescribeNetworkAcls(ctx, &ec2.DescribeNetworkAclsInput{NetworkAclIds: []string{id}})
	if err != nil {
		return nil, err
	}

	if len(networkacls.NetworkAcls) == 0 {
		return nil, errors.New("aws network acl not found")
	}

	res := []any{}
	for _, entry := range networkacls.NetworkAcls[0].Entries {
		egress := convert.ToValue(entry.Egress)
		entryId := fmt.Sprintf("%s-%d", id, convert.ToValue(entry.RuleNumber))
		if egress {
			entryId += "-egress"
		} else {
			entryId += "-ingress"
		}
		args := map[string]*llx.RawData{
			"egress":        llx.BoolData(egress),
			"ruleAction":    llx.StringData(string(entry.RuleAction)),
			"ruleNumber":    llx.IntDataDefault(entry.RuleNumber, 0),
			"protocol":      llx.StringDataPtr(entry.Protocol),
			"cidrBlock":     llx.StringDataPtr(entry.CidrBlock),
			"ipv6CidrBlock": llx.StringDataPtr(entry.Ipv6CidrBlock),
			"id":            llx.StringData(entryId),
		}
		if entry.PortRange != nil {
			mqlPortRange, err := CreateResource(a.MqlRuntime, ResourceAwsEc2NetworkaclEntryPortrange,
				map[string]*llx.RawData{
					"from": llx.IntDataDefault(entry.PortRange.From, -1),
					"to":   llx.IntDataDefault(entry.PortRange.To, -1),
					"id":   llx.StringData(fmt.Sprintf("%s-%d", entryId, convert.ToValue(entry.PortRange.From))),
				})
			if err != nil {
				return nil, err
			}
			args["portRange"] = llx.ResourceData(mqlPortRange, mqlPortRange.MqlName())
		} else {
			args["portRange"] = llx.NilData
		}

		mqlAclEntry, err := CreateResource(a.MqlRuntime, ResourceAwsEc2NetworkaclEntry, args)
		if err != nil {
			return nil, err
		}
		// Back-reference so an entry can compare itself against its siblings,
		// which is what shadowing depends on.
		mqlAclEntry.(*mqlAwsEc2NetworkaclEntry).parentAcl = a
		res = append(res, mqlAclEntry)
	}

	return res, nil
}

func (a *mqlAwsEc2NetworkaclEntry) portRange() (*mqlAwsEc2NetworkaclEntryPortrange, error) {
	return a.PortRange.Data, nil
}

func (a *mqlAwsEc2Securitygroup) isAttachedToNetworkInterface() (bool, error) {
	// Reuse the cached networkInterfaces field (same group-id DescribeNetworkInterfaces
	// call) so a policy that queries both this and networkInterfaces/instances only
	// hits the API once.
	nis := a.GetNetworkInterfaces()
	if nis.Error != nil {
		return false, nis.Error
	}
	return len(nis.Data) > 0, nil
}

type mqlAwsEc2SecuritygroupInternal struct {
	cacheIpPerms       []ec2types.IpPermission
	cacheIpPermsEgress []ec2types.IpPermission
	groupId            string
	region             string
	cacheVpc           *string
}

func (a *mqlAwsEc2) getSecurityGroups(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ec2>getSecurityGroups>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			params := &ec2.DescribeSecurityGroupsInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			}
			paginator := ec2.NewDescribeSecurityGroupsPaginator(svc, params)
			for paginator.HasMorePages() {
				securityGroups, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, group := range securityGroups.SecurityGroups {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(group.Tags)) {
						log.Debug().Interface("securitygroup", group.GroupId).Msg("excluding security group due to filters")
						continue
					}

					mqlSG, err := buildSecurityGroupResource(a.MqlRuntime, region, conn.AccountId(), group)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSG)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2Securitygroup) vpc() (*mqlAwsVpc, error) {
	if a.cacheVpc != nil {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		mqlVpc, err := NewResource(a.MqlRuntime, ResourceAwsVpc,
			map[string]*llx.RawData{
				"arn": llx.StringData(fmt.Sprintf(vpcArnPattern, a.region, conn.AccountId(), convert.ToValue(a.cacheVpc))),
			})
		if err != nil {
			return nil, err
		}
		return mqlVpc.(*mqlAwsVpc), nil
	}
	a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

type mqlAwsEc2SecuritygroupIppermissionInternal struct {
	cachePrefixListIds []ec2types.PrefixListId
	cacheRegion        string
	cacheAccountId     string
}

func buildIpRangeDetails(ranges []ec2types.IpRange) ([]any, []any) {
	ipRanges := []any{}
	ipRangeDetails := []any{}
	for r := range ranges {
		iprange := ranges[r]
		if iprange.CidrIp != nil {
			ipRanges = append(ipRanges, *iprange.CidrIp)
		}
		ipRangeDetails = append(ipRangeDetails, map[string]any{
			"cidr":        convert.ToValue(iprange.CidrIp),
			"description": convert.ToValue(iprange.Description),
		})
	}
	return ipRanges, ipRangeDetails
}

func buildIpv6RangeDetails(ranges []ec2types.Ipv6Range) ([]any, []any) {
	ipv6Ranges := []any{}
	ipv6RangeDetails := []any{}
	for r := range ranges {
		iprange := ranges[r]
		if iprange.CidrIpv6 != nil {
			ipv6Ranges = append(ipv6Ranges, *iprange.CidrIpv6)
		}
		ipv6RangeDetails = append(ipv6RangeDetails, map[string]any{
			"cidr":        convert.ToValue(iprange.CidrIpv6),
			"description": convert.ToValue(iprange.Description),
		})
	}
	return ipv6Ranges, ipv6RangeDetails
}

func (a *mqlAwsEc2Securitygroup) ipPermissions() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	accountId := conn.AccountId()
	mqlIpPermissions := []any{}
	for p, permission := range a.cacheIpPerms {
		ipRanges, ipRangeDetails := buildIpRangeDetails(permission.IpRanges)
		ipv6Ranges, ipv6RangeDetails := buildIpv6RangeDetails(permission.Ipv6Ranges)
		prefixListIds, err := convert.JsonToDictSlice(permission.PrefixListIds)
		if err != nil {
			return nil, err
		}
		userIdGroupPairs, err := convert.JsonToDictSlice(permission.UserIdGroupPairs)
		if err != nil {
			return nil, err
		}
		permissionID := a.groupId + "-" + strconv.Itoa(p)
		peers, err := buildSecurityGroupPeers(a.MqlRuntime, permissionID, a.region, accountId, permission.UserIdGroupPairs)
		if err != nil {
			return nil, err
		}
		mqlSecurityGroupIpPermission, err := CreateResource(a.MqlRuntime, ResourceAwsEc2SecuritygroupIppermission,
			map[string]*llx.RawData{
				"id":               llx.StringData(permissionID),
				"fromPort":         llx.IntDataDefault(permission.FromPort, -1),
				"toPort":           llx.IntDataDefault(permission.ToPort, -1),
				"ipProtocol":       llx.StringDataPtr(permission.IpProtocol),
				"ipRanges":         llx.ArrayData(ipRanges, types.Any),
				"ipRangeDetails":   llx.ArrayData(ipRangeDetails, types.Any),
				"ipv6Ranges":       llx.ArrayData(ipv6Ranges, types.Any),
				"ipv6RangeDetails": llx.ArrayData(ipv6RangeDetails, types.Any),
				"prefixListIds":    llx.ArrayData(prefixListIds, types.Any),
				"userIdGroupPairs": llx.ArrayData(userIdGroupPairs, types.Any),
				"peers":            llx.ArrayData(peers, types.Resource("aws.ec2.securitygroup.ippermission.peer")),
			})
		if err != nil {
			return nil, err
		}
		mqlPerm := mqlSecurityGroupIpPermission.(*mqlAwsEc2SecuritygroupIppermission)
		mqlPerm.cachePrefixListIds = permission.PrefixListIds
		mqlPerm.cacheRegion = a.region
		mqlPerm.cacheAccountId = accountId

		mqlIpPermissions = append(mqlIpPermissions, mqlSecurityGroupIpPermission)
	}
	return mqlIpPermissions, nil
}

func (a *mqlAwsEc2Securitygroup) ipPermissionsEgress() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	accountId := conn.AccountId()
	mqlIpPermissionsEgress := []any{}
	for p := range a.cacheIpPermsEgress {
		permission := a.cacheIpPermsEgress[p]
		ipRanges, ipRangeDetails := buildIpRangeDetails(permission.IpRanges)
		ipv6Ranges, ipv6RangeDetails := buildIpv6RangeDetails(permission.Ipv6Ranges)
		prefixListIds, err := convert.JsonToDictSlice(permission.PrefixListIds)
		if err != nil {
			return nil, err
		}
		userIdGroupPairs, err := convert.JsonToDictSlice(permission.UserIdGroupPairs)
		if err != nil {
			return nil, err
		}
		permissionID := a.groupId + "-" + strconv.Itoa(p) + "-egress"
		peers, err := buildSecurityGroupPeers(a.MqlRuntime, permissionID, a.region, accountId, permission.UserIdGroupPairs)
		if err != nil {
			return nil, err
		}
		mqlSecurityGroupIpPermission, err := CreateResource(a.MqlRuntime, ResourceAwsEc2SecuritygroupIppermission,
			map[string]*llx.RawData{
				"id":               llx.StringData(permissionID),
				"fromPort":         llx.IntDataDefault(permission.FromPort, -1),
				"toPort":           llx.IntDataDefault(permission.ToPort, -1),
				"ipProtocol":       llx.StringDataPtr(permission.IpProtocol),
				"ipRanges":         llx.ArrayData(ipRanges, types.Any),
				"ipRangeDetails":   llx.ArrayData(ipRangeDetails, types.Any),
				"ipv6Ranges":       llx.ArrayData(ipv6Ranges, types.Any),
				"ipv6RangeDetails": llx.ArrayData(ipv6RangeDetails, types.Any),
				"prefixListIds":    llx.ArrayData(prefixListIds, types.Any),
				"userIdGroupPairs": llx.ArrayData(userIdGroupPairs, types.Any),
				"peers":            llx.ArrayData(peers, types.Resource("aws.ec2.securitygroup.ippermission.peer")),
			})
		if err != nil {
			return nil, err
		}
		mqlPerm := mqlSecurityGroupIpPermission.(*mqlAwsEc2SecuritygroupIppermission)
		mqlPerm.cachePrefixListIds = permission.PrefixListIds
		mqlPerm.cacheRegion = a.region
		mqlPerm.cacheAccountId = accountId

		mqlIpPermissionsEgress = append(mqlIpPermissionsEgress, mqlSecurityGroupIpPermission)
	}
	return mqlIpPermissionsEgress, nil
}

func (a *mqlAwsEc2SecuritygroupIppermission) prefixLists() ([]any, error) {
	res := []any{}
	for _, pl := range a.cachePrefixListIds {
		if pl.PrefixListId == nil {
			continue
		}
		plArn := fmt.Sprintf("arn:aws:ec2:%s:%s:prefix-list/%s", a.cacheRegion, a.cacheAccountId, *pl.PrefixListId)
		mqlPL, err := NewResource(a.MqlRuntime, ResourceAwsEc2ManagedPrefixList,
			map[string]*llx.RawData{"arn": llx.StringData(plArn)})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPL)
	}
	return res, nil
}

func (a *mqlAwsEc2) keypairs() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getKeypairs(conn), 5)
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

func (a *mqlAwsEc2Keypair) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2) getKeypairs(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ec2>getKeypairs>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()
			res := []any{}

			params := &ec2.DescribeKeyPairsInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			}
			keyPairs, err := svc.DescribeKeyPairs(ctx, params)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}

			for _, kp := range keyPairs.KeyPairs {
				if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(kp.Tags)) {
					log.Debug().Interface("keypair", kp.KeyPairId).Msg("excluding keypair due to filters")
					continue
				}
				mqlKeypair, err := CreateResource(a.MqlRuntime, ResourceAwsEc2Keypair,
					map[string]*llx.RawData{
						"arn":         llx.StringData(fmt.Sprintf(keypairArnPattern, region, conn.AccountId(), convert.ToValue(kp.KeyPairId))),
						"fingerprint": llx.StringDataPtr(kp.KeyFingerprint),
						"name":        llx.StringDataPtr(kp.KeyName),
						"type":        llx.StringData(string(kp.KeyType)),
						"tags":        llx.MapData(toInterfaceMap(ec2TagsToMap(kp.Tags)), types.String),
						"region":      llx.StringData(region),
						"createdAt":   llx.TimeDataPtr(kp.CreateTime),
					})
				if err != nil {
					return nil, err
				}
				res = append(res, mqlKeypair)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsEc2Keypair(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["name"] == nil {
		return nil, nil, errors.New("name required to fetch aws ec2 keypair")
	}
	n := args["name"].Value.(string)
	if n == "" {
		return nil, nil, errors.New("ec2 keypair name cannot be empty")
	}
	if args["region"] == nil {
		return nil, nil, errors.New("region required to fetch aws ec2 keypair")
	}
	r := args["region"].Value.(string)

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(r)
	ctx := context.Background()
	kps, err := svc.DescribeKeyPairs(ctx, &ec2.DescribeKeyPairsInput{KeyNames: []string{n}})
	if err != nil {
		// it is quite common for instances to get created with a keypair and then that keypair be deleted
		var ae smithy.APIError
		if errors.As(err, &ae) {
			if ae.ErrorCode() == "InvalidKeyPair.NotFound" {
				log.Warn().Msgf("key %s does not exist in %s region", n, r)
				// A deleted keypair is a legitimate empty state, but it still
				// needs a unique cache key: id() falls back to arn, which this
				// path leaves empty, so every deleted keypair in the account
				// aliased to whichever one resolved first. Unknown attributes
				// are null rather than "" so they read as unknown, not empty.
				args["__id"] = llx.StringData("aws.ec2.keypair/" + r + "/" + n)
				args["fingerprint"] = llx.NilData
				args["type"] = llx.NilData
				args["tags"] = llx.MapData(map[string]any{}, types.String)
				args["arn"] = llx.StringData("")
				args["createdAt"] = llx.NilData
				return args, nil, nil
			}
		}
		log.Error().Err(err).Msg("cannot fetch keypair")
		return nil, nil, err
	}

	if len(kps.KeyPairs) > 0 {
		kp := kps.KeyPairs[0]
		args["fingerprint"] = llx.StringData(convert.ToValue(kp.KeyFingerprint))
		args["name"] = llx.StringData(convert.ToValue(kp.KeyName))
		args["type"] = llx.StringData(string(kp.KeyType))
		args["tags"] = llx.MapData(toInterfaceMap(ec2TagsToMap(kp.Tags)), types.String)
		args["region"] = llx.StringData(r)
		args["arn"] = llx.StringData(fmt.Sprintf(keypairArnPattern, r, conn.AccountId(), convert.ToValue(kp.KeyPairId)))
		args["createdAt"] = llx.TimeDataPtr(kp.CreateTime)

		return args, nil, nil
	}
	// Same as the InvalidKeyPair.NotFound path above: unique key, null unknowns.
	args["__id"] = llx.StringData("aws.ec2.keypair/" + r + "/" + n)
	args["fingerprint"] = llx.NilData
	args["type"] = llx.NilData
	args["tags"] = llx.MapData(map[string]any{}, types.String)
	args["arn"] = llx.StringData("")
	args["createdAt"] = llx.NilData
	return args, nil, nil
}

func (a *mqlAwsEc2) images() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	var res []any
	poolOfJobs := jobpool.CreatePool(a.getImagesJob(conn), 5)

	poolOfJobs.Run()
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}

	for _, job := range poolOfJobs.Jobs {
		res = append(res, job.Result.([]any)...)
	}

	return res, nil
}

// createBlockDeviceMappings converts the AWS BlockDeviceMapping slice to MQL resources
func createBlockDeviceMappings(runtime *plugin.Runtime, imageKey string, mappings []ec2types.BlockDeviceMapping) ([]any, error) {
	result := make([]any, 0, len(mappings))
	for _, mapping := range mappings {
		deviceName := convert.ToValue(mapping.DeviceName)
		mappingID := fmt.Sprintf("%s/device/%s", imageKey, deviceName)

		args := map[string]*llx.RawData{
			"__id":        llx.StringData(mappingID),
			"deviceName":  llx.StringDataPtr(mapping.DeviceName),
			"virtualName": llx.StringDataPtr(mapping.VirtualName),
			"noDevice":    llx.BoolData(mapping.NoDevice != nil && *mapping.NoDevice != ""),
		}

		// Create an EBS block device resource if present
		if mapping.Ebs != nil {
			ebsID := fmt.Sprintf("%s/ebs", mappingID)
			mqlEbs, err := CreateResource(runtime, ResourceAwsEc2ImageEbsBlockDevice,
				map[string]*llx.RawData{
					"__id":                llx.StringData(ebsID),
					"encrypted":           llx.BoolDataPtr(mapping.Ebs.Encrypted),
					"snapshotId":          llx.StringDataPtr(mapping.Ebs.SnapshotId),
					"volumeSize":          llx.IntDataDefault(mapping.Ebs.VolumeSize, 0),
					"volumeType":          llx.StringData(string(mapping.Ebs.VolumeType)),
					"iops":                llx.IntDataDefault(mapping.Ebs.Iops, 0),
					"throughput":          llx.IntDataDefault(mapping.Ebs.Throughput, 0),
					"deleteOnTermination": llx.BoolDataPtr(mapping.Ebs.DeleteOnTermination),
				})
			if err != nil {
				return nil, err
			}
			mqlEbs.(*mqlAwsEc2ImageEbsBlockDevice).cacheKmsKeyId = convert.ToValue(mapping.Ebs.KmsKeyId)
			args["ebs"] = llx.ResourceData(mqlEbs, mqlEbs.MqlName())
		} else {
			args["ebs"] = llx.NilData
		}

		mqlMapping, err := CreateResource(runtime, ResourceAwsEc2ImageBlockDeviceMapping, args)
		if err != nil {
			return nil, err
		}
		result = append(result, mqlMapping)
	}
	return result, nil
}

// createImageWatermarks converts the AWS ImageWatermark slice to MQL resources
func createImageWatermarks(runtime *plugin.Runtime, imageKey string, watermarks []ec2types.ImageWatermark) ([]any, error) {
	result := make([]any, 0, len(watermarks))
	for _, watermark := range watermarks {
		watermarkKey := convert.ToValue(watermark.WatermarkKey)
		mqlWatermark, err := CreateResource(runtime, ResourceAwsEc2ImageWatermark,
			map[string]*llx.RawData{
				"__id":                 llx.StringData(fmt.Sprintf("%s/watermark/%s", imageKey, watermarkKey)),
				"watermarkKey":         llx.StringDataPtr(watermark.WatermarkKey),
				"createdAt":            llx.TimeDataPtr(watermark.WatermarkCreationTime),
				"sourceImageId":        llx.StringDataPtr(watermark.SourceImageId),
				"sourceImageRegion":    llx.StringDataPtr(watermark.SourceImageRegion),
				"sourceImageCreatedAt": llx.TimeDataPtr(watermark.SourceImageCreationTime),
			})
		if err != nil {
			return nil, err
		}
		result = append(result, mqlWatermark)
	}
	return result, nil
}

func (a *mqlAwsEc2) getImagesJob(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}

	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Str("region", region).Msgf("ec2>getImagesJob>calling aws with region")

			svc := conn.Ec2(region)
			ctx := context.Background()
			var res []any

			// Only fetch images owned by this account
			params := &ec2.DescribeImagesInput{
				Owners: []string{"self"},
			}
			paginator := ec2.NewDescribeImagesPaginator(svc, params)
			for paginator.HasMorePages() {
				images, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}

				for _, image := range images.Images {
					imageKey := region + "/" + convert.ToValue(image.ImageId)
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(image.Tags)) {
						log.Debug().Interface("image", image.ImageId).Msg("excluding image due to filters")
						continue
					}

					// Create block device mapping MQL resources
					blockDeviceMappings, err := createBlockDeviceMappings(a.MqlRuntime, imageKey, image.BlockDeviceMappings)
					if err != nil {
						return nil, err
					}

					// Create watermark MQL resources
					watermarks, err := createImageWatermarks(a.MqlRuntime, imageKey, image.ImageWatermarks)
					if err != nil {
						return nil, err
					}

					// Parse creation date
					var createdAt *time.Time
					if image.CreationDate != nil {
						t, err := time.Parse(time.RFC3339, *image.CreationDate)
						if err != nil {
							log.Warn().Str("imageId", convert.ToValue(image.ImageId)).Err(err).
								Str("bad_value", *image.CreationDate).Msg("failed to parse image CreationDate")
						} else {
							createdAt = &t
						}
					}
					// Parse deprecation date
					var deprecatedAt *time.Time
					if image.DeprecationTime != nil {
						t, err := time.Parse(time.RFC3339, *image.DeprecationTime)
						if err != nil {
							log.Warn().Str("imageId", convert.ToValue(image.ImageId)).Err(err).
								Str("bad_value", *image.DeprecationTime).Msg("failed to parse image DeprecationTime")
						} else {
							deprecatedAt = &t
						}
					}
					// Parse last launched time
					var lastLaunchedAt *time.Time
					if image.LastLaunchedTime != nil {
						t, err := time.Parse(time.RFC3339, *image.LastLaunchedTime)
						if err != nil {
							log.Warn().Str("imageId", convert.ToValue(image.ImageId)).Err(err).
								Str("bad_value", *image.LastLaunchedTime).Msg("failed to parse image LastLaunchedTime")
						} else {
							lastLaunchedAt = &t
						}
					}
					imageProductCodes, err := convert.JsonToDictSlice(image.ProductCodes)
					if err != nil {
						return nil, err
					}
					mqlImage, err := CreateResource(a.MqlRuntime, ResourceAwsEc2Image,
						map[string]*llx.RawData{
							"id":                       llx.StringDataPtr(image.ImageId),
							"name":                     llx.StringDataPtr(image.Name),
							"architecture":             llx.StringData(string(image.Architecture)),
							"ownerId":                  llx.StringDataPtr(image.OwnerId),
							"ownerAlias":               llx.StringDataPtr(image.ImageOwnerAlias),
							"createdAt":                llx.TimeDataPtr(createdAt),
							"deprecatedAt":             llx.TimeDataPtr(deprecatedAt),
							"enaSupport":               llx.BoolDataPtr(image.EnaSupport),
							"tpmSupport":               llx.StringData(string(image.TpmSupport)),
							"imdsSupport":              llx.StringData(imdsSupport(image.ImdsSupport)),
							"state":                    llx.StringData(string(image.State)),
							"public":                   llx.BoolDataPtr(image.Public),
							"rootDeviceType":           llx.StringData(string(image.RootDeviceType)),
							"virtualizationType":       llx.StringData(string(image.VirtualizationType)),
							"blockDeviceMappings":      llx.ArrayData(blockDeviceMappings, types.Resource(ResourceAwsEc2ImageBlockDeviceMapping)),
							"tags":                     llx.MapData(toInterfaceMap(ec2TagsToMap(image.Tags)), types.String),
							"region":                   llx.StringData(region),
							"description":              llx.StringDataPtr(image.Description),
							"imageType":                llx.StringData(string(image.ImageType)),
							"freeTierEligible":         llx.BoolDataPtr(image.FreeTierEligible),
							"imageAllowed":             llx.BoolDataPtr(image.ImageAllowed),
							"deregistrationProtection": llx.StringDataPtr(image.DeregistrationProtection),
							"lastLaunchedAt":           llx.TimeDataPtr(lastLaunchedAt),
							"platformDetails":          llx.StringDataPtr(image.PlatformDetails),
							"bootMode":                 llx.StringData(bootMode(string(image.BootMode))),
							"rootDeviceName":           llx.StringDataPtr(image.RootDeviceName),
							"sourceImageId":            llx.StringDataPtr(image.SourceImageId),
							"sourceImageRegion":        llx.StringDataPtr(image.SourceImageRegion),
							"sourceInstanceId":         llx.StringDataPtr(image.SourceInstanceId),
							"productCodes":             llx.ArrayData(imageProductCodes, types.Dict),
							"watermarks":               llx.ArrayData(watermarks, types.Resource(ResourceAwsEc2ImageWatermark)),
						})
					if err != nil {
						return nil, err
					}
					res = append(res, mqlImage)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2) securityGroups() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSecurityGroups(conn), 5)
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

type ebsEncryption struct {
	region                 string
	ebsEncryptionByDefault bool
}

func (a *mqlAwsEc2) ebsEncryptionByDefault() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := make(map[string]any)
	poolOfJobs := jobpool.CreatePool(a.getEbsEncryptionPerRegion(conn), 5)
	poolOfJobs.Run()

	// check for errors
	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	// get all the results
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			jobResult := poolOfJobs.Jobs[i].Result.(ebsEncryption)
			res[jobResult.region] = jobResult.ebsEncryptionByDefault
		}
	}
	return res, nil
}

func (a *mqlAwsEc2) getEbsEncryptionPerRegion(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)

	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ec2>getEbsEncryptionPerRegion>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()

			ebsEncryptionRes, err := svc.GetEbsEncryptionByDefault(ctx, &ec2.GetEbsEncryptionByDefaultInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return nil, nil
				}
				return nil, err
			}
			structVal := ebsEncryption{
				region:                 region,
				ebsEncryptionByDefault: convert.ToValue(ebsEncryptionRes.EbsEncryptionByDefault),
			}
			return jobpool.JobResult(structVal), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type serialConsoleResult struct {
	region  string
	enabled bool
}

func (a *mqlAwsEc2) serialConsoleAccessEnabled() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := make(map[string]any)
	poolOfJobs := jobpool.CreatePool(a.getSerialConsolePerRegion(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			jobResult := poolOfJobs.Jobs[i].Result.(serialConsoleResult)
			res[jobResult.region] = jobResult.enabled
		}
	}
	return res, nil
}

func (a *mqlAwsEc2) getSerialConsolePerRegion(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()

			resp, err := svc.GetSerialConsoleAccessStatus(ctx, &ec2.GetSerialConsoleAccessStatusInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					return nil, nil
				}
				return nil, err
			}
			return jobpool.JobResult(serialConsoleResult{
				region:  region,
				enabled: convert.ToValue(resp.SerialConsoleAccessEnabled),
			}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type imageBlockResult struct {
	region string
	state  string
}

func (a *mqlAwsEc2) imageBlockPublicAccess() (map[string]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := make(map[string]any)
	poolOfJobs := jobpool.CreatePool(a.getImageBlockPerRegion(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		if poolOfJobs.Jobs[i].Result != nil {
			jobResult := poolOfJobs.Jobs[i].Result.(imageBlockResult)
			res[jobResult.region] = jobResult.state
		}
	}
	return res, nil
}

func (a *mqlAwsEc2) getImageBlockPerRegion(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()

			resp, err := svc.GetImageBlockPublicAccessState(ctx, &ec2.GetImageBlockPublicAccessStateInput{})
			if err != nil {
				if Is400AccessDeniedError(err) {
					return nil, nil
				}
				return nil, err
			}
			return jobpool.JobResult(imageBlockResult{
				region: region,
				state:  convert.ToValue(resp.ImageBlockPublicAccessState),
			}), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2) instances() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInstances(conn), 5)
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

func (a *mqlAwsEc2) getEc2Instances(ctx context.Context, svc *ec2.Client, filters connection.DiscoveryFilters) ([]ec2types.Instance, error) {
	res := []ec2types.Instance{}
	paginator := ec2.NewDescribeInstancesPaginator(svc, &ec2.DescribeInstancesInput{
		Filters:     filters.General.ToServerSideEc2Filters(),
		InstanceIds: filters.Ec2.InstanceIds,
	})
	for paginator.HasMorePages() {
		reservations, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, reservation := range reservations.Reservations {
			for _, instance := range reservation.Instances {
				if shouldExcludeInstance(instance, filters) {
					log.Debug().Interface("instance", instance.InstanceId).Msg("excluding ec2 instance due to filters")
					continue
				}
				res = append(res, instance)
			}
		}
	}
	return res, nil
}

func (a *mqlAwsEc2) getInstances(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			log.Debug().Msgf("ec2>getInstances>calling aws with region %s", region)

			svc := conn.Ec2(region)
			ctx := context.Background()
			var res []any

			instances, err := a.getEc2Instances(ctx, svc, conn.Filters)
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				// AWS returns an error response when trying to find an instance with a specific identifier if it cannot find it in some region.
				// we do not propagate this error upward because an instance can be found in one region and return an error for all others which
				// would be the expected behavior.
				if Is400InstanceNotFoundError(err) {
					log.Debug().Str("region", region).Msg("could not find instance in region")
					return res, nil
				}
				return nil, err
			}
			res, err = a.gatherInstanceInfo(instances, region)
			if err != nil {
				return nil, err
			}

			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// stateTransitionReasonTime pulls the timestamp out of a StateTransitionReason
// such as "User initiated (2026-04-05 20:44:17 GMT)".
var stateTransitionReasonTime = regexp.MustCompile(`.*\((\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2}) GMT\)`)

// parseStateTransitionTime reads the transition timestamp out of an instance's
// StateTransitionReason, or reports nil when there is none.
//
// A running instance has an empty StateTransitionReason - the API documents it as
// "This might be an empty string" - so there is no timestamp to report and the
// field has to be null. It used to be a zero time.Time handed to llx.TimeData,
// which is a non-nil pointer, so every running instance carried a value that
// compared as older than any real date.
func parseStateTransitionTime(reason string) *time.Time {
	match := stateTransitionReasonTime.FindStringSubmatch(reason)
	if len(match) != 2 {
		return nil
	}
	t, err := time.Parse(time.DateTime, match[1])
	if err != nil {
		// The reason named a transition but the timestamp did not parse. Keep the
		// existing sentinel rather than null: something did happen, and we know
		// it was in the past.
		log.Error().Str("reason", reason).Err(err).
			Msg("cannot parse state transition time for ec2 instance")
		past := llx.NeverPastTime
		return &past
	}
	return &t
}

func (a *mqlAwsEc2) gatherInstanceInfo(instances []ec2types.Instance, regionVal string) ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	for _, instance := range instances {
		mqlDevices := []any{}
		for _, device := range instance.BlockDeviceMappings {
			if device.Ebs == nil {
				continue
			}
			mqlInstanceDevice, err := CreateResource(a.MqlRuntime, ResourceAwsEc2InstanceDevice,
				map[string]*llx.RawData{
					"__id": llx.StringData(instanceDeviceCacheKey(regionVal,
						convert.ToValue(instance.InstanceId), convert.ToValue(device.DeviceName))),
					"deleteOnTermination": llx.BoolData(convert.ToValue(device.Ebs.DeleteOnTermination)),
					"status":              llx.StringData(string(device.Ebs.Status)),
					"deviceName":          llx.StringData(convert.ToValue(device.DeviceName)),
				})
			if err != nil {
				return nil, err
			}
			mqlInstanceDevice.(*mqlAwsEc2InstanceDevice).cacheVolumeId = convert.ToValue(device.Ebs.VolumeId)
			mqlInstanceDevice.(*mqlAwsEc2InstanceDevice).region = regionVal
			mqlDevices = append(mqlDevices, mqlInstanceDevice)
		}

		stateReason, err := convert.JsonToDict(instance.StateReason)
		if err != nil {
			return nil, err
		}
		mqlStateReason, err := newMqlEc2StateReason(a.MqlRuntime, convert.ToValue(instance.InstanceId), instance.StateReason)
		if err != nil {
			return nil, err
		}

		stateTransitionTime := parseStateTransitionTime(convert.ToValue(instance.StateTransitionReason))
		var detailedMonitoring string
		if instance.Monitoring != nil {
			detailedMonitoring = string(instance.Monitoring.State)
		}
		var stateName string
		if instance.State != nil {
			stateName = string(instance.State.Name)
		}
		instanceArn := fmt.Sprintf(ec2InstanceArnPattern, regionVal, conn.AccountId(), convert.ToValue(instance.InstanceId))
		args := map[string]*llx.RawData{
			"architecture":       llx.StringData(string(instance.Architecture)),
			"arn":                llx.StringData(instanceArn),
			"detailedMonitoring": llx.StringData(detailedMonitoring),
			"deviceMappings":     llx.ArrayData(mqlDevices, types.Type(ResourceAwsEc2InstanceDevice)),
			"ebsOptimized":       llx.BoolDataPtr(instance.EbsOptimized),
			"enaSupported":       llx.BoolDataPtr(instance.EnaSupport),
			"hypervisor":         llx.StringData(string(instance.Hypervisor)),
			"instanceId":         llx.StringDataPtr(instance.InstanceId),
			"instanceLifecycle":  llx.StringData(string(instance.InstanceLifecycle)),
			"instanceType":       llx.StringData(string(instance.InstanceType)),
			"launchedAt":         llx.TimeDataPtr(instance.LaunchTime),
			"platformDetails":    llx.StringDataPtr(instance.PlatformDetails),
			"privateDnsName":     llx.StringDataPtr(instance.PrivateDnsName),
			"privateIp":          llx.StringDataPtr(instance.PrivateIpAddress),
			"publicDnsName":      llx.StringDataPtr(instance.PublicDnsName),
			"publicIp":           llx.StringDataPtr(instance.PublicIpAddress),
			"region":             llx.StringData(regionVal),
			"rootDeviceName":     llx.StringDataPtr(instance.RootDeviceName),
			"rootDeviceType":     llx.StringData(string(instance.RootDeviceType)),
			"state":              llx.StringData(stateName),
			"stateReason":        llx.MapData(stateReason, types.Any),
			"stateChangeReason":  mqlStateReason,
			// "iamInstanceProfile":    llx.MapData(iamInstanceProfile, types.Any),
			"stateTransitionReason": llx.StringDataPtr(instance.StateTransitionReason),
			"stateTransitionTime":   llx.TimeDataPtr(stateTransitionTime),
			"tags":                  llx.MapData(toInterfaceMap(ec2TagsToMap(instance.Tags)), types.String),
			"tpmSupport":            llx.StringDataPtr(instance.TpmSupport),
			"bootMode":              llx.StringData(bootMode(string(instance.BootMode))),
			"sourceDestCheck":       llx.BoolDataPtr(instance.SourceDestCheck),
			"ipv6Address":           llx.StringDataPtr(instance.Ipv6Address),
		}

		var enclaveEnabled bool
		if instance.EnclaveOptions != nil {
			enclaveEnabled = convert.ToValue(instance.EnclaveOptions.Enabled)
		}
		args["enclaveEnabled"] = llx.BoolData(enclaveEnabled)

		// CPU options
		if instance.CpuOptions != nil {
			args["cpuCoreCount"] = llx.IntDataPtr(instance.CpuOptions.CoreCount)
			args["cpuThreadsPerCore"] = llx.IntDataPtr(instance.CpuOptions.ThreadsPerCore)
		} else {
			args["cpuCoreCount"] = llx.NilData
			args["cpuThreadsPerCore"] = llx.NilData
		}

		// Hibernation
		var hibernationConfigured *bool
		if instance.HibernationOptions != nil {
			hibernationConfigured = instance.HibernationOptions.Configured
		}
		args["hibernationConfigured"] = llx.BoolDataPtr(hibernationConfigured)

		// Maintenance options
		if instance.MaintenanceOptions != nil {
			args["maintenanceAutoRecovery"] = llx.StringData(bootMode(string(instance.MaintenanceOptions.AutoRecovery)))
		} else {
			args["maintenanceAutoRecovery"] = llx.NilData
		}

		args["currentInstanceBootMode"] = llx.StringData(bootMode(string(instance.CurrentInstanceBootMode)))
		args["spotInstanceRequestId"] = llx.StringDataPtr(instance.SpotInstanceRequestId)
		args["virtualizationType"] = llx.StringData(string(instance.VirtualizationType))

		// Operator: whether an AWS service provider manages the instance
		if instance.Operator != nil {
			args["managedByOperator"] = llx.BoolDataPtr(instance.Operator.Managed)
			args["operatorPrincipal"] = llx.StringDataPtr(instance.Operator.Principal)
		} else {
			args["managedByOperator"] = llx.BoolData(false)
			args["operatorPrincipal"] = llx.StringData("")
		}

		// Placement
		if instance.Placement != nil {
			p := instance.Placement
			mqlPlacement, err := CreateResource(a.MqlRuntime, ResourceAwsEc2InstancePlacement,
				map[string]*llx.RawData{
					"__id":                 llx.StringData(instanceArn + "/placement"),
					"availabilityZone":     llx.StringDataPtr(p.AvailabilityZone),
					"availabilityZoneId":   llx.StringDataPtr(p.AvailabilityZoneId),
					"tenancy":              llx.StringData(string(p.Tenancy)),
					"groupName":            llx.StringDataPtr(p.GroupName),
					"groupId":              llx.StringDataPtr(p.GroupId),
					"hostId":               llx.StringDataPtr(p.HostId),
					"hostResourceGroupArn": llx.StringDataPtr(p.HostResourceGroupArn),
					"partitionNumber":      llx.IntDataPtr(p.PartitionNumber),
					"affinity":             llx.StringDataPtr(p.Affinity),
				})
			if err != nil {
				return nil, err
			}
			args["placement"] = llx.ResourceData(mqlPlacement, ResourceAwsEc2InstancePlacement)
		} else {
			args["placement"] = llx.NilData
		}

		if instance.MetadataOptions != nil {
			args["httpEndpoint"] = llx.StringData(string(instance.MetadataOptions.HttpEndpoint))
			args["httpTokens"] = llx.StringData(string(instance.MetadataOptions.HttpTokens))
			args["httpPutResponseHopLimit"] = llx.IntDataDefault(instance.MetadataOptions.HttpPutResponseHopLimit, 1)
			args["imdsv2Required"] = llx.BoolData(instance.MetadataOptions.HttpTokens == ec2types.HttpTokensStateRequired)
		} else {
			args["httpEndpoint"] = llx.NilData
			args["httpTokens"] = llx.NilData
			args["httpPutResponseHopLimit"] = llx.IntData(1)
			args["imdsv2Required"] = llx.BoolData(false)
		}
		// add vpc if there is one
		var vpcArn string
		if instance.VpcId != nil {
			vpcArn = fmt.Sprintf(vpcArnPattern, regionVal, conn.AccountId(), convert.ToValue(instance.VpcId))
		}

		mqlEc2Instance, err := CreateResource(a.MqlRuntime, ResourceAwsEc2Instance, args)
		if err != nil {
			return nil, err
		}
		mqlEc2Instance.(*mqlAwsEc2Instance).cacheLaunchTime = instance.LaunchTime
		mqlEc2Instance.(*mqlAwsEc2Instance).cacheVpcArn = vpcArn
		mqlEc2Instance.(*mqlAwsEc2Instance).instanceCache = instance
		res = append(res, mqlEc2Instance)
	}
	return res, nil
}

type mqlAwsEc2InstanceInternal struct {
	cacheLaunchTime *time.Time
	cacheVpcArn     string
	instanceCache   ec2types.Instance
}

func (i *mqlAwsEc2Instance) networkInterfaces() ([]any, error) {
	conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(i.Region.Data)
	ctx := context.Background()
	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, ec2types.Filter{Name: aws.String("attachment.instance-id"), Values: []string{i.InstanceId.Data}})
	params := &ec2.DescribeNetworkInterfacesInput{Filters: filters}
	res := []any{}
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(svc, params)
	for paginator.HasMorePages() {
		nis, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, networkingInterface := range nis.NetworkInterfaces {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(networkingInterface.TagSet)) {
				log.Debug().Interface("networkInterface", networkingInterface.NetworkInterfaceId).Msg("excluding network interface due to filters")
				continue
			}
			_, mqlEni, err := buildNetworkInterfaceResource(i.MqlRuntime, i.Region.Data, networkingInterface)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlEni)
		}
	}
	return res, nil
}

// instanceTypeHypervisorCache memoizes the mapping from EC2 instance type to its
// hypervisor (nitro or xen). DescribeInstanceTypes is the only API that reports
// it, and the value is an immutable, region-independent property of the instance
// type, so we cache it process-wide to avoid an API call per instance (many
// instances share a type).
var instanceTypeHypervisorCache sync.Map // map[string]string

func (i *mqlAwsEc2Instance) instanceTypeHypervisor() (string, error) {
	instanceType := i.InstanceType.Data
	if instanceType == "" {
		return "", nil
	}
	if v, ok := instanceTypeHypervisorCache.Load(instanceType); ok {
		return v.(string), nil
	}

	conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(i.Region.Data)
	resp, err := svc.DescribeInstanceTypes(context.Background(), &ec2.DescribeInstanceTypesInput{
		InstanceTypes: []ec2types.InstanceType{ec2types.InstanceType(instanceType)},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			// Don't mask the missing permission behind an empty "not Nitro"
			// answer; surface it so it can be granted.
			log.Warn().Str("instanceType", instanceType).Str("instance", i.InstanceId.Data).
				Msg("no permission for ec2:DescribeInstanceTypes; cannot determine instance-type hypervisor")
			return "", nil
		}
		return "", err
	}

	// A running instance's type always exists in its own region, so an empty
	// result is unexpected. Don't cache it, or we'd poison the process-wide
	// cache for regions where the type does exist.
	if len(resp.InstanceTypes) == 0 {
		return "", nil
	}

	hypervisor := string(resp.InstanceTypes[0].Hypervisor)
	instanceTypeHypervisorCache.Store(instanceType, hypervisor)
	return hypervisor, nil
}

type mqlAwsEc2NetworkinterfaceInternal struct {
	networkInterfaceCache   ec2types.NetworkInterface
	region                  string
	cacheAttachmentInstance *string
	cacheElasticIp          *string
}

func initAwsEc2Networkinterface(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// A reference already materialized by an earlier referrer or by the
	// list that built it. NewResource consults the cache only after this
	// init returns, so without this the same target is fetched once per
	// referring resource and the result discarded.
	if cached := cachedArgByArn(runtime, ResourceAwsEc2Networkinterface, args); cached != nil {
		return args, cached, nil
	}

	if args["id"] == nil {
		return nil, nil, errors.New("id required to fetch aws network interface")
	}
	eniId := args["id"].Value.(string)

	var region string
	if args["region"] != nil {
		region = args["region"].Value.(string)
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	// With the id and a region in hand the ARN is derivable, so check before
	// paying for a lookup -- and before the region fan-out below, which costs
	// one call per region for a single interface. Callers that pass an id
	// rather than an ARN miss the check above, which is the case this catches.
	if region != "" {
		if cached := cachedByArn(runtime, ResourceAwsEc2Networkinterface,
			fmt.Sprintf(networkInterfaceArnPattern, region, conn.AccountId(), eniId)); cached != nil {
			return args, cached, nil
		}
	}

	if region == "" {
		// Region is required for a targeted DescribeNetworkInterfaces lookup, but
		// it's not encoded in the ENI id itself. Fan out across regions in
		// parallel and take the first hit instead of probing serially.
		regions, err := conn.Regions()
		if err != nil {
			return nil, nil, err
		}
		type eniHit struct {
			region string
			eni    ec2types.NetworkInterface
		}
		hits := make(chan eniHit, len(regions))
		var wg sync.WaitGroup
		for _, r := range regions {
			wg.Add(1)
			go func(r string) {
				defer wg.Done()
				svc := conn.Ec2(r)
				resp, err := svc.DescribeNetworkInterfaces(context.Background(), &ec2.DescribeNetworkInterfacesInput{
					NetworkInterfaceIds: []string{eniId},
				})
				if err != nil {
					return
				}
				if len(resp.NetworkInterfaces) > 0 {
					hits <- eniHit{region: r, eni: resp.NetworkInterfaces[0]}
				}
			}(r)
		}
		wg.Wait()
		close(hits)
		for hit := range hits {
			return buildNetworkInterfaceResource(runtime, hit.region, hit.eni)
		}
		return nil, nil, errors.New("network interface not found")
	}

	svc := conn.Ec2(region)
	ctx := context.Background()
	resp, err := svc.DescribeNetworkInterfaces(ctx, &ec2.DescribeNetworkInterfacesInput{
		NetworkInterfaceIds: []string{eniId},
	})
	if err != nil {
		return nil, nil, err
	}
	if len(resp.NetworkInterfaces) == 0 {
		return nil, nil, errors.New("network interface not found")
	}
	return buildNetworkInterfaceResource(runtime, region, resp.NetworkInterfaces[0])
}

func buildNetworkInterfaceResource(runtime *plugin.Runtime, region string, eni ec2types.NetworkInterface) (map[string]*llx.RawData, plugin.Resource, error) {
	var publicIp, publicDnsName string
	var cacheElasticIp *string
	if eni.Association != nil {
		publicIp = convert.ToValue(eni.Association.PublicIp)
		publicDnsName = convert.ToValue(eni.Association.PublicDnsName)
		// Only resolve to an aws.ec2.eip when an AllocationId is present; a raw
		// auto-assigned public IP (no AllocationId) does not back an EIP resource.
		if eni.Association.AllocationId != nil && *eni.Association.AllocationId != "" {
			cacheElasticIp = eni.Association.PublicIp
		}
	}
	var attachmentStatus string
	var attachmentTime *time.Time
	var deviceIndex, networkCardIndex *int32
	var deleteOnTermination bool
	var attachmentInstanceID *string
	var instanceOwnerID *string
	if eni.Attachment != nil {
		attachmentStatus = string(eni.Attachment.Status)
		attachmentTime = eni.Attachment.AttachTime
		deviceIndex = eni.Attachment.DeviceIndex
		networkCardIndex = eni.Attachment.NetworkCardIndex
		deleteOnTermination = convert.ToValue(eni.Attachment.DeleteOnTermination)
		attachmentInstanceID = eni.Attachment.InstanceId
		instanceOwnerID = eni.Attachment.InstanceOwnerId
	}

	args := map[string]*llx.RawData{
		"__id":                llx.StringDataPtr(eni.NetworkInterfaceId),
		"availabilityZone":    llx.StringDataPtr(eni.AvailabilityZone),
		"description":         llx.StringDataPtr(eni.Description),
		"id":                  llx.StringDataPtr(eni.NetworkInterfaceId),
		"ipv6Native":          llx.BoolDataPtr(eni.Ipv6Native),
		"macAddress":          llx.StringDataPtr(eni.MacAddress),
		"privateDnsName":      llx.StringDataPtr(eni.PrivateDnsName),
		"privateIpAddress":    llx.StringDataPtr(eni.PrivateIpAddress),
		"requesterManaged":    llx.BoolDataPtr(eni.RequesterManaged),
		"sourceDestCheck":     llx.BoolDataPtr(eni.SourceDestCheck),
		"status":              llx.StringData(string(eni.Status)),
		"tags":                llx.MapData(toInterfaceMap(ec2TagsToMap(eni.TagSet)), types.String),
		"region":              llx.StringData(region),
		"interfaceType":       llx.StringData(string(eni.InterfaceType)),
		"publicIp":            llx.StringData(publicIp),
		"publicDnsName":       llx.StringData(publicDnsName),
		"attachmentStatus":    llx.StringData(attachmentStatus),
		"attachmentTime":      llx.TimeDataPtr(attachmentTime),
		"deviceIndex":         llx.IntDataPtr(deviceIndex),
		"networkCardIndex":    llx.IntDataPtr(networkCardIndex),
		"deleteOnTermination": llx.BoolData(deleteOnTermination),
		"ownerId":             llx.StringDataPtr(eni.OwnerId),
		"requesterId":         llx.StringDataPtr(eni.RequesterId),
		"instanceOwnerId":     llx.StringDataPtr(instanceOwnerID),
	}
	res, err := CreateResource(runtime, ResourceAwsEc2Networkinterface, args)
	if err != nil {
		return nil, nil, err
	}
	mqlEni := res.(*mqlAwsEc2Networkinterface)
	mqlEni.networkInterfaceCache = eni
	mqlEni.region = region
	mqlEni.cacheAttachmentInstance = attachmentInstanceID
	mqlEni.cacheElasticIp = cacheElasticIp
	return nil, mqlEni, nil
}

func (i *mqlAwsEc2Networkinterface) arn() (string, error) {
	account := i.OwnerId.Data
	if account == "" {
		conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
		account = conn.AccountId()
	}
	return fmt.Sprintf(networkInterfaceArnPattern, i.Region.Data, account, i.Id.Data), nil
}

func (i *mqlAwsEc2Networkinterface) elasticIp() (*mqlAwsEc2Eip, error) {
	if i.cacheElasticIp == nil || *i.cacheElasticIp == "" {
		i.ElasticIp.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlEip, err := NewResource(i.MqlRuntime, "aws.ec2.eip",
		map[string]*llx.RawData{
			"publicIp": llx.StringDataPtr(i.cacheElasticIp),
			"region":   llx.StringData(i.region),
		})
	if err != nil {
		return nil, err
	}
	return mqlEip.(*mqlAwsEc2Eip), nil
}

func (i *mqlAwsEc2Networkinterface) instance() (*mqlAwsEc2Instance, error) {
	if i.cacheAttachmentInstance == nil || *i.cacheAttachmentInstance == "" {
		i.Instance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
	mqlInst, err := NewResource(i.MqlRuntime, "aws.ec2.instance",
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(ec2InstanceArnPattern, i.region, conn.AccountId(), *i.cacheAttachmentInstance)),
		})
	if err != nil {
		return nil, err
	}
	return mqlInst.(*mqlAwsEc2Instance), nil
}

func (i *mqlAwsEc2Networkinterface) securityGroups() ([]any, error) {
	if i.networkInterfaceCache.Groups != nil {
		sgs := []any{}
		conn := i.MqlRuntime.Connection.(*connection.AwsConnection)

		for _, group := range i.networkInterfaceCache.Groups {
			mqlSg, err := NewResource(i.MqlRuntime, ResourceAwsEc2Securitygroup,
				map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, i.region, conn.AccountId(), *group.GroupId))})
			if err != nil {
				return nil, err
			}
			sgs = append(sgs, mqlSg)
		}
		return sgs, nil
	}
	i.SecurityGroups.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (i *mqlAwsEc2Networkinterface) subnet() (*mqlAwsVpcSubnet, error) {
	subn := i.networkInterfaceCache.SubnetId
	conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
	if subn != nil {
		arn := fmt.Sprintf(subnetArnPattern, i.region, conn.AccountId(), *subn)
		res, err := NewResource(i.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{"arn": llx.StringData(arn)})
		if err != nil {
			return nil, err
		}
		return res.(*mqlAwsVpcSubnet), nil
	}
	i.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (i *mqlAwsEc2Networkinterface) vpc() (*mqlAwsVpc, error) {
	vpcId := i.networkInterfaceCache.VpcId
	if vpcId != nil {
		conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
		vpcArn := fmt.Sprintf(vpcArnPattern, i.region, conn.AccountId(), convert.ToValue(vpcId))
		res, err := NewResource(i.MqlRuntime, ResourceAwsVpc, map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
		if err != nil {
			return nil, err
		}
		return res.(*mqlAwsVpc), nil
	}
	i.Vpc.State = plugin.StateIsNull | plugin.StateIsSet
	return nil, nil
}

func (i *mqlAwsEc2Instance) securityGroups() ([]any, error) {
	if i.instanceCache.SecurityGroups != nil {
		sgs := []any{}
		conn := i.MqlRuntime.Connection.(*connection.AwsConnection)

		for _, sg := range i.instanceCache.SecurityGroups {
			mqlSg, err := NewResource(i.MqlRuntime, ResourceAwsEc2Securitygroup,
				map[string]*llx.RawData{"arn": llx.StringData(fmt.Sprintf(securityGroupArnPattern, i.Region.Data, conn.AccountId(), convert.ToValue(sg.GroupId)))})
			if err != nil {
				return nil, err
			}
			sgs = append(sgs, mqlSg)
		}
		return sgs, nil
	}
	i.SecurityGroups.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (i *mqlAwsEc2Instance) image() (*mqlAwsEc2Image, error) {
	if i.instanceCache.ImageId != nil {
		mqlImage, err := NewResource(i.MqlRuntime, ResourceAwsEc2Image,
			map[string]*llx.RawData{
				"id":     llx.StringDataPtr(i.instanceCache.ImageId),
				"region": llx.StringData(i.Region.Data),
			})
		if err == nil {
			return mqlImage.(*mqlAwsEc2Image), nil
		}
	}
	i.Image.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (i *mqlAwsEc2Instance) keypair() (*mqlAwsEc2Keypair, error) {
	if i.instanceCache.KeyName != nil {
		mqlKeyPair, err := NewResource(i.MqlRuntime, ResourceAwsEc2Keypair,
			map[string]*llx.RawData{
				"region": llx.StringData(i.Region.Data),
				"name":   llx.StringDataPtr(i.instanceCache.KeyName),
			})
		if err == nil {
			return mqlKeyPair.(*mqlAwsEc2Keypair), nil
		}
	}
	i.Keypair.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

func (i *mqlAwsEc2Image) id() (string, error) {
	return i.Region.Data + "/" + i.Id.Data, nil
}

func (i *mqlAwsEc2Image) launchPermissions() ([]any, error) {
	imageId := i.Id.Data
	region := i.Region.Data
	conn := i.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Ec2(region)
	ctx := context.Background()

	result, err := svc.DescribeImageAttribute(ctx, &ec2.DescribeImageAttributeInput{
		ImageId:   aws.String(imageId),
		Attribute: ec2types.ImageAttributeNameLaunchPermission,
	})
	if err != nil {
		return nil, err
	}

	imageKey := i.Region.Data + "/" + i.Id.Data
	permissions := make([]any, 0, len(result.LaunchPermissions))
	for _, perm := range result.LaunchPermissions {
		// Build unique ID based on which field is set
		var permId string
		switch {
		case perm.UserId != nil:
			permId = fmt.Sprintf("%s/user/%s", imageKey, *perm.UserId)
		case perm.Group != "":
			permId = fmt.Sprintf("%s/group/%s", imageKey, string(perm.Group))
		case perm.OrganizationArn != nil:
			permId = fmt.Sprintf("%s/org/%s", imageKey, *perm.OrganizationArn)
		case perm.OrganizationalUnitArn != nil:
			permId = fmt.Sprintf("%s/ou/%s", imageKey, *perm.OrganizationalUnitArn)
		default:
			permId = fmt.Sprintf("%s/unknown", imageKey)
		}

		mqlPermission, err := CreateResource(i.MqlRuntime, ResourceAwsEc2ImageLaunchPermission,
			map[string]*llx.RawData{
				"__id":                  llx.StringData(permId),
				"userId":                llx.StringDataPtr(perm.UserId),
				"group":                 llx.StringData(string(perm.Group)),
				"organizationArn":       llx.StringDataPtr(perm.OrganizationArn),
				"organizationalUnitArn": llx.StringDataPtr(perm.OrganizationalUnitArn),
			})
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, mqlPermission)
	}

	return permissions, nil
}

func (a *mqlAwsEc2ImageEbsBlockDevice) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringData(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEc2ImageEbsBlockDevice) snapshot() (*mqlAwsEc2Snapshot, error) {
	if a.SnapshotId.Data == "" {
		a.Snapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlSnap, err := NewResource(a.MqlRuntime, ResourceAwsEc2Snapshot,
		map[string]*llx.RawData{
			"id": llx.StringData(a.SnapshotId.Data),
		})
	if err != nil {
		return nil, err
	}
	return mqlSnap.(*mqlAwsEc2Snapshot), nil
}

// sourceImage resolves the AMI this image was copied from when it is still
// present in this account. The source may be owned by another account or
// deregistered; in that case the reference is null and the sourceImageId field
// carries the lineage id.
func (i *mqlAwsEc2Image) sourceImage() (*mqlAwsEc2Image, error) {
	if !i.SourceImageId.IsSet() || i.SourceImageId.Data == "" {
		i.SourceImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	region := i.SourceImageRegion.Data
	if region == "" {
		region = i.Region.Data
	}
	mqlImage, err := NewResource(i.MqlRuntime, ResourceAwsEc2Image,
		map[string]*llx.RawData{
			"id":     llx.StringData(i.SourceImageId.Data),
			"region": llx.StringData(region),
		})
	if err != nil {
		i.SourceImage.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return mqlImage.(*mqlAwsEc2Image), nil
}

// sourceInstance resolves the instance this AMI was created from when it is
// still present in this account. The instance is frequently terminated; in that
// case the reference is null and the sourceInstanceId field carries the
// lineage id.
func (i *mqlAwsEc2Image) sourceInstance() (*mqlAwsEc2Instance, error) {
	if !i.SourceInstanceId.IsSet() || i.SourceInstanceId.Data == "" {
		i.SourceInstance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := fmt.Sprintf(ec2InstanceArnPattern, i.Region.Data, conn.AccountId(), i.SourceInstanceId.Data)
	mqlInstance, err := NewResource(i.MqlRuntime, ResourceAwsEc2Instance,
		map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		i.SourceInstance.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return mqlInstance.(*mqlAwsEc2Instance), nil
}

func initAwsEc2Image(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["id"] == nil || args["region"] == nil {
		return nil, nil, errors.New("id and region required to fetch aws ec2 image")
	}

	imageId, _ := args["id"].Value.(string)
	region, _ := args["region"].Value.(string)
	if imageId == "" || region == "" {
		return nil, nil, errors.New("id and region required to fetch aws ec2 image")
	}
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	ctx := context.Background()
	images, err := svc.DescribeImages(ctx, &ec2.DescribeImagesInput{ImageIds: []string{imageId}})
	if err != nil {
		args["id"] = llx.StringData(imageId)
		args["name"] = llx.StringData("not found")
		args["architecture"] = llx.NilData
		args["ownerId"] = llx.NilData
		args["ownerAlias"] = llx.NilData
		args["createdAt"] = llx.NilData
		args["deprecatedAt"] = llx.NilData
		args["tpmSupport"] = llx.NilData
		args["imdsSupport"] = llx.NilData
		args["enaSupport"] = llx.NilData
		args["state"] = llx.NilData
		args["public"] = llx.NilData
		args["rootDeviceType"] = llx.NilData
		args["virtualizationType"] = llx.NilData
		args["blockDeviceMappings"] = llx.NilData
		args["tags"] = llx.NilData
		args["region"] = llx.StringData(region)
		args["description"] = llx.NilData
		args["imageType"] = llx.NilData
		args["freeTierEligible"] = llx.NilData
		args["imageAllowed"] = llx.NilData
		args["deregistrationProtection"] = llx.NilData
		args["lastLaunchedAt"] = llx.NilData
		args["platformDetails"] = llx.NilData
		args["bootMode"] = llx.NilData
		args["rootDeviceName"] = llx.NilData
		args["sourceImageId"] = llx.NilData
		args["sourceImageRegion"] = llx.NilData
		args["sourceInstanceId"] = llx.NilData
		args["productCodes"] = llx.NilData
		args["watermarks"] = llx.NilData
		return args, nil, nil
	}

	if len(images.Images) > 0 {
		image := images.Images[0]
		imageKey := region + "/" + imageId

		// Create block device mapping MQL resources
		blockDeviceMappings, err := createBlockDeviceMappings(runtime, imageKey, image.BlockDeviceMappings)
		if err != nil {
			return nil, nil, err
		}

		// Create watermark MQL resources
		watermarks, err := createImageWatermarks(runtime, imageKey, image.ImageWatermarks)
		if err != nil {
			return nil, nil, err
		}

		args["id"] = llx.StringData(imageId)
		args["name"] = llx.StringDataPtr(image.Name)
		args["architecture"] = llx.StringData(string(image.Architecture))
		args["ownerId"] = llx.StringDataPtr(image.OwnerId)
		args["ownerAlias"] = llx.StringDataPtr(image.ImageOwnerAlias)
		args["enaSupport"] = llx.BoolDataPtr(image.EnaSupport)
		args["tpmSupport"] = llx.StringData(string(image.TpmSupport))
		args["imdsSupport"] = llx.StringData(imdsSupport(image.ImdsSupport))
		args["state"] = llx.StringData(string(image.State))
		args["public"] = llx.BoolDataPtr(image.Public)
		args["rootDeviceType"] = llx.StringData(string(image.RootDeviceType))
		args["virtualizationType"] = llx.StringData(string(image.VirtualizationType))
		args["blockDeviceMappings"] = llx.ArrayData(blockDeviceMappings, types.Resource(ResourceAwsEc2ImageBlockDeviceMapping))
		args["tags"] = llx.MapData(toInterfaceMap(ec2TagsToMap(image.Tags)), types.String)
		args["region"] = llx.StringData(region)
		args["description"] = llx.StringDataPtr(image.Description)
		args["imageType"] = llx.StringData(string(image.ImageType))
		args["freeTierEligible"] = llx.BoolDataPtr(image.FreeTierEligible)
		args["imageAllowed"] = llx.BoolDataPtr(image.ImageAllowed)
		args["deregistrationProtection"] = llx.StringDataPtr(image.DeregistrationProtection)
		args["platformDetails"] = llx.StringDataPtr(image.PlatformDetails)
		args["bootMode"] = llx.StringData(bootMode(string(image.BootMode)))
		args["rootDeviceName"] = llx.StringDataPtr(image.RootDeviceName)
		args["sourceImageId"] = llx.StringDataPtr(image.SourceImageId)
		args["sourceImageRegion"] = llx.StringDataPtr(image.SourceImageRegion)
		args["sourceInstanceId"] = llx.StringDataPtr(image.SourceInstanceId)
		imageProductCodes, err := convert.JsonToDictSlice(image.ProductCodes)
		if err != nil {
			return nil, nil, err
		}
		args["productCodes"] = llx.ArrayData(imageProductCodes, types.Dict)
		args["watermarks"] = llx.ArrayData(watermarks, types.Resource(ResourceAwsEc2ImageWatermark))
		if image.CreationDate == nil {
			args["createdAt"] = llx.NilData
		} else {
			createdAt, err := time.Parse(time.RFC3339, *image.CreationDate)
			if err != nil {
				return nil, nil, err
			}
			args["createdAt"] = llx.TimeData(createdAt)
		}
		if image.DeprecationTime == nil {
			args["deprecatedAt"] = llx.NilData
		} else {
			deprecateTime, err := time.Parse(time.RFC3339, *image.DeprecationTime)
			if err != nil {
				return nil, nil, err
			}
			args["deprecatedAt"] = llx.TimeData(deprecateTime)
		}
		if image.LastLaunchedTime == nil {
			args["lastLaunchedAt"] = llx.NilData
		} else {
			lastLaunchedAt, err := time.Parse(time.RFC3339, *image.LastLaunchedTime)
			if err != nil {
				log.Warn().Str("imageId", convert.ToValue(image.ImageId)).Err(err).
					Str("bad_value", *image.LastLaunchedTime).Msg("failed to parse image LastLaunchedTime")
				args["lastLaunchedAt"] = llx.NilData
			} else {
				args["lastLaunchedAt"] = llx.TimeData(lastLaunchedAt)
			}
		}
		return args, nil, nil
	}

	return nil, nil, errors.New("image not found")
}

func (a *mqlAwsEc2Securitygroup) id() (string, error) {
	return a.Arn.Data, nil
}

func buildSecurityGroupResource(runtime *plugin.Runtime, region, accountID string, group ec2types.SecurityGroup) (*mqlAwsEc2Securitygroup, error) {
	args := map[string]*llx.RawData{
		"arn":         llx.StringData(fmt.Sprintf(securityGroupArnPattern, region, accountID, convert.ToValue(group.GroupId))),
		"id":          llx.StringDataPtr(group.GroupId),
		"name":        llx.StringDataPtr(group.GroupName),
		"description": llx.StringDataPtr(group.Description),
		"tags":        llx.MapData(toInterfaceMap(ec2TagsToMap(group.Tags)), types.String),
		"region":      llx.StringData(region),
		"ownerId":     llx.StringDataPtr(group.OwnerId),
	}
	mqlSG, err := CreateResource(runtime, ResourceAwsEc2Securitygroup, args)
	if err != nil {
		return nil, err
	}
	sg := mqlSG.(*mqlAwsEc2Securitygroup)
	sg.cacheIpPerms = group.IpPermissions
	sg.cacheIpPermsEgress = group.IpPermissionsEgress
	sg.groupId = convert.ToValue(group.GroupId)
	sg.region = region
	sg.cacheVpc = group.VpcId
	return sg, nil
}

func initAwsEc2Securitygroup(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// Already materialized by an earlier reference or by the list that
	// built it: NewResource consults the cache only after this init
	// returns, so without this the same target is fetched once per
	// referring resource and the result thrown away.
	if cached := cachedArgByArn(runtime, ResourceAwsEc2Securitygroup, args); cached != nil {
		return args, cached, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformSecurityGroup); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil && args["id"] == nil {
		return nil, nil, errors.New("arn or id required to fetch aws security group")
	}

	// Derive region + groupId for a single targeted DescribeSecurityGroups
	// call instead of listing every SG in every region.
	var region, groupId string
	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		if parsed, err := arn.Parse(arnVal); err == nil && strings.HasPrefix(parsed.Resource, "security-group/") {
			region = parsed.Region
			groupId = strings.TrimPrefix(parsed.Resource, "security-group/")
		}
	}
	if args["id"] != nil && groupId == "" {
		groupId = args["id"].Value.(string)
	}
	if args["region"] != nil {
		if r, ok := args["region"].Value.(string); ok && r != "" {
			region = r
		}
	}

	if region != "" && groupId != "" {
		conn := runtime.Connection.(*connection.AwsConnection)

		// Check again now that the ARN can be derived. The check above only
		// fires for a caller that passed one, and the callers that pass an id
		// instead are the hot path: a policy scan over 160 assets spent 2,862
		// DescribeSecurityGroups calls on 102 distinct groups, 40% of all its
		// API traffic, because every reference re-derived the same group.
		if cached := cachedByArn(runtime, ResourceAwsEc2Securitygroup,
			NewSecurityGroupArn(region, conn.AccountId(), groupId)); cached != nil {
			return args, cached, nil
		}

		svc := conn.Ec2(region)
		resp, err := svc.DescribeSecurityGroups(context.Background(), &ec2.DescribeSecurityGroupsInput{
			GroupIds: []string{groupId},
		})
		if err != nil {
			return nil, nil, err
		}
		if len(resp.SecurityGroups) > 0 {
			sg, err := buildSecurityGroupResource(runtime, region, conn.AccountId(), resp.SecurityGroups[0])
			if err != nil {
				return nil, nil, err
			}
			return args, sg, nil
		}
		return nil, nil, errors.New("security group does not exist")
	}

	// Fallback: scan the cached list (e.g. when called with just an opaque id
	// and no region hint).
	obj, err := CreateResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	awsEc2 := obj.(*mqlAwsEc2)
	rawResources := awsEc2.GetSecurityGroups()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	var match func(secGroup *mqlAwsEc2Securitygroup) bool
	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		match = func(secGroup *mqlAwsEc2Securitygroup) bool {
			return secGroup.Arn.Data == arnVal
		}
	}
	if args["id"] != nil {
		idVal := args["id"].Value.(string)
		match = func(secGroup *mqlAwsEc2Securitygroup) bool {
			return secGroup.Id.Data == idVal
		}
	}

	for _, rawResource := range rawResources.Data {
		securityGroup := rawResource.(*mqlAwsEc2Securitygroup)
		if match(securityGroup) {
			return args, securityGroup, nil
		}
	}

	return nil, nil, errors.New("security group does not exist")
}

func (a *mqlAwsEc2SecuritygroupIppermission) id() (string, error) {
	return a.Id.Data, nil
}

// includesPublicSource reports whether the rule allows traffic from the entire
// internet — an IPv4 range of 0.0.0.0/0 or an IPv6 range of ::/0.
func (a *mqlAwsEc2SecuritygroupIppermission) includesPublicSource() (bool, error) {
	ipv4 := a.GetIpRanges()
	if ipv4.Error != nil {
		return false, ipv4.Error
	}
	if anyCidrPublic(ipv4.Data) {
		return true, nil
	}
	ipv6 := a.GetIpv6Ranges()
	if ipv6.Error != nil {
		return false, ipv6.Error
	}
	if anyCidrPublic(ipv6.Data) {
		return true, nil
	}

	// A referenced managed prefix list can itself contain public ranges, so a
	// rule that names only a prefix list can still be internet-facing.
	prefixLists := a.GetPrefixLists()
	if prefixLists.Error != nil {
		return false, prefixLists.Error
	}
	for _, pl := range prefixLists.Data {
		mpl, ok := pl.(*mqlAwsEc2ManagedPrefixList)
		if !ok {
			continue
		}
		entries := mpl.GetEntries()
		if entries.Error != nil {
			return false, entries.Error
		}
		for _, e := range entries.Data {
			entry, ok := e.(*mqlAwsEc2ManagedPrefixListEntry)
			if ok && cidrIsPublic(entry.Cidr.Data) {
				return true, nil
			}
		}
	}
	return false, nil
}

// anyStringEquals reports whether any element of the slice equals target.
func anyStringEquals(list []any, target string) bool {
	for _, item := range list {
		if s, ok := item.(string); ok && s == target {
			return true
		}
	}
	return false
}

type mqlAwsEc2InstanceDeviceInternal struct {
	cacheVolumeId string
	region        string
}

// instanceDeviceCacheKey identifies one block device mapping.
//
// A device is identified by the instance it is attached to and its name in that
// instance. The volume id is not usable here: it lives on the Internal struct,
// which is only populated after the generated constructor has already computed
// the cache key from it.
func instanceDeviceCacheKey(region, instanceID, deviceName string) string {
	return region + "/" + instanceID + "/" + deviceName
}

// id is a fallback only. gatherInstanceInfo passes an explicit "__id", which
// wins, because cacheVolumeId is still empty while the generated constructor
// runs and every device would otherwise share one cache entry.
func (a *mqlAwsEc2InstanceDevice) id() (string, error) {
	return a.cacheVolumeId, nil
}

func (a *mqlAwsEc2InstanceDevice) volume() (*mqlAwsEc2Volume, error) {
	volumeID := a.cacheVolumeId
	if volumeID == "" {
		a.Volume.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	arnStr := fmt.Sprintf(volumeArnPattern, a.region, conn.AccountId(), volumeID)
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Volume,
		map[string]*llx.RawData{"arn": llx.StringData(arnStr)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Volume), nil
}

func (a *mqlAwsEc2Instance) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2Instance) vpc() (*mqlAwsVpc, error) {
	// Instances without a VPC (terminated instances drop VpcId) have no ARN to
	// resolve; treat that as a null field rather than falling through with an
	// empty arn, which would trigger an account-wide VPC scan that ends in a
	// misleading "vpc does not exist" error.
	vpcArn := a.cacheVpcArn
	if vpcArn == "" {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc", map[string]*llx.RawData{"arn": llx.StringData(vpcArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

func (a *mqlAwsEc2Instance) ssm() (any, error) {
	instanceId := a.InstanceId.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ssm(region)
	ctx := context.Background()
	instanceIdFilter := "InstanceIds"
	params := &ssm.DescribeInstanceInformationInput{
		Filters: []ssmtypes.InstanceInformationStringFilter{
			{Key: &instanceIdFilter, Values: []string{instanceId}},
		},
	}
	ssmInstanceInfo, err := svc.DescribeInstanceInformation(ctx, params)
	if err != nil {
		return nil, err
	}
	res, err := convert.JsonToDict(ssmInstanceInfo)
	if err != nil {
		return nil, err
	}
	return res, nil
}

func (a *mqlAwsEc2Instance) patchState() (any, error) {
	var res any
	instanceId := a.InstanceId.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ssm(region)
	ctx := context.Background()

	ssmPatchInfo, err := svc.DescribeInstancePatchStates(ctx, &ssm.DescribeInstancePatchStatesInput{InstanceIds: []string{instanceId}})
	if err != nil {
		return nil, err
	}
	if len(ssmPatchInfo.InstancePatchStates) > 0 {
		if instanceId == convert.ToValue(ssmPatchInfo.InstancePatchStates[0].InstanceId) {
			res, err = convert.JsonToDict(ssmPatchInfo.InstancePatchStates[0])
			if err != nil {
				return nil, err
			}
		}
	}
	return res, nil
}

func (a *mqlAwsEc2Instance) instanceStatus() (any, error) {
	var res any
	instanceId := a.InstanceId.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Ec2(region)
	ctx := context.Background()

	instanceStatus, err := svc.DescribeInstanceStatus(ctx, &ec2.DescribeInstanceStatusInput{
		InstanceIds:         []string{instanceId},
		IncludeAllInstances: aws.Bool(true),
	})
	if err != nil {
		return nil, err
	}

	if len(instanceStatus.InstanceStatuses) > 0 {
		if instanceId == convert.ToValue(instanceStatus.InstanceStatuses[0].InstanceId) {
			res, err = convert.JsonToDict(instanceStatus.InstanceStatuses[0])
			if err != nil {
				return nil, err
			}
		}
	}

	return res, nil
}

func (a *mqlAwsEc2Instance) disableApiTermination() (bool, error) {
	instanceId := a.InstanceId.Data
	region := a.Region.Data
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)

	svc := conn.Ec2(region)
	ctx := context.Background()

	result, err := svc.DescribeInstanceAttribute(ctx, &ec2.DescribeInstanceAttributeInput{
		InstanceId: aws.String(instanceId),
		Attribute:  ec2types.InstanceAttributeNameDisableApiTermination,
	})
	if err != nil {
		return false, err
	}

	if result.DisableApiTermination != nil && result.DisableApiTermination.Value != nil {
		return *result.DisableApiTermination.Value, nil
	}

	return false, nil
}

func (a *mqlAwsEc2Instance) iamInstanceProfile() (*mqlAwsIamInstanceProfile, error) {
	if a.instanceCache.IamInstanceProfile == nil {
		a.IamInstanceProfile.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}

	arn := a.instanceCache.IamInstanceProfile.Arn

	res, err := NewResource(a.MqlRuntime, ResourceAwsIamInstanceProfile, map[string]*llx.RawData{
		"arn": llx.StringDataPtr(arn),
	})
	if err != nil {
		return nil, err
	}

	return res.(*mqlAwsIamInstanceProfile), nil
}

func (a *mqlAwsEc2) volumes() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVolumes(conn), 5)
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

func (a *mqlAwsEc2) getVolumes(conn *connection.AwsConnection) []*jobpool.Job {
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

			params := &ec2.DescribeVolumesInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			}
			paginator := ec2.NewDescribeVolumesPaginator(svc, params)
			for paginator.HasMorePages() {
				volumes, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, vol := range volumes.Volumes {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(vol.Tags)) {
						log.Debug().Interface("volume", vol.VolumeId).Msg("excluding volume due to filters")
						continue
					}
					mqlVol, err := buildVolumeResource(a.MqlRuntime, region, conn.AccountId(), vol)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlVol)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func initAwsEc2Volume(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// A reference already materialized by an earlier referrer or by the
	// list that built it. NewResource consults the cache only after this
	// init returns, so without this the same target is fetched once per
	// referring resource and the result discarded.
	if cached := cachedArgByArn(runtime, ResourceAwsEc2Volume, args); cached != nil {
		return args, cached, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEbsVolume); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch aws volume")
	}
	arnVal := args["arn"].Value.(string)

	parsed, err := arn.Parse(arnVal)
	if err == nil && parsed.Region != "" && strings.HasPrefix(parsed.Resource, "volume/") {
		volumeId := strings.TrimPrefix(parsed.Resource, "volume/")
		conn := runtime.Connection.(*connection.AwsConnection)
		svc := conn.Ec2(parsed.Region)
		resp, err := svc.DescribeVolumes(context.Background(), &ec2.DescribeVolumesInput{
			VolumeIds: []string{volumeId},
		})
		if err != nil {
			return nil, nil, err
		}
		if len(resp.Volumes) > 0 {
			mqlVol, err := buildVolumeResource(runtime, parsed.Region, conn.AccountId(), resp.Volumes[0])
			if err != nil {
				return nil, nil, err
			}
			return args, mqlVol, nil
		}
		return nil, nil, errors.New("volume does not exist")
	}

	// Fallback: scan the cached list when the ARN is unparseable.
	obj, err := CreateResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	awsEc2 := obj.(*mqlAwsEc2)
	rawResources := awsEc2.GetVolumes()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, rawResource := range rawResources.Data {
		volume := rawResource.(*mqlAwsEc2Volume)
		if volume.Arn.Data == arnVal {
			return args, volume, nil
		}
	}
	return nil, nil, errors.New("volume does not exist")
}

func buildVolumeResource(runtime *plugin.Runtime, region, accountID string, vol ec2types.Volume) (*mqlAwsEc2Volume, error) {
	jsonAttachments, err := convert.JsonToDictSlice(vol.Attachments)
	if err != nil {
		return nil, err
	}
	mqlVol, err := CreateResource(runtime, ResourceAwsEc2Volume,
		map[string]*llx.RawData{
			"arn":                llx.StringData(fmt.Sprintf(volumeArnPattern, region, accountID, convert.ToValue(vol.VolumeId))),
			"attachments":        llx.ArrayData(jsonAttachments, types.Any),
			"availabilityZone":   llx.StringDataPtr(vol.AvailabilityZone),
			"createTime":         llx.TimeDataPtr(vol.CreateTime),
			"encrypted":          llx.BoolDataPtr(vol.Encrypted),
			"id":                 llx.StringDataPtr(vol.VolumeId),
			"iops":               llx.IntDataDefault(vol.Iops, 0),
			"multiAttachEnabled": llx.BoolDataPtr(vol.MultiAttachEnabled),
			"region":             llx.StringData(region),
			"size":               llx.IntDataDefault(vol.Size, 0),
			"state":              llx.StringData(string(vol.State)),
			"tags":               llx.MapData(toInterfaceMap(ec2TagsToMap(vol.Tags)), types.String),
			"throughput":         llx.IntDataDefault(vol.Throughput, 0),
			"volumeType":         llx.StringData(string(vol.VolumeType)),
			"sseType":            llx.StringData(deriveVolumeSseType(vol)),
			"fastRestored":       llx.BoolDataPtr(vol.FastRestored),
			"snapshotId":         llx.StringDataPtr(vol.SnapshotId),
		})
	if err != nil {
		return nil, err
	}
	v := mqlVol.(*mqlAwsEc2Volume)
	v.cacheKmsKeyId = vol.KmsKeyId
	v.cacheSourceVolumeId = vol.SourceVolumeId
	return v, nil
}

type mqlAwsEc2VolumeInternal struct {
	cacheKmsKeyId       *string
	cacheSourceVolumeId *string
}

// snapshot resolves the source snapshot when it is still present in this
// account. Volumes are frequently created from snapshots owned by Amazon (AMI
// snapshots) or from since-deleted snapshots, which cannot be fetched; in that
// case the reference is null and the snapshotId field carries the lineage id.
func (a *mqlAwsEc2Volume) snapshot() (*mqlAwsEc2Snapshot, error) {
	if !a.SnapshotId.IsSet() || a.SnapshotId.Data == "" {
		a.Snapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlSnap, err := NewResource(a.MqlRuntime, ResourceAwsEc2Snapshot,
		map[string]*llx.RawData{"id": llx.StringData(a.SnapshotId.Data)})
	if err != nil {
		a.Snapshot.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return mqlSnap.(*mqlAwsEc2Snapshot), nil
}

// sourceVolume resolves the volume this volume was copied from when it is still
// present in this account. The source id is only set for volume copies, and the
// source is frequently since-deleted; in that case the reference is null.
func (a *mqlAwsEc2Volume) sourceVolume() (*mqlAwsEc2Volume, error) {
	if a.cacheSourceVolumeId == nil || *a.cacheSourceVolumeId == "" {
		a.SourceVolume.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	volumeArn := fmt.Sprintf(volumeArnPattern, a.Region.Data, conn.AccountId(), *a.cacheSourceVolumeId)
	mqlVol, err := NewResource(a.MqlRuntime, ResourceAwsEc2Volume,
		map[string]*llx.RawData{"arn": llx.StringData(volumeArn)})
	if err != nil {
		a.SourceVolume.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return mqlVol.(*mqlAwsEc2Volume), nil
}

func (a *mqlAwsEc2Volume) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// KmsKeyId is already an ARN from the AWS API
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func initAwsEc2Instance(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	log.Debug().Msg("init an ec2 instance")
	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEc2Instance); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil {
		return nil, nil, errors.New("arn required to fetch ec2 instance")
	}
	arnVal := args["arn"].Value.(string)

	if cached := cachedByArn(runtime, ResourceAwsEc2Instance, arnVal); cached != nil {
		return args, cached, nil
	}

	// Parse the ARN to extract region + instance id and target a single
	// DescribeInstances call. Fall back to the cross-region list path only
	// when the ARN is malformed.
	parsed, err := arn.Parse(arnVal)
	if err == nil && parsed.Region != "" && strings.HasPrefix(parsed.Resource, "instance/") {
		instanceId := strings.TrimPrefix(parsed.Resource, "instance/")
		obj, err := CreateResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
		if err != nil {
			return nil, nil, err
		}
		mqlEc2 := obj.(*mqlAwsEc2)

		conn := runtime.Connection.(*connection.AwsConnection)
		svc := conn.Ec2(parsed.Region)
		resp, err := svc.DescribeInstances(context.Background(), &ec2.DescribeInstancesInput{
			InstanceIds: []string{instanceId},
		})
		if err != nil {
			return nil, nil, err
		}
		for _, reservation := range resp.Reservations {
			if len(reservation.Instances) == 0 {
				continue
			}
			res, err := mqlEc2.gatherInstanceInfo(reservation.Instances[:1], parsed.Region)
			if err != nil {
				return nil, nil, err
			}
			if len(res) > 0 {
				return args, res[0].(*mqlAwsEc2Instance), nil
			}
		}
		return nil, nil, errors.New("ec2 instance does not exist")
	}

	// Fallback for unparseable ARNs: scan the cached list.
	obj, err := CreateResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	mqlEc2 := obj.(*mqlAwsEc2)
	rawResources := mqlEc2.GetInstances()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	for _, rawResource := range rawResources.Data {
		instance := rawResource.(*mqlAwsEc2Instance)
		if instance.Arn.Data == arnVal {
			return args, instance, nil
		}
	}
	return nil, nil, errors.New("ec2 instance does not exist")
}

func buildSnapshotResource(runtime *plugin.Runtime, region, accountID string, snapshot ec2types.Snapshot) (*mqlAwsEc2Snapshot, error) {
	mqlSnap, err := CreateResource(runtime, ResourceAwsEc2Snapshot,
		map[string]*llx.RawData{
			"arn":                 llx.StringData(fmt.Sprintf(snapshotArnPattern, region, accountID, convert.ToValue(snapshot.SnapshotId))),
			"completionTime":      llx.TimeDataPtr(snapshot.CompletionTime),
			"description":         llx.StringDataPtr(snapshot.Description),
			"encrypted":           llx.BoolDataPtr(snapshot.Encrypted),
			"id":                  llx.StringDataPtr(snapshot.SnapshotId),
			"region":              llx.StringData(region),
			"startTime":           llx.TimeDataPtr(snapshot.StartTime),
			"state":               llx.StringData(string(snapshot.State)),
			"storageTier":         llx.StringData(string(snapshot.StorageTier)),
			"tags":                llx.MapData(toInterfaceMap(ec2TagsToMap(snapshot.Tags)), types.String),
			"volumeId":            llx.StringDataPtr(snapshot.VolumeId),
			"volumeSize":          llx.IntDataDefault(snapshot.VolumeSize, 0),
			"dataEncryptionKeyId": llx.StringDataPtr(snapshot.DataEncryptionKeyId),
			"ownerAlias":          llx.StringDataPtr(snapshot.OwnerAlias),
			"ownerId":             llx.StringDataPtr(snapshot.OwnerId),
			"outpostArn":          llx.StringDataPtr(snapshot.OutpostArn),
			"transferType":        llx.StringData(string(snapshot.TransferType)),
			"restoreExpiryTime":   llx.TimeDataPtr(snapshot.RestoreExpiryTime),
		})
	if err != nil {
		return nil, err
	}
	s := mqlSnap.(*mqlAwsEc2Snapshot)
	s.cacheKmsKeyId = snapshot.KmsKeyId
	return s, nil
}

func initAwsEc2Snapshot(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	// A reference already materialized by an earlier referrer or by the
	// list that built it. NewResource consults the cache only after this
	// init returns, so without this the same target is fetched once per
	// referring resource and the result discarded.
	if cached := cachedArgByArn(runtime, ResourceAwsEc2Snapshot, args); cached != nil {
		return args, cached, nil
	}

	if len(args) == 0 {
		if assetArn := getAssetIdentifier(runtime, connection.PlatformEbsSnapshot); assetArn != "" {
			args["arn"] = llx.StringData(assetArn)
		}
	}

	if args["arn"] == nil && args["id"] == nil {
		return nil, nil, errors.New("arn or id required to fetch aws snapshot")
	}

	// Targeted path: arn carries the region and snapshot id.
	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		if parsed, err := arn.Parse(arnVal); err == nil && parsed.Region != "" && strings.HasPrefix(parsed.Resource, "snapshot/") {
			snapshotId := strings.TrimPrefix(parsed.Resource, "snapshot/")
			conn := runtime.Connection.(*connection.AwsConnection)
			svc := conn.Ec2(parsed.Region)
			resp, err := svc.DescribeSnapshots(context.Background(), &ec2.DescribeSnapshotsInput{
				SnapshotIds: []string{snapshotId},
			})
			if err != nil {
				return nil, nil, err
			}
			if len(resp.Snapshots) > 0 {
				mqlSnap, err := buildSnapshotResource(runtime, parsed.Region, conn.AccountId(), resp.Snapshots[0])
				if err != nil {
					return nil, nil, err
				}
				return args, mqlSnap, nil
			}
			return nil, nil, errors.New("snapshot does not exist")
		}
	}

	// Fallback: scan the cached list when only an opaque id was supplied or
	// the arn was unparseable.
	obj, err := CreateResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	awsEc2 := obj.(*mqlAwsEc2)
	rawResources := awsEc2.GetSnapshots()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}
	var match func(snapshot *mqlAwsEc2Snapshot) bool
	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		match = func(snapshot *mqlAwsEc2Snapshot) bool {
			return snapshot.Arn.Data == arnVal
		}
	}
	if args["id"] != nil {
		idVal := args["id"].Value.(string)
		match = func(snap *mqlAwsEc2Snapshot) bool {
			return snap.Id.Data == idVal
		}
	}
	for _, rawResource := range rawResources.Data {
		snapshot := rawResource.(*mqlAwsEc2Snapshot)
		if match(snapshot) {
			return args, snapshot, nil
		}
	}
	return nil, nil, errors.New("snapshot does not exist")
}

func (a *mqlAwsEc2Volume) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2Snapshot) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2) vpnConnections() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getVpnConnections(conn), 5)
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

func (a *mqlAwsEc2) getVpnConnections(conn *connection.AwsConnection) []*jobpool.Job {
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

			vpnConnections, err := svc.DescribeVpnConnections(ctx, &ec2.DescribeVpnConnectionsInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}
			for _, vpnConn := range vpnConnections.VpnConnections {
				if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(vpnConn.Tags)) {
					log.Debug().Interface("vpnConnection", vpnConn.VpnConnectionId).Msg("excluding vpn connection due to filters")
					continue
				}
				mqlVpnConn, err := newMqlVpnConnection(a.MqlRuntime, region, conn.AccountId(), vpnConn)
				if err != nil {
					return nil, err
				}
				res = append(res, mqlVpnConn)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2) snapshots() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getSnapshots(conn), 5)
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

func (a *mqlAwsEc2) getSnapshots(conn *connection.AwsConnection) []*jobpool.Job {
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

			filters := conn.Filters.General.ToServerSideEc2Filters()
			filters = append(filters, ec2types.Filter{Name: aws.String("owner-id"), Values: []string{conn.AccountId()}})
			params := &ec2.DescribeSnapshotsInput{
				Filters: filters,
			}
			paginator := ec2.NewDescribeSnapshotsPaginator(svc, params)
			for paginator.HasMorePages() {
				snapshots, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, snapshot := range snapshots.Snapshots {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(snapshot.Tags)) {
						log.Debug().Interface("snapshot", snapshot.SnapshotId).Msg("excluding snapshot due to filters")
						continue
					}
					mqlSnap, err := buildSnapshotResource(a.MqlRuntime, region, conn.AccountId(), snapshot)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlSnap)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEc2SnapshotInternal struct {
	cacheKmsKeyId *string

	cvpOnce   sync.Once
	cvp       []ec2types.CreateVolumePermission
	cvpErr    error
	cvpDenied bool
}

// fetchCreateVolumePermissions reads the snapshot's createVolumePermission
// attribute once. Four fields answer from it (the deprecated dict, the two
// typed lists, and isPublic), and without memoizing, a query touching more
// than one of them repeats DescribeSnapshotAttribute per field per snapshot.
func (a *mqlAwsEc2Snapshot) fetchCreateVolumePermissions() ([]ec2types.CreateVolumePermission, bool, error) {
	a.cvpOnce.Do(func() {
		id := a.Id.Data
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Ec2(a.Region.Data)
		attribute, err := svc.DescribeSnapshotAttribute(context.Background(), &ec2.DescribeSnapshotAttributeInput{
			SnapshotId: &id,
			Attribute:  ec2types.SnapshotAttributeNameCreateVolumePermission,
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Debug().Str("snapshot", id).Msg("access denied when retrieving snapshot volume permissions")
				a.cvpDenied = true
				return
			}
			a.cvpErr = err
			return
		}
		a.cvp = attribute.CreateVolumePermissions
	})
	return a.cvp, a.cvpDenied, a.cvpErr
}

// sourceVolume resolves the volume the snapshot was created from when it is
// still present in this account. Snapshots commonly outlive the volume they
// were taken from, so the volume is frequently gone; in that case the reference
// is null and the volumeId field carries the lineage id.
func (a *mqlAwsEc2Snapshot) sourceVolume() (*mqlAwsEc2Volume, error) {
	if !a.VolumeId.IsSet() || a.VolumeId.Data == "" {
		a.SourceVolume.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	volumeArn := fmt.Sprintf(volumeArnPattern, a.Region.Data, conn.AccountId(), a.VolumeId.Data)
	mqlVol, err := NewResource(a.MqlRuntime, ResourceAwsEc2Volume,
		map[string]*llx.RawData{"arn": llx.StringData(volumeArn)})
	if err != nil {
		a.SourceVolume.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return mqlVol.(*mqlAwsEc2Volume), nil
}

func (a *mqlAwsEc2Snapshot) kmsKey() (*mqlAwsKmsKey, error) {
	if a.cacheKmsKeyId == nil || *a.cacheKmsKeyId == "" {
		a.KmsKey.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// KmsKeyId is already an ARN from the AWS API
	mqlKey, err := NewResource(a.MqlRuntime, ResourceAwsKmsKey,
		map[string]*llx.RawData{
			"arn": llx.StringDataPtr(a.cacheKmsKeyId),
		})
	if err != nil {
		return nil, err
	}
	return mqlKey.(*mqlAwsKmsKey), nil
}

func (a *mqlAwsEc2Snapshot) isPublic() (bool, error) {
	perms, denied, err := a.fetchCreateVolumePermissions()
	if err != nil {
		return false, err
	}
	if denied {
		// Reading false out of a denied call would assert the snapshot is
		// definitively not public when its permissions were never read.
		a.IsPublic.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	for _, p := range perms {
		if p.Group == ec2types.PermissionGroupAll {
			return true, nil
		}
	}
	return false, nil
}

func (a *mqlAwsEc2Snapshot) createVolumePermissionUserIds() ([]any, error) {
	perms, denied, err := a.fetchCreateVolumePermissions()
	if err != nil {
		return nil, err
	}
	if denied {
		// Reading "no accounts" out of a denied call would report the snapshot
		// as unshared when it may not be.
		a.CreateVolumePermissionUserIds.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for _, p := range perms {
		if p.UserId != nil && *p.UserId != "" {
			res = append(res, *p.UserId)
		}
	}
	return res, nil
}

func (a *mqlAwsEc2Snapshot) createVolumePermissionGroups() ([]any, error) {
	perms, denied, err := a.fetchCreateVolumePermissions()
	if err != nil {
		return nil, err
	}
	if denied {
		a.CreateVolumePermissionGroups.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res := []any{}
	for _, p := range perms {
		if p.Group != "" {
			res = append(res, string(p.Group))
		}
	}
	return res, nil
}

func (a *mqlAwsEc2Snapshot) createVolumePermission() ([]any, error) {
	perms, denied, err := a.fetchCreateVolumePermissions()
	if err != nil {
		return nil, err
	}
	if denied {
		a.CreateVolumePermission.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return convert.JsonToDictSlice(perms)
}

func (a *mqlAwsEc2) internetGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getInternetGateways(conn), 5)
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

func (a *mqlAwsEc2) getInternetGateways(conn *connection.AwsConnection) []*jobpool.Job {
	tasks := make([]*jobpool.Job, 0)
	regions, err := conn.Regions()
	if err != nil {
		return []*jobpool.Job{{Err: err}}
	}
	for _, region := range regions {
		f := func() (jobpool.JobResult, error) {
			svc := conn.Ec2(region)
			ctx := context.Background()
			params := &ec2.DescribeInternetGatewaysInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			}
			res := []any{}
			paginator := ec2.NewDescribeInternetGatewaysPaginator(svc, params)
			for paginator.HasMorePages() {
				internetGws, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, gateway := range internetGws.InternetGateways {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(gateway.Tags)) {
						log.Debug().Interface("igw", gateway.InternetGatewayId).Msg("excluding internet gateway due to filters")
						continue
					}
					mqlInternetGw, err := newMqlAwsEc2Internetgateway(a.MqlRuntime, region, conn, gateway)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlInternetGw)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

func (a *mqlAwsEc2Internetgateway) id() (string, error) {
	return a.Arn.Data, nil
}

// newMqlAwsEc2Internetgateway builds an aws.ec2.internetgateway resource from an
// SDK InternetGateway. Shared by the account-level list and the by-id init so
// both paths produce an identically shaped resource.
func newMqlAwsEc2Internetgateway(runtime *plugin.Runtime, region string, conn *connection.AwsConnection, gateway ec2types.InternetGateway) (plugin.Resource, error) {
	jsonAttachments, err := convert.JsonToDictSlice(gateway.Attachments)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, ResourceAwsEc2Internetgateway,
		map[string]*llx.RawData{
			"arn":         llx.StringData(fmt.Sprintf(internetGwArnPattern, region, conn.AccountId(), convert.ToValue(gateway.InternetGatewayId))),
			"id":          llx.StringData(convert.ToValue(gateway.InternetGatewayId)),
			"region":      llx.StringData(region),
			"attachments": llx.ArrayData(jsonAttachments, types.Any),
			"tags":        llx.MapData(toInterfaceMap(ec2TagsToMap(gateway.Tags)), types.String),
		})
}

func initAwsEc2Internetgateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil && args["id"] == nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	var igwID, region string
	if args["id"] != nil {
		igwID, _ = args["id"].Value.(string)
	}
	if args["region"] != nil {
		region, _ = args["region"].Value.(string)
	}
	if args["arn"] != nil {
		if parsed, err := arn.Parse(args["arn"].Value.(string)); err == nil {
			region = parsed.Region
			parts := strings.Split(parsed.Resource, "/")
			if len(parts) == 2 {
				igwID = parts[1]
			}
		}
	}
	// Without both id and region a targeted lookup is not possible; hand back a
	// bare resource.
	if igwID == "" || region == "" {
		return args, nil, nil
	}

	// Reuse the internet gateway already materialized by aws.ec2.internetGateways()
	// (routes commonly share one gateway) before spending a DescribeInternetGateways call.
	cacheID := ResourceAwsEc2Internetgateway + "\x00" + fmt.Sprintf(internetGwArnPattern, region, conn.AccountId(), igwID)
	if cached, ok := runtime.Resources.Get(cacheID); ok {
		return args, cached, nil
	}

	svc := conn.Ec2(region)
	resp, err := svc.DescribeInternetGateways(context.Background(), &ec2.DescribeInternetGatewaysInput{
		InternetGatewayIds: []string{igwID},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil, fmt.Errorf("access denied fetching aws.ec2.internetGateway with id %q in region %s", igwID, region)
		}
		return nil, nil, err
	}
	if len(resp.InternetGateways) == 0 {
		return nil, nil, fmt.Errorf("aws.ec2.internetGateway with id %q not found", igwID)
	}
	res, err := newMqlAwsEc2Internetgateway(runtime, region, conn, resp.InternetGateways[0])
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAwsEc2Transitgateway) id() (string, error) {
	return a.Arn.Data, nil
}

// newMqlAwsEc2Transitgateway builds an aws.ec2.transitgateway from an SDK
// TransitGateway, flattening its Options block. Shared by the account-level list
// and the by-id init.
func newMqlAwsEc2Transitgateway(runtime *plugin.Runtime, region string, tgw ec2types.TransitGateway) (plugin.Resource, error) {
	tgwArn := convert.ToValue(tgw.TransitGatewayArn)
	if tgwArn == "" {
		tgwArn = fmt.Sprintf(transitGatewayArnPattern, region, convert.ToValue(tgw.OwnerId), convert.ToValue(tgw.TransitGatewayId))
	}

	// Flatten Options
	var amazonSideAsn int64
	var autoAcceptSharedAttachments, defaultRouteTableAssociation, defaultRouteTablePropagation bool
	var dnsSupport, multicastSupport, vpnEcmpSupport bool
	var transitGatewayCidrBlocks []string
	var associationDefaultRouteTableId, propagationDefaultRouteTableId string
	if opts := tgw.Options; opts != nil {
		if opts.AmazonSideAsn != nil {
			amazonSideAsn = *opts.AmazonSideAsn
		}
		autoAcceptSharedAttachments = string(opts.AutoAcceptSharedAttachments) == "enable"
		defaultRouteTableAssociation = string(opts.DefaultRouteTableAssociation) == "enable"
		defaultRouteTablePropagation = string(opts.DefaultRouteTablePropagation) == "enable"
		dnsSupport = string(opts.DnsSupport) == "enable"
		multicastSupport = string(opts.MulticastSupport) == "enable"
		vpnEcmpSupport = string(opts.VpnEcmpSupport) == "enable"
		transitGatewayCidrBlocks = opts.TransitGatewayCidrBlocks
		associationDefaultRouteTableId = convert.ToValue(opts.AssociationDefaultRouteTableId)
		propagationDefaultRouteTableId = convert.ToValue(opts.PropagationDefaultRouteTableId)
	}

	mqlTgw, err := CreateResource(runtime, ResourceAwsEc2Transitgateway,
		map[string]*llx.RawData{
			"__id":                           llx.StringData(tgwArn),
			"arn":                            llx.StringData(tgwArn),
			"id":                             llx.StringData(convert.ToValue(tgw.TransitGatewayId)),
			"ownerId":                        llx.StringData(convert.ToValue(tgw.OwnerId)),
			"state":                          llx.StringData(string(tgw.State)),
			"description":                    llx.StringData(convert.ToValue(tgw.Description)),
			"region":                         llx.StringData(region),
			"createdAt":                      llx.TimeDataPtr(tgw.CreationTime),
			"tags":                           llx.MapData(toInterfaceMap(ec2TagsToMap(tgw.Tags)), types.String),
			"amazonSideAsn":                  llx.IntData(amazonSideAsn),
			"autoAcceptSharedAttachments":    llx.BoolData(autoAcceptSharedAttachments),
			"defaultRouteTableAssociation":   llx.BoolData(defaultRouteTableAssociation),
			"defaultRouteTablePropagation":   llx.BoolData(defaultRouteTablePropagation),
			"dnsSupport":                     llx.BoolData(dnsSupport),
			"multicastSupport":               llx.BoolData(multicastSupport),
			"vpnEcmpSupport":                 llx.BoolData(vpnEcmpSupport),
			"transitGatewayCidrBlocks":       llx.ArrayData(convert.SliceAnyToInterface(transitGatewayCidrBlocks), types.String),
			"associationDefaultRouteTableId": llx.StringData(associationDefaultRouteTableId),
			"propagationDefaultRouteTableId": llx.StringData(propagationDefaultRouteTableId),
		})
	if err != nil {
		return nil, err
	}
	mqlTgw.(*mqlAwsEc2Transitgateway).region = region
	return mqlTgw, nil
}

func initAwsEc2Transitgateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil && args["id"] == nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	var tgwID, region string
	if args["id"] != nil {
		tgwID, _ = args["id"].Value.(string)
	}
	if args["region"] != nil {
		region, _ = args["region"].Value.(string)
	}
	if args["arn"] != nil {
		if parsed, err := arn.Parse(args["arn"].Value.(string)); err == nil {
			region = parsed.Region
			parts := strings.Split(parsed.Resource, "/")
			if len(parts) == 2 {
				tgwID = parts[1]
			}
		}
	}
	if tgwID == "" || region == "" {
		return args, nil, nil
	}

	// Reuse a transit gateway already listed before spending an API call. The
	// cache key uses the caller's account; a cross-account shared gateway misses
	// here and is fetched below (still correct).
	cacheID := ResourceAwsEc2Transitgateway + "\x00" + fmt.Sprintf(transitGatewayArnPattern, region, conn.AccountId(), tgwID)
	if cached, ok := runtime.Resources.Get(cacheID); ok {
		return args, cached, nil
	}

	svc := conn.Ec2(region)
	resp, err := svc.DescribeTransitGateways(context.Background(), &ec2.DescribeTransitGatewaysInput{
		TransitGatewayIds: []string{tgwID},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil, fmt.Errorf("access denied fetching aws.ec2.transitGateway with id %q in region %s", tgwID, region)
		}
		return nil, nil, err
	}
	if len(resp.TransitGateways) == 0 {
		return nil, nil, fmt.Errorf("aws.ec2.transitGateway with id %q not found", tgwID)
	}
	res, err := newMqlAwsEc2Transitgateway(runtime, region, resp.TransitGateways[0])
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAwsEc2) transitGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getTransitGateways(conn), 5)
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

func (a *mqlAwsEc2) getTransitGateways(conn *connection.AwsConnection) []*jobpool.Job {
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
			paginator := ec2.NewDescribeTransitGatewaysPaginator(svc, &ec2.DescribeTransitGatewaysInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, tgw := range page.TransitGateways {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(tgw.Tags)) {
						log.Debug().Interface("tgw", tgw.TransitGatewayId).Msg("excluding transit gateway due to filters")
						continue
					}
					mqlTgw, err := newMqlAwsEc2Transitgateway(a.MqlRuntime, region, tgw)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlTgw)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// Transit gateway internal and methods (#38-39)

type mqlAwsEc2TransitgatewayInternal struct {
	region string
}

func (a *mqlAwsEc2TransitgatewayAttachment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsEc2TransitgatewayAttachment) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(tgwAttachmentArnPattern, a.Region.Data, conn.AccountId(), a.Id.Data), nil
}

func (a *mqlAwsEc2TransitgatewayRouteTable) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsEc2TransitgatewayRouteTable) arn() (string, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	return fmt.Sprintf(tgwRouteTableArnPattern, a.Region.Data, conn.AccountId(), a.Id.Data), nil
}

func (a *mqlAwsEc2Transitgateway) attachments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.region)
	ctx := context.Background()

	filterKeyVal := "transit-gateway-id"
	params := &ec2.DescribeTransitGatewayAttachmentsInput{
		Filters: []ec2types.Filter{{Name: &filterKeyVal, Values: []string{a.Id.Data}}},
	}
	paginator := ec2.NewDescribeTransitGatewayAttachmentsPaginator(svc, params)
	attachments := []any{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return attachments, nil
			}
			return nil, err
		}
		for _, att := range page.TransitGatewayAttachments {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(att.Tags)) {
				continue
			}
			mqlAtt, err := newMqlAwsEc2TransitgatewayAttachment(a.MqlRuntime, a.region, att)
			if err != nil {
				return nil, err
			}
			attachments = append(attachments, mqlAtt)
		}
	}
	return attachments, nil
}

func (a *mqlAwsEc2Transitgateway) routeTables() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.region)
	ctx := context.Background()

	filterKeyVal := "transit-gateway-id"
	params := &ec2.DescribeTransitGatewayRouteTablesInput{
		Filters: []ec2types.Filter{{Name: &filterKeyVal, Values: []string{a.Id.Data}}},
	}
	paginator := ec2.NewDescribeTransitGatewayRouteTablesPaginator(svc, params)
	routeTables := []any{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return routeTables, nil
			}
			return nil, err
		}
		for _, rt := range page.TransitGatewayRouteTables {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(rt.Tags)) {
				continue
			}
			mqlRt, err := CreateResource(a.MqlRuntime, ResourceAwsEc2TransitgatewayRouteTable,
				map[string]*llx.RawData{
					"id":                           llx.StringData(convert.ToValue(rt.TransitGatewayRouteTableId)),
					"transitGatewayId":             llx.StringData(convert.ToValue(rt.TransitGatewayId)),
					"state":                        llx.StringData(string(rt.State)),
					"defaultAssociationRouteTable": llx.BoolData(convert.ToValue(rt.DefaultAssociationRouteTable)),
					"defaultPropagationRouteTable": llx.BoolData(convert.ToValue(rt.DefaultPropagationRouteTable)),
					"createdAt":                    llx.TimeDataPtr(rt.CreationTime),
					"tags":                         llx.MapData(toInterfaceMap(ec2TagsToMap(rt.Tags)), types.String),
					"region":                       llx.StringData(a.region),
				})
			if err != nil {
				return nil, err
			}
			routeTables = append(routeTables, mqlRt)
		}
	}
	return routeTables, nil
}

func (a *mqlAwsEc2Vpnconnection) id() (string, error) {
	return a.Arn.Data, nil
}

// id is a fallback only. A telemetry entry carries nothing but its outside IP,
// which is empty while the tunnel is provisioning and is not scoped to a
// connection, so the creator passes a connection-scoped, indexed __id instead.
func (a *mqlAwsEc2Vgwtelemetry) id() (string, error) {
	return a.OutsideIpAddress.Data, nil
}

// listValuesToStrings extracts the Value field from AWS SDK "...ListValue"
// structs into a []any of strings, guarding nil pointers.
func listValuesToStrings[T any](values []T, get func(T) *string) []any {
	result := []any{}
	for i := range values {
		if v := get(values[i]); v != nil {
			result = append(result, *v)
		}
	}
	return result
}

// dhGroupNumbersToInts extracts the *int32 Value field from AWS SDK DH-group
// "...ListValue" structs into a []any of int64, guarding nil pointers.
func dhGroupNumbersToInts[T any](values []T, get func(T) *int32) []any {
	result := []any{}
	for i := range values {
		if v := get(values[i]); v != nil {
			result = append(result, int64(*v))
		}
	}
	return result
}

// VPN connection enhancement (#3)

type mqlAwsEc2VpnconnectionInternal struct {
	cacheVpnGatewayId      *string
	cacheTransitGatewayId  *string
	cacheCustomerGatewayId *string
	region                 string
	accountID              string
}

func newMqlVpnConnection(runtime *plugin.Runtime, region string, accountID string, vpnConn ec2types.VpnConnection) (*mqlAwsEc2Vpnconnection, error) {
	connID := convert.ToValue(vpnConn.VpnConnectionId)

	mqlVgwT := []any{}
	for i, vgwT := range vpnConn.VgwTelemetry {
		mqlVgwTelemetry, err := CreateResource(runtime, ResourceAwsEc2Vgwtelemetry,
			map[string]*llx.RawData{
				// Scoped to the connection and indexed, for the same reason the
				// tunnel options below are: the outside IP is the only thing
				// distinguishing one telemetry entry from another, and it is
				// empty while a tunnel is still provisioning - so both tunnels
				// of a new connection keyed identically, and every connection
				// in that state shared one row across the whole account.
				"__id":             llx.StringData(fmt.Sprintf("%s/vgwTelemetry/%d/%s", connID, i, convert.ToValue(vgwT.OutsideIpAddress))),
				"outsideIpAddress": llx.StringData(convert.ToValue(vgwT.OutsideIpAddress)),
				"status":           llx.StringData(string(vgwT.Status)),
				"statusMessage":    llx.StringData(convert.ToValue(vgwT.StatusMessage)),
			})
		if err != nil {
			return nil, err
		}
		mqlVgwT = append(mqlVgwT, mqlVgwTelemetry)
	}

	var staticRoutesOnly, enableAcceleration bool
	var localIpv4, remoteIpv4, localIpv6, remoteIpv6, outsideIpType, tunnelIpVersion string
	mqlTunnelOpts := []any{}
	if opts := vpnConn.Options; opts != nil {
		staticRoutesOnly = convert.ToValue(opts.StaticRoutesOnly)
		enableAcceleration = convert.ToValue(opts.EnableAcceleration)
		localIpv4 = convert.ToValue(opts.LocalIpv4NetworkCidr)
		remoteIpv4 = convert.ToValue(opts.RemoteIpv4NetworkCidr)
		localIpv6 = convert.ToValue(opts.LocalIpv6NetworkCidr)
		remoteIpv6 = convert.ToValue(opts.RemoteIpv6NetworkCidr)
		outsideIpType = convert.ToValue(opts.OutsideIpAddressType)
		tunnelIpVersion = string(opts.TunnelInsideIpVersion)

		for i, tun := range opts.TunnelOptions {
			outsideIP := convert.ToValue(tun.OutsideIpAddress)
			mqlTunnelOpt, err := CreateResource(runtime, ResourceAwsEc2VpnconnectionTunnelOption,
				map[string]*llx.RawData{
					// index disambiguates tunnels whose outside IP is still empty during provisioning
					"__id":                       llx.StringData(fmt.Sprintf("%s/tunnelOption/%d/%s", connID, i, outsideIP)),
					"outsideIpAddress":           llx.StringData(outsideIP),
					"tunnelInsideCidr":           llx.StringData(convert.ToValue(tun.TunnelInsideCidr)),
					"ikeVersions":                llx.ArrayData(listValuesToStrings(tun.IkeVersions, func(v ec2types.IKEVersionsListValue) *string { return v.Value }), types.String),
					"phase1EncryptionAlgorithms": llx.ArrayData(listValuesToStrings(tun.Phase1EncryptionAlgorithms, func(v ec2types.Phase1EncryptionAlgorithmsListValue) *string { return v.Value }), types.String),
					"phase2EncryptionAlgorithms": llx.ArrayData(listValuesToStrings(tun.Phase2EncryptionAlgorithms, func(v ec2types.Phase2EncryptionAlgorithmsListValue) *string { return v.Value }), types.String),
					"phase1IntegrityAlgorithms":  llx.ArrayData(listValuesToStrings(tun.Phase1IntegrityAlgorithms, func(v ec2types.Phase1IntegrityAlgorithmsListValue) *string { return v.Value }), types.String),
					"phase2IntegrityAlgorithms":  llx.ArrayData(listValuesToStrings(tun.Phase2IntegrityAlgorithms, func(v ec2types.Phase2IntegrityAlgorithmsListValue) *string { return v.Value }), types.String),
					"phase1DHGroupNumbers":       llx.ArrayData(dhGroupNumbersToInts(tun.Phase1DHGroupNumbers, func(v ec2types.Phase1DHGroupNumbersListValue) *int32 { return v.Value }), types.Int),
					"phase2DHGroupNumbers":       llx.ArrayData(dhGroupNumbersToInts(tun.Phase2DHGroupNumbers, func(v ec2types.Phase2DHGroupNumbersListValue) *int32 { return v.Value }), types.Int),
				})
			if err != nil {
				return nil, err
			}
			mqlTunnelOpts = append(mqlTunnelOpts, mqlTunnelOpt)
		}
	}

	mqlVpnConn, err := CreateResource(runtime, ResourceAwsEc2Vpnconnection,
		map[string]*llx.RawData{
			"arn":                   llx.StringData(fmt.Sprintf(vpnConnArnPattern, region, accountID, convert.ToValue(vpnConn.VpnConnectionId))),
			"id":                    llx.StringData(convert.ToValue(vpnConn.VpnConnectionId)),
			"region":                llx.StringData(region),
			"state":                 llx.StringData(string(vpnConn.State)),
			"type":                  llx.StringData(string(vpnConn.Type)),
			"category":              llx.StringData(convert.ToValue(vpnConn.Category)),
			"staticRoutesOnly":      llx.BoolData(staticRoutesOnly),
			"enableAcceleration":    llx.BoolData(enableAcceleration),
			"localIpv4NetworkCidr":  llx.StringData(localIpv4),
			"remoteIpv4NetworkCidr": llx.StringData(remoteIpv4),
			"localIpv6NetworkCidr":  llx.StringData(localIpv6),
			"remoteIpv6NetworkCidr": llx.StringData(remoteIpv6),
			"outsideIpAddressType":  llx.StringData(outsideIpType),
			"tunnelInsideIpVersion": llx.StringData(tunnelIpVersion),
			"tags":                  llx.MapData(toInterfaceMap(ec2TagsToMap(vpnConn.Tags)), types.String),
			"vgwTelemetry":          llx.ArrayData(mqlVgwT, types.Resource(ResourceAwsEc2Vgwtelemetry)),
			"tunnelOptions":         llx.ArrayData(mqlTunnelOpts, types.Resource(ResourceAwsEc2VpnconnectionTunnelOption)),
		})
	if err != nil {
		return nil, err
	}
	res := mqlVpnConn.(*mqlAwsEc2Vpnconnection)
	res.cacheVpnGatewayId = vpnConn.VpnGatewayId
	res.cacheTransitGatewayId = vpnConn.TransitGatewayId
	res.cacheCustomerGatewayId = vpnConn.CustomerGatewayId
	res.region = region
	res.accountID = accountID
	return res, nil
}

func (a *mqlAwsEc2Vpnconnection) vpnGateway() (*mqlAwsVpcVpnGateway, error) {
	if a.cacheVpnGatewayId == nil || *a.cacheVpnGatewayId == "" {
		a.VpnGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	mqlVgw, err := NewResource(a.MqlRuntime, ResourceAwsVpcVpnGateway,
		map[string]*llx.RawData{
			"arn": llx.StringData(fmt.Sprintf(vpnGatewayArnPattern, a.region, a.accountID, *a.cacheVpnGatewayId)),
		})
	if err != nil {
		return nil, err
	}
	return mqlVgw.(*mqlAwsVpcVpnGateway), nil
}

func (a *mqlAwsEc2Vpnconnection) transitGateway() (*mqlAwsEc2Transitgateway, error) {
	if a.cacheTransitGatewayId == nil || *a.cacheTransitGatewayId == "" {
		a.TransitGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	// NOTE: For cross-account TGWs (shared via RAM), the TGW owner may differ
	// from the VPN connection owner. This ARN assumes same-account ownership.
	// Cross-account TGWs will still resolve if previously fetched via
	// aws.ec2.transitGateways, since the cache lookup is by __id (ARN).
	tgwArn := fmt.Sprintf(transitGatewayArnPattern, a.region, a.accountID, *a.cacheTransitGatewayId)
	mqlTgw, err := NewResource(a.MqlRuntime, ResourceAwsEc2Transitgateway,
		map[string]*llx.RawData{"arn": llx.StringData(tgwArn)})
	if err != nil {
		return nil, err
	}
	return mqlTgw.(*mqlAwsEc2Transitgateway), nil
}

func (a *mqlAwsEc2Vpnconnection) customerGateway() (*mqlAwsEc2CustomerGateway, error) {
	if a.cacheCustomerGatewayId == nil || *a.cacheCustomerGatewayId == "" {
		a.CustomerGateway.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	cgwArn := fmt.Sprintf(customerGatewayArnPattern, a.region, a.accountID, *a.cacheCustomerGatewayId)
	mqlCgw, err := NewResource(a.MqlRuntime, ResourceAwsEc2CustomerGateway,
		map[string]*llx.RawData{"arn": llx.StringData(cgwArn)})
	if err != nil {
		return nil, err
	}
	return mqlCgw.(*mqlAwsEc2CustomerGateway), nil
}

// Customer gateway (#4)

const customerGatewayArnPattern = "arn:aws:ec2:%s:%s:customer-gateway/%s"
const egressOnlyIgwArnPattern = "arn:aws:ec2:%s:%s:egress-only-internet-gateway/%s"

func (a *mqlAwsEc2CustomerGateway) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2CustomerGateway) certificate() (*mqlAwsAcmCertificate, error) {
	arnVal := a.cacheCertificateArn
	if arnVal == "" {
		a.Certificate.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, ResourceAwsAcmCertificate,
		map[string]*llx.RawData{"arn": llx.StringData(arnVal)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAcmCertificate), nil
}

func initAwsEc2CustomerGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}

	if args["arn"] == nil && args["id"] == nil {
		return nil, nil, errors.New("arn or id required to fetch aws customer gateway")
	}

	// Load all customer gateways and find the match
	obj, err := CreateResource(runtime, ResourceAwsEc2, map[string]*llx.RawData{})
	if err != nil {
		return nil, nil, err
	}
	awsEc2 := obj.(*mqlAwsEc2)

	rawResources := awsEc2.GetCustomerGateways()
	if rawResources.Error != nil {
		return nil, nil, rawResources.Error
	}

	var match func(cgw *mqlAwsEc2CustomerGateway) bool
	if args["arn"] != nil {
		arnVal := args["arn"].Value.(string)
		match = func(cgw *mqlAwsEc2CustomerGateway) bool {
			return cgw.Arn.Data == arnVal
		}
	} else if args["id"] != nil {
		idVal := args["id"].Value.(string)
		match = func(cgw *mqlAwsEc2CustomerGateway) bool {
			return cgw.Id.Data == idVal
		}
	}

	for _, rawResource := range rawResources.Data {
		cgw := rawResource.(*mqlAwsEc2CustomerGateway)
		if match(cgw) {
			return args, cgw, nil
		}
	}
	return nil, nil, errors.New("customer gateway not found")
}

func (a *mqlAwsEc2) customerGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getCustomerGateways(conn), 5)
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

func (a *mqlAwsEc2) getCustomerGateways(conn *connection.AwsConnection) []*jobpool.Job {
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

			resp, err := svc.DescribeCustomerGateways(ctx, &ec2.DescribeCustomerGatewaysInput{
				Filters: conn.Filters.General.ToServerSideEc2Filters(),
			})
			if err != nil {
				if Is400AccessDeniedError(err) {
					log.Warn().Str("region", region).Msg("error accessing region for AWS API")
					return res, nil
				}
				return nil, err
			}
			for _, cgw := range resp.CustomerGateways {
				if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(cgw.Tags)) {
					continue
				}

				mqlCgw, err := CreateResource(a.MqlRuntime, ResourceAwsEc2CustomerGateway,
					map[string]*llx.RawData{
						"id":             llx.StringData(convert.ToValue(cgw.CustomerGatewayId)),
						"arn":            llx.StringData(fmt.Sprintf(customerGatewayArnPattern, region, conn.AccountId(), convert.ToValue(cgw.CustomerGatewayId))),
						"region":         llx.StringData(region),
						"state":          llx.StringData(convert.ToValue(cgw.State)),
						"type":           llx.StringData(convert.ToValue(cgw.Type)),
						"bgpAsn":         llx.StringData(convert.ToValue(cgw.BgpAsn)),
						"bgpAsnExtended": llx.StringDataPtr(cgw.BgpAsnExtended),
						"ipAddress":      llx.StringData(convert.ToValue(cgw.IpAddress)),
						"deviceName":     llx.StringData(convert.ToValue(cgw.DeviceName)),
						"tags":           llx.MapData(toInterfaceMap(ec2TagsToMap(cgw.Tags)), types.String),
					})
				if err != nil {
					return nil, err
				}
				mqlCgw.(*mqlAwsEc2CustomerGateway).cacheCertificateArn = convert.ToValue(cgw.CertificateArn)
				res = append(res, mqlCgw)
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// Egress-only internet gateway (#5)

func (a *mqlAwsEc2EgressOnlyInternetGateway) id() (string, error) {
	return a.Arn.Data, nil
}

// newMqlAwsEc2EgressOnlyInternetGateway builds an aws.ec2.egressOnlyInternetGateway
// from an SDK EgressOnlyInternetGateway. Shared by the account-level list and the
// by-id init.
func newMqlAwsEc2EgressOnlyInternetGateway(runtime *plugin.Runtime, region string, conn *connection.AwsConnection, eigw ec2types.EgressOnlyInternetGateway) (plugin.Resource, error) {
	attachments, err := convert.JsonToDictSlice(eigw.Attachments)
	if err != nil {
		return nil, err
	}
	return CreateResource(runtime, ResourceAwsEc2EgressOnlyInternetGateway,
		map[string]*llx.RawData{
			"id":          llx.StringData(convert.ToValue(eigw.EgressOnlyInternetGatewayId)),
			"arn":         llx.StringData(fmt.Sprintf(egressOnlyIgwArnPattern, region, conn.AccountId(), convert.ToValue(eigw.EgressOnlyInternetGatewayId))),
			"region":      llx.StringData(region),
			"attachments": llx.ArrayData(attachments, types.Any),
			"tags":        llx.MapData(toInterfaceMap(ec2TagsToMap(eigw.Tags)), types.String),
		})
}

func initAwsEc2EgressOnlyInternetGateway(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["arn"] == nil && args["id"] == nil {
		return args, nil, nil
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	var eigwID, region string
	if args["id"] != nil {
		eigwID, _ = args["id"].Value.(string)
	}
	if args["region"] != nil {
		region, _ = args["region"].Value.(string)
	}
	if args["arn"] != nil {
		if parsed, err := arn.Parse(args["arn"].Value.(string)); err == nil {
			region = parsed.Region
			parts := strings.Split(parsed.Resource, "/")
			if len(parts) == 2 {
				eigwID = parts[1]
			}
		}
	}
	if eigwID == "" || region == "" {
		return args, nil, nil
	}

	// Reuse an egress-only gateway already listed before spending an API call.
	cacheID := ResourceAwsEc2EgressOnlyInternetGateway + "\x00" + fmt.Sprintf(egressOnlyIgwArnPattern, region, conn.AccountId(), eigwID)
	if cached, ok := runtime.Resources.Get(cacheID); ok {
		return args, cached, nil
	}

	svc := conn.Ec2(region)
	resp, err := svc.DescribeEgressOnlyInternetGateways(context.Background(), &ec2.DescribeEgressOnlyInternetGatewaysInput{
		EgressOnlyInternetGatewayIds: []string{eigwID},
	})
	if err != nil {
		if Is400AccessDeniedError(err) {
			return nil, nil, fmt.Errorf("access denied fetching aws.ec2.egressOnlyInternetGateway with id %q in region %s", eigwID, region)
		}
		return nil, nil, err
	}
	if len(resp.EgressOnlyInternetGateways) == 0 {
		return nil, nil, fmt.Errorf("aws.ec2.egressOnlyInternetGateway with id %q not found", eigwID)
	}
	res, err := newMqlAwsEc2EgressOnlyInternetGateway(runtime, region, conn, resp.EgressOnlyInternetGateways[0])
	if err != nil {
		return nil, nil, err
	}
	return args, res, nil
}

func (a *mqlAwsEc2) egressOnlyInternetGateways() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getEgressOnlyIGWs(conn), 5)
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

func (a *mqlAwsEc2) getEgressOnlyIGWs(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ec2.NewDescribeEgressOnlyInternetGatewaysPaginator(svc, &ec2.DescribeEgressOnlyInternetGatewaysInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, eigw := range page.EgressOnlyInternetGateways {
					if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(eigw.Tags)) {
						continue
					}
					mqlEigw, err := newMqlAwsEc2EgressOnlyInternetGateway(a.MqlRuntime, region, conn, eigw)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlEigw)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

// Transit gateway peering attachment (#7)

func (a *mqlAwsEc2TransitgatewayPeeringAttachment) id() (string, error) {
	return a.Id.Data, nil
}

func (a *mqlAwsEc2Transitgateway) peeringAttachments() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(a.region)
	ctx := context.Background()

	filterKeyVal := "transit-gateway-id"
	params := &ec2.DescribeTransitGatewayPeeringAttachmentsInput{
		Filters: []ec2types.Filter{{Name: &filterKeyVal, Values: []string{a.Id.Data}}},
	}
	paginator := ec2.NewDescribeTransitGatewayPeeringAttachmentsPaginator(svc, params)
	attachments := []any{}
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				return attachments, nil
			}
			return nil, err
		}
		for _, pa := range page.TransitGatewayPeeringAttachments {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(pa.Tags)) {
				continue
			}

			requesterInfo, _ := convert.JsonToDict(pa.RequesterTgwInfo)
			accepterInfo, _ := convert.JsonToDict(pa.AccepterTgwInfo)

			var statusCode, statusMessage string
			if pa.Status != nil {
				statusCode = convert.ToValue(pa.Status.Code)
				statusMessage = convert.ToValue(pa.Status.Message)
			}

			mqlPa, err := CreateResource(a.MqlRuntime, ResourceAwsEc2TransitgatewayPeeringAttachment,
				map[string]*llx.RawData{
					"id":               llx.StringData(convert.ToValue(pa.TransitGatewayAttachmentId)),
					"state":            llx.StringData(string(pa.State)),
					"createdAt":        llx.TimeDataPtr(pa.CreationTime),
					"tags":             llx.MapData(toInterfaceMap(ec2TagsToMap(pa.Tags)), types.String),
					"region":           llx.StringData(a.region),
					"requesterTgwInfo": llx.DictData(requesterInfo),
					"accepterTgwInfo":  llx.DictData(accepterInfo),
					"statusCode":       llx.StringData(statusCode),
					"statusMessage":    llx.StringData(statusMessage),
				})
			if err != nil {
				return nil, err
			}
			attachments = append(attachments, mqlPa)
		}
	}
	return attachments, nil
}

// true if the instance should be excluded from results. filtering for excluded regions should happen before we retrieve the EC2 instance.
func shouldExcludeInstance(instance ec2types.Instance, filters connection.DiscoveryFilters) bool {
	hasExcludedId := filters.Ec2.MatchesExcludeInstanceIds(instance.InstanceId)
	hasExcludedTag := filters.General.MatchesExcludeTags(ec2TagsToMap(instance.Tags))
	return hasExcludedId || hasExcludedTag
}

// tags in AWS are guaranteed to have a unique key, so we can convert the slice to a map for easier processing
func ec2TagsToMap(tags []ec2types.Tag) map[string]string {
	return tagsToStringMap(tags, func(t ec2types.Tag) *string { return t.Key }, func(t ec2types.Tag) *string { return t.Value })
}

const launchTemplateArnPattern = "arn:aws:ec2:%s:%s:launch-template/%s"

func (a *mqlAwsEc2) launchTemplates() ([]any, error) {
	conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
	res := []any{}
	poolOfJobs := jobpool.CreatePool(a.getLaunchTemplates(conn), 5)
	poolOfJobs.Run()

	if poolOfJobs.HasErrors() {
		return nil, poolOfJobs.GetErrors()
	}
	for i := range poolOfJobs.Jobs {
		res = append(res, poolOfJobs.Jobs[i].Result.([]any)...)
	}
	return res, nil
}

func (a *mqlAwsEc2) getLaunchTemplates(conn *connection.AwsConnection) []*jobpool.Job {
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

			paginator := ec2.NewDescribeLaunchTemplatesPaginator(svc, &ec2.DescribeLaunchTemplatesInput{})
			for paginator.HasMorePages() {
				page, err := paginator.NextPage(ctx)
				if err != nil {
					if Is400AccessDeniedError(err) {
						log.Warn().Str("region", region).Msg("error accessing region for AWS API")
						return res, nil
					}
					return nil, err
				}
				for _, lt := range page.LaunchTemplates {
					mqlLtRes, err := buildLaunchTemplateResource(a.MqlRuntime, region, conn.AccountId(), lt)
					if err != nil {
						return nil, err
					}
					res = append(res, mqlLtRes)
				}
			}
			return jobpool.JobResult(res), nil
		}
		tasks = append(tasks, jobpool.NewJob(f))
	}
	return tasks
}

type mqlAwsEc2LaunchtemplateInternal struct {
	region           string
	launchTemplateId string
	ltDataOnce       sync.Once
	ltData           *ec2types.ResponseLaunchTemplateData
	ltDataErr        error
}

func buildLaunchTemplateResource(runtime *plugin.Runtime, region, accountID string, lt ec2types.LaunchTemplate) (*mqlAwsEc2Launchtemplate, error) {
	ltId := convert.ToValue(lt.LaunchTemplateId)
	ltArn := fmt.Sprintf(launchTemplateArnPattern, region, accountID, ltId)

	mqlLt, err := CreateResource(runtime, ResourceAwsEc2Launchtemplate,
		map[string]*llx.RawData{
			"id":             llx.StringData(ltId),
			"arn":            llx.StringData(ltArn),
			"name":           llx.StringDataPtr(lt.LaunchTemplateName),
			"region":         llx.StringData(region),
			"createdAt":      llx.TimeDataPtr(lt.CreateTime),
			"createdBy":      llx.StringDataPtr(lt.CreatedBy),
			"defaultVersion": llx.IntData(convert.ToValue(lt.DefaultVersionNumber)),
			"latestVersion":  llx.IntData(convert.ToValue(lt.LatestVersionNumber)),
			"tags":           llx.MapData(toInterfaceMap(ec2TagsToMap(lt.Tags)), types.String),
		})
	if err != nil {
		return nil, err
	}
	mqlLtRes := mqlLt.(*mqlAwsEc2Launchtemplate)
	mqlLtRes.region = region
	mqlLtRes.launchTemplateId = ltId
	return mqlLtRes, nil
}

func initAwsEc2Launchtemplate(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["region"] == nil || (args["id"] == nil && args["name"] == nil) {
		return nil, nil, errors.New("region and id or name required to fetch aws ec2 launch template")
	}
	region := args["region"].Value.(string)

	input := &ec2.DescribeLaunchTemplatesInput{}
	if args["id"] != nil {
		input.LaunchTemplateIds = []string{args["id"].Value.(string)}
	} else {
		input.LaunchTemplateNames = []string{args["name"].Value.(string)}
	}

	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	resp, err := svc.DescribeLaunchTemplates(context.Background(), input)
	if err != nil {
		// Falling through with `args, nil, nil` built a husk: args holds only
		// region plus id/name, arn is never set, so id() returned "" and every
		// unresolvable launch template shared the empty cache key while its
		// other fields stayed unset (not null).
		if Is400AccessDeniedError(err) || IsServiceNotAvailableInRegionError(err) {
			return nil, nil, errors.Wrap(err, "could not access aws ec2 launch template")
		}
		return nil, nil, err
	}
	if len(resp.LaunchTemplates) == 0 {
		return nil, nil, errors.New("aws ec2 launch template does not exist")
	}
	mqlLt, err := buildLaunchTemplateResource(runtime, region, conn.AccountId(), resp.LaunchTemplates[0])
	if err != nil {
		return nil, nil, err
	}
	return args, mqlLt, nil
}

func (a *mqlAwsEc2Launchtemplate) id() (string, error) {
	return a.Arn.Data, nil
}

func (a *mqlAwsEc2Launchtemplate) fetchLaunchTemplateData() (*ec2types.ResponseLaunchTemplateData, error) {
	a.ltDataOnce.Do(func() {
		conn := a.MqlRuntime.Connection.(*connection.AwsConnection)
		svc := conn.Ec2(a.region)
		ctx := context.Background()

		ltId := a.launchTemplateId
		resp, err := svc.DescribeLaunchTemplateVersions(ctx, &ec2.DescribeLaunchTemplateVersionsInput{
			LaunchTemplateId: &ltId,
			Versions:         []string{"$Default"},
		})
		if err != nil {
			if Is400AccessDeniedError(err) {
				return
			}
			a.ltDataErr = err
			return
		}
		if len(resp.LaunchTemplateVersions) > 0 {
			a.ltData = resp.LaunchTemplateVersions[0].LaunchTemplateData
		}
	})
	return a.ltData, a.ltDataErr
}

func (a *mqlAwsEc2Launchtemplate) userData() (string, error) {
	data, err := a.fetchLaunchTemplateData()
	if err != nil {
		return "", err
	}
	if data == nil || data.UserData == nil || *data.UserData == "" {
		return "", nil
	}
	decoded, err := base64.StdEncoding.DecodeString(*data.UserData)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

func (a *mqlAwsEc2Launchtemplate) metadataOptions() (any, error) {
	data, err := a.fetchLaunchTemplateData()
	if err != nil {
		return nil, err
	}
	if data == nil || data.MetadataOptions == nil {
		return nil, nil
	}
	return convert.JsonToDict(data.MetadataOptions)
}

func (a *mqlAwsEc2Launchtemplate) instanceMetadata() (*mqlAwsEc2LaunchtemplateInstanceMetadataOptions, error) {
	opts, err := a.launchTemplateMetadataOptions()
	if err != nil {
		return nil, err
	}
	if opts == nil {
		a.InstanceMetadata.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	hopLimit := llx.NilData
	if opts.HttpPutResponseHopLimit != nil {
		hopLimit = llx.IntData(int64(*opts.HttpPutResponseHopLimit))
	}
	res, err := CreateResource(a.MqlRuntime, "aws.ec2.launchtemplate.instanceMetadataOptions", map[string]*llx.RawData{
		"__id":                    llx.StringData(a.Arn.Data + "/metadataOptions"),
		"httpTokens":              llx.StringData(string(opts.HttpTokens)),
		"httpEndpoint":            llx.StringData(string(opts.HttpEndpoint)),
		"httpPutResponseHopLimit": hopLimit,
		"httpProtocolIpv6":        llx.StringData(string(opts.HttpProtocolIpv6)),
		"instanceMetadataTags":    llx.StringData(string(opts.InstanceMetadataTags)),
		"state":                   llx.StringData(string(opts.State)),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2LaunchtemplateInstanceMetadataOptions), nil
}

func (a *mqlAwsEc2Launchtemplate) launchTemplateMetadataOptions() (*ec2types.LaunchTemplateInstanceMetadataOptions, error) {
	data, err := a.fetchLaunchTemplateData()
	if err != nil {
		return nil, err
	}
	if data == nil {
		return nil, nil
	}
	return data.MetadataOptions, nil
}

func (a *mqlAwsEc2Launchtemplate) securityGroupIds() ([]any, error) {
	data, err := a.fetchLaunchTemplateData()
	if err != nil {
		return nil, err
	}
	if data == nil {
		return []any{}, nil
	}
	res := make([]any, 0, len(data.SecurityGroupIds))
	for _, sg := range data.SecurityGroupIds {
		res = append(res, sg)
	}
	return res, nil
}

func (a *mqlAwsEc2Launchtemplate) iamInstanceProfile() (string, error) {
	data, err := a.fetchLaunchTemplateData()
	if err != nil {
		return "", err
	}
	if data == nil || data.IamInstanceProfile == nil {
		return "", nil
	}
	if data.IamInstanceProfile.Arn != nil {
		return *data.IamInstanceProfile.Arn, nil
	}
	if data.IamInstanceProfile.Name != nil {
		return *data.IamInstanceProfile.Name, nil
	}
	return "", nil
}

func (a *mqlAwsEc2Launchtemplate) instanceType() (string, error) {
	data, err := a.fetchLaunchTemplateData()
	if err != nil {
		return "", err
	}
	if data == nil {
		return "", nil
	}
	return string(data.InstanceType), nil
}

func (a *mqlAwsEc2Launchtemplate) imageId() (string, error) {
	data, err := a.fetchLaunchTemplateData()
	if err != nil {
		return "", err
	}
	if data == nil || data.ImageId == nil {
		return "", nil
	}
	return *data.ImageId, nil
}

// networkInterfacesByFilter fetches the network interfaces in a region that match
// a single server-side EC2 filter and returns them as typed
// aws.ec2.networkinterface resources. It backs the security-group and subnet
// backreferences, which both reduce to "which ENIs reference me".
func networkInterfacesByFilter(runtime *plugin.Runtime, region, filterName, filterValue string) ([]any, error) {
	conn := runtime.Connection.(*connection.AwsConnection)
	svc := conn.Ec2(region)
	ctx := context.Background()
	filters := conn.Filters.General.ToServerSideEc2Filters()
	filters = append(filters, ec2types.Filter{Name: aws.String(filterName), Values: []string{filterValue}})
	params := &ec2.DescribeNetworkInterfacesInput{Filters: filters}
	res := []any{}
	paginator := ec2.NewDescribeNetworkInterfacesPaginator(svc, params)
	for paginator.HasMorePages() {
		nis, err := paginator.NextPage(ctx)
		if err != nil {
			if Is400AccessDeniedError(err) {
				log.Warn().Str("region", region).Msg("access denied for DescribeNetworkInterfaces")
				return res, nil
			}
			return nil, err
		}
		for _, ni := range nis.NetworkInterfaces {
			if conn.Filters.General.MatchesExcludeTags(ec2TagsToMap(ni.TagSet)) {
				log.Debug().Interface("networkInterface", ni.NetworkInterfaceId).Msg("excluding network interface due to filters")
				continue
			}
			_, mqlEni, err := buildNetworkInterfaceResource(runtime, region, ni)
			if err != nil {
				return nil, err
			}
			res = append(res, mqlEni)
		}
	}
	return res, nil
}

// instancesFromNetworkInterfaces projects a set of network interfaces onto the
// distinct EC2 instances they are attached to, dropping interfaces that are not
// attached to an instance (for example load balancer, RDS, or Lambda ENIs).
func instancesFromNetworkInterfaces(enis []any) ([]any, error) {
	seen := map[string]struct{}{}
	res := []any{}
	for _, e := range enis {
		eni, ok := e.(*mqlAwsEc2Networkinterface)
		if !ok {
			continue
		}
		inst := eni.GetInstance()
		if inst.Error != nil {
			// An ENI can reference an instance that is terminated or otherwise
			// no longer resolvable. A single missing instance should not break
			// the whole backref scan, so log and skip it.
			log.Warn().Err(inst.Error).Msg("skipping network interface whose instance could not be resolved")
			continue
		}
		if inst.Data == nil {
			continue
		}
		arn := inst.Data.Arn.Data
		if _, dup := seen[arn]; dup {
			continue
		}
		seen[arn] = struct{}{}
		res = append(res, inst.Data)
	}
	return res, nil
}

func (a *mqlAwsEc2Securitygroup) networkInterfaces() ([]any, error) {
	return networkInterfacesByFilter(a.MqlRuntime, a.Region.Data, "group-id", a.Id.Data)
}

func (a *mqlAwsEc2Securitygroup) instances() ([]any, error) {
	nis := a.GetNetworkInterfaces()
	if nis.Error != nil {
		return nil, nis.Error
	}
	return instancesFromNetworkInterfaces(nis.Data)
}

// securityGroupsAllowPublicIngress reports whether any of the given security
// groups permits inbound traffic from 0.0.0.0/0 or ::/0. It shares the traversal
// with openIngressRulesFromSecurityGroups so the two cannot diverge.
func securityGroupsAllowPublicIngress(sgs *plugin.TValue[[]any]) (bool, error) {
	rules, err := openIngressRulesFromSecurityGroups(sgs)
	if err != nil {
		return false, err
	}
	return len(rules) > 0, nil
}

// subnet returns the subnet of the instance's primary network interface, which
// is what ec2types.Instance.SubnetId reports. Instances with additional ENIs in
// other subnets are not represented here.
func (i *mqlAwsEc2Instance) subnet() (*mqlAwsVpcSubnet, error) {
	subnetId := i.instanceCache.SubnetId
	if subnetId == nil || *subnetId == "" {
		i.Subnet.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	conn := i.MqlRuntime.Connection.(*connection.AwsConnection)
	arn := fmt.Sprintf(subnetArnPattern, i.Region.Data, conn.AccountId(), *subnetId)
	res, err := NewResource(i.MqlRuntime, ResourceAwsVpcSubnet, map[string]*llx.RawData{"arn": llx.StringData(arn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcSubnet), nil
}

// instanceInPublicSubnet reports whether the instance's subnet routes to an
// internet gateway (the defining property of a public subnet).
func instanceInPublicSubnet(i *mqlAwsEc2Instance) (bool, error) {
	subnet := i.GetSubnet()
	if subnet.Error != nil {
		return false, subnet.Error
	}
	if subnet.Data == nil {
		return false, nil
	}
	rt := subnet.Data.GetRouteTable()
	if rt.Error != nil {
		return false, rt.Error
	}
	if rt.Data == nil {
		return false, nil
	}
	entries := rt.Data.GetRouteEntries()
	if entries.Error != nil {
		return false, entries.Error
	}
	for _, e := range entries.Data {
		route, ok := e.(*mqlAwsVpcRoutetableRoute)
		if !ok {
			continue
		}
		gw := route.GetGatewayId()
		if gw.Error == nil && strings.HasPrefix(gw.Data, "igw-") {
			return true, nil
		}
	}
	return false, nil
}

// instanceSubnetNaclAllowsPublicIngress reports whether the instance's subnet
// network ACL permits inbound internet traffic. Missing subnet/NACL data does
// not block (it defaults to allow), so it never overrides the other positive
// signals on its own.
func instanceSubnetNaclAllowsPublicIngress(i *mqlAwsEc2Instance) (bool, error) {
	subnet := i.GetSubnet()
	if subnet.Error != nil {
		return false, subnet.Error
	}
	if subnet.Data == nil {
		return true, nil
	}
	nacl := subnet.Data.GetNetworkAcl()
	if nacl.Error != nil {
		return false, nacl.Error
	}
	if nacl.Data == nil {
		return true, nil
	}
	return networkAclAllowsPublicIngress(nacl.Data)
}

// instanceOpenIngressRules returns the security group ingress rules across the
// instance's attached security groups that permit inbound traffic from the
// internet.
func instanceOpenIngressRules(i *mqlAwsEc2Instance) ([]any, error) {
	rules := []any{}
	sgs := i.GetSecurityGroups()
	if sgs.Error != nil {
		return nil, sgs.Error
	}
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

// instanceInternetFacingLoadBalancers returns the load balancers that route to
// the instance and have an internet-facing scheme.
func instanceInternetFacingLoadBalancers(i *mqlAwsEc2Instance) ([]any, error) {
	res := []any{}
	lbs := i.GetLoadBalancers()
	if lbs.Error != nil {
		return nil, lbs.Error
	}
	for _, l := range lbs.Data {
		lb, ok := l.(*mqlAwsElbLoadbalancer)
		if !ok {
			continue
		}
		scheme := lb.GetScheme()
		if scheme.Error != nil {
			return nil, scheme.Error
		}
		if scheme.Data == "internet-facing" {
			res = append(res, lb)
		}
	}
	return res, nil
}

func (i *mqlAwsEc2Instance) exposure() (*mqlAwsEc2InstanceExposure, error) {
	arn := i.GetArn()
	if arn.Error != nil {
		return nil, arn.Error
	}

	publicIp := i.GetPublicIp()
	if publicIp.Error != nil {
		return nil, publicIp.Error
	}
	hasPublicIp := publicIp.Data != ""

	inPublicSubnet, err := instanceInPublicSubnet(i)
	if err != nil {
		return nil, err
	}

	openRules, err := instanceOpenIngressRules(i)
	if err != nil {
		return nil, err
	}
	sgAllows := len(openRules) > 0

	naclAllows, err := instanceSubnetNaclAllowsPublicIngress(i)
	if err != nil {
		return nil, err
	}

	internetFacingLBs, err := instanceInternetFacingLoadBalancers(i)
	if err != nil {
		return nil, err
	}

	internetReachable := hasPublicIp && inPublicSubnet && sgAllows && naclAllows

	res, err := CreateResource(i.MqlRuntime, "aws.ec2.instance.exposure", map[string]*llx.RawData{
		"__id":                        llx.StringData(arn.Data + "/exposure"),
		"internetReachable":           llx.BoolData(internetReachable),
		"hasPublicIp":                 llx.BoolData(hasPublicIp),
		"inPublicSubnet":              llx.BoolData(inPublicSubnet),
		"securityGroupAllowsIngress":  llx.BoolData(sgAllows),
		"networkAclAllowsIngress":     llx.BoolData(naclAllows),
		"openIngressRules":            llx.ArrayData(openRules, types.Resource("aws.ec2.securitygroup.ippermission")),
		"internetFacingLoadBalancers": llx.ArrayData(internetFacingLBs, types.Resource("aws.elb.loadbalancer")),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2InstanceExposure), nil
}

// naclIngressRule is the shape of a network ACL inbound rule needed to decide
// public reachability. Protocol, source range, and port range are all part of
// that decision: network ACLs are evaluated per packet, so a rule only shadows a
// higher-numbered rule for the traffic it actually matches.
type naclIngressRule struct {
	ruleNumber int
	allow      bool
	public     bool   // source is 0.0.0.0/0 or ::/0
	protocol   string // "-1" means all protocols
	// cidr is the rule's source range. An empty value means the source was not
	// recorded and the rule is treated as matching any source.
	cidr     string
	fromPort int64
	toPort   int64
	// allPorts is true when the rule carries no port range, which for a network
	// ACL means every port for the protocol.
	allPorts bool
}

// ports returns the rule's port span.
func (r naclIngressRule) ports() portRange {
	if r.allPorts {
		return portRange{all: true}
	}
	return newPortRange(r.fromPort, r.toPort)
}

// covers reports whether r matches every packet that other matches, i.e.
// whether a lower-numbered r fully shadows other.
//
// The source range is part of this: an IPv4 and an IPv6 rule never match the
// same packet, so a deny on 0.0.0.0/0 does not shadow an allow on ::/0.
func (r naclIngressRule) covers(other naclIngressRule) bool {
	if !protocolCovers(r.protocol, other.protocol) {
		return false
	}
	if !cidrCovers(r.cidr, other.cidr) {
		return false
	}
	return r.ports().covers(other.ports())
}

// naclAllowsPublicIngress reports whether a network ACL permits inbound traffic
// from the internet.
//
// Network ACL rules are evaluated in ascending rule-number order and the first
// rule matching a given packet wins. The decision is therefore per
// (protocol, port), not global: a public ALLOW is only blocked when some
// lower-numbered public DENY covers its entire protocol and port range.
//
// The previous implementation compared rule numbers alone, so the very common
// layout of a narrow deny in front of a broad allow --
//
//	rule  90 DENY  0.0.0.0/0 tcp/3389
//	rule 100 ALLOW 0.0.0.0/0 all
//
// -- was read as "denied", and an instance reachable on every other port
// reported internetReachable == false.
func naclAllowsPublicIngress(rules []naclIngressRule) bool {
	ordered := make([]naclIngressRule, len(rules))
	copy(ordered, rules)
	sort.SliceStable(ordered, func(i, j int) bool {
		return ordered[i].ruleNumber < ordered[j].ruleNumber
	})

	for i, allow := range ordered {
		if !allow.public || !allow.allow {
			continue
		}
		shadowed := false
		for _, deny := range ordered[:i] {
			if !deny.public || deny.allow {
				continue
			}
			if deny.covers(allow) {
				shadowed = true
				break
			}
		}
		if !shadowed {
			return true
		}
	}
	return false
}

// networkAclAllowsPublicIngress evaluates a network ACL's inbound rules for
// reachability from the internet.
func networkAclAllowsPublicIngress(nacl *mqlAwsEc2Networkacl) (bool, error) {
	entries := nacl.GetEntries()
	if entries.Error != nil {
		return false, entries.Error
	}
	rules := make([]naclIngressRule, 0, len(entries.Data))
	for _, e := range entries.Data {
		entry, ok := e.(*mqlAwsEc2NetworkaclEntry)
		if !ok || entry.Egress.Data {
			continue
		}
		rules = append(rules, naclEntryRule(entry))
	}
	return naclAllowsPublicIngress(rules), nil
}

// loadBalancers returns the load balancers that route traffic to this instance.
// AWS has no "describe load balancers by instance" API, so this scans the
// account's load balancers (a cross-region list cached after first use) and
// matches on the instances each one targets — directly for classic ELBs, and
// through target groups for Application and Network Load Balancers.
func (i *mqlAwsEc2Instance) loadBalancers() ([]any, error) {
	obj, err := CreateResource(i.MqlRuntime, ResourceAwsElb, map[string]*llx.RawData{})
	if err != nil {
		return nil, err
	}
	lbs := obj.(*mqlAwsElb).GetLoadBalancers()
	if lbs.Error != nil {
		return nil, lbs.Error
	}
	instanceArn := i.Arn.Data
	res := []any{}
	for _, l := range lbs.Data {
		lb, ok := l.(*mqlAwsElbLoadbalancer)
		if !ok {
			continue
		}
		targets, err := loadBalancerTargetsInstance(lb, instanceArn)
		if err != nil {
			return nil, err
		}
		if targets {
			res = append(res, lb)
		}
	}
	return res, nil
}

// loadBalancerTargetsInstance reports whether a load balancer routes traffic to
// the given instance. Classic ELBs register instances directly; Application and
// Network Load Balancers register them through target groups, so both paths are
// checked.
func loadBalancerTargetsInstance(lb *mqlAwsElbLoadbalancer, instanceArn string) (bool, error) {
	insts := lb.GetInstances()
	if insts.Error != nil {
		return false, insts.Error
	}
	for _, x := range insts.Data {
		if inst, ok := x.(*mqlAwsEc2Instance); ok && inst.Arn.Data == instanceArn {
			return true, nil
		}
	}

	tgs := lb.GetTargetGroups()
	if tgs.Error != nil {
		return false, tgs.Error
	}
	for _, t := range tgs.Data {
		tg, ok := t.(*mqlAwsElbTargetgroup)
		if !ok {
			continue
		}
		ec2Targets := tg.GetEc2Targets()
		if ec2Targets.Error != nil {
			return false, ec2Targets.Error
		}
		for _, x := range ec2Targets.Data {
			if inst, ok := x.(*mqlAwsEc2Instance); ok && inst.Arn.Data == instanceArn {
				return true, nil
			}
		}
	}
	return false, nil
}

func (i *mqlAwsEc2Instance) cloudformationStack() (*mqlAwsCloudformationStack, error) {
	stack, err := cloudformationStackForTags(i.MqlRuntime, i.Region.Data, i.Tags.Data)
	if err != nil {
		return nil, err
	}
	if stack == nil {
		i.CloudformationStack.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	return stack, nil
}

func (a *mqlAwsEc2Securitygroup) cloudformationStack() (*mqlAwsCloudformationStack, error) {
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

func (i *mqlAwsEc2Instance) managedBy() (string, error) {
	return managedByFromTags(i.Tags.Data), nil
}

func (a *mqlAwsEc2Securitygroup) managedBy() (string, error) {
	return managedByFromTags(a.Tags.Data), nil
}

func (i *mqlAwsEc2Instance) capacityReservation() (*mqlAwsEc2CapacityReservation, error) {
	crID := convert.ToValue(i.instanceCache.CapacityReservationId)
	if crID == "" {
		i.CapacityReservation.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(i.MqlRuntime, "aws.ec2.capacityReservation",
		map[string]*llx.RawData{
			"id":     llx.StringData(crID),
			"region": llx.StringData(i.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2CapacityReservation), nil
}

func (i *mqlAwsEc2Instance) autoScalingGroup() (*mqlAwsAutoscalingGroup, error) {
	raw, ok := i.Tags.Data["aws:autoscaling:groupName"]
	groupName, _ := raw.(string)
	if !ok || groupName == "" {
		i.AutoScalingGroup.State = plugin.StateIsNull | plugin.StateIsSet
		return nil, nil
	}
	res, err := NewResource(i.MqlRuntime, ResourceAwsAutoscalingGroup,
		map[string]*llx.RawData{
			"name":   llx.StringData(groupName),
			"region": llx.StringData(i.Region.Data),
		})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsAutoscalingGroup), nil
}

func (i *mqlAwsEc2Image) sharedWithAccounts() ([]any, error) {
	perms := i.GetLaunchPermissions()
	if perms.Error != nil {
		return nil, perms.Error
	}
	res := []any{}
	for _, p := range perms.Data {
		perm, ok := p.(*mqlAwsEc2ImageLaunchPermission)
		if !ok {
			continue
		}
		userId := perm.GetUserId()
		if userId.Error != nil {
			return nil, userId.Error
		}
		if userId.Data != "" {
			res = append(res, userId.Data)
		}
	}
	return res, nil
}

func (i *mqlAwsEc2Image) sharedExternally() (bool, error) {
	public := i.GetPublic()
	if public.Error != nil {
		return false, public.Error
	}
	if public.Data {
		return true, nil
	}
	accounts := i.GetSharedWithAccounts()
	if accounts.Error != nil {
		return false, accounts.Error
	}
	return len(accounts.Data) > 0, nil
}

// accountIdsFromVolumePermissions extracts the account IDs from a snapshot's
// createVolumePermission entries, ignoring the public ("all" group) entry which
// carries no UserId.
func accountIdsFromVolumePermissions(perms []any) []any {
	res := []any{}
	for _, p := range perms {
		m, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if uid, ok := m["UserId"].(string); ok && uid != "" {
			res = append(res, uid)
		}
	}
	return res
}

func (a *mqlAwsEc2Snapshot) sharedWithAccounts() ([]any, error) {
	perms := a.GetCreateVolumePermission()
	if perms.Error != nil {
		return nil, perms.Error
	}
	return accountIdsFromVolumePermissions(perms.Data), nil
}

func (a *mqlAwsEc2Snapshot) sharedExternally() (bool, error) {
	public := a.GetIsPublic()
	if public.Error != nil {
		return false, public.Error
	}
	if public.Data {
		return true, nil
	}
	accounts := a.GetSharedWithAccounts()
	if accounts.Error != nil {
		return false, accounts.Error
	}
	return len(accounts.Data) > 0, nil
}

type mqlAwsEc2ImageEbsBlockDeviceInternal struct {
	cacheKmsKeyId string
}

type mqlAwsEc2CustomerGatewayInternal struct {
	cacheCertificateArn string
}

// deriveVolumeSseType returns the volume's SSE type, deriving it for
// regions/accounts where DescribeVolumes omits SseType: an encrypted volume
// always has a KMS key (sse-kms), an unencrypted one has no SSE at all.
// Without this, encryption-type checks can never pass where the field is
// missing from the API response.
func deriveVolumeSseType(vol ec2types.Volume) string {
	if sse := string(vol.SseType); sse != "" {
		return sse
	}
	if convert.ToValue(vol.Encrypted) {
		return "sse-kms"
	}
	return "none"
}

// newMqlEc2StateReason builds the reason an instance entered its current
// state. A nil StateReason means EC2 reports no reason, which is the usual
// case for an instance that has always been running, so the reference reads
// null rather than as an empty code.
func newMqlEc2StateReason(runtime *plugin.Runtime, ownerID string, sr *ec2types.StateReason) (*llx.RawData, error) {
	if sr == nil {
		return llx.NilData, nil
	}
	res, err := CreateResource(runtime, "aws.ec2.stateReason", map[string]*llx.RawData{
		"__id":    llx.StringData(ownerID + "/stateReason"),
		"code":    llx.StringData(convert.ToValue(sr.Code)),
		"message": llx.StringData(convert.ToValue(sr.Message)),
	})
	if err != nil {
		return nil, err
	}
	return llx.ResourceData(res, "aws.ec2.stateReason"), nil
}
