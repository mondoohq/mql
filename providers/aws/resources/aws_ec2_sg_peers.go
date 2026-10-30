// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strconv"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

type mqlAwsEc2SecuritygroupIppermissionPeerInternal struct {
	cacheGroupId             string
	cacheAccountId           string
	cacheVpcId               string
	cachePeeringConnectionId string
	cacheRegion              string
	cacheScanningAccountId   string
}

// buildSecurityGroupPeers turns a rule's security group references into typed
// resources. permissionID scopes the cache key: the same group can be
// referenced by several rules on one security group, and by both an ingress and
// an egress rule, so keying on the referenced group alone would collapse them
// into a single instance.
func buildSecurityGroupPeers(
	runtime *plugin.Runtime,
	permissionID, region, scanningAccountID string,
	pairs []ec2types.UserIdGroupPair,
) ([]any, error) {
	res := make([]any, 0, len(pairs))
	for i := range pairs {
		pair := pairs[i]
		groupID := convert.ToValue(pair.GroupId)

		mqlPeer, err := CreateResource(runtime, "aws.ec2.securitygroup.ippermission.peer",
			map[string]*llx.RawData{
				"__id":          llx.StringData(permissionID + "/peer/" + strconv.Itoa(i) + "/" + groupID),
				"groupId":       llx.StringData(groupID),
				"groupName":     llx.StringData(convert.ToValue(pair.GroupName)),
				"accountId":     llx.StringData(convert.ToValue(pair.UserId)),
				"description":   llx.StringData(convert.ToValue(pair.Description)),
				"peeringStatus": llx.StringData(convert.ToValue(pair.PeeringStatus)),
			})
		if err != nil {
			return nil, err
		}

		peer := mqlPeer.(*mqlAwsEc2SecuritygroupIppermissionPeer)
		peer.cacheGroupId = groupID
		peer.cacheAccountId = convert.ToValue(pair.UserId)
		peer.cacheVpcId = convert.ToValue(pair.VpcId)
		peer.cachePeeringConnectionId = convert.ToValue(pair.VpcPeeringConnectionId)
		peer.cacheRegion = region
		peer.cacheScanningAccountId = scanningAccountID

		res = append(res, mqlPeer)
	}
	return res, nil
}

// peerIsResolvable reports whether the referenced group can be described with
// the credentials scanning this account.
//
// A reference that names another account cannot be, and neither can one that
// crosses a VPC peering connection, since peering may put the group in another
// region and the rule carries no region of its own to build an ARN from.
func peerIsResolvable(groupID, accountID, peeringConnectionID, scanningAccountID string) bool {
	if groupID == "" || peeringConnectionID != "" {
		return false
	}
	// An empty UserId means AWS did not name an owner, which happens for
	// references within the scanned account.
	return accountID == "" || accountID == scanningAccountID
}

// securityGroup resolves the referenced group when it is readable here.
//
// Building an ARN for a group in another account would produce a resource that
// fails to resolve, and because a failed resolution is logged and skipped that
// would surface as a silently absent group rather than as the cross-account
// reference it is. Returning null while leaving groupId and accountId
// populated states the limit instead of hiding it.
func (a *mqlAwsEc2SecuritygroupIppermissionPeer) securityGroup() (*mqlAwsEc2Securitygroup, error) {
	if !peerIsResolvable(a.cacheGroupId, a.cacheAccountId, a.cachePeeringConnectionId, a.cacheScanningAccountId) {
		a.SecurityGroup.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	sgArn := fmt.Sprintf("arn:aws:ec2:%s:%s:security-group/%s", a.cacheRegion, a.cacheScanningAccountId, a.cacheGroupId)
	res, err := NewResource(a.MqlRuntime, ResourceAwsEc2Securitygroup,
		map[string]*llx.RawData{"arn": llx.StringData(sgArn)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsEc2Securitygroup), nil
}

// vpc resolves the VPC of the referenced group. AWS returns it only when the
// reference crosses a peering connection; within one VPC the field is empty
// because the VPC is the rule's own.
//
// Resolution is limited to the scanned account. initAwsVpc falls back to
// scanning the cached VPC list and returns an error when it finds no match, so
// a VPC on the far side of a cross-account peering would fail the query rather
// than come back empty. Same-account peering, including across regions, still
// resolves: the fallback searches every listed region.
func (a *mqlAwsEc2SecuritygroupIppermissionPeer) vpc() (*mqlAwsVpc, error) {
	crossAccount := a.cacheAccountId != "" && a.cacheAccountId != a.cacheScanningAccountId
	if a.cacheVpcId == "" || crossAccount {
		a.Vpc.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc",
		map[string]*llx.RawData{"id": llx.StringData(a.cacheVpcId)})
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpc), nil
}

// peeringConnection resolves the peering connection the reference crosses.
//
// The region is a required lookup hint, not a schema field:
// initAwsVpcPeeringConnection returns without fetching when it is missing,
// which would leave a blank resource whose fields are unset rather than null.
// The rule's own region is the right hint because the peering connection is
// visible from both sides, so it exists in this account's region even when the
// referenced group belongs to another account.
func (a *mqlAwsEc2SecuritygroupIppermissionPeer) peeringConnection() (*mqlAwsVpcPeeringConnection, error) {
	if a.cachePeeringConnectionId == "" {
		a.PeeringConnection.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	res, err := NewResource(a.MqlRuntime, "aws.vpc.peeringConnection",
		peeringConnectionLookupArgs(a.cachePeeringConnectionId, a.cacheRegion))
	if err != nil {
		return nil, err
	}
	return res.(*mqlAwsVpcPeeringConnection), nil
}

// peeringConnectionLookupArgs builds the argument set initAwsVpcPeeringConnection
// needs. Both keys are required: without region the init returns early and the
// runtime builds a blank resource instead of fetching.
func peeringConnectionLookupArgs(peeringConnectionID, region string) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"id":     llx.StringData(peeringConnectionID),
		"region": llx.StringData(region),
	}
}
