// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestEc2TagsToMap(t *testing.T) {
	t.Run("converts tags to map", func(t *testing.T) {
		tags := []ec2types.Tag{
			{Key: aws.String("Name"), Value: aws.String("my-vpc")},
			{Key: aws.String("env"), Value: aws.String("prod")},
		}
		result := ec2TagsToMap(tags)
		assert.Equal(t, "my-vpc", result["Name"])
		assert.Equal(t, "prod", result["env"])
		assert.Len(t, result, 2)
	})

	t.Run("skips nil keys and represents a nil value as empty string", func(t *testing.T) {
		// Unified tag-conversion policy (see tagsToStringMap): a nil key is
		// dropped (a tag key is never legitimately empty), but a present key
		// with a nil value is kept as "" so the tag remains visible.
		tags := []ec2types.Tag{
			{Key: aws.String("good"), Value: aws.String("val")},
			{Key: nil, Value: aws.String("orphan-val")},
			{Key: aws.String("orphan-key"), Value: nil},
		}
		result := ec2TagsToMap(tags)
		assert.Equal(t, map[string]string{"good": "val", "orphan-key": ""}, result)
	})

	t.Run("returns empty map for nil slice", func(t *testing.T) {
		result := ec2TagsToMap(nil)
		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})

	t.Run("returns empty map for empty slice", func(t *testing.T) {
		result := ec2TagsToMap([]ec2types.Tag{})
		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})
}

func TestToInterfaceMap(t *testing.T) {
	t.Run("converts string map to any map", func(t *testing.T) {
		input := map[string]string{"a": "1", "b": "2"}
		result := toInterfaceMap(input)
		assert.Equal(t, "1", result["a"])
		assert.Equal(t, "2", result["b"])
		assert.Len(t, result, 2)
	})

	t.Run("returns empty map for empty input", func(t *testing.T) {
		result := toInterfaceMap(map[string]string{})
		assert.NotNil(t, result)
		assert.Len(t, result, 0)
	})
}

func TestVpcFilter(t *testing.T) {
	filter := vpcFilter("vpc-12345")
	assert.Equal(t, "vpc-id", *filter.Name)
	assert.Equal(t, []string{"vpc-12345"}, filter.Values)
}

func TestParseTimeOrZero(t *testing.T) {
	t.Run("parses RFC3339 format", func(t *testing.T) {
		s := "2024-01-15T10:30:00Z"
		result := parseTimeOrZero(&s)
		assert.Equal(t, 2024, result.Year())
		assert.Equal(t, time.January, result.Month())
		assert.Equal(t, 15, result.Day())
	})

	t.Run("parses ISO 8601 without timezone", func(t *testing.T) {
		s := "2024-06-20T14:00:00"
		result := parseTimeOrZero(&s)
		assert.Equal(t, 2024, result.Year())
		assert.Equal(t, time.June, result.Month())
	})

	t.Run("returns zero time for nil", func(t *testing.T) {
		result := parseTimeOrZero(nil)
		assert.True(t, result.IsZero())
	})

	t.Run("returns zero time for empty string", func(t *testing.T) {
		s := ""
		result := parseTimeOrZero(&s)
		assert.True(t, result.IsZero())
	})

	t.Run("returns zero time for garbage input", func(t *testing.T) {
		s := "not-a-date"
		result := parseTimeOrZero(&s)
		assert.True(t, result.IsZero())
	})
}

func TestArnPatterns(t *testing.T) {
	tests := []struct {
		name     string
		pattern  string
		region   string
		account  string
		resource string
		expected string
	}{
		{"VPN connection", vpnConnArnPattern, "us-east-1", "123456789012", "vpn-abc", "arn:aws:ec2:us-east-1:123456789012:vpn-connection/vpn-abc"},
		{"VPN gateway", vpnGatewayArnPattern, "eu-west-1", "999999999999", "vgw-xyz", "arn:aws:ec2:eu-west-1:999999999999:vpn-gateway/vgw-xyz"},
		{"customer gateway", customerGatewayArnPattern, "us-west-2", "111111111111", "cgw-123", "arn:aws:ec2:us-west-2:111111111111:customer-gateway/cgw-123"},
		{"egress-only IGW", egressOnlyIgwArnPattern, "ap-south-1", "222222222222", "eigw-456", "arn:aws:ec2:ap-south-1:222222222222:egress-only-internet-gateway/eigw-456"},
		{"subnet", subnetArnPattern, "us-east-1", "123456789012", "subnet-aaa", "arn:aws:ec2:us-east-1:123456789012:subnet/subnet-aaa"},
		{"route table", routeTableArnPattern, "us-east-1", "123456789012", "rtb-bbb", "arn:aws:ec2:us-east-1:123456789012:route-table/rtb-bbb"},
		{"network ACL", networkAclArnPattern, "us-east-1", "123456789012", "acl-ccc", "arn:aws:ec2:us-east-1:123456789012:network-acl/acl-ccc"},
		{"transit gateway", transitGatewayArnPattern, "us-east-1", "123456789012", "tgw-ddd", "arn:aws:ec2:us-east-1:123456789012:transit-gateway/tgw-ddd"},
		// Synthesized ARNs for resources with no ARN in their describe response.
		// Expected strings follow the AWS Service Authorization Reference; the
		// segment/delimiter differences below are deliberate and load-bearing.
		{"VPC endpoint", vpcEndpointArnPattern, "us-east-1", "123456789012", "vpce-0abc123", "arn:aws:ec2:us-east-1:123456789012:vpc-endpoint/vpce-0abc123"},
		{"VPC flow log", vpcFlowLogArnPattern, "us-east-1", "123456789012", "fl-0abc123", "arn:aws:ec2:us-east-1:123456789012:vpc-flow-log/fl-0abc123"},
		{"NAT gateway", natGatewayArnPattern, "us-east-1", "123456789012", "nat-0abc123", "arn:aws:ec2:us-east-1:123456789012:natgateway/nat-0abc123"},
		{"network interface", networkInterfaceArnPattern, "us-east-1", "123456789012", "eni-0abc123", "arn:aws:ec2:us-east-1:123456789012:network-interface/eni-0abc123"},
		{"DHCP options", dhcpOptionsArnPattern, "us-east-1", "123456789012", "dopt-0abc123", "arn:aws:ec2:us-east-1:123456789012:dhcp-options/dopt-0abc123"},
		{"TGW attachment", tgwAttachmentArnPattern, "us-east-1", "123456789012", "tgw-attach-0abc123", "arn:aws:ec2:us-east-1:123456789012:transit-gateway-attachment/tgw-attach-0abc123"},
		{"TGW route table", tgwRouteTableArnPattern, "us-east-1", "123456789012", "tgw-rtb-0abc123", "arn:aws:ec2:us-east-1:123456789012:transit-gateway-route-table/tgw-rtb-0abc123"},
		{"CloudHSM cluster", cloudhsmClusterArnPattern, "us-east-1", "123456789012", "cluster-abc", "arn:aws:cloudhsm:us-east-1:123456789012:cluster/cluster-abc"},
		{"GuardDuty detector", guarddutyDetectorArnPattern, "us-east-1", "123456789012", "det-abc", "arn:aws:guardduty:us-east-1:123456789012:detector/det-abc"},
		{"Cognito identity pool", cognitoIdentityPoolArnPattern, "us-east-1", "123456789012", "us-east-1:guid", "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/us-east-1:guid"},
		{"Glue database", glueDatabaseArnPattern, "us-east-1", "123456789012", "mydb", "arn:aws:glue:us-east-1:123456789012:database/mydb"},
		{"Glue connection", glueConnectionArnPattern, "us-east-1", "123456789012", "myconn", "arn:aws:glue:us-east-1:123456789012:connection/myconn"},
		{"Glue workflow", glueWorkflowArnPattern, "us-east-1", "123456789012", "mywf", "arn:aws:glue:us-east-1:123456789012:workflow/mywf"},
		{"Athena data catalog", athenaDataCatalogArnPattern, "us-east-1", "123456789012", "mycatalog", "arn:aws:athena:us-east-1:123456789012:datacatalog/mycatalog"},
		{"WorkSpaces workspace", workspacesWorkspaceArnPattern, "us-east-1", "123456789012", "ws-abc", "arn:aws:workspaces:us-east-1:123456789012:workspace/ws-abc"},
		{"WorkSpaces directory", workspacesDirectoryArnPattern, "us-east-1", "123456789012", "d-abc", "arn:aws:workspaces:us-east-1:123456789012:directory/d-abc"},
		{"WorkSpaces IP group", workspacesIpGroupArnPattern, "us-east-1", "123456789012", "wsipg-abc", "arn:aws:workspaces:us-east-1:123456789012:workspaceipgroup/wsipg-abc"},
		// colon delimiter before the identifier, not a slash
		{"Redshift subnet group", redshiftSubnetGroupArnPattern, "us-east-1", "123456789012", "mygroup", "arn:aws:redshift:us-east-1:123456789012:subnetgroup:mygroup"},
		{"Redshift event subscription", redshiftEventSubscriptionArnPattern, "us-east-1", "123456789012", "mysub", "arn:aws:redshift:us-east-1:123456789012:eventsubscription:mysub"},
		{"Lambda event source mapping", lambdaEventSourceMappingArnPattern, "us-east-1", "123456789012", "uuid-abc", "arn:aws:lambda:us-east-1:123456789012:event-source-mapping:uuid-abc"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := fmt.Sprintf(tt.pattern, tt.region, tt.account, tt.resource)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNewMqlVpnConnection(t *testing.T) {
	runtime := testRuntime()

	t.Run("extracts all fields from VpnConnection", func(t *testing.T) {
		vpnConn := ec2types.VpnConnection{
			VpnConnectionId:   aws.String("vpn-12345"),
			State:             ec2types.VpnStateAvailable,
			Type:              ec2types.GatewayTypeIpsec1,
			Category:          aws.String("VPN"),
			VpnGatewayId:      aws.String("vgw-aaa"),
			TransitGatewayId:  aws.String("tgw-bbb"),
			CustomerGatewayId: aws.String("cgw-ccc"),
			Tags: []ec2types.Tag{
				{Key: aws.String("Name"), Value: aws.String("test-vpn")},
			},
			Options: &ec2types.VpnConnectionOptions{
				StaticRoutesOnly:      aws.Bool(true),
				EnableAcceleration:    aws.Bool(false),
				LocalIpv4NetworkCidr:  aws.String("10.0.0.0/16"),
				RemoteIpv4NetworkCidr: aws.String("172.16.0.0/16"),
				OutsideIpAddressType:  aws.String("PublicIpv4"),
				TunnelInsideIpVersion: ec2types.TunnelInsideIpVersionIpv4,
			},
		}

		result, err := newMqlVpnConnection(runtime, "us-east-1", "123456789012", vpnConn)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "vpn-12345", result.Id.Data)
		assert.Equal(t, "us-east-1", result.Region.Data)
		assert.Equal(t, "available", result.State.Data)
		assert.Equal(t, "ipsec.1", result.Type.Data)
		assert.Equal(t, "VPN", result.Category.Data)
		assert.True(t, result.StaticRoutesOnly.Data)
		assert.False(t, result.EnableAcceleration.Data)
		assert.Equal(t, "10.0.0.0/16", result.LocalIpv4NetworkCidr.Data)
		assert.Equal(t, "172.16.0.0/16", result.RemoteIpv4NetworkCidr.Data)
		assert.Equal(t, "PublicIpv4", result.OutsideIpAddressType.Data)
		assert.Equal(t, "ipv4", result.TunnelInsideIpVersion.Data)
		assert.Contains(t, result.Arn.Data, "vpn-12345")

		// Verify internal cache for typed references
		assert.Equal(t, "vgw-aaa", *result.cacheVpnGatewayId)
		assert.Equal(t, "tgw-bbb", *result.cacheTransitGatewayId)
		assert.Equal(t, "cgw-ccc", *result.cacheCustomerGatewayId)
		assert.Equal(t, "us-east-1", result.region)
		assert.Equal(t, "123456789012", result.accountID)
	})

	t.Run("handles nil Options gracefully", func(t *testing.T) {
		vpnConn := ec2types.VpnConnection{
			VpnConnectionId: aws.String("vpn-nil-opts"),
			State:           ec2types.VpnStatePending,
			Options:         nil,
		}

		result, err := newMqlVpnConnection(runtime, "us-west-2", "111111111111", vpnConn)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.False(t, result.StaticRoutesOnly.Data)
		assert.False(t, result.EnableAcceleration.Data)
		assert.Empty(t, result.LocalIpv4NetworkCidr.Data)
		assert.Empty(t, result.TunnelInsideIpVersion.Data)
	})

	t.Run("handles nil gateway IDs", func(t *testing.T) {
		vpnConn := ec2types.VpnConnection{
			VpnConnectionId:   aws.String("vpn-no-gw"),
			VpnGatewayId:      nil,
			TransitGatewayId:  nil,
			CustomerGatewayId: nil,
		}

		result, err := newMqlVpnConnection(runtime, "us-east-1", "123456789012", vpnConn)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Nil(t, result.cacheVpnGatewayId)
		assert.Nil(t, result.cacheTransitGatewayId)
		assert.Nil(t, result.cacheCustomerGatewayId)
	})

	t.Run("populates tunnel IKE crypto options", func(t *testing.T) {
		vpnConn := ec2types.VpnConnection{
			VpnConnectionId: aws.String("vpn-tunnels"),
			State:           ec2types.VpnStateAvailable,
			Options: &ec2types.VpnConnectionOptions{
				TunnelOptions: []ec2types.TunnelOption{
					{
						OutsideIpAddress: aws.String("203.0.113.10"),
						TunnelInsideCidr: aws.String("169.254.10.0/30"),
						IkeVersions: []ec2types.IKEVersionsListValue{
							{Value: aws.String("ikev2")},
						},
						Phase1EncryptionAlgorithms: []ec2types.Phase1EncryptionAlgorithmsListValue{
							{Value: aws.String("AES256")},
							{Value: aws.String("AES256-GCM-16")},
						},
						Phase2EncryptionAlgorithms: []ec2types.Phase2EncryptionAlgorithmsListValue{
							{Value: aws.String("AES256")},
						},
						Phase1IntegrityAlgorithms: []ec2types.Phase1IntegrityAlgorithmsListValue{
							{Value: aws.String("SHA2-256")},
						},
						Phase2IntegrityAlgorithms: []ec2types.Phase2IntegrityAlgorithmsListValue{
							{Value: aws.String("SHA2-512")},
						},
						Phase1DHGroupNumbers: []ec2types.Phase1DHGroupNumbersListValue{
							{Value: aws.Int32(20)},
							{Value: aws.Int32(21)},
						},
						Phase2DHGroupNumbers: []ec2types.Phase2DHGroupNumbersListValue{
							{Value: aws.Int32(20)},
						},
					},
					{
						// second tunnel with mostly nil pointers to exercise nil-safety
						OutsideIpAddress: aws.String("203.0.113.20"),
					},
				},
			},
		}

		result, err := newMqlVpnConnection(runtime, "us-east-1", "123456789012", vpnConn)
		require.NoError(t, err)
		require.NotNil(t, result)

		tunnels := result.TunnelOptions.Data
		require.Len(t, tunnels, 2)

		t0 := tunnels[0].(*mqlAwsEc2VpnconnectionTunnelOption)
		assert.Equal(t, "203.0.113.10", t0.OutsideIpAddress.Data)
		assert.Equal(t, "169.254.10.0/30", t0.TunnelInsideCidr.Data)
		assert.Equal(t, []any{"ikev2"}, t0.IkeVersions.Data)
		assert.Equal(t, []any{"AES256", "AES256-GCM-16"}, t0.Phase1EncryptionAlgorithms.Data)
		assert.Equal(t, []any{"AES256"}, t0.Phase2EncryptionAlgorithms.Data)
		assert.Equal(t, []any{"SHA2-256"}, t0.Phase1IntegrityAlgorithms.Data)
		assert.Equal(t, []any{"SHA2-512"}, t0.Phase2IntegrityAlgorithms.Data)
		assert.Equal(t, []any{int64(20), int64(21)}, t0.Phase1DHGroupNumbers.Data)
		assert.Equal(t, []any{int64(20)}, t0.Phase2DHGroupNumbers.Data)

		t1 := tunnels[1].(*mqlAwsEc2VpnconnectionTunnelOption)
		assert.Equal(t, "203.0.113.20", t1.OutsideIpAddress.Data)
		assert.Empty(t, t1.TunnelInsideCidr.Data)
		assert.Empty(t, t1.IkeVersions.Data)
		assert.Empty(t, t1.Phase1DHGroupNumbers.Data)
	})

	t.Run("tunnels with empty outside IPs get distinct ids", func(t *testing.T) {
		// Both tunnels of a Site-to-Site VPN report an empty outside IP while
		// still provisioning; the __id must stay unique so they don't collide
		// in the resource cache.
		vpnConn := ec2types.VpnConnection{
			VpnConnectionId: aws.String("vpn-provisioning"),
			Options: &ec2types.VpnConnectionOptions{
				TunnelOptions: []ec2types.TunnelOption{
					{},
					{},
				},
			},
		}

		result, err := newMqlVpnConnection(runtime, "us-east-1", "123456789012", vpnConn)
		require.NoError(t, err)
		require.NotNil(t, result)

		tunnels := result.TunnelOptions.Data
		require.Len(t, tunnels, 2)

		id0 := tunnels[0].(*mqlAwsEc2VpnconnectionTunnelOption).MqlID()
		id1 := tunnels[1].(*mqlAwsEc2VpnconnectionTunnelOption).MqlID()
		assert.NotEqual(t, id0, id1)
		assert.Contains(t, id0, "vpn-provisioning")
	})

	t.Run("empty tunnel options list", func(t *testing.T) {
		vpnConn := ec2types.VpnConnection{
			VpnConnectionId: aws.String("vpn-no-tunnels"),
			Options:         &ec2types.VpnConnectionOptions{},
		}
		result, err := newMqlVpnConnection(runtime, "us-east-1", "123456789012", vpnConn)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Empty(t, result.TunnelOptions.Data)
	})
}

func TestTunnelOptionValueHelpers(t *testing.T) {
	t.Run("listValuesToStrings extracts values and skips nil", func(t *testing.T) {
		in := []ec2types.IKEVersionsListValue{
			{Value: aws.String("ikev1")},
			{Value: nil},
			{Value: aws.String("ikev2")},
		}
		out := listValuesToStrings(in, func(v ec2types.IKEVersionsListValue) *string { return v.Value })
		assert.Equal(t, []any{"ikev1", "ikev2"}, out)
	})

	t.Run("listValuesToStrings on nil slice returns empty (non-nil)", func(t *testing.T) {
		out := listValuesToStrings(nil, func(v ec2types.IKEVersionsListValue) *string { return v.Value })
		assert.NotNil(t, out)
		assert.Empty(t, out)
	})

	t.Run("dhGroupNumbersToInts converts int32 to int64 and skips nil", func(t *testing.T) {
		in := []ec2types.Phase1DHGroupNumbersListValue{
			{Value: aws.Int32(14)},
			{Value: nil},
			{Value: aws.Int32(24)},
		}
		out := dhGroupNumbersToInts(in, func(v ec2types.Phase1DHGroupNumbersListValue) *int32 { return v.Value })
		assert.Equal(t, []any{int64(14), int64(24)}, out)
	})

	t.Run("dhGroupNumbersToInts on nil slice returns empty (non-nil)", func(t *testing.T) {
		out := dhGroupNumbersToInts(nil, func(v ec2types.Phase1DHGroupNumbersListValue) *int32 { return v.Value })
		assert.NotNil(t, out)
		assert.Empty(t, out)
	})
}

func TestEipNullStateOnMissingCache(t *testing.T) {
	t.Run("networkInterface returns null when NetworkInterfaceId is nil", func(t *testing.T) {
		eip := &mqlAwsEc2Eip{}
		// eipCache is zero-valued — NetworkInterfaceId is nil
		result, err := eip.networkInterface()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, eip.NetworkInterface.IsNull())
		assert.True(t, eip.NetworkInterface.IsSet())
	})

	t.Run("networkInterface returns null when NetworkInterfaceId is empty", func(t *testing.T) {
		eip := &mqlAwsEc2Eip{}
		eip.eipCache = ec2types.Address{
			NetworkInterfaceId: aws.String(""),
		}
		result, err := eip.networkInterface()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, eip.NetworkInterface.IsNull())
		assert.True(t, eip.NetworkInterface.IsSet())
	})

}

func TestFlowLogNullStateOnMissingCache(t *testing.T) {
	t.Run("iamRole returns null when DeliverLogsPermissionArn is nil", func(t *testing.T) {
		fl := &mqlAwsVpcFlowlog{}
		result, err := fl.iamRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, fl.IamRole.IsNull())
		assert.True(t, fl.IamRole.IsSet())
	})

	t.Run("iamRole returns null when DeliverLogsPermissionArn is empty", func(t *testing.T) {
		fl := &mqlAwsVpcFlowlog{}
		empty := ""
		fl.cacheDeliverLogsPermissionArn = &empty
		result, err := fl.iamRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, fl.IamRole.IsNull())
		assert.True(t, fl.IamRole.IsSet())
	})

	t.Run("logGroup returns null when destinationType is not cloud-watch-logs", func(t *testing.T) {
		fl := &mqlAwsVpcFlowlog{}
		logGroup := "my-log-group"
		fl.cacheLogGroupName = &logGroup
		fl.cacheLogDestinationType = "s3"
		result, err := fl.logGroup()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, fl.LogGroup.IsNull())
		assert.True(t, fl.LogGroup.IsSet())
	})

	t.Run("s3Bucket returns null when destinationType is not s3", func(t *testing.T) {
		fl := &mqlAwsVpcFlowlog{}
		dest := "arn:aws:logs:us-east-1:123456789012:log-group:my-group"
		fl.cacheLogDestination = &dest
		fl.cacheLogDestinationType = "cloud-watch-logs"
		result, err := fl.s3Bucket()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, fl.S3Bucket.IsNull())
		assert.True(t, fl.S3Bucket.IsSet())
	})

	t.Run("s3Bucket returns null when destination ARN is unparseable", func(t *testing.T) {
		fl := &mqlAwsVpcFlowlog{}
		dest := "not-an-arn"
		fl.cacheLogDestination = &dest
		fl.cacheLogDestinationType = "s3"
		result, err := fl.s3Bucket()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, fl.S3Bucket.IsNull())
		assert.True(t, fl.S3Bucket.IsSet())
	})
}

func TestPeeringConnectionFields(t *testing.T) {
	runtime := testRuntime()

	t.Run("dnsResolutionEnabled is true when requester allows it", func(t *testing.T) {
		pc := ec2types.VpcPeeringConnection{
			VpcPeeringConnectionId: aws.String("pcx-123"),
			Status:                 &ec2types.VpcPeeringConnectionStateReason{Message: aws.String("active")},
			RequesterVpcInfo: &ec2types.VpcPeeringConnectionVpcInfo{
				OwnerId: aws.String("111111111111"),
				VpcId:   aws.String("vpc-req"),
				PeeringOptions: &ec2types.VpcPeeringConnectionOptionsDescription{
					AllowDnsResolutionFromRemoteVpc: aws.Bool(true),
				},
			},
			AccepterVpcInfo: &ec2types.VpcPeeringConnectionVpcInfo{
				OwnerId: aws.String("222222222222"),
				VpcId:   aws.String("vpc-acc"),
				PeeringOptions: &ec2types.VpcPeeringConnectionOptionsDescription{
					AllowDnsResolutionFromRemoteVpc: aws.Bool(false),
				},
			},
		}

		// Simulate the logic from peeringConnections() creation
		dnsResolution := false
		if pc.RequesterVpcInfo != nil && pc.RequesterVpcInfo.PeeringOptions != nil &&
			pc.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil {
			dnsResolution = *pc.RequesterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc
		}
		if !dnsResolution && pc.AccepterVpcInfo != nil && pc.AccepterVpcInfo.PeeringOptions != nil &&
			pc.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc != nil {
			dnsResolution = *pc.AccepterVpcInfo.PeeringOptions.AllowDnsResolutionFromRemoteVpc
		}

		assert.True(t, dnsResolution)

		var requesterAccountId string
		if pc.RequesterVpcInfo != nil {
			requesterAccountId = *pc.RequesterVpcInfo.OwnerId
		}
		assert.Equal(t, "111111111111", requesterAccountId)

		_ = runtime // used by other tests that need resource creation
	})
}

func TestVpnGatewayNullState(t *testing.T) {
	t.Run("vpnGateway returns null when VpnGatewayId is nil", func(t *testing.T) {
		vpn := &mqlAwsEc2Vpnconnection{}
		result, err := vpn.vpnGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, vpn.VpnGateway.IsNull())
		assert.True(t, vpn.VpnGateway.IsSet())
	})

	t.Run("transitGateway returns null when TransitGatewayId is nil", func(t *testing.T) {
		vpn := &mqlAwsEc2Vpnconnection{}
		result, err := vpn.transitGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, vpn.TransitGateway.IsNull())
		assert.True(t, vpn.TransitGateway.IsSet())
	})

	t.Run("customerGateway returns null when CustomerGatewayId is nil", func(t *testing.T) {
		vpn := &mqlAwsEc2Vpnconnection{}
		result, err := vpn.customerGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, vpn.CustomerGateway.IsNull())
		assert.True(t, vpn.CustomerGateway.IsSet())
	})

	t.Run("customerGateway returns null when CustomerGatewayId is empty", func(t *testing.T) {
		vpn := &mqlAwsEc2Vpnconnection{}
		empty := ""
		vpn.cacheCustomerGatewayId = &empty
		result, err := vpn.customerGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, vpn.CustomerGateway.IsNull())
		assert.True(t, vpn.CustomerGateway.IsSet())
	})
}

// TestRouteNextHopNullState covers how a route table route resolves its
// polymorphic gatewayId into the correct typed next-hop. gatewayId can name an
// internet gateway (igw-), a virtual private gateway (vgw-), a VPC endpoint, or
// the local route, so internetGateway() and vpnGateway() must each resolve only
// their own prefix and return a set-null value otherwise (never cross-resolve).
func TestRouteNextHopNullState(t *testing.T) {
	t.Run("internetGateway is null when gatewayId is empty", func(t *testing.T) {
		route := &mqlAwsVpcRoutetableRoute{}
		result, err := route.internetGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, route.InternetGateway.IsNull())
		assert.True(t, route.InternetGateway.IsSet())
	})

	t.Run("internetGateway is null when gatewayId is a virtual private gateway", func(t *testing.T) {
		route := &mqlAwsVpcRoutetableRoute{}
		route.GatewayId = plugin.TValue[string]{Data: "vgw-0123456789abcdef0", State: plugin.StateIsSet}
		result, err := route.internetGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, route.InternetGateway.IsNull())
		assert.True(t, route.InternetGateway.IsSet())
	})

	t.Run("vpnGateway is null when gatewayId is empty", func(t *testing.T) {
		route := &mqlAwsVpcRoutetableRoute{}
		result, err := route.vpnGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, route.VpnGateway.IsNull())
		assert.True(t, route.VpnGateway.IsSet())
	})

	t.Run("vpnGateway is null when gatewayId is an internet gateway", func(t *testing.T) {
		route := &mqlAwsVpcRoutetableRoute{}
		route.GatewayId = plugin.TValue[string]{Data: "igw-0123456789abcdef0", State: plugin.StateIsSet}
		result, err := route.vpnGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, route.VpnGateway.IsNull())
		assert.True(t, route.VpnGateway.IsSet())
	})

	t.Run("egressOnlyInternetGateway is null when id is empty", func(t *testing.T) {
		route := &mqlAwsVpcRoutetableRoute{}
		result, err := route.egressOnlyInternetGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, route.EgressOnlyInternetGateway.IsNull())
		assert.True(t, route.EgressOnlyInternetGateway.IsSet())
	})

	t.Run("transitGateway is null when transitGatewayId is empty", func(t *testing.T) {
		route := &mqlAwsVpcRoutetableRoute{}
		result, err := route.transitGateway()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, route.TransitGateway.IsNull())
		assert.True(t, route.TransitGateway.IsSet())
	})

	t.Run("peeringConnection is null when vpcPeeringConnectionId is empty", func(t *testing.T) {
		route := &mqlAwsVpcRoutetableRoute{}
		result, err := route.peeringConnection()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, route.PeeringConnection.IsNull())
		assert.True(t, route.PeeringConnection.IsSet())
	})
}

func TestNatgatewayAddressCacheKey(t *testing.T) {
	// two private NAT gateway addresses without an AllocationId must not collide
	a := natgatewayAddressCacheKey("eni-0a1b2c3d", "10.0.0.5")
	b := natgatewayAddressCacheKey("eni-4e5f6a7b", "10.0.0.6")
	assert.Equal(t, "eni-0a1b2c3d/10.0.0.5", a)
	assert.Equal(t, "eni-4e5f6a7b/10.0.0.6", b)
	assert.NotEqual(t, a, b)
}

// TestVgwTelemetryKeyIsScopedToItsConnection pins that a VPN connection's
// telemetry entries are told apart from each other and from other connections'.
//
// A telemetry entry carries nothing but its outside IP, and that IP is empty
// while a tunnel is still provisioning. Keying on it alone meant both tunnels
// of a new connection shared one row, and so did every connection in that state
// across the whole account — so a query for tunnel status during a rollout, the
// moment it matters most, read one entry repeated.
func TestVgwTelemetryKeyIsScopedToItsConnection(t *testing.T) {
	newConn := func(id string, outsideIPs ...string) *mqlAwsEc2Vpnconnection {
		telemetry := make([]ec2types.VgwTelemetry, 0, len(outsideIPs))
		for _, ip := range outsideIPs {
			telemetry = append(telemetry, ec2types.VgwTelemetry{
				OutsideIpAddress: aws.String(ip),
				Status:           ec2types.TelemetryStatusDown,
			})
		}
		conn, err := newMqlVpnConnection(testRuntime(), "us-east-1", "000000000000",
			ec2types.VpnConnection{
				VpnConnectionId: aws.String(id),
				VgwTelemetry:    telemetry,
			})
		require.NoError(t, err)
		return conn
	}

	keys := func(conn *mqlAwsEc2Vpnconnection) []string {
		out := []string{}
		for _, raw := range conn.VgwTelemetry.Data {
			out = append(out, raw.(*mqlAwsEc2Vgwtelemetry).MqlID())
		}
		return out
	}

	t.Run("both tunnels of a provisioning connection are distinct", func(t *testing.T) {
		// Neither tunnel has an outside IP yet, which is the case that collapsed
		// them onto one row.
		got := keys(newConn("vpn-0aaaaaaaaaaaaaaaa", "", ""))
		require.Len(t, got, 2)
		assert.NotEqual(t, got[0], got[1])
	})

	t.Run("two provisioning connections do not share entries", func(t *testing.T) {
		first := keys(newConn("vpn-0aaaaaaaaaaaaaaaa", "", ""))
		second := keys(newConn("vpn-0bbbbbbbbbbbbbbbb", "", ""))
		for _, a := range first {
			assert.NotContains(t, second, a)
		}
	})

	t.Run("established tunnels stay distinct too", func(t *testing.T) {
		got := keys(newConn("vpn-0aaaaaaaaaaaaaaaa", "203.0.113.1", "203.0.113.2"))
		require.Len(t, got, 2)
		assert.NotEqual(t, got[0], got[1])
	})
}

// TestNatgatewayAddressKeyIsSetAtCreation pins that a NAT gateway address is
// keyed by its ENI, not just its private IP.
//
// The key helper was always correct; what was broken is that id() reads it from
// cacheNetworkInterfaceId, which the creator assigns *after* CreateResource has
// already computed the key. So the ENI was always empty at the moment it
// mattered, every address keyed on its private IP alone, and two VPCs built
// from the same CIDR plan aliased onto one row — with the post-construction
// writes then racing on the shared object.
func TestNatgatewayAddressKeyIsSetAtCreation(t *testing.T) {
	// A fresh runtime per gateway: these all describe different gateways, and a
	// shared runtime would legitimately return the first one from cache.
	newAddress := func(natGatewayId, eni, privateIp string) *mqlAwsVpcNatgatewayAddress {
		runtime := testRuntime()
		gw := ec2types.NatGateway{
			NatGatewayId: aws.String(natGatewayId),
			NatGatewayAddresses: []ec2types.NatGatewayAddress{{
				NetworkInterfaceId: aws.String(eni),
				PrivateIp:          aws.String(privateIp),
			}},
		}
		nat, err := newMqlAwsVpcNatgateway(runtime, "us-east-1", gw)
		require.NoError(t, err)
		require.Len(t, nat.Addresses.Data, 1)
		return nat.Addresses.Data[0].(*mqlAwsVpcNatgatewayAddress)
	}

	t.Run("the eni reaches the cache key", func(t *testing.T) {
		addr := newAddress("nat-0aaaaaaaaaaaaaaaa", "eni-0aaaaaaaaaaaaaaaa", "10.0.1.10")
		assert.Equal(t, "eni-0aaaaaaaaaaaaaaaa/10.0.1.10", addr.MqlID(),
			"the key must carry the ENI, which id() could never see")
	})

	t.Run("two vpcs with the same private ip do not alias", func(t *testing.T) {
		first := newAddress("nat-0aaaaaaaaaaaaaaaa", "eni-0aaaaaaaaaaaaaaaa", "10.0.1.10")
		second := newAddress("nat-0bbbbbbbbbbbbbbbb", "eni-0bbbbbbbbbbbbbbbb", "10.0.1.10")
		assert.NotEqual(t, first.MqlID(), second.MqlID())
	})

	t.Run("an address with no eni still keys on its private ip", func(t *testing.T) {
		addr := newAddress("nat-0ccccccccccccccccc", "", "10.0.1.10")
		assert.Equal(t, "/10.0.1.10", addr.MqlID())
	})
}
