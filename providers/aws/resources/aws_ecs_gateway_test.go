// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestFlattenEcsGatewayConfiguration(t *testing.T) {
	// Synthetic: no gateway exists in the verification account; built from the
	// DescribeGateway shape for a shared-ALB gateway.
	t.Run("shared ALB with S3 access logs", func(t *testing.T) {
		out := flattenEcsGatewayConfiguration(&ecstypes.DescribeGatewayConfigurationMemberHostSharedAlb{
			Value: ecstypes.DescribeGatewayAlbConfiguration{
				Scheme:          ecstypes.GatewayElbSchemeInternetFacing,
				HttpDesync:      ecstypes.GatewayAlbDesyncMitigationModeStrictest,
				Protocol:        ecstypes.GatewayAlbProtocol("HTTPS"),
				Port:            aws.Int32(443),
				MaxAlbCount:     aws.Int32(3),
				CurrentAlbCount: aws.Int32(1),
				WebACLArn:       aws.String("arn:aws:wafv2:us-east-1:123456789012:regional/webacl/gw/abc"),
				NetworkConfiguration: &ecstypes.GatewayElbNetworkConfiguration{
					IpAddressType:        ecstypes.GatewayElbIpAddressTypeDualstack,
					Subnets:              []string{"subnet-1", "subnet-2"},
					InboundSecurityGroup: aws.String("sg-1"),
				},
				AccessLogs: &ecstypes.GatewayElbAccessLogConfiguration{
					Destination: &ecstypes.GatewayElbAccessLogDestinationMemberS3{
						Value: ecstypes.GatewayElbAccessLogS3Destination{
							Bucket: aws.String("logs-bucket"),
							Prefix: aws.String("gw/"),
						},
					},
				},
			},
		})
		assert.Equal(t, ecsGatewayConfigurationHostSharedAlb, out.configurationType)
		assert.Equal(t, "internet-facing", out.fields["scheme"].Value)
		assert.Equal(t, "strictest", out.fields["httpDesyncMitigationMode"].Value)
		assert.Equal(t, "HTTPS", out.fields["listenerProtocol"].Value)
		assert.Equal(t, int64(443), out.fields["listenerPort"].Value)
		assert.Equal(t, int64(3), out.fields["maxAlbCount"].Value)
		assert.Equal(t, int64(1), out.fields["currentAlbCount"].Value)
		assert.Equal(t, "dualstack", out.fields["ipAddressType"].Value)
		assert.Equal(t, true, out.fields["accessLogsEnabled"].Value)
		assert.Equal(t, "gw/", out.fields["accessLogsPrefix"].Value)
		assert.Equal(t, "logs-bucket", out.accessLogsBucket)
		assert.Equal(t, []string{"subnet-1", "subnet-2"}, out.subnetIds)
		assert.Equal(t, "sg-1", out.inboundSG)
		assert.Equal(t, "arn:aws:wafv2:us-east-1:123456789012:regional/webacl/gw/abc", out.webAclArn)
	})

	// Synthetic: a shared ALB without access logs or network configuration.
	t.Run("shared ALB without access logs", func(t *testing.T) {
		out := flattenEcsGatewayConfiguration(&ecstypes.DescribeGatewayConfigurationMemberHostSharedAlb{
			Value: ecstypes.DescribeGatewayAlbConfiguration{Scheme: ecstypes.GatewayElbSchemeInternal},
		})
		assert.Equal(t, "internal", out.fields["scheme"].Value)
		assert.Equal(t, false, out.fields["accessLogsEnabled"].Value)
		assert.Same(t, llx.NilData, out.fields["accessLogsPrefix"])
		assert.Same(t, llx.NilData, out.fields["ipAddressType"])
		assert.Same(t, llx.NilData, out.fields["httpDesyncMitigationMode"])
		assert.Empty(t, out.accessLogsBucket)
		assert.Empty(t, out.webAclArn)
	})

	// Synthetic: a union member this SDK does not model reports unknown and null
	// load balancer fields rather than an empty configuration type.
	for name, cfg := range map[string]ecstypes.DescribeGatewayConfiguration{
		"unknown member": &ecstypes.UnknownUnionMember{Tag: "futureKind"},
		"nil":            nil,
	} {
		t.Run(name, func(t *testing.T) {
			out := flattenEcsGatewayConfiguration(cfg)
			assert.Equal(t, ecsGatewayConfigurationUnknown, out.configurationType)
			for field, raw := range out.fields {
				assert.Same(t, llx.NilData, raw, field)
			}
		})
	}
}
