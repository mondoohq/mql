// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	batch_types "github.com/aws/aws-sdk-go-v2/service/batch/types"
	ddtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	ecstypes "github.com/aws/aws-sdk-go-v2/service/ecs/types"
	elasticache_types "github.com/aws/aws-sdk-go-v2/service/elasticache/types"
	globalaccelerator_types "github.com/aws/aws-sdk-go-v2/service/globalaccelerator/types"
	transfertypes "github.com/aws/aws-sdk-go-v2/service/transfer/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestServerlessCacheExposureInputs(t *testing.T) {
	tests := []struct {
		connectionType string
		wantNull       bool
		wantPublic     bool
		wantSgsApply   bool
	}{
		{connectionType: string(elasticache_types.ConnectionTypePublic), wantPublic: true, wantSgsApply: false},
		{connectionType: string(elasticache_types.ConnectionTypeVpc), wantPublic: false, wantSgsApply: true},
		// ElastiCache defaults an unreported connection type to vpc.
		{connectionType: "", wantPublic: false, wantSgsApply: true},
		// A value this SDK does not know must not be reported as private.
		{connectionType: "something-new", wantNull: true, wantSgsApply: true},
	}
	for _, tt := range tests {
		t.Run(tt.connectionType, func(t *testing.T) {
			pub, sgsApply := serverlessCacheExposureInputs(tt.connectionType)
			require.NotNil(t, pub)
			assert.Equal(t, tt.wantSgsApply, sgsApply)
			assert.Equal(t, tt.wantNull, publicAccessIsUnknown(pub))
			if !tt.wantNull {
				assert.Equal(t, tt.wantPublic, pub.Data)
			}
		})
	}
}

// TestServerlessCacheExposureVerdict runs the decision through the shared
// exposure builder: a public cache is internet-reachable even though its
// security group is closed (the group only gates the VPC endpoint), while a
// vpc cache is not reachable even with an open group.
func TestServerlessCacheExposureVerdict(t *testing.T) {
	runtime := testRuntime()

	pub, sgsApply := serverlessCacheExposureInputs("public")
	var sgs *plugin.TValue[[]any]
	if sgsApply {
		sgs = securityGroupsTValue(runtime, false)
	}
	exposure, err := buildNetworkExposure(runtime, "public-cache/exposure", pub, sgs)
	require.NoError(t, err)
	assert.True(t, exposure.InternetReachable.Data)
	assert.True(t, exposure.PubliclyAccessible.Data)

	pub, sgsApply = serverlessCacheExposureInputs("vpc")
	sgs = nil
	if sgsApply {
		sgs = securityGroupsTValue(runtime, true)
	}
	exposure, err = buildNetworkExposure(runtime, "vpc-cache/exposure", pub, sgs)
	require.NoError(t, err)
	assert.False(t, exposure.InternetReachable.Data)
	assert.False(t, exposure.PubliclyAccessible.IsNull())
	assert.True(t, exposure.SecurityGroupAllowsIngress.Data)
}

func TestBatchEksAccessEntry(t *testing.T) {
	desired, status := batchEksAccessEntry(nil)
	assert.Nil(t, desired, "not EKS-backed")
	assert.Nil(t, status)

	desired, status = batchEksAccessEntry(&batch_types.EksConfiguration{EksClusterArn: aws.String("arn")})
	assert.Nil(t, desired, "EKS-backed without an access entry")
	assert.Nil(t, status)

	desired, status = batchEksAccessEntry(&batch_types.EksConfiguration{
		AccessEntry: &batch_types.EksAccessEntry{DesiredState: batch_types.EksAccessEntryDesiredStateInheritFromCluster},
	})
	require.NotNil(t, desired)
	assert.Equal(t, "INHERIT_FROM_CLUSTER", *desired)
	assert.Nil(t, status, "an unset observed state is null, not empty")

	desired, status = batchEksAccessEntry(&batch_types.EksConfiguration{
		AccessEntry: &batch_types.EksAccessEntry{
			DesiredState: batch_types.EksAccessEntryDesiredStateEnabled,
			Status:       batch_types.EksAccessEntryStatusActive,
		},
	})
	require.NotNil(t, desired)
	require.NotNil(t, status)
	assert.Equal(t, "ENABLED", *desired)
	assert.Equal(t, "ACTIVE", *status)
}

func TestDynamodbFilterSpecificationToDict(t *testing.T) {
	assert.Nil(t, dynamodbFilterSpecificationToDict(nil), "an export without a filter is null")

	got := dynamodbFilterSpecificationToDict(&ddtypes.FilterSpecification{
		FilterExpression:         aws.String("#s = :active"),
		ExpressionAttributeNames: map[string]string{"#s": "status"},
		ExpressionAttributeValues: map[string]ddtypes.AttributeValue{
			":active": &ddtypes.AttributeValueMemberS{Value: "active"},
			":n":      &ddtypes.AttributeValueMemberN{Value: "42"},
			":b":      &ddtypes.AttributeValueMemberB{Value: []byte("hi")},
			":l": &ddtypes.AttributeValueMemberL{Value: []ddtypes.AttributeValue{
				&ddtypes.AttributeValueMemberBOOL{Value: true},
			}},
			":m": &ddtypes.AttributeValueMemberM{Value: map[string]ddtypes.AttributeValue{
				"k": &ddtypes.AttributeValueMemberNULL{Value: true},
			}},
		},
	})
	require.NotNil(t, got)
	assert.Equal(t, "#s = :active", got["filterExpression"])
	assert.Nil(t, got["keyConditionExpression"], "unset expressions are null, not empty")
	assert.Nil(t, got["projectionExpression"])
	assert.Equal(t, map[string]any{"#s": "status"}, got["expressionAttributeNames"])

	values := got["expressionAttributeValues"].(map[string]any)
	assert.Equal(t, map[string]any{"S": "active"}, values[":active"])
	assert.Equal(t, map[string]any{"N": "42"}, values[":n"])
	assert.Equal(t, map[string]any{"B": "aGk="}, values[":b"])
	assert.Equal(t, map[string]any{"L": []any{map[string]any{"BOOL": true}}}, values[":l"])
	assert.Equal(t, map[string]any{"M": map[string]any{"k": map[string]any{"NULL": true}}}, values[":m"])
}

func TestTransferSftpPorts(t *testing.T) {
	assert.Nil(t, transferSftpPorts(nil))
	assert.Nil(t, transferSftpPorts(&transfertypes.ProtocolDetails{}), "no reported ports is null, not an empty list")

	got := transferSftpPorts(&transfertypes.ProtocolDetails{SftpPorts: []transfertypes.SftpPortWithOptions{
		{SftpPort: aws.Int32(22)},
		{SftpPort: aws.Int32(2222), CommunicationMode: transfertypes.CommunicationModeClientTalkFirst},
	}})
	require.Len(t, got, 2)
	assert.Equal(t, map[string]any{"port": int64(22), "communicationMode": nil}, got[0])
	assert.Equal(t, map[string]any{"port": int64(2222), "communicationMode": "CLIENT_TALK_FIRST"}, got[1])
}

func TestPrimaryEcsDeployment(t *testing.T) {
	assert.Nil(t, primaryEcsDeployment(nil))
	assert.Nil(t, primaryEcsDeployment([]ecstypes.Deployment{{Status: aws.String("ACTIVE")}}))

	deployments := []ecstypes.Deployment{
		{Id: aws.String("old"), Status: aws.String("ACTIVE")},
		{Id: aws.String("new"), Status: aws.String("PRIMARY")},
	}
	got := primaryEcsDeployment(deployments)
	require.NotNil(t, got)
	assert.Equal(t, "new", aws.ToString(got.Id))
}

// TestGlobalAcceleratorIpSetDetailsKeys pins the dict keys the ipSets field
// documents for the address details added in globalaccelerator v1.45.0. The
// entries are produced by JSON-encoding the SDK struct, so a renamed SDK field
// would silently change the keys users query.
func TestGlobalAcceleratorIpSetDetailsKeys(t *testing.T) {
	got, err := convert.JsonToDictSlice([]globalaccelerator_types.IpSet{{
		IpAddressDetails: []globalaccelerator_types.IpAddressDetail{{
			IpAddress:   aws.String("192.0.2.1"),
			NetworkZone: aws.String("us-west-2-pdx-1"),
		}},
	}})
	require.NoError(t, err)
	require.Len(t, got, 1)
	details := got[0].(map[string]any)["IpAddressDetails"].([]any)
	require.Len(t, details, 1)
	assert.Equal(t, map[string]any{"IpAddress": "192.0.2.1", "NetworkZone": "us-west-2-pdx-1"}, details[0])
}
