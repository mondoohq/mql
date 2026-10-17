// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/llx"
)

func TestIsVpcNotFoundError(t *testing.T) {
	notFound := &smithy.GenericAPIError{Code: "InvalidVpcID.NotFound", Message: "The vpc ID 'vpc-0abc' does not exist"}
	assert.True(t, isVpcNotFoundError(notFound))
	// Wrapped, as the SDK's operation errors are.
	assert.True(t, isVpcNotFoundError(fmt.Errorf("operation error EC2: DescribeVpcs, %w", notFound)))

	assert.False(t, isVpcNotFoundError(&smithy.GenericAPIError{Code: "UnauthorizedOperation"}))
	assert.False(t, isVpcNotFoundError(errors.New("InvalidVpcID.NotFound")))
	assert.False(t, isVpcNotFoundError(nil))
}

func TestDeriveVpcTargetFromSubnetLookupArn(t *testing.T) {
	// awsResolveVpcFromSubnets passes the VPC's ARN, so initAwsVpc gets the
	// region and describes the VPC directly instead of searching the
	// tag-filtered list.
	vpcArn := fmt.Sprintf(vpcArnPattern, "eu-west-1", "123456789012", "vpc-0abc")
	args := map[string]*llx.RawData{"arn": llx.StringData(vpcArn)}
	region, vpcId := deriveVpcTarget(nil, args)
	assert.Equal(t, "eu-west-1", region)
	assert.Equal(t, "vpc-0abc", vpcId)
}
