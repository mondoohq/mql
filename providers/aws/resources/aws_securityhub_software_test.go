// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/securityhub/types"
	"github.com/stretchr/testify/assert"
)

func TestSecurityhubSoftwarePackageId(t *testing.T) {
	// Synthetic: GetSoftwareV2 entries; no target showed these.
	base := types.SoftwareResult{PackageName: aws.String("openssl"), PackageType: aws.String("operating-system")}
	withVersion := base
	withVersion.PackageVersion = aws.String("3.0.8")
	otherVersion := base
	otherVersion.PackageVersion = aws.String("3.0.9")
	emptyVersion := base
	emptyVersion.PackageVersion = aws.String("")
	otherType := withVersion
	otherType.PackageType = aws.String("library")

	ids := map[string]bool{}
	for _, sw := range []types.SoftwareResult{base, withVersion, otherVersion, emptyVersion, otherType} {
		ids[securityhubSoftwarePackageId("us-east-1", sw)] = true
	}
	assert.Len(t, ids, 5, "name, type and version (absent vs empty) each separate entries")
	assert.NotEqual(t,
		securityhubSoftwarePackageId("us-east-1", withVersion),
		securityhubSoftwarePackageId("eu-west-1", withVersion),
		"the same package read from two regions is two entries")
}

func TestSecurityhubSoftwareResourceArn(t *testing.T) {
	const acct = "111122223333"

	t.Run("bare instance id", func(t *testing.T) {
		// Synthetic: resource id as an instance ID.
		r := softwareResourceRef{resourceId: "i-0abc", resourceType: "AWS::EC2::Instance", resourceRegion: "us-east-1", ownerAccountId: acct, partition: "aws"}
		assert.Equal(t, "arn:aws:ec2:us-east-1:111122223333:instance/i-0abc", securityhubSoftwareResourceArn(r, "AWS::EC2::Instance", acct))
	})

	t.Run("resource id already an ARN", func(t *testing.T) {
		// Synthetic: resource id as an ARN.
		id := "arn:aws:lambda:eu-west-1:111122223333:function:fn"
		r := softwareResourceRef{resourceId: id, resourceType: "AWS::Lambda::Function"}
		assert.Equal(t, id, securityhubSoftwareResourceArn(r, "AWS::Lambda::Function", acct))
	})

	t.Run("bare function name falls back to recording region and account", func(t *testing.T) {
		// Synthetic: no resource region, partition or owner account.
		r := softwareResourceRef{resourceId: "fn", resourceType: "AWS::Lambda::Function", region: "us-west-2", accountId: acct}
		assert.Equal(t, "arn:aws:lambda:us-west-2:111122223333:function:fn", securityhubSoftwareResourceArn(r, "AWS::Lambda::Function", acct))
	})

	t.Run("govcloud partition", func(t *testing.T) {
		// Synthetic: partition carried into the built ARN.
		r := softwareResourceRef{resourceId: "i-1", resourceType: "AWS::EC2::Instance", resourceRegion: "us-gov-west-1", ownerAccountId: acct, partition: "aws-us-gov"}
		assert.Equal(t, "arn:aws-us-gov:ec2:us-gov-west-1:111122223333:instance/i-1", securityhubSoftwareResourceArn(r, "AWS::EC2::Instance", acct))
	})

	t.Run("other type, other account, empty id", func(t *testing.T) {
		// Synthetic: cases that must not resolve.
		lambda := softwareResourceRef{resourceId: "fn", resourceType: "AWS::Lambda::Function", ownerAccountId: acct}
		assert.Equal(t, "", securityhubSoftwareResourceArn(lambda, "AWS::EC2::Instance", acct))
		foreign := softwareResourceRef{resourceId: "i-1", resourceType: "AWS::EC2::Instance", ownerAccountId: "999999999999"}
		assert.Equal(t, "", securityhubSoftwareResourceArn(foreign, "AWS::EC2::Instance", acct))
		foreignArn := softwareResourceRef{resourceId: "arn:aws:ec2:us-east-1:999999999999:instance/i-1", resourceType: "AWS::EC2::Instance"}
		assert.Equal(t, "", securityhubSoftwareResourceArn(foreignArn, "AWS::EC2::Instance", acct))
		empty := softwareResourceRef{resourceType: "AWS::EC2::Instance", ownerAccountId: acct}
		assert.Equal(t, "", securityhubSoftwareResourceArn(empty, "AWS::EC2::Instance", acct))
	})
}

func TestIsSecurityHubV2NotEnabled(t *testing.T) {
	// Measured: DescribeSecurityHubV2 in a region without Security Hub answered
	// ResourceNotFoundException "You are not subscribed to HubV2", 2026-11-05.
	assert.True(t, isSecurityHubV2NotEnabled(fmt.Errorf("op: %w", &types.ResourceNotFoundException{Message: aws.String("You are not subscribed to HubV2")})))
	// Measured: DescribeHub in the same account answered InvalidAccessException, 2026-11-05.
	assert.True(t, isSecurityHubV2NotEnabled(&types.InvalidAccessException{}))
	// Synthetic: an access denial or a transport error is not "not enabled".
	assert.False(t, isSecurityHubV2NotEnabled(&types.AccessDeniedException{}))
	assert.False(t, isSecurityHubV2NotEnabled(errors.New("connection reset")))
	assert.False(t, isSecurityHubV2NotEnabled(nil))
}
