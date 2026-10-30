// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	autoscalingtypes "github.com/aws/aws-sdk-go-v2/service/autoscaling/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"time"
)

func TestAutoscalingGroupServiceLinkedRole(t *testing.T) {
	t.Run("empty arn sets null state", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		result, err := g.serviceLinkedRole()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, g.ServiceLinkedRole.IsNull())
		assert.True(t, g.ServiceLinkedRole.IsSet())
	})
}

func TestAutoscalingGroupLaunchTemplate(t *testing.T) {
	t.Run("empty arn sets null state", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		result, err := g.launchTemplate()
		require.NoError(t, err)
		require.Nil(t, result)
		assert.True(t, g.LaunchTemplate.IsNull())
		assert.True(t, g.LaunchTemplate.IsSet())
	})
}

func TestAutoscalingGroupSubnets(t *testing.T) {
	t.Run("no subnet ids returns empty slice", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		result, err := g.subnets()
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

func TestPopulateAutoscalingGroupInternals(t *testing.T) {
	region := "us-east-1"
	accountID := "111122223333"

	t.Run("populates launch template arn from id", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		group := autoscalingtypes.AutoScalingGroup{
			LaunchTemplate: &autoscalingtypes.LaunchTemplateSpecification{
				LaunchTemplateId:   aws.String("lt-0123456789abcdef0"),
				LaunchTemplateName: aws.String("my-template"),
				Version:            aws.String("2"),
			},
		}
		populateAutoscalingGroupInternals(g, group, region, accountID)
		assert.Equal(t, "lt-0123456789abcdef0", g.cacheLaunchTemplateId)
		assert.Equal(t, "my-template", g.cacheLaunchTemplateName)
		assert.Equal(t, "arn:aws:ec2:us-east-1:111122223333:launch-template/lt-0123456789abcdef0", g.cacheLaunchTemplateArn)
	})

	t.Run("nil launch template leaves cache empty", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		populateAutoscalingGroupInternals(g, autoscalingtypes.AutoScalingGroup{}, region, accountID)
		assert.Empty(t, g.cacheLaunchTemplateArn)
	})

	t.Run("parses comma-separated VPCZoneIdentifier", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		group := autoscalingtypes.AutoScalingGroup{
			VPCZoneIdentifier: aws.String("subnet-aaa, subnet-bbb,subnet-ccc"),
		}
		populateAutoscalingGroupInternals(g, group, region, accountID)
		assert.Equal(t, []string{"subnet-aaa", "subnet-bbb", "subnet-ccc"}, g.cacheSubnetIds)
	})

	t.Run("empty VPCZoneIdentifier produces no subnet ids", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		group := autoscalingtypes.AutoScalingGroup{
			VPCZoneIdentifier: aws.String("  "),
		}
		populateAutoscalingGroupInternals(g, group, region, accountID)
		assert.Empty(t, g.cacheSubnetIds)
	})

	t.Run("nil VPCZoneIdentifier produces no subnet ids", func(t *testing.T) {
		g := &mqlAwsAutoscalingGroup{}
		populateAutoscalingGroupInternals(g, autoscalingtypes.AutoScalingGroup{}, region, accountID)
		assert.Empty(t, g.cacheSubnetIds)
	})
}

func TestAutoscalingAccountSettingArgs(t *testing.T) {
	// Measured: aws autoscaling describe-account-settings, us-east-1, 2026-10-23.
	// The setting has enforcement type none, so the enforcement values are absent.
	t.Run("setting without enforcement", func(t *testing.T) {
		args := autoscalingAccountSettingArgs("us-east-1", autoscalingtypes.AccountSetting{
			Name:            aws.String("launchBeforeTerminate"),
			Value:           aws.String("disabled"),
			EnforcementType: aws.String("none"),
		})
		assert.Equal(t, "us-east-1/launchBeforeTerminate", args["__id"].Value)
		assert.Equal(t, "launchBeforeTerminate", args["name"].Value)
		assert.Equal(t, "disabled", args["value"].Value)
		assert.Equal(t, "none", args["enforcementType"].Value)
		assert.Same(t, llx.NilData, args["enforcementDate"])
		assert.Same(t, llx.NilData, args["defaultValue"])
		assert.Same(t, llx.NilData, args["enforcedValue"])
	})
	// Synthetic: a phased-in setting with hard enforcement; no target showed this.
	t.Run("setting with enforcement", func(t *testing.T) {
		when := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
		args := autoscalingAccountSettingArgs("eu-west-1", autoscalingtypes.AccountSetting{
			Name:            aws.String("exampleSetting"),
			Value:           aws.String("enabled"),
			EnforcementType: aws.String("hard"),
			EnforcementDate: &when,
			DefaultValue:    aws.String("disabled"),
			EnforcedValue:   aws.String("enabled"),
		})
		assert.Equal(t, "eu-west-1/exampleSetting", args["__id"].Value)
		assert.Equal(t, &when, args["enforcementDate"].Value)
		assert.Equal(t, "disabled", args["defaultValue"].Value)
		assert.Equal(t, "enabled", args["enforcedValue"].Value)
	})
}
