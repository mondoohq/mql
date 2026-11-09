// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	ramtypes "github.com/aws/aws-sdk-go-v2/service/ram/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestRamPermissionArgs(t *testing.T) {
	// Synthetic: an AWS managed permission summary as ListResourceSharePermissions
	// returns it.
	p := ramtypes.ResourceSharePermissionSummary{
		Arn:                   aws.String("arn:aws:ram::aws:permission/AWSRAMDefaultPermissionSubnet"),
		Name:                  aws.String("AWSRAMDefaultPermissionSubnet"),
		Version:               aws.String("2"),
		DefaultVersion:        aws.Bool(false),
		IsResourceTypeDefault: aws.Bool(true),
		PermissionType:        ramtypes.PermissionTypeAwsManaged,
		ResourceOwner:         ramtypes.ResourceOwnerSelf,
		FeatureSet:            ramtypes.PermissionFeatureSetStandard,
		Status:                aws.String("ATTACHABLE"),
		ResourceType:          aws.String("ec2:Subnet"),
	}
	shareA := "arn:aws:ram:us-east-1:111111111111:resource-share/a"
	shareB := "arn:aws:ram:us-east-1:111111111111:resource-share/b"

	args := ramPermissionArgs(shareA, "us-east-1", p)
	assert.Equal(t, "AWSRAMDefaultPermissionSubnet", args["name"].Value)
	assert.Equal(t, "2", args["version"].Value)
	assert.Equal(t, false, args["defaultVersion"].Value)
	assert.Equal(t, true, args["isResourceTypeDefault"].Value)
	assert.Equal(t, "AWS_MANAGED", args["permissionType"].Value)
	assert.Equal(t, "SELF", args["resourceOwner"].Value)
	assert.Equal(t, "STANDARD", args["featureSet"].Value)
	assert.Equal(t, "ec2:Subnet", args["resourceType"].Value)
	assert.Equal(t, "us-east-1", args["region"].Value)
	assert.Empty(t, args["templateParameters"].Value)

	// The same permission version on two shares must not share a cache entry,
	// because template parameter values belong to the association.
	assert.NotEqual(t, args["__id"].Value, ramPermissionArgs(shareB, "us-east-1", p)["__id"].Value)
	// Two versions of one permission on the same share are distinct too.
	p3 := p
	p3.Version = aws.String("3")
	assert.NotEqual(t, args["__id"].Value, ramPermissionArgs(shareA, "us-east-1", p3)["__id"].Value)

	// Absent optional booleans stay null instead of reading false.
	p.DefaultVersion = nil
	assert.Nil(t, ramPermissionArgs(shareA, "us-east-1", p)["defaultVersion"].Value)
}

func TestRamTemplateParametersToDicts(t *testing.T) {
	// Synthetic: a template parameter with assigned values.
	got := ramTemplateParametersToDicts([]ramtypes.PermissionTemplateParameter{{
		Name:        aws.String("allowedPrincipals"),
		Description: aws.String("Principals allowed"),
		Type:        ramtypes.PermissionTemplateParameterTypeStringList,
		Values:      []string{"a", "b"},
	}})
	assert.Equal(t, []any{map[string]any{
		"name":        "allowedPrincipals",
		"description": "Principals allowed",
		"type":        "STRING_LIST",
		"values":      []any{"a", "b"},
	}}, got)
}

func TestRamTemplateParameterInputs(t *testing.T) {
	// Synthetic: GetPermission requires a value for every declared parameter.
	full := []ramtypes.PermissionTemplateParameter{
		{Name: aws.String("p1"), Values: []string{"x"}},
		{Name: aws.String("p2"), Values: []string{"y", "z"}},
	}
	got := ramTemplateParameterInputs(full)
	require.Len(t, got, 2)
	assert.Equal(t, "p2", *got[1].Name)
	assert.Equal(t, []string{"y", "z"}, got[1].Values)

	partial := []ramtypes.PermissionTemplateParameter{
		{Name: aws.String("p1"), Values: []string{"x"}},
		{Name: aws.String("p2")},
	}
	assert.Nil(t, ramTemplateParameterInputs(partial))
	assert.Nil(t, ramTemplateParameterInputs(nil))
}

func TestParseRamPermissionVersion(t *testing.T) {
	v := parseRamPermissionVersion("3")
	require.NotNil(t, v)
	assert.Equal(t, int32(3), *v)

	// Synthetic: a version that cannot be sent must not fall back to the
	// default version silently.
	assert.Nil(t, parseRamPermissionVersion(""))
	assert.Nil(t, parseRamPermissionVersion("0"))
	assert.Nil(t, parseRamPermissionVersion("v1"))
}

func TestParseRamPermissionPolicy(t *testing.T) {
	// Measured: `aws ram get-permission` for
	// arn:aws:ram::aws:permission/AWSRAMDefaultPermissionSubnet version 1,
	// 2026-11-09; the Action list is cut to its first two entries.
	got, err := parseRamPermissionPolicy(`{"Effect":"Allow","Action":["ec2:AssignIpv6Address","ec2:AssignPrivateIpAddress"]}`)
	require.NoError(t, err)
	assert.Equal(t, map[string]any{
		"Effect": "Allow",
		"Action": []any{"ec2:AssignIpv6Address", "ec2:AssignPrivateIpAddress"},
	}, got)

	_, err = parseRamPermissionPolicy(`{"Effect":`)
	require.Error(t, err)
	assert.Equal(t, llx.ErrorKind_ERROR_KIND_MALFORMED_DATA, llx.KindOf(err))
}
