// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	rsstypes "github.com/aws/aws-sdk-go-v2/service/redshiftserverless/types"
	"github.com/stretchr/testify/assert"
)

func TestRedshiftServerlessIamRoleArns(t *testing.T) {
	got := redshiftServerlessIamRoleArns([]string{
		"IamRole(applyStatus=in-sync, iamRoleArn=arn:aws:iam::123456789012:role/rs-copy)",
		"arn:aws:iam::123456789012:role/plain",
		"IamRole(iamRoleArn=arn:aws:iam::123456789012:role/path/nested, applyStatus=adding)",
		"garbage",
	})
	assert.Equal(t, []string{
		"arn:aws:iam::123456789012:role/rs-copy",
		"arn:aws:iam::123456789012:role/plain",
		"arn:aws:iam::123456789012:role/path/nested",
	}, got)
	assert.Empty(t, redshiftServerlessIamRoleArns(nil))
}

func TestRedshiftServerlessKmsKeyRef(t *testing.T) {
	assert.Nil(t, redshiftServerlessKmsKeyRef(aws.String("AWS_OWNED_KMS_KEY")))
	assert.Nil(t, redshiftServerlessKmsKeyRef(aws.String("")))
	assert.Nil(t, redshiftServerlessKmsKeyRef(nil))
	assert.Equal(t, "1234abcd-12ab", *redshiftServerlessKmsKeyRef(aws.String("1234abcd-12ab")))
}

func TestRedshiftServerlessConfigParameters(t *testing.T) {
	got := redshiftServerlessConfigParameters([]rsstypes.ConfigParameter{
		{ParameterKey: aws.String("require_ssl"), ParameterValue: aws.String("true")},
		{ParameterKey: aws.String("enable_user_activity_logging"), ParameterValue: aws.String("false")},
		{ParameterKey: nil, ParameterValue: aws.String("orphan")},
		{ParameterKey: aws.String("search_path"), ParameterValue: nil},
	})
	assert.Equal(t, map[string]any{
		"require_ssl":                  "true",
		"enable_user_activity_logging": "false",
		"search_path":                  "",
	}, got)
}
