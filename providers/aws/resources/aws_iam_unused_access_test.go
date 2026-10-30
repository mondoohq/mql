// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUnusedAccessDetails(t *testing.T) {
	lastAccessed := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	t.Run("unused permission", func(t *testing.T) {
		got := parseUnusedAccessDetails([]aatypes.FindingDetails{
			&aatypes.FindingDetailsMemberUnusedPermissionDetails{
				Value: aatypes.UnusedPermissionDetails{
					ServiceNamespace: aws.String("s3"),
					LastAccessed:     &lastAccessed,
					Actions: []aatypes.UnusedAction{
						{Action: aws.String("s3:DeleteBucket")},
						{Action: aws.String("s3:PutBucketPolicy")},
					},
				},
			},
		})
		assert.Equal(t, &lastAccessed, got.lastAccessed)
		assert.Equal(t, "s3", got.serviceNamespace)
		assert.Equal(t, []any{"s3:DeleteBucket", "s3:PutBucketPolicy"}, got.actions)
		assert.Empty(t, got.accessKeyId)
	})

	t.Run("unused role", func(t *testing.T) {
		got := parseUnusedAccessDetails([]aatypes.FindingDetails{
			&aatypes.FindingDetailsMemberUnusedIamRoleDetails{
				Value: aatypes.UnusedIamRoleDetails{LastAccessed: &lastAccessed},
			},
		})
		assert.Equal(t, &lastAccessed, got.lastAccessed)
		assert.Empty(t, got.serviceNamespace)
		assert.Empty(t, got.actions)
	})

	t.Run("unused access key", func(t *testing.T) {
		got := parseUnusedAccessDetails([]aatypes.FindingDetails{
			&aatypes.FindingDetailsMemberUnusedIamUserAccessKeyDetails{
				Value: aatypes.UnusedIamUserAccessKeyDetails{
					AccessKeyId:  aws.String("AKIAEXAMPLE"),
					LastAccessed: &lastAccessed,
				},
			},
		})
		assert.Equal(t, "AKIAEXAMPLE", got.accessKeyId)
		assert.Equal(t, &lastAccessed, got.lastAccessed)
	})

	t.Run("unused password", func(t *testing.T) {
		got := parseUnusedAccessDetails([]aatypes.FindingDetails{
			&aatypes.FindingDetailsMemberUnusedIamUserPasswordDetails{
				Value: aatypes.UnusedIamUserPasswordDetails{LastAccessed: &lastAccessed},
			},
		})
		assert.Equal(t, &lastAccessed, got.lastAccessed)
	})

	// A role or key that was never used at all reports no last-accessed time,
	// which must stay null rather than becoming a zero timestamp.
	t.Run("never used leaves the time null", func(t *testing.T) {
		got := parseUnusedAccessDetails([]aatypes.FindingDetails{
			&aatypes.FindingDetailsMemberUnusedIamRoleDetails{
				Value: aatypes.UnusedIamRoleDetails{},
			},
		})
		assert.Nil(t, got.lastAccessed)
	})

	t.Run("external access detail carries no unused data", func(t *testing.T) {
		got := parseUnusedAccessDetails([]aatypes.FindingDetails{
			&aatypes.FindingDetailsMemberExternalAccessDetails{
				Value: aatypes.ExternalAccessDetails{
					Action:    []string{"s3:GetObject"},
					IsPublic:  aws.Bool(true),
					Condition: map[string]string{},
				},
			},
		})
		assert.Nil(t, got.lastAccessed)
		assert.Empty(t, got.serviceNamespace)
		assert.Empty(t, got.actions)
		assert.Empty(t, got.accessKeyId)
	})

	t.Run("no details", func(t *testing.T) {
		got := parseUnusedAccessDetails(nil)
		assert.Nil(t, got.lastAccessed)
		assert.Empty(t, got.actions)
	})
}

// A finding that is not an unused-access finding must resolve its unused fields
// without an API call, which this exercises by leaving the runtime unset — any
// attempt to reach the connection would panic.
func TestUnusedAccessFieldsSkipNonUnusedFindings(t *testing.T) {
	finding := &mqlAwsIamAccessAnalyzerFinding{
		Id:     setString("finding-1"),
		Type:   setString("ExternalAccessGranted"),
		Region: setString("us-east-1"),
	}

	lastAccessed, err := finding.lastAccessedAt()
	require.NoError(t, err)
	assert.Nil(t, lastAccessed)

	namespace, err := finding.unusedServiceNamespace()
	require.NoError(t, err)
	assert.Empty(t, namespace)

	actions, err := finding.unusedActions()
	require.NoError(t, err)
	assert.Equal(t, []any{}, actions)

	accessKeyId, err := finding.unusedAccessKeyId()
	require.NoError(t, err)
	assert.Empty(t, accessKeyId)
}

func TestJobErrorDetails(t *testing.T) {
	assert.Equal(t, "no reason reported", jobErrorDetails(nil))
	assert.Equal(t, "service not supported (SERVICE_ERROR)", jobErrorDetails(&iamtypes.ErrorDetails{
		Message: aws.String("service not supported"),
		Code:    aws.String("SERVICE_ERROR"),
	}))
}
