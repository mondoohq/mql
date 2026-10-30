// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	iamtypes "github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestAnyWildcardResource(t *testing.T) {
	assert.True(t, anyWildcardResource([]any{"arn:aws:s3:::bucket", "*"}))

	// A service namespace wildcard names every resource of that kind in the
	// account - every bucket, every secret - which is as broad as `*` within
	// the service. This is the same `:*` test anyWildcardAction applies.
	assert.True(t, anyWildcardResource([]any{"arn:aws:s3:::*"}))
	assert.True(t, anyWildcardResource([]any{"arn:aws:secretsmanager:us-east-1:000000000000:secret:*"}))
	assert.True(t, anyWildcardResource([]any{"arn:aws:s3:::bucket", "arn:aws:s3:::*"}))

	// An ARN that wildcards the account as well as the resource is broader
	// still, not narrower, so it matches for the same reason.
	assert.True(t, anyWildcardResource([]any{"arn:aws:iam::*:*"}))

	// A path wildcard under a named resource is every object in one bucket,
	// which is scoped to that bucket and is what a correct bucket policy looks
	// like.
	assert.False(t, anyWildcardResource([]any{"arn:aws:s3:::bucket/*"}))
	assert.False(t, anyWildcardResource([]any{"arn:aws:s3:::bucket"}))
	assert.False(t, anyWildcardResource([]any{}))
	assert.False(t, anyWildcardResource([]any{42}))
}

func TestAnyWildcardAction(t *testing.T) {
	tests := []struct {
		name    string
		actions []any
		want    bool
	}{
		{"global wildcard", []any{"s3:GetObject", "*"}, true},
		{"service-wide wildcard", []any{"s3:*"}, true},
		{"other service-wide wildcard", []any{"ec2:DescribeInstances", "iam:*"}, true},
		{"no wildcard", []any{"s3:GetObject", "s3:PutObject"}, false},
		{"prefix wildcard is not service-wide", []any{"s3:Get*"}, false},
		{"empty", []any{}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, anyWildcardAction(tc.actions))
		})
	}
}

func TestConditionDeniesInsecureTransport(t *testing.T) {
	tests := []struct {
		name       string
		conditions any
		want       bool
	}{
		{
			name:       "string false",
			conditions: map[string]any{"Bool": map[string]any{"aws:SecureTransport": "false"}},
			want:       true,
		},
		{
			name:       "bool false",
			conditions: map[string]any{"Bool": map[string]any{"aws:SecureTransport": false}},
			want:       true,
		},
		{
			name:       "list with false",
			conditions: map[string]any{"Bool": map[string]any{"aws:SecureTransport": []any{"false"}}},
			want:       true,
		},
		{
			name:       "case-insensitive operator and key",
			conditions: map[string]any{"bool": map[string]any{"AWS:SecureTransport": "false"}},
			want:       true,
		},
		{
			name:       "value true does not match",
			conditions: map[string]any{"Bool": map[string]any{"aws:SecureTransport": "true"}},
			want:       false,
		},
		{
			name:       "different condition key",
			conditions: map[string]any{"Bool": map[string]any{"aws:MultiFactorAuthPresent": "false"}},
			want:       false,
		},
		{
			name:       "different operator",
			conditions: map[string]any{"StringEquals": map[string]any{"aws:SecureTransport": "false"}},
			want:       false,
		},
		{
			name:       "nil",
			conditions: nil,
			want:       false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, conditionDeniesInsecureTransport(tc.conditions))
		})
	}
}

func TestCidrEntryIsPublic(t *testing.T) {
	assert.True(t, cidrEntryIsPublic("0.0.0.0/0", ""))
	assert.True(t, cidrEntryIsPublic("", "::/0"))
	assert.False(t, cidrEntryIsPublic("10.0.0.0/8", ""))
	assert.False(t, cidrEntryIsPublic("", "2001:db8::/32"))
}

func TestIsCredentialReportPlaceholder(t *testing.T) {
	for _, v := range []string{"", "N/A", "no_information", "not_supported"} {
		assert.True(t, isCredentialReportPlaceholder(v), v)
	}
	assert.False(t, isCredentialReportPlaceholder("2020-01-01T00:00:00Z"))
}

func TestDaysSince(t *testing.T) {
	assert.Equal(t, int64(0), daysSince(time.Now().Add(48*time.Hour))) // future clamps to 0
	assert.GreaterOrEqual(t, daysSince(time.Now().Add(-72*time.Hour)), int64(2))
}

func credentialEntry(props map[string]any) *mqlAwsIamUsercredentialreportentry {
	e := &mqlAwsIamUsercredentialreportentry{}
	e.Properties = plugin.TValue[map[string]any]{Data: props, State: plugin.StateIsSet}
	return e
}

func TestCredentialReportIsRoot(t *testing.T) {
	root, err := credentialEntry(map[string]any{"user": "<root_account>"}).isRoot()
	require.NoError(t, err)
	assert.True(t, root)

	user, err := credentialEntry(map[string]any{"user": "alice"}).isRoot()
	require.NoError(t, err)
	assert.False(t, user)
}

func TestPasswordInactiveDays(t *testing.T) {
	t.Run("uses last-used date", func(t *testing.T) {
		e := credentialEntry(map[string]any{
			"password_enabled":   "true",
			"password_last_used": "2020-01-01T00:00:00Z",
			"user_creation_time": "2019-01-01T00:00:00Z",
		})
		days, err := e.passwordInactiveDays()
		require.NoError(t, err)
		ref, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
		assert.Equal(t, daysSince(ref), days)
	})

	t.Run("never used falls back to creation time", func(t *testing.T) {
		e := credentialEntry(map[string]any{
			"password_enabled":   "true",
			"password_last_used": "no_information",
			"user_creation_time": "2020-01-01T00:00:00Z",
		})
		days, err := e.passwordInactiveDays()
		require.NoError(t, err)
		ref, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
		assert.Equal(t, daysSince(ref), days)
	})

	t.Run("disabled password is null", func(t *testing.T) {
		e := credentialEntry(map[string]any{"password_enabled": "false"})
		_, err := e.passwordInactiveDays()
		require.NoError(t, err)
		assert.True(t, e.PasswordInactiveDays.IsNull())
		assert.True(t, e.PasswordInactiveDays.IsSet())
	})
}

func TestAccessKeyInactiveDays(t *testing.T) {
	t.Run("uses last-used date", func(t *testing.T) {
		e := credentialEntry(map[string]any{
			"access_key_1_active":         "true",
			"access_key_1_last_used_date": "2021-06-01T00:00:00Z",
			"access_key_1_last_rotated":   "2020-01-01T00:00:00Z",
		})
		days, err := e.accessKey1InactiveDays()
		require.NoError(t, err)
		ref, _ := time.Parse(time.RFC3339, "2021-06-01T00:00:00Z")
		assert.Equal(t, daysSince(ref), days)
	})

	t.Run("never used falls back to rotation time", func(t *testing.T) {
		e := credentialEntry(map[string]any{
			"access_key_2_active":         "true",
			"access_key_2_last_used_date": "N/A",
			"access_key_2_last_rotated":   "2020-01-01T00:00:00Z",
		})
		days, err := e.accessKey2InactiveDays()
		require.NoError(t, err)
		ref, _ := time.Parse(time.RFC3339, "2020-01-01T00:00:00Z")
		assert.Equal(t, daysSince(ref), days)
	})

	t.Run("inactive key is null", func(t *testing.T) {
		e := credentialEntry(map[string]any{"access_key_1_active": "false"})
		_, err := e.accessKey1InactiveDays()
		require.NoError(t, err)
		assert.True(t, e.AccessKey1InactiveDays.IsNull())
		assert.True(t, e.AccessKey1InactiveDays.IsSet())
	})
}

func TestPasswordPolicyData(t *testing.T) {
	t.Run("no policy configured", func(t *testing.T) {
		args := passwordPolicyData("123456789012", nil)
		assert.Equal(t, "aws.iam.passwordPolicy/123456789012", args["__id"].Value)
		assert.Equal(t, false, args["exists"].Value)
		for _, field := range []string{
			"minimumPasswordLength", "requireUppercaseCharacters", "requireLowercaseCharacters",
			"requireSymbols", "requireNumbers", "passwordReusePrevention", "maxPasswordAge",
			"expirePasswords", "hardExpiry", "allowUsersToChangePassword",
		} {
			assert.Same(t, llx.NilData, args[field], field)
		}
	})

	t.Run("populated policy", func(t *testing.T) {
		pp := &iamtypes.PasswordPolicy{
			RequireUppercaseCharacters: true,
			RequireLowercaseCharacters: false,
			RequireSymbols:             true,
			RequireNumbers:             true,
			ExpirePasswords:            true,
			AllowUsersToChangePassword: true,
			MinimumPasswordLength:      aws.Int32(14),
			PasswordReusePrevention:    aws.Int32(24),
			MaxPasswordAge:             nil, // unset -> null
			HardExpiry:                 aws.Bool(false),
		}
		args := passwordPolicyData("123456789012", pp)
		assert.Equal(t, true, args["exists"].Value)
		assert.Equal(t, true, args["requireUppercaseCharacters"].Value)
		assert.Equal(t, false, args["requireLowercaseCharacters"].Value)
		assert.Equal(t, true, args["requireSymbols"].Value)
		assert.Equal(t, int64(14), args["minimumPasswordLength"].Value)
		assert.Equal(t, int64(24), args["passwordReusePrevention"].Value)
		assert.Equal(t, false, args["hardExpiry"].Value)
		// optional settings the policy leaves unset are null, not zero
		assert.Same(t, llx.NilData, args["maxPasswordAge"])
	})
}
