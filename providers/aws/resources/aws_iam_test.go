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
)

// TestIamPolicyCacheKeysAreDistinct is the regression test for the deleted
// mqlAwsIamPolicy.id(). CreateResource keys the runtime cache on
// name + "\x00" + MqlID() and returns the *cached* instance on a hit, so a
// resource with no id() and no explicit __id gave every IAM policy in a scan
// the empty key -- and every one after the first resolved to the first one's
// data. A wildcard-Allow check then inspected a single arbitrary policy.
//
// This goes through CreateResource rather than asserting the id() formula
// directly: the previous SageMaker tests asserted the formula and passed while
// production ids were all empty.
func TestIamPolicyCacheKeysAreDistinct(t *testing.T) {
	runtime := testRuntime()

	first, err := CreateResource(runtime, "aws.iam.policy", map[string]*llx.RawData{
		"arn": llx.StringData("arn:aws:iam::111111111111:policy/first"),
	})
	require.NoError(t, err)

	second, err := CreateResource(runtime, "aws.iam.policy", map[string]*llx.RawData{
		"arn": llx.StringData("arn:aws:iam::111111111111:policy/second"),
	})
	require.NoError(t, err)

	assert.NotEmpty(t, first.MqlID(), "policy must have a non-empty cache key")
	assert.NotEqual(t, first.MqlID(), second.MqlID(), "two policies must not share a cache key")

	// The second call must return the second policy, not the cached first one.
	require.NotSame(t, first, second)
	assert.Equal(t, "arn:aws:iam::111111111111:policy/second",
		second.(*mqlAwsIamPolicy).Arn.Data)
}

// TestIamLoginProfileCacheKeysAreDistinct covers the login profile, whose id
// method was named `init` -- a name the code generator never registers -- so
// __id stayed empty and every user reported the first user's console-password
// profile. Keying on the creation timestamp would also collide for users
// created within the same second.
func TestIamLoginProfileCacheKeysAreDistinct(t *testing.T) {
	runtime := testRuntime()

	alice, err := CreateResource(runtime, "aws.iam.loginProfile", map[string]*llx.RawData{
		"__id":                  llx.StringData("arn:aws:iam::111111111111:user/alice/loginProfile"),
		"passwordResetRequired": llx.BoolData(true),
	})
	require.NoError(t, err)

	bob, err := CreateResource(runtime, "aws.iam.loginProfile", map[string]*llx.RawData{
		"__id":                  llx.StringData("arn:aws:iam::111111111111:user/bob/loginProfile"),
		"passwordResetRequired": llx.BoolData(false),
	})
	require.NoError(t, err)

	assert.NotEqual(t, alice.MqlID(), bob.MqlID())
	assert.True(t, alice.(*mqlAwsIamLoginProfile).PasswordResetRequired.Data)
	assert.False(t, bob.(*mqlAwsIamLoginProfile).PasswordResetRequired.Data)
}

// TestIsServiceLinkedRolePath pins the one signal IAM gives for a
// service-linked role. roles() derived it inline while initAwsIamRole did not
// set the field at all, so a role reached through the init reported null --
// and since that init-built resource is cached under the role ARN, a query
// touching aws.iam.role(...) degraded isServiceLinked to null for
// aws.iam.roles in the same scan.
func TestIsServiceLinkedRolePath(t *testing.T) {
	for _, tc := range []struct {
		name string
		path string
		want bool
	}{
		{"service-linked", "/aws-service-role/", true},
		{"service-linked with service", "/aws-service-role/elasticbeanstalk.amazonaws.com/", true},
		{"plain role", "/", false},
		{"customer path", "/my-team/", false},
		{"empty path", "", false},
		// A customer-chosen path that merely mentions the segment is not
		// service-linked: IAM only treats the leading prefix as the signal.
		{"prefix not at start", "/team/aws-service-role/", false},
		// The trailing slash in the prefix is load-bearing: a customer path that
		// merely starts with the same characters must not be reported as
		// service-linked.
		{"similar prefix", "/aws-service-role-ish/", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, isServiceLinkedRolePath(tc.path))
		})
	}
}

func TestVirtualMfaDeviceArgsUserArn(t *testing.T) {
	enabled := time.Date(2023, 1, 8, 9, 25, 27, 0, time.UTC)

	t.Run("assigned to root", func(t *testing.T) {
		// Root device: ListVirtualMFADevices reports the root user by ARN with no
		// UserName. Account ID and serial number are placeholders.
		args := virtualMfaDeviceArgs(iamtypes.VirtualMFADevice{
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/authenticator"),
			EnableDate:   aws.Time(enabled),
			User:         &iamtypes.User{Arn: aws.String("arn:aws:iam::123456789012:root")},
		})
		assert.Equal(t, "arn:aws:iam::123456789012:root", args["userArn"].Value)
	})

	t.Run("assigned to an IAM user", func(t *testing.T) {
		// IAM user device: the response carries both the ARN and the UserName.
		// Account ID and names are placeholders.
		args := virtualMfaDeviceArgs(iamtypes.VirtualMFADevice{
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/alice"),
			EnableDate:   aws.Time(enabled),
			User: &iamtypes.User{
				Arn:      aws.String("arn:aws:iam::123456789012:user/alice"),
				UserName: aws.String("alice"),
			},
		})
		assert.Equal(t, "arn:aws:iam::123456789012:user/alice", args["userArn"].Value)
	})

	t.Run("unassigned", func(t *testing.T) {
		// A device created but never enabled has no User. Placeholder serial number.
		args := virtualMfaDeviceArgs(iamtypes.VirtualMFADevice{
			SerialNumber: aws.String("arn:aws:iam::123456789012:mfa/spare"),
		})
		assert.Nil(t, args["userArn"].Value)
	})
}

// Synthetic: SAML key hash entries; no target showed this.
func TestSamlKeyHashesToMap(t *testing.T) {
	t.Run("hashes are grouped by issuer", func(t *testing.T) {
		got := samlKeyHashesToMap([]iamtypes.SAMLKeyHashEntry{
			{IssuerURL: aws.String("https://idp-a.example.com"), KeyHashes: []string{"h1", "h2"}},
			{IssuerURL: aws.String("https://idp-b.example.com"), KeyHashes: []string{"h3"}},
			{IssuerURL: aws.String("https://idp-a.example.com"), KeyHashes: []string{"h4"}},
		})
		assert.Equal(t, map[string]any{
			"https://idp-a.example.com": []any{"h1", "h2", "h4"},
			"https://idp-b.example.com": []any{"h3"},
		}, got)
	})

	t.Run("no entries is an empty map", func(t *testing.T) {
		assert.Empty(t, samlKeyHashesToMap(nil))
	})
}

// Synthetic: context provider key definitions; no target showed this.
func TestContextProviderKeyMappings(t *testing.T) {
	got := contextProviderKeyMappings([]iamtypes.ContextProviderKeyDefinition{
		{SourceKey: aws.String("email"), TargetKey: aws.String("user_email")},
		{SourceKey: aws.String("dept")},
		{TargetKey: aws.String("orphan")},
	})
	assert.Equal(t, map[string]any{
		"email": "user_email",
		"dept":  "",
	}, got)
}
