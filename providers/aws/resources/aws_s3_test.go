// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"errors"
	nethttp "net/http"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers/aws/resources/awspolicy"
)

func TestS3BucketArnValidation(t *testing.T) {
	tests := []struct {
		name   string
		arnStr string
		valid  bool
	}{
		{"standard partition", "arn:aws:s3:::my-bucket", true},
		{"govcloud partition", "arn:aws-us-gov:s3:::my-bucket", true},
		{"china partition", "arn:aws-cn:s3:::my-bucket", true},
		{"wrong service", "arn:aws:ec2:us-east-1:123456789012:instance/i-1234", false},
		{"not an ARN", "not-an-arn", false},
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := arn.Parse(tt.arnStr)
			isValidS3 := err == nil && parsed.Service == "s3"
			assert.Equal(t, tt.valid, isValidS3)
		})
	}
}

// s3HTTPError builds an S3-style error carrying an HTTP status code, mirroring
// what the SDK surfaces for GetBucketLogging / GetBucketPolicyStatus etc.
func s3HTTPError(code int, apiErr error) error {
	return &smithyhttp.ResponseError{
		Response: &smithyhttp.Response{Response: &nethttp.Response{StatusCode: code}},
		Err:      apiErr,
	}
}

// TestIsS3BucketInaccessible guards the cross-account regression: a CloudTrail
// organization trail references a log bucket owned by the management account, so
// a member-account scan must treat the resulting 403 (and a deleted-bucket 404)
// as "no data" rather than failing the check, while genuine errors still surface.
func TestIsS3BucketInaccessible(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"nil error", nil, false},
		{"cross-account 403 AccessDenied", s3HTTPError(403, &smithy.GenericAPIError{Code: "AccessDenied", Message: "Access Denied"}), true},
		{"bare 403 forbidden", s3HTTPError(403, &smithy.GenericAPIError{Code: "Forbidden"}), true},
		{"deleted bucket 404", s3HTTPError(404, &smithy.GenericAPIError{Code: "NoSuchBucket"}), true},
		{"typed NotFound", &s3types.NotFound{}, true},
		{"transient 500", s3HTTPError(500, &smithy.GenericAPIError{Code: "InternalError"}), false},
		{"unrelated error", errors.New("boom"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isS3BucketInaccessible(tt.err))
		})
	}
}

// pabConfig builds a Block Public Access configuration with all four flags set.
func pabConfig(blockAcls, blockPolicy, ignoreAcls, restrictBuckets bool) *s3types.PublicAccessBlockConfiguration {
	return &s3types.PublicAccessBlockConfiguration{
		BlockPublicAcls:       aws.Bool(blockAcls),
		BlockPublicPolicy:     aws.Bool(blockPolicy),
		IgnorePublicAcls:      aws.Bool(ignoreAcls),
		RestrictPublicBuckets: aws.Bool(restrictBuckets),
	}
}

// TestS3BucketIsPublic pins AWS's actual Block Public Access semantics.
// BlockPublicAcls and BlockPublicPolicy only reject *new* public grants, so
// they must not suppress one that already exists; only IgnorePublicAcls and
// RestrictPublicBuckets neutralize existing ACL and policy grants respectively.
// Treating any of the four as "not public" reported the standard
// static-site/CDN bucket (blockPublicAcls on, `Principal: "*"` policy) private.
func TestS3BucketIsPublic(t *testing.T) {
	tests := []struct {
		name           string
		pab            *s3types.PublicAccessBlockConfiguration
		policyIsPublic bool
		aclIsPublic    bool
		want           bool
	}{
		{"no pab, nothing public", nil, false, false, false},
		{"no pab, public policy", nil, true, false, true},
		{"no pab, public acl", nil, false, true, true},

		{"blockPublicAcls on, public policy still public", pabConfig(true, false, false, false), true, false, true},
		{"blockPublicPolicy on, public policy still public", pabConfig(false, true, false, false), true, false, true},
		{"blockPublicAcls+ignorePublicAcls on, public policy still public", pabConfig(true, false, true, false), true, false, true},
		{"blockPublicAcls on, public acl still public", pabConfig(true, false, false, false), false, true, true},

		{"restrictPublicBuckets suppresses a public policy", pabConfig(false, false, false, true), true, false, false},
		{"ignorePublicAcls suppresses a public acl", pabConfig(false, false, true, false), false, true, false},

		{"restrictPublicBuckets does not suppress a public acl", pabConfig(false, false, false, true), false, true, true},
		{"ignorePublicAcls does not suppress a public policy", pabConfig(false, false, true, false), true, false, true},

		{"all four on", pabConfig(true, true, true, true), true, true, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, s3BucketIsPublic(tt.pab, tt.policyIsPublic, tt.aclIsPublic))
		})
	}
}

func TestS3GrantsArePublic(t *testing.T) {
	group := func(uri string) s3types.Grant {
		return s3types.Grant{Grantee: &s3types.Grantee{Type: s3types.TypeGroup, URI: aws.String(uri)}}
	}
	assert.False(t, s3GrantsArePublic(nil))
	assert.False(t, s3GrantsArePublic([]s3types.Grant{{Grantee: nil}}))
	assert.False(t, s3GrantsArePublic([]s3types.Grant{group("http://acs.amazonaws.com/groups/s3/LogDelivery")}))
	assert.True(t, s3GrantsArePublic([]s3types.Grant{group(s3AllUsersGroup)}))
	assert.True(t, s3GrantsArePublic([]s3types.Grant{group(s3AuthenticatedUsersGroup)}))
	assert.False(t, s3GrantsArePublic([]s3types.Grant{
		{Grantee: &s3types.Grantee{Type: s3types.TypeCanonicalUser, ID: aws.String("abc")}},
	}))
}

func TestS3PolicyGrantsPublicAccess(t *testing.T) {
	parse := func(t *testing.T, doc string) *awspolicy.S3BucketPolicy {
		t.Helper()
		var p awspolicy.S3BucketPolicy
		require.NoError(t, json.Unmarshal([]byte(doc), &p))
		return &p
	}

	assert.False(t, s3PolicyGrantsPublicAccess(nil))

	assert.True(t, s3PolicyGrantsPublicAccess(parse(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)))

	assert.False(t, s3PolicyGrantsPublicAccess(parse(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)))

	// a wildcard principal under Deny is not a public grant
	assert.False(t, s3PolicyGrantsPublicAccess(parse(t, `{"Version":"2012-10-17","Statement":[
		{"Effect":"Deny","Principal":{"AWS":"*"},"Action":"s3:*","Resource":"arn:aws:s3:::b/*"}]}`)))
}
