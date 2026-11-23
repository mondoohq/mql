// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// originMtlsClientCertificate returns null when no client cert ARN was extracted
// from the origin's CustomOriginConfig (i.e. origin mTLS isn't configured).
func TestCloudfrontOriginMtlsClientCertificateNullWhenCacheEmpty(t *testing.T) {
	o := &mqlAwsCloudfrontDistributionOrigin{}
	got, err := o.originMtlsClientCertificate()
	require.NoError(t, err)
	assert.Nil(t, got)
	assert.True(t, o.OriginMtlsClientCertificate.IsNull())
	assert.True(t, o.OriginMtlsClientCertificate.IsSet())
}

func TestS3BucketFromOriginDomain(t *testing.T) {
	cases := []struct {
		domain string
		want   string
	}{
		// Measured: origin domain Terraform's bucket_regional_domain_name produced for an S3 origin with OAC, us-west-2, 2026-11-23.
		{"mqlv-te-cf-f96b4356bc33b6cd1915bd0af7.s3.us-west-2.amazonaws.com", "mqlv-te-cf-f96b4356bc33b6cd1915bd0af7"},
		// Synthetic: the virtual-hosted REST endpoint forms CloudFront accepts for an S3 origin.
		{"my-bucket.s3.amazonaws.com", "my-bucket"},
		{"my-bucket.s3.us-west-2.amazonaws.com", "my-bucket"},
		{"my-bucket.s3-us-west-2.amazonaws.com", "my-bucket"},
		{"my-bucket.s3.dualstack.us-west-2.amazonaws.com", "my-bucket"},
		// Synthetic: bucket names may contain dots; the bucket ends at the S3 label.
		{"assets.example.com.s3.eu-central-1.amazonaws.com", "assets.example.com"},
		// Synthetic: static website endpoints, configured as custom origins.
		{"site-bucket.s3-website-us-east-1.amazonaws.com", "site-bucket"},
		{"site-bucket.s3-website.eu-west-1.amazonaws.com", "site-bucket"},
		// Synthetic: China partition and a trailing dot.
		{"cn-bucket.s3.cn-north-1.amazonaws.com.cn", "cn-bucket"},
		{"My-Bucket.s3.amazonaws.com.", "my-bucket"},
		// Synthetic: hosts that are not buckets.
		{"ap-123456789012.s3-accesspoint.us-west-2.amazonaws.com", ""},
		{"olap-alias.s3-object-lambda.us-west-2.amazonaws.com", ""},
		{"dir--usw2-az1--x-s3.s3express-usw2-az1.us-west-2.amazonaws.com", ""},
		{"api.example.com", ""},
		{"abc123.execute-api.us-east-1.amazonaws.com", ""},
		{"s3.amazonaws.com", ""},
		{"", ""},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, s3BucketFromOriginDomain(c.domain), c.domain)
	}
}

func TestCloudfrontCertificateSource(t *testing.T) {
	// Synthetic: the three mutually exclusive certificate fields.
	assert.Equal(t, "acm", cloudfrontCertificateSource(&cftypes.ViewerCertificate{ACMCertificateArn: aws.String("arn:aws:acm:us-east-1:123456789012:certificate/abc")}))
	assert.Equal(t, "iam", cloudfrontCertificateSource(&cftypes.ViewerCertificate{IAMCertificateId: aws.String("ASCAEXAMPLE")}))
	assert.Equal(t, "cloudfront", cloudfrontCertificateSource(&cftypes.ViewerCertificate{CloudFrontDefaultCertificate: aws.Bool(true)}))
	assert.Equal(t, "", cloudfrontCertificateSource(&cftypes.ViewerCertificate{CloudFrontDefaultCertificate: aws.Bool(false)}))
	assert.Equal(t, "", cloudfrontCertificateSource(nil))
}

// Synthetic: origin HTTP version on S3 and custom origins; no target showed this.
func TestCloudfrontOriginHttpVersion(t *testing.T) {
	assert.Nil(t, cloudfrontOriginHttpVersion(nil), "S3 origin")
	assert.Nil(t, cloudfrontOriginHttpVersion(&cftypes.CustomOriginConfig{}), "custom origin with no version set")
	got := cloudfrontOriginHttpVersion(&cftypes.CustomOriginConfig{OriginHttpVersion: cftypes.OriginHttpVersionHttp2})
	require.NotNil(t, got)
	assert.Equal(t, "http2", *got)
}
