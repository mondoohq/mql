// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	aatypes "github.com/aws/aws-sdk-go-v2/service/accessanalyzer/types"
	cftypes "github.com/aws/aws-sdk-go-v2/service/cloudfront/types"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	waftypes "github.com/aws/aws-sdk-go-v2/service/wafv2/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// TestCloudfrontOriginTls covers the origin leg of a CloudFront distribution.
// The viewer leg can enforce HTTPS while the origin leg runs in plaintext or
// negotiates a deprecated TLS version, so an S3 origin (which carries no custom
// origin config) must not report a protocol policy at all rather than reporting
// one that reads as plaintext.
func TestCloudfrontOriginTls(t *testing.T) {
	tests := []struct {
		name          string
		config        *cftypes.CustomOriginConfig
		wantPolicy    string
		wantProtocols []any
	}{
		{
			name:          "s3 origin has no custom origin config",
			config:        nil,
			wantPolicy:    "",
			wantProtocols: []any{},
		},
		{
			name: "plaintext to origin",
			config: &cftypes.CustomOriginConfig{
				OriginProtocolPolicy: cftypes.OriginProtocolPolicyHttpOnly,
			},
			wantPolicy:    "http-only",
			wantProtocols: []any{},
		},
		{
			name: "match-viewer downgrades with the viewer",
			config: &cftypes.CustomOriginConfig{
				OriginProtocolPolicy: cftypes.OriginProtocolPolicyMatchViewer,
				OriginSslProtocols: &cftypes.OriginSslProtocols{
					Items: []cftypes.SslProtocol{cftypes.SslProtocolTLSv1, cftypes.SslProtocolTLSv12},
				},
			},
			wantPolicy:    "match-viewer",
			wantProtocols: []any{"TLSv1", "TLSv1.2"},
		},
		{
			name: "https-only with modern tls",
			config: &cftypes.CustomOriginConfig{
				OriginProtocolPolicy: cftypes.OriginProtocolPolicyHttpsOnly,
				OriginSslProtocols: &cftypes.OriginSslProtocols{
					Items: []cftypes.SslProtocol{cftypes.SslProtocolTLSv12},
				},
			},
			wantPolicy:    "https-only",
			wantProtocols: []any{"TLSv1.2"},
		},
		{
			name: "protocol list absent on an https origin",
			config: &cftypes.CustomOriginConfig{
				OriginProtocolPolicy: cftypes.OriginProtocolPolicyHttpsOnly,
			},
			wantPolicy:    "https-only",
			wantProtocols: []any{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy, protocols := cloudfrontOriginTls(test.config)
			assert.Equal(t, test.wantPolicy, policy)
			assert.Equal(t, test.wantProtocols, protocols)
			// Never nil: a nil slice would serialize as null and read as
			// "unknown" rather than "no protocols reported".
			assert.NotNil(t, protocols)
		})
	}
}

// TestWafRuleActionString pins the RuleAction union to the same action names
// aws.waf.rule.action uses, so a rule flipped to Count through an override
// reads the same as a rule whose own action is Count.
func TestWafRuleActionString(t *testing.T) {
	tests := []struct {
		name   string
		action *waftypes.RuleAction
		want   string
	}{
		{"nil action", nil, ""},
		{"empty union", &waftypes.RuleAction{}, ""},
		{"allow", &waftypes.RuleAction{Allow: &waftypes.AllowAction{}}, "allow"},
		{"block", &waftypes.RuleAction{Block: &waftypes.BlockAction{}}, "block"},
		{"count", &waftypes.RuleAction{Count: &waftypes.CountAction{}}, "count"},
		{"captcha", &waftypes.RuleAction{Captcha: &waftypes.CaptchaAction{}}, "captcha"},
		{"challenge", &waftypes.RuleAction{Challenge: &waftypes.ChallengeAction{}}, "challenge"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, wafRuleActionString(test.action))
		})
	}
}

// TestWafRuleActionOverridesToMap covers the override map that decides whether
// a managed rule group actually blocks. An override to count leaves the group
// reading as enabled while the overridden rules take no action, so every
// override has to survive into the map.
func TestWafRuleActionOverridesToMap(t *testing.T) {
	t.Run("no overrides yields an empty map", func(t *testing.T) {
		got := wafRuleActionOverridesToMap(nil)
		require.NotNil(t, got)
		assert.Empty(t, got)
	})

	t.Run("overrides keyed by rule name", func(t *testing.T) {
		got := wafRuleActionOverridesToMap([]waftypes.RuleActionOverride{
			{Name: aws.String("SizeRestrictions_BODY"), ActionToUse: &waftypes.RuleAction{Count: &waftypes.CountAction{}}},
			{Name: aws.String("NoUserAgent_HEADER"), ActionToUse: &waftypes.RuleAction{Block: &waftypes.BlockAction{}}},
		})
		assert.Equal(t, map[string]any{
			"SizeRestrictions_BODY": "count",
			"NoUserAgent_HEADER":    "block",
		}, got)
	})

	t.Run("an unnamed override is dropped rather than keyed on empty", func(t *testing.T) {
		got := wafRuleActionOverridesToMap([]waftypes.RuleActionOverride{
			{ActionToUse: &waftypes.RuleAction{Count: &waftypes.CountAction{}}},
		})
		assert.Empty(t, got)
	})

	t.Run("an override with no action reads as empty, not as allow", func(t *testing.T) {
		got := wafRuleActionOverridesToMap([]waftypes.RuleActionOverride{
			{Name: aws.String("SomeRule")},
		})
		assert.Equal(t, map[string]any{"SomeRule": ""}, got)
	})
}

// TestArchiveRuleFilterToDict covers the archive-rule criteria. An absent
// comparison must stay absent: an empty Eq list would read as "matches
// nothing" when the rule actually tests something else entirely.
func TestArchiveRuleFilterToDict(t *testing.T) {
	t.Run("empty filter", func(t *testing.T) {
		got, err := archiveRuleFilterToDict(nil)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("only the comparisons that are set survive", func(t *testing.T) {
		got, err := archiveRuleFilterToDict(map[string]aatypes.Criterion{
			"resource":      {Eq: []string{"arn:aws:s3:::example"}},
			"isPublic":      {Exists: aws.Bool(true)},
			"principal.AWS": {Contains: []string{"123"}, Neq: []string{"456"}},
		})
		require.NoError(t, err)

		assert.Equal(t, map[string]any{"Eq": []any{"arn:aws:s3:::example"}}, got["resource"])
		assert.Equal(t, map[string]any{"Exists": true}, got["isPublic"])
		assert.Equal(t, map[string]any{
			"Contains": []any{"123"},
			"Neq":      []any{"456"},
		}, got["principal.AWS"])
	})

	t.Run("a false Exists is reported, not dropped", func(t *testing.T) {
		got, err := archiveRuleFilterToDict(map[string]aatypes.Criterion{
			"error": {Exists: aws.Bool(false)},
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{"Exists": false}, got["error"])
	})

	t.Run("a criterion with nothing set yields an empty dict", func(t *testing.T) {
		got, err := archiveRuleFilterToDict(map[string]aatypes.Criterion{"resource": {}})
		require.NoError(t, err)
		assert.Equal(t, map[string]any{}, got["resource"])
	})
}

// TestOpensearchDomainIsPublicInVpc covers the VPC short-circuit on the
// OpenSearch domain. A VPC domain has no publicly resolvable endpoint, so it is
// unreachable from the internet no matter what its access policy says, and the
// check must not fall through to reading the policy.
func TestOpensearchDomainIsPublicInVpc(t *testing.T) {
	domain := &mqlAwsOpensearchDomain{}
	domain.cacheVpcId = "vpc-0123456789abcdef0"
	// PolicyStatements is deliberately left unset: reaching it would mean the
	// VPC short-circuit did not fire.
	got, err := domain.isPublic()
	require.NoError(t, err)
	assert.False(t, got)
}

// TestElbListenerCertificateAcmResolution covers the certificate reference on a
// listener certificate. A listener can present an IAM server certificate, which
// ACM does not know about; resolving one would build a blank certificate whose
// every field reads null, so it has to resolve to an explicit null instead.
func TestElbListenerCertificateAcmResolution(t *testing.T) {
	for _, arn := range []string{
		"arn:aws:iam::123456789012:server-certificate/example",
		"",
	} {
		cert := &mqlAwsElbListenerCertificate{}
		cert.Arn = plugin.TValue[string]{Data: arn, State: plugin.StateIsSet}
		got, err := cert.acmCertificate()
		require.NoError(t, err)
		require.Nil(t, got)
		assert.True(t, cert.AcmCertificate.IsNull())
		assert.True(t, cert.AcmCertificate.IsSet())
	}
}

// TestS3ObjectLockRetentionWithoutConfig covers the default-retention fields on
// a bucket that has no Object Lock configuration to read. They must resolve to
// null rather than to a zero-day COMPLIANCE retention, which would report a
// bucket with no WORM protection as having the strongest kind.
func TestS3ObjectLockRetentionWithoutConfig(t *testing.T) {
	newBucket := func() *mqlAwsS3Bucket {
		bucket := &mqlAwsS3Bucket{}
		// A placeholder bucket short-circuits fetchObjectLockConfig before it
		// reaches the API, which is the no-configuration case.
		bucket.Exists = plugin.TValue[bool]{Data: false, State: plugin.StateIsSet}
		return bucket
	}

	bucket := newBucket()
	mode, err := bucket.objectLockRetentionMode()
	require.NoError(t, err)
	assert.Equal(t, "", mode)
	assert.True(t, bucket.ObjectLockRetentionMode.IsNull())

	bucket = newBucket()
	days, err := bucket.objectLockRetentionDays()
	require.NoError(t, err)
	assert.Equal(t, int64(0), days)
	assert.True(t, bucket.ObjectLockRetentionDays.IsNull())

	bucket = newBucket()
	years, err := bucket.objectLockRetentionYears()
	require.NoError(t, err)
	assert.Equal(t, int64(0), years)
	assert.True(t, bucket.ObjectLockRetentionYears.IsNull())
}

// TestS3DefaultObjectLockRetention covers the retention rule lookup itself:
// Object Lock can be enabled with no default retention rule at all, in which
// case objects are protected only when the writer sets retention on each PUT.
func TestS3DefaultObjectLockRetention(t *testing.T) {
	tests := []struct {
		name   string
		config *s3types.ObjectLockConfiguration
		want   *s3types.DefaultRetention
	}{
		{
			name:   "object lock not configured",
			config: nil,
		},
		{
			name:   "enabled with no rule",
			config: &s3types.ObjectLockConfiguration{ObjectLockEnabled: s3types.ObjectLockEnabledEnabled},
		},
		{
			name: "rule with no default retention",
			config: &s3types.ObjectLockConfiguration{
				ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
				Rule:              &s3types.ObjectLockRule{},
			},
		},
		{
			name: "compliance retention in years",
			config: &s3types.ObjectLockConfiguration{
				ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
				Rule: &s3types.ObjectLockRule{
					DefaultRetention: &s3types.DefaultRetention{
						Mode:  s3types.ObjectLockRetentionModeCompliance,
						Years: aws.Int32(7),
					},
				},
			},
			want: &s3types.DefaultRetention{
				Mode:  s3types.ObjectLockRetentionModeCompliance,
				Years: aws.Int32(7),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			bucket := &mqlAwsS3Bucket{}
			bucket.Exists = plugin.TValue[bool]{Data: true, State: plugin.StateIsSet}
			bucket.objectLockConfig = test.config
			// Mark the once as already run so no API call is attempted.
			bucket.objectLockOnce.Do(func() {})

			got, err := bucket.defaultObjectLockRetention()
			require.NoError(t, err)
			if test.want == nil {
				assert.Nil(t, got)
				return
			}
			require.NotNil(t, got)
			assert.Equal(t, test.want.Mode, got.Mode)
			assert.Equal(t, test.want.Years, got.Years)
			assert.Equal(t, test.want.Days, got.Days)
		})
	}
}

// TestS3ObjectLockRetentionValues covers the split between a day-expressed and
// a year-expressed retention period. Exactly one of the two is set, and the
// other must read null rather than zero so a seven-year hold does not also
// report as a zero-day one.
func TestS3ObjectLockRetentionValues(t *testing.T) {
	newBucket := func(retention *s3types.DefaultRetention) *mqlAwsS3Bucket {
		bucket := &mqlAwsS3Bucket{}
		bucket.Exists = plugin.TValue[bool]{Data: true, State: plugin.StateIsSet}
		bucket.objectLockConfig = &s3types.ObjectLockConfiguration{
			ObjectLockEnabled: s3types.ObjectLockEnabledEnabled,
			Rule:              &s3types.ObjectLockRule{DefaultRetention: retention},
		}
		bucket.objectLockOnce.Do(func() {})
		return bucket
	}

	t.Run("governance retention in days", func(t *testing.T) {
		retention := &s3types.DefaultRetention{
			Mode: s3types.ObjectLockRetentionModeGovernance,
			Days: aws.Int32(30),
		}

		bucket := newBucket(retention)
		mode, err := bucket.objectLockRetentionMode()
		require.NoError(t, err)
		assert.Equal(t, "GOVERNANCE", mode)
		assert.False(t, bucket.ObjectLockRetentionMode.IsNull())

		bucket = newBucket(retention)
		days, err := bucket.objectLockRetentionDays()
		require.NoError(t, err)
		assert.Equal(t, int64(30), days)

		bucket = newBucket(retention)
		years, err := bucket.objectLockRetentionYears()
		require.NoError(t, err)
		assert.Equal(t, int64(0), years)
		assert.True(t, bucket.ObjectLockRetentionYears.IsNull(), "an unset year period must not read as zero years")
	})

	t.Run("compliance retention in years", func(t *testing.T) {
		retention := &s3types.DefaultRetention{
			Mode:  s3types.ObjectLockRetentionModeCompliance,
			Years: aws.Int32(7),
		}

		bucket := newBucket(retention)
		mode, err := bucket.objectLockRetentionMode()
		require.NoError(t, err)
		assert.Equal(t, "COMPLIANCE", mode)

		bucket = newBucket(retention)
		years, err := bucket.objectLockRetentionYears()
		require.NoError(t, err)
		assert.Equal(t, int64(7), years)

		bucket = newBucket(retention)
		days, err := bucket.objectLockRetentionDays()
		require.NoError(t, err)
		assert.Equal(t, int64(0), days)
		assert.True(t, bucket.ObjectLockRetentionDays.IsNull(), "an unset day period must not read as zero days")
	})
}
