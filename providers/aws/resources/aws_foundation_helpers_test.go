// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestExtractFilterPatternValues(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		field   string
		want    []string
	}{
		{
			name:    "quoted event source",
			pattern: `{ ($.eventSource = "organizations.amazonaws.com") }`,
			field:   "eventSource",
			want:    []string{"organizations.amazonaws.com"},
		},
		{
			name:    "unquoted no spaces",
			pattern: `($.eventName=DeleteGroupPolicy)||($.eventName=PutGroupPolicy)`,
			field:   "eventName",
			want:    []string{"DeleteGroupPolicy", "PutGroupPolicy"},
		},
		{
			name:    "unquoted with spaces",
			pattern: `($.eventName = CreateVpc) || ($.eventName = DeleteVpc)`,
			field:   "eventName",
			want:    []string{"CreateVpc", "DeleteVpc"},
		},
		{
			name:    "inequality is excluded",
			pattern: `($.errorCode = "AccessDenied*") && ($.eventName != "HeadBucket")`,
			field:   "eventName",
			want:    []string{},
		},
		{
			name:    "errorCode with wildcard value",
			pattern: `($.errorCode = "*UnauthorizedOperation") || ($.errorCode = "AccessDenied*")`,
			field:   "errorCode",
			want:    []string{"*UnauthorizedOperation", "AccessDenied*"},
		},
		{
			name:    "dotted field name",
			pattern: `$.userIdentity.type = "Root" && $.eventType != "AwsServiceEvent"`,
			field:   "userIdentity.type",
			want:    []string{"Root"},
		},
		{
			name:    "deduplicates repeats",
			pattern: `($.eventName = StopLogging) || ($.eventName = StopLogging)`,
			field:   "eventName",
			want:    []string{"StopLogging"},
		},
		{
			name:    "no match",
			pattern: `($.eventName = ConsoleLogin)`,
			field:   "eventSource",
			want:    []string{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, extractFilterPatternValues(filterPatternValueRe(tc.field), tc.pattern))
		})
	}
}

func TestIsActiveSubscriptionArn(t *testing.T) {
	assert.True(t, isActiveSubscriptionArn("arn:aws:sns:us-east-1:123456789012:topic:uuid"))
	assert.False(t, isActiveSubscriptionArn(""))
	assert.False(t, isActiveSubscriptionArn("PendingConfirmation"))
	assert.False(t, isActiveSubscriptionArn("Deleted"))
}

func TestAnyStringEquals(t *testing.T) {
	assert.True(t, anyStringEquals([]any{"10.0.0.0/8", "0.0.0.0/0"}, "0.0.0.0/0"))
	assert.False(t, anyStringEquals([]any{"10.0.0.0/8"}, "0.0.0.0/0"))
	assert.False(t, anyStringEquals([]any{}, "0.0.0.0/0"))
}

func TestIpPermissionIncludesPublicSource(t *testing.T) {
	mk := func(ipv4, ipv6 []any) *mqlAwsEc2SecuritygroupIppermission {
		p := &mqlAwsEc2SecuritygroupIppermission{}
		p.IpRanges = plugin.TValue[[]any]{Data: ipv4, State: plugin.StateIsSet}
		p.Ipv6Ranges = plugin.TValue[[]any]{Data: ipv6, State: plugin.StateIsSet}
		// Pre-resolve the prefix-list field so includesPublicSource does not lazily
		// compute it, which would dereference a runtime this synthetic resource does
		// not have. The CIDR cases below never reference a prefix list.
		p.PrefixLists = plugin.TValue[[]any]{Data: []any{}, State: plugin.StateIsSet}
		return p
	}

	t.Run("public ipv4", func(t *testing.T) {
		got, err := mk([]any{"0.0.0.0/0"}, nil).includesPublicSource()
		require.NoError(t, err)
		assert.True(t, got)
	})
	t.Run("public ipv6", func(t *testing.T) {
		got, err := mk([]any{"10.0.0.0/8"}, []any{"::/0"}).includesPublicSource()
		require.NoError(t, err)
		assert.True(t, got)
	})
	t.Run("private only", func(t *testing.T) {
		got, err := mk([]any{"10.0.0.0/8", "192.168.0.0/16"}, []any{"2001:db8::/32"}).includesPublicSource()
		require.NoError(t, err)
		assert.False(t, got)
	})
}

func TestHasWildcardPrincipal(t *testing.T) {
	assert.True(t, hasWildcardPrincipal(map[string]any{"AWS": []any{"*"}}))
	assert.True(t, hasWildcardPrincipal(map[string]any{"Service": []any{"s3.amazonaws.com", "*"}}))
	assert.False(t, hasWildcardPrincipal(map[string]any{"AWS": []any{"arn:aws:iam::123456789012:root"}}))
	assert.False(t, hasWildcardPrincipal(nil))
}

func TestHasSourceScopingCondition(t *testing.T) {
	tests := []struct {
		name       string
		conditions any
		want       bool
	}{
		{
			name:       "scoped by source account",
			conditions: map[string]any{"StringEquals": map[string]any{"aws:SourceAccount": "123456789012"}},
			want:       true,
		},
		{
			name:       "scoped by source arn (case-insensitive key)",
			conditions: map[string]any{"ArnLike": map[string]any{"AWS:SourceArn": "arn:aws:s3:::bucket"}},
			want:       true,
		},
		{
			name:       "wildcard scoping value does not count",
			conditions: map[string]any{"StringEquals": map[string]any{"aws:SourceArn": "*"}},
			want:       false,
		},
		{
			name:       "wildcard in list value does not count",
			conditions: map[string]any{"StringEquals": map[string]any{"aws:PrincipalOrgID": []any{"*"}}},
			want:       false,
		},
		{
			name:       "unrelated condition key",
			conditions: map[string]any{"StringEquals": map[string]any{"aws:Region": "us-east-1"}},
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
			assert.Equal(t, tc.want, hasSourceScopingCondition(tc.conditions))
		})
	}
}

// TestIsRestrictingConditionOperator pins which IAM condition operators narrow
// a grant. Negated forms and Null widen it: StringNotEquals on
// aws:PrincipalOrgID means "allow everyone OUTSIDE my org" and Null means
// "allow principals for which the key is absent", both strictly worse than an
// unconditional public grant.
func TestIsRestrictingConditionOperator(t *testing.T) {
	restricting := []string{
		"StringEquals", "stringequals", "StringLike", "StringEqualsIgnoreCase",
		"ArnEquals", "ArnLike",
		"StringEqualsIfExists", "ForAnyValue:StringEquals", "ForAllValues:StringLike",
	}
	for _, op := range restricting {
		assert.True(t, isRestrictingConditionOperator(op), "expected %q to restrict", op)
	}

	widening := []string{
		"StringNotEquals", "StringNotLike", "ArnNotEquals", "ArnNotLike",
		"Null", "NotIpAddress", "DateLessThan", "Bool",
	}
	for _, op := range widening {
		assert.False(t, isRestrictingConditionOperator(op), "expected %q not to restrict", op)
	}
}

// TestHasSourceScopingConditionOperators covers the operator gate and the
// widened scoping-key set. Before the gate, a negated operator on a scoping key
// read as "scoped" and the resource reported not-public.
func TestHasSourceScopingConditionOperators(t *testing.T) {
	cond := func(op, key, val string) any {
		return map[string]any{op: map[string]any{key: val}}
	}

	t.Run("restricting operators scope the grant", func(t *testing.T) {
		assert.True(t, hasSourceScopingCondition(cond("StringEquals", "aws:PrincipalOrgID", "o-myorg")))
		assert.True(t, hasSourceScopingCondition(cond("ArnLike", "aws:SourceArn", "arn:aws:sns:us-east-1:1:t")))
		assert.True(t, hasSourceScopingCondition(cond("StringEquals", "aws:SourceAccount", "111111111111")))
		assert.True(t, hasSourceScopingCondition(cond("StringEquals", "aws:SourceOwner", "111111111111")))
	})

	t.Run("newly recognized scoping keys", func(t *testing.T) {
		// the shape AWS's own service-linked KMS grants carry
		assert.True(t, hasSourceScopingCondition(cond("StringEquals", "kms:CallerAccount", "111111111111")))
		assert.True(t, hasSourceScopingCondition(cond("StringEquals", "aws:SourceVpce", "vpce-123")))
		assert.True(t, hasSourceScopingCondition(cond("StringEquals", "aws:PrincipalAccount", "111111111111")))
	})

	t.Run("negated and Null operators do not scope", func(t *testing.T) {
		assert.False(t, hasSourceScopingCondition(cond("StringNotEquals", "aws:PrincipalOrgID", "o-myorg")))
		assert.False(t, hasSourceScopingCondition(cond("ArnNotLike", "aws:SourceArn", "arn:aws:sns:us-east-1:1:t")))
		assert.False(t, hasSourceScopingCondition(cond("Null", "aws:PrincipalOrgID", "true")))
	})

	t.Run("wildcard values and unrelated keys do not scope", func(t *testing.T) {
		assert.False(t, hasSourceScopingCondition(cond("StringEquals", "aws:SourceArn", "*")))
		assert.False(t, hasSourceScopingCondition(cond("StringEquals", "s3:x-amz-acl", "public-read")))
		assert.False(t, hasSourceScopingCondition(nil))
		assert.False(t, hasSourceScopingCondition("not-a-map"))
	})
}
