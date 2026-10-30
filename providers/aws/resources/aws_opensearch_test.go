// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	opensearch_types "github.com/aws/aws-sdk-go-v2/service/opensearch/types"
	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
)

func TestParseAuditLogEnabled(t *testing.T) {
	t.Run("nil map returns false", func(t *testing.T) {
		assert.False(t, parseAuditLogEnabled(nil))
	})

	t.Run("empty map returns false", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{}
		assert.False(t, parseAuditLogEnabled(opts))
	})

	t.Run("map without AUDIT_LOGS key returns false", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"INDEX_SLOW_LOGS": {Enabled: convert.ToPtr(true)},
		}
		assert.False(t, parseAuditLogEnabled(opts))
	})

	t.Run("AUDIT_LOGS with nil Enabled returns false", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"AUDIT_LOGS": {Enabled: nil},
		}
		assert.False(t, parseAuditLogEnabled(opts))
	})

	t.Run("AUDIT_LOGS with Enabled false returns false", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"AUDIT_LOGS": {Enabled: convert.ToPtr(false)},
		}
		assert.False(t, parseAuditLogEnabled(opts))
	})

	t.Run("AUDIT_LOGS with Enabled true returns true", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"AUDIT_LOGS": {Enabled: convert.ToPtr(true)},
		}
		assert.True(t, parseAuditLogEnabled(opts))
	})
}

// TestParseLogPublishingOption verifies that each log type is read by its own
// key and that the CloudWatch log group ARN comes back alongside the enabled
// flag. A disabled log type still names the log group it would publish to, so
// the ARN must not be suppressed when publishing is off.
func TestParseLogPublishingOption(t *testing.T) {
	arn := "arn:aws:logs:us-east-1:123456789012:log-group:/aws/opensearch/audit"

	t.Run("nil options read as disabled with no log group", func(t *testing.T) {
		enabled, group := parseLogPublishingOption(nil, "AUDIT_LOGS")
		assert.False(t, enabled)
		assert.Nil(t, group)
	})

	t.Run("log type absent reads as disabled with no log group", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"AUDIT_LOGS": {Enabled: convert.ToPtr(true), CloudWatchLogsLogGroupArn: &arn},
		}
		enabled, group := parseLogPublishingOption(opts, "INDEX_SLOW_LOGS")
		assert.False(t, enabled)
		assert.Nil(t, group)
	})

	t.Run("enabled log type returns its log group", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"SEARCH_SLOW_LOGS": {Enabled: convert.ToPtr(true), CloudWatchLogsLogGroupArn: &arn},
		}
		enabled, group := parseLogPublishingOption(opts, "SEARCH_SLOW_LOGS")
		assert.True(t, enabled)
		assert.Equal(t, arn, *group)
	})

	t.Run("disabled log type still names its log group", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"ES_APPLICATION_LOGS": {Enabled: convert.ToPtr(false), CloudWatchLogsLogGroupArn: &arn},
		}
		enabled, group := parseLogPublishingOption(opts, "ES_APPLICATION_LOGS")
		assert.False(t, enabled)
		assert.Equal(t, arn, *group)
	})

	t.Run("absent Enabled reads as disabled", func(t *testing.T) {
		opts := map[string]opensearch_types.LogPublishingOption{
			"AUDIT_LOGS": {CloudWatchLogsLogGroupArn: &arn},
		}
		enabled, _ := parseLogPublishingOption(opts, "AUDIT_LOGS")
		assert.False(t, enabled)
	})

	t.Run("log types do not read each other's values", func(t *testing.T) {
		auditArn := "arn:aws:logs:us-east-1:123456789012:log-group:/audit"
		indexArn := "arn:aws:logs:us-east-1:123456789012:log-group:/index-slow"
		opts := map[string]opensearch_types.LogPublishingOption{
			"AUDIT_LOGS":       {Enabled: convert.ToPtr(true), CloudWatchLogsLogGroupArn: &auditArn},
			"INDEX_SLOW_LOGS":  {Enabled: convert.ToPtr(false), CloudWatchLogsLogGroupArn: &indexArn},
			"SEARCH_SLOW_LOGS": {Enabled: convert.ToPtr(true)},
		}

		enabled, group := parseLogPublishingOption(opts, "AUDIT_LOGS")
		assert.True(t, enabled)
		assert.Equal(t, auditArn, *group)

		enabled, group = parseLogPublishingOption(opts, "INDEX_SLOW_LOGS")
		assert.False(t, enabled)
		assert.Equal(t, indexArn, *group)

		enabled, group = parseLogPublishingOption(opts, "SEARCH_SLOW_LOGS")
		assert.True(t, enabled)
		assert.Nil(t, group)
	})
}
