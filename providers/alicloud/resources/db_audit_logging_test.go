// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	rkvclient "github.com/alibabacloud-go/r-kvstore-20150101/v8/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisAuditEnabled(t *testing.T) {
	// the API returns this member as a string, not a boolean
	assert.True(t, redisAuditEnabled(new("true")))
	assert.True(t, redisAuditEnabled(new("True")))
	assert.True(t, redisAuditEnabled(new(" true ")))
	assert.False(t, redisAuditEnabled(new("false")))
	// an instance nobody could read must fail an "auditing is on" check, not
	// pass it
	assert.False(t, redisAuditEnabled(nil))
	assert.False(t, redisAuditEnabled(new("")))
	assert.False(t, redisAuditEnabled(new("1")))
}

func TestRedisAuditRetentionDays(t *testing.T) {
	tests := []struct {
		name      string
		retention *string
		expected  int64
	}{
		{"typical", new("30"), 30},
		{"whitespace tolerated", new(" 365 "), 365},
		{"zero", new("0"), 0},
		// an unusable value must fail a minimum-retention check rather than
		// satisfy it
		{"absent", nil, 0},
		{"empty", new(""), 0},
		{"unparseable", new("thirty"), 0},
		{"negative", new("-1"), 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, redisAuditRetentionDays(test.retention))
		})
	}
}

func TestPolardbAuditCollecting(t *testing.T) {
	assert.True(t, polardbAuditCollecting(new("Enable")))
	assert.True(t, polardbAuditCollecting(new("enable")))
	// transitional states are not yet recording
	assert.False(t, polardbAuditCollecting(new("Enabling")))
	assert.False(t, polardbAuditCollecting(new("Disabling")))
	assert.False(t, polardbAuditCollecting(new("Disable")))
	assert.False(t, polardbAuditCollecting(nil))
	assert.False(t, polardbAuditCollecting(new("")))
}

// TestRedisAuditConfigDecode pins the struct tags the two Redis fields depend
// on. Both members are strings on the wire, so a mistyped tag would silently
// report an audited instance as unaudited.
func TestRedisAuditConfigDecode(t *testing.T) {
	var body rkvclient.DescribeAuditLogConfigResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{"DbAudit":"true","Retention":"30"}`), &body))

	assert.True(t, redisAuditEnabled(body.DbAudit))
	assert.Equal(t, int64(30), redisAuditRetentionDays(body.Retention))

	var empty rkvclient.DescribeAuditLogConfigResponseBody
	require.NoError(t, json.Unmarshal([]byte(`{}`), &empty))
	assert.False(t, redisAuditEnabled(empty.DbAudit))
	assert.Equal(t, int64(0), redisAuditRetentionDays(empty.Retention))
}
