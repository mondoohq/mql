// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestParseOssBucketArn covers the OSS delivery-target parser that decides
// whether a Cloud Config delivery channel resolves to a bucket. A parsing bug
// makes the ossBucket reference silently null, which reads as "this channel
// does not deliver to OSS".
func TestParseOssBucketArn(t *testing.T) {
	tests := []struct {
		name string
		arn  string
		want string
	}{
		{"bare bucket", "acs:oss:cn-shanghai:100931896542:audit-logs", "audit-logs"},
		{"bucket with prefix", "acs:oss:cn-shanghai:100931896542:audit-logs/config/", "audit-logs"},
		{"empty account field", "acs:oss:cn-hangzhou::audit-logs", "audit-logs"},
		{"empty string", "", ""},
		{"another service", "acs:log:cn-shanghai:100931896542:project/p", ""},
		{"truncated arn", "acs:oss:cn-shanghai:100931896542", ""},
		{"not an arn", "audit-logs", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, parseOssBucketArn(tt.arn))
		})
	}
}

// TestParseSlsLogstoreArn covers the Log Service delivery-target parser. The
// project-only ARN case matters: a delivery channel names a logstore, and
// accepting a project-only ARN would build a logstore reference with an empty
// name.
func TestParseSlsLogstoreArn(t *testing.T) {
	tests := []struct {
		name                              string
		arn                               string
		wantRegion, wantProject, wantName string
	}{
		{
			name:        "well-formed arn",
			arn:         "acs:log:cn-hangzhou:100931896542:project/audit-project/logstore/config-store",
			wantRegion:  "cn-hangzhou",
			wantProject: "audit-project",
			wantName:    "config-store",
		},
		{"project only", "acs:log:cn-hangzhou:100931896542:project/audit-project", "", "", ""},
		{"empty logstore", "acs:log:cn-hangzhou:1009:project/audit-project/logstore/", "", "", ""},
		{"empty project", "acs:log:cn-hangzhou:1009:project//logstore/config-store", "", "", ""},
		{"empty string", "", "", "", ""},
		{"another service", "acs:oss:cn-hangzhou:1009:audit-logs", "", "", ""},
		{"truncated arn", "acs:log:cn-hangzhou:1009", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			region, project, name := parseSlsLogstoreArn(tt.arn)
			assert.Equal(t, tt.wantRegion, region)
			assert.Equal(t, tt.wantProject, project)
			assert.Equal(t, tt.wantName, name)
		})
	}
}

// TestConfigNextToken covers the token-pagination guard. The repeated-token case
// is the one that matters: an endpoint that echoes its cursor back would
// otherwise re-request the same page until the agent count cap, multiplying
// every record it returns.
func TestConfigNextToken(t *testing.T) {
	t.Run("first page hands out a token", func(t *testing.T) {
		next, more := configNextToken("", "page-2")
		assert.True(t, more)
		assert.Equal(t, "page-2", next)
	})
	t.Run("empty token ends the walk", func(t *testing.T) {
		next, more := configNextToken("page-2", "")
		assert.False(t, more)
		assert.Equal(t, "", next)
	})
	t.Run("repeated token ends the walk", func(t *testing.T) {
		next, more := configNextToken("page-2", "page-2")
		assert.False(t, more)
		assert.Equal(t, "", next)
	})
	t.Run("distinct token continues the walk", func(t *testing.T) {
		next, more := configNextToken("page-2", "page-3")
		assert.True(t, more)
		assert.Equal(t, "page-3", next)
	})
}
