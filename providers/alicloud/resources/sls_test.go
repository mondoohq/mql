// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"testing"

	tea "github.com/alibabacloud-go/tea/tea"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSlsPolicyAbsent covers the classifier that decides whether a failed
// GetProjectPolicy means "no policy attached" or "the read failed". Matching a
// transport error would report a project whose policy was never read as not
// public, so the negative cases carry the weight here.
func TestSlsPolicyAbsent(t *testing.T) {
	sdkErr := func(status int) error {
		return &tea.SDKError{
			Code:       new("ProjectPolicyNotExist"),
			StatusCode: new(status),
			Message:    new("policy not found"),
		}
	}

	t.Run("404 means no policy attached", func(t *testing.T) {
		assert.True(t, slsPolicyAbsent(sdkErr(404)))
	})
	t.Run("wrapped 404 is still matched", func(t *testing.T) {
		assert.True(t, slsPolicyAbsent(fmt.Errorf("get project policy: %w", sdkErr(404))))
	})
	t.Run("403 is a real failure", func(t *testing.T) {
		assert.False(t, slsPolicyAbsent(sdkErr(403)))
	})
	t.Run("500 is a real failure", func(t *testing.T) {
		assert.False(t, slsPolicyAbsent(sdkErr(500)))
	})
	t.Run("transport error is not matched", func(t *testing.T) {
		assert.False(t, slsPolicyAbsent(errors.New("dial tcp: i/o timeout")))
	})
	t.Run("SDK error without a status is not matched", func(t *testing.T) {
		assert.False(t, slsPolicyAbsent(&tea.SDKError{Code: new("Throttling")}))
	})
}

// TestLogProjectPolicyIsPublic covers the SLS project policy shapes through the
// shared policy parser. SLS writes Principal as a bare array rather than the
// keyed object a RAM trust policy uses, so this pins that the shared parser
// reaches the same verdict on the SLS envelope.
func TestLogProjectPolicyIsPublic(t *testing.T) {
	tests := []struct {
		name string
		doc  string
		want bool
	}{
		{
			name: "no policy attached",
			doc:  "",
			want: false,
		},
		{
			name: "wildcard principal in a bare array",
			doc: `{"Version":"1","Statement":[{"Action":["log:GetLogStoreLogs"],
			      "Resource":"acs:log:*:*:project/audit/logstore/*","Effect":"Allow",
			      "Principal":["*"]}]}`,
			want: true,
		},
		{
			name: "wildcard principal as a lone string",
			doc: `{"Version":"1","Statement":{"Action":"log:*",
			      "Resource":"acs:log:*:*:project/audit/*","Effect":"Allow","Principal":"*"}}`,
			want: true,
		},
		{
			name: "named account principal",
			doc: `{"Version":"1","Statement":[{"Action":["log:GetLogStoreLogs"],
			      "Resource":"acs:log:*:*:project/audit/logstore/*","Effect":"Allow",
			      "Principal":["acs:ram::100931896542:root"]}]}`,
			want: false,
		},
		{
			name: "wildcard principal that is denied",
			doc: `{"Version":"1","Statement":[{"Action":["log:*"],
			      "Resource":"acs:log:*:*:project/audit/*","Effect":"Deny","Principal":["*"]}]}`,
			want: false,
		},
		{
			name: "no principal at all",
			doc: `{"Version":"1","Statement":[{"Action":["log:*"],
			      "Resource":"acs:log:*:*:project/audit/*","Effect":"Allow"}]}`,
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			statements, err := parsePolicyDocument(tt.doc)
			require.NoError(t, err)
			assert.Equal(t, tt.want, policyGrantsAnonymousAccess(statements))
		})
	}
}
