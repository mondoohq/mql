// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"
	"time"

	cloudssoclient "github.com/alibabacloud-go/cloudsso-20210515/client"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCloudssoParseTime(t *testing.T) {
	strPtr := func(s string) *string { return &s }

	t.Run("parses an RFC3339 timestamp", func(t *testing.T) {
		got := cloudssoParseTime(strPtr("2021-11-01T02:38:27Z"))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2021, 11, 1, 2, 38, 27, 0, time.UTC), got.UTC())
	})

	t.Run("parses an offset timestamp", func(t *testing.T) {
		got := cloudssoParseTime(strPtr("2021-11-01T10:38:27+08:00"))
		require.NotNil(t, got)
		assert.Equal(t, time.Date(2021, 11, 1, 2, 38, 27, 0, time.UTC), got.UTC())
	})

	// An unparseable value must stay null rather than becoming the zero time,
	// which would render as the year 1 and read as a real timestamp.
	t.Run("nil and unparseable values stay null", func(t *testing.T) {
		assert.Nil(t, cloudssoParseTime(nil))
		assert.Nil(t, cloudssoParseTime(strPtr("")))
		assert.Nil(t, cloudssoParseTime(strPtr("2021-11-01")))
		assert.Nil(t, cloudssoParseTime(strPtr("not a time")))
	})
}

// Synthetic: GetSecurityInfoPreference answers shaped after the API model; no live directory was read.
func TestSecurityEmailSelfService(t *testing.T) {
	allowed := true
	denied := false
	cases := []struct {
		name string
		resp *cloudssoclient.GetSecurityInfoPreferenceResponse
		want bool
	}{
		{"nil response", nil, false},
		{"no body", &cloudssoclient.GetSecurityInfoPreferenceResponse{}, false},
		{"no preference", &cloudssoclient.GetSecurityInfoPreferenceResponse{Body: &cloudssoclient.GetSecurityInfoPreferenceResponseBody{}}, false},
		{"unset defaults to false", &cloudssoclient.GetSecurityInfoPreferenceResponse{Body: &cloudssoclient.GetSecurityInfoPreferenceResponseBody{
			SecurityInfoPreference: &cloudssoclient.GetSecurityInfoPreferenceResponseBodySecurityInfoPreference{},
		}}, false},
		{"allowed", &cloudssoclient.GetSecurityInfoPreferenceResponse{Body: &cloudssoclient.GetSecurityInfoPreferenceResponseBody{
			SecurityInfoPreference: &cloudssoclient.GetSecurityInfoPreferenceResponseBodySecurityInfoPreference{AllowUserManageSecurityEmail: &allowed},
		}}, true},
		{"denied", &cloudssoclient.GetSecurityInfoPreferenceResponse{Body: &cloudssoclient.GetSecurityInfoPreferenceResponseBody{
			SecurityInfoPreference: &cloudssoclient.GetSecurityInfoPreferenceResponseBodySecurityInfoPreference{AllowUserManageSecurityEmail: &denied},
		}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := securityEmailSelfService(tc.resp); got != tc.want {
				t.Fatalf("securityEmailSelfService() = %v, want %v", got, tc.want)
			}
		})
	}
}
