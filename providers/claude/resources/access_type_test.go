// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/anthropics/anthropic-sdk-go/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// access_type is optional on the user profile payload. An absent value has to
// report null: an empty string would read as a third access type that is
// neither application nor passthrough, and a query filtering on either would
// silently exclude the profile without saying why.
func TestClaudeAccessType(t *testing.T) {
	for _, tc := range []struct {
		name     string
		in       anthropic.UserProfileAccessType
		wantNil  bool
		wantData string
	}{
		{name: "absent", in: "", wantNil: true},
		{
			name:     "application",
			in:       anthropic.UserProfileAccessTypeApplication,
			wantData: "application",
		},
		{
			name:     "passthrough",
			in:       anthropic.UserProfileAccessTypePassthrough,
			wantData: "passthrough",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := claudeAccessType(tc.in)
			require.NotNil(t, got)

			if tc.wantNil {
				assert.Nil(t, got.Value, "an absent access type must report null, not an empty string")
				return
			}
			assert.Equal(t, tc.wantData, got.Value)
		})
	}
}
