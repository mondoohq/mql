// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/slack-go/slack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/types"
)

func TestSetTeamArgs(t *testing.T) {
	cases := []struct {
		name string
		// Synthetic: team.info responses shaped after the documented response
		// at docs.slack.dev/reference/methods/team.info; no workspace was scanned.
		body                     string
		wantSlackbotAvailability any
	}{
		{
			name:                     "own workspace reports availability",
			body:                     `{"ok":true,"team":{"id":"T123","name":"Example","domain":"example","email_domain":"example.com","slackbot_availability":"restricted"}}`,
			wantSlackbotAvailability: "restricted",
		},
		{
			name:                     "external team omits the field",
			body:                     `{"ok":true,"team":{"id":"T123","name":"Example","domain":"example","email_domain":"example.com"}}`,
			wantSlackbotAvailability: nil,
		},
		{
			name:                     "empty string is treated as absent",
			body:                     `{"ok":true,"team":{"id":"T123","name":"Example","domain":"example","email_domain":"example.com","slackbot_availability":""}}`,
			wantSlackbotAvailability: nil,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var resp slack.TeamResponse
			require.NoError(t, json.Unmarshal([]byte(tc.body), &resp))

			args := map[string]*llx.RawData{}
			setTeamArgs(args, &resp.Team)

			assert.Equal(t, "T123", args["id"].Value)
			assert.Equal(t, "Example", args["name"].Value)
			assert.Equal(t, "example", args["domain"].Value)
			assert.Equal(t, "example.com", args["emailDomain"].Value)

			got := args["slackbotAvailability"]
			require.NotNil(t, got)
			assert.Equal(t, tc.wantSlackbotAvailability, got.Value)
			if tc.wantSlackbotAvailability == nil {
				assert.Equal(t, types.Nil, got.Type)
				tv, ok := plugin.RawToTValue[string](got.Value, got.Error)
				require.True(t, ok)
				assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, tv.State)
			}
		})
	}
}
