// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fetchCopilotBilling serves body from GET /orgs/{org}/copilot/billing and
// returns what getCopilotOrgBilling decodes from it.
func fetchCopilotBilling(t *testing.T, body string) *copilotOrgBilling {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasSuffix(r.URL.Path, "/orgs/acme/copilot/billing"), r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)

	details, err := getCopilotOrgBilling(context.Background(), newTestGithubClient(t, srv), "acme")
	require.NoError(t, err)
	require.NotNil(t, details)
	return details
}

func TestCopilotOrgBilling_Measured(t *testing.T) {
	// Measured: GitHub REST API GET /orgs/{org}/copilot/billing on a Copilot
	// Business organization, 2026-10-28 (gh api). No copilot_chat key.
	details := fetchCopilotBilling(t, `{"seat_breakdown":{"pending_invitation":0,"pending_cancellation":0,"added_this_cycle":0,"total":0,"active_this_cycle":0,"inactive_this_cycle":0},"seat_management_setting":"unconfigured","plan_type":"business","public_code_suggestions":"block","ide_chat":"enabled","cli":"unconfigured","platform_chat":"enabled"}`)

	args := copilotArgs("acme", details)
	assert.Equal(t, "enabled", args["ideChat"].Value)
	assert.Equal(t, "enabled", args["platformChat"].Value)
	assert.Equal(t, "unconfigured", args["cli"].Value)
	assert.Equal(t, "business", args["planType"].Value)
	assert.Equal(t, "block", args["publicCodeSuggestions"].Value)
	assert.Equal(t, "unconfigured", args["seatManagementSetting"].Value)
	// The deprecated copilotChat reports the IDE chat policy rather than an empty string.
	assert.Equal(t, "enabled", args["copilotChat"].Value)
}

func TestCopilotOrgBilling_DocumentedExample(t *testing.T) {
	// Synthetic: the copilot-organization-details example from
	// github/rest-api-description (descriptions/api.github.com), with distinct
	// values per policy so a swapped key is caught.
	details := fetchCopilotBilling(t, `{
		"seat_breakdown": {"total": 12, "added_this_cycle": 9, "pending_invitation": 1, "pending_cancellation": 2, "active_this_cycle": 10, "inactive_this_cycle": 11},
		"seat_management_setting": "assign_selected",
		"ide_chat": "disabled",
		"platform_chat": "enabled",
		"cli": "unconfigured",
		"public_code_suggestions": "allow",
		"plan_type": "enterprise"
	}`)

	args := copilotArgs("acme", details)
	assert.Equal(t, "github.organization.copilot/acme", args["__id"].Value)
	assert.Equal(t, "disabled", args["ideChat"].Value)
	assert.Equal(t, "enabled", args["platformChat"].Value)
	assert.Equal(t, "unconfigured", args["cli"].Value)
	assert.Equal(t, "enterprise", args["planType"].Value)
	assert.Equal(t, "disabled", args["copilotChat"].Value)
	assert.Equal(t, "assign_selected", args["seatManagementSetting"].Value)
	assert.Equal(t, int64(12), args["seatsTotal"].Value)
	assert.Equal(t, int64(9), args["seatsAddedThisCycle"].Value)
	assert.Equal(t, int64(1), args["seatsPendingInvitation"].Value)
	assert.Equal(t, int64(2), args["seatsPendingCancellation"].Value)
	assert.Equal(t, int64(10), args["seatsActiveThisCycle"].Value)
	assert.Equal(t, int64(11), args["seatsInactiveThisCycle"].Value)
}

func TestCopilotOrgBilling_OptionalPoliciesAbsent(t *testing.T) {
	// Synthetic: only the required keys (seat_breakdown,
	// public_code_suggestions, seat_management_setting); no target showed this.
	details := fetchCopilotBilling(t, `{"seat_breakdown":{"total":3},"public_code_suggestions":"block","seat_management_setting":"assign_all"}`)

	args := copilotArgs("acme", details)
	for _, field := range []string{"ideChat", "platformChat", "cli", "planType", "copilotChat"} {
		assert.Nil(t, args[field].Value, field+" must be null when the API omits it")
	}
	assert.Equal(t, int64(3), args["seatsTotal"].Value)
}

func TestCopilotOrgBilling_LegacyCopilotChat(t *testing.T) {
	// Synthetic: a response that still carries copilot_chat alongside
	// ide_chat; no target showed this. copilot_chat wins for copilotChat.
	details := fetchCopilotBilling(t, `{"seat_breakdown":{"total":1},"public_code_suggestions":"block","seat_management_setting":"assign_all","copilot_chat":"disabled","ide_chat":"enabled"}`)

	args := copilotArgs("acme", details)
	assert.Equal(t, "disabled", args["copilotChat"].Value)
	assert.Equal(t, "enabled", args["ideChat"].Value)
}
