// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeChannel(t *testing.T, raw string) map[string]any {
	t.Helper()
	var c godo.NotificationChannel
	require.NoError(t, json.Unmarshal([]byte(raw), &c))
	args, err := notificationChannelArgs(&c)
	require.NoError(t, err)
	out := map[string]any{}
	for k, v := range args {
		out[k] = v.Value
	}
	return out
}

// Synthetic: a webhook channel in the shape of godo's NotificationChannel JSON, whose URL carries a token in its path; no live account was checked.
func TestNotificationChannelArgsWebhook(t *testing.T) {
	got := decodeChannel(t, `{
		"id":"ch-1","name":"pager","channel_type":"CHANNEL_TYPE_WEBHOOK",
		"webhook":{"url":"HTTPS://hooks.example.com/T0K3N/alert","bearer_token":{"token":"****"},"signature":{"secret":"****"},"headers":{"X-Api-Key":"hdr-secret"}},
		"usage":{"rule_count":3}
	}`)
	assert.Equal(t, "https", got["webhookScheme"])
	assert.Equal(t, true, got["webhookHasSignature"])
	assert.Equal(t, true, got["webhookHasAuth"])
	assert.Equal(t, int64(3), got["ruleCount"])
	assert.Equal(t, []any{}, got["emailTo"])

	raw, err := json.Marshal(got)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "T0K3N")
	assert.NotContains(t, string(raw), "hdr-secret")
}

// Synthetic: a webhook with neither signing nor authentication, over plain http; no live account was checked.
func TestNotificationChannelArgsUnauthenticatedWebhook(t *testing.T) {
	got := decodeChannel(t, `{"id":"ch-2","channel_type":"CHANNEL_TYPE_WEBHOOK","webhook":{"url":"http://hooks.example.com/x"}}`)
	assert.Equal(t, "http", got["webhookScheme"])
	assert.Equal(t, false, got["webhookHasSignature"])
	assert.Equal(t, false, got["webhookHasAuth"])
	assert.Nil(t, got["ruleCount"], "no usage block is null, not zero rules")
}

// Synthetic: email and Slack channels; the Slack webhook URL never surfaces and webhook fields stay null; no live account was checked.
func TestNotificationChannelArgsEmailAndSlack(t *testing.T) {
	email := decodeChannel(t, `{"id":"ch-3","channel_type":"CHANNEL_TYPE_EMAIL","email":{"to":"a@example.com, b@example.com;c@example.com"}}`)
	assert.Equal(t, []any{"a@example.com", "b@example.com", "c@example.com"}, email["emailTo"])
	assert.Nil(t, email["webhookHasSignature"])
	assert.Nil(t, email["webhookHasAuth"])
	assert.Equal(t, "", email["webhookScheme"])

	slack := decodeChannel(t, `{"id":"ch-4","channel_type":"CHANNEL_TYPE_SLACK","slack":{"webhook_url":"https://hooks.slack.com/services/T/B/SLACKSECRET","channel":"#ops"}}`)
	assert.Equal(t, "#ops", slack["slackChannel"])
	raw, err := json.Marshal(slack)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "SLACKSECRET")
}

// Synthetic: bindings as godo's AlertRuleSpec decodes them; no live account was checked.
func TestAlertRuleChannelIDs(t *testing.T) {
	var rule godo.AlertRule
	require.NoError(t, json.Unmarshal([]byte(`{"id":"r1","spec":{"name":"cpu","notification_channels":[
		{"notification_channel_id":"ch-1"},{"notification_channel_id":""},{"notification_channel_id":"ch-2"},{"notification_channel_id":"ch-1"}
	]}}`), &rule))
	assert.Equal(t, []string{"ch-1", "ch-2"}, alertRuleChannelIDs(&rule))

	// Synthetic: a rule without bindings notifies nobody.
	assert.Empty(t, alertRuleChannelIDs(&godo.AlertRule{}))
}

// Synthetic: the alert rule endpoint takes its own options type, so the page must be carried into it; no live account was checked.
func TestListInsightsAlertRulesFollowsPages(t *testing.T) {
	var pages []string
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		w.Header().Set("Content-Type", "application/json")
		if page == "" || page == "1" {
			fmt.Fprint(w, `{"alert_rules":[{"id":"r1","spec":{"name":"cpu"}}],"links":{"pages":{"next":"https://api.digitalocean.com/v2/insights/alert-rules?page=2","last":"https://api.digitalocean.com/v2/insights/alert-rules?page=2"}},"meta":{"total":2}}`)
			return
		}
		fmt.Fprint(w, `{"alert_rules":[{"id":"r2","spec":{"name":"mem"}}],"links":{"pages":{"prev":"https://api.digitalocean.com/v2/insights/alert-rules?page=1"}},"meta":{"total":2}}`)
	})
	rules, err := listInsightsAlertRules(context.Background(), client.Insights)
	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, "r2", rules[1].ID)
	assert.Equal(t, "2", pages[1])
}

// Synthetic: an alert rule resolves its channels from the channel listing and skips a deleted one; no live account was checked.
func TestAlertRuleChannelsResolve(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/insights/notification-channels": {200, `{"notification_channels":[{"id":"ch-1","name":"pager","channel_type":"CHANNEL_TYPE_EMAIL"}],"links":{},"meta":{"total":1}}`},
	})
	r := &mqlDigitaloceanInsightsAlertRule{MqlRuntime: rt}
	r.cacheChannelIDs = []string{"ch-1", "ch-deleted"}
	out, err := r.channels()
	require.NoError(t, err)
	require.Len(t, out, 1)
	assert.Equal(t, "pager", out[0].(*mqlDigitaloceanInsightsNotificationChannel).Name.Data)
}
