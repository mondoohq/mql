// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestGodoClient(t *testing.T, handler http.HandlerFunc) *godo.Client {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	client, err := godo.New(srv.Client(), godo.SetBaseURL(srv.URL+"/"))
	require.NoError(t, err)
	return client
}

func TestPaginateToken(t *testing.T) {
	pages := map[string]struct {
		items []int
		next  string
	}{
		"":   {[]int{1, 2}, "p2"},
		"p2": {[]int{3}, "p3"},
		"p3": {[]int{4}, ""},
	}
	var asked []string
	got, err := paginateToken(context.Background(), func(_ context.Context, token string) ([]int, string, error) {
		asked = append(asked, token)
		p := pages[token]
		return p.items, p.next, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []int{1, 2, 3, 4}, got)
	assert.Equal(t, []string{"", "p2", "p3"}, asked)
}

func TestPaginateToken_RepeatedTokenFails(t *testing.T) {
	// An endpoint cycling p2 -> p3 -> p2 would loop forever.
	next := map[string]string{"": "p2", "p2": "p3", "p3": "p2"}
	_, err := paginateToken(context.Background(), func(_ context.Context, token string) ([]int, string, error) {
		return []int{0}, next[token], nil
	})
	require.Error(t, err)

	// Handing back the token just requested is the same failure.
	_, err = paginateToken(context.Background(), func(_ context.Context, token string) ([]int, string, error) {
		return []int{0}, "same", nil
	})
	require.Error(t, err)
}

func TestPaginateToken_ErrorPropagates(t *testing.T) {
	boom := errors.New("boom")
	_, err := paginateToken(context.Background(), func(_ context.Context, token string) ([]int, string, error) {
		if token == "p2" {
			return nil, "", boom
		}
		return []int{1}, "p2", nil
	})
	require.ErrorIs(t, err, boom)
}

func TestListHostedAgentTriggers_FollowsPageToken(t *testing.T) {
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/agents/triggers", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page_token") {
		case "":
			fmt.Fprint(w, `{"triggers":[{"trigger_id":"t-1"},{"trigger_id":"t-2"}],"next_page_token":"tok-2"}`)
		case "tok-2":
			fmt.Fprint(w, `{"triggers":[{"trigger_id":"t-3"}]}`)
		default:
			t.Fatalf("unexpected page token %q", r.URL.Query().Get("page_token"))
		}
	})
	triggers, err := listHostedAgentTriggers(context.Background(), client.HostedAgentTriggers)
	require.NoError(t, err)
	ids := []string{}
	for _, tr := range triggers {
		ids = append(ids, tr.TriggerID)
	}
	assert.Equal(t, []string{"t-1", "t-2", "t-3"}, ids)
}

func TestListHostedAgentConfigs_FollowsPageToken(t *testing.T) {
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/agents/configs", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page_token") {
		case "":
			fmt.Fprint(w, `{"configs":[{"id":"c-1"}],"next_page_token":"tok-2"}`)
		case "tok-2":
			fmt.Fprint(w, `{"configs":[{"id":"c-2"}],"next_page_token":""}`)
		default:
			t.Fatalf("unexpected page token %q", r.URL.Query().Get("page_token"))
		}
	})
	configs, err := listHostedAgentConfigs(context.Background(), client.HostedAgents)
	require.NoError(t, err)
	require.Len(t, configs, 2)
	assert.Equal(t, "c-2", configs[1].ID)
}

func TestHostedAgentConfigArgs_Decode(t *testing.T) {
	raw := `{
		"id": "cfg-1",
		"name": "reviewer",
		"agentspec_schema_version": "v1alpha1",
		"content_hash": "sha256:abc",
		"created_by": "user@example.com",
		"created_at": "2026-05-01T10:00:00Z",
		"updated_at": "2026-05-02T10:00:00Z"
	}`
	var c godo.HostedAgentConfigSummary
	require.NoError(t, json.Unmarshal([]byte(raw), &c))
	args, err := hostedAgentConfigArgs(&c)
	require.NoError(t, err)
	assert.Equal(t, "digitalocean.hostedAgentConfig/cfg-1", args["__id"].Value)
	assert.Equal(t, "reviewer", args["name"].Value)
	assert.Equal(t, "v1alpha1", args["agentSpecSchemaVersion"].Value)
	assert.Equal(t, "sha256:abc", args["contentHash"].Value)
	assert.Equal(t, "user@example.com", args["createdBy"].Value)
	assert.NotNil(t, args["createdAt"].Value)
	assert.NotNil(t, args["updatedAt"].Value)

	// Absent timestamps stay null rather than reading as year 1.
	args, err = hostedAgentConfigArgs(&godo.HostedAgentConfigSummary{ID: "cfg-2"})
	require.NoError(t, err)
	assert.Nil(t, args["createdAt"].Value)
	assert.Nil(t, args["updatedAt"].Value)

	_, err = hostedAgentConfigArgs(&godo.HostedAgentConfigSummary{})
	require.Error(t, err)
}

func TestHostedAgentCredentialDicts(t *testing.T) {
	raw := `{"config":{"id":"cfg-1","credentials":[
		{"name":"OPENAI_API_KEY","source":"tenantSecret","provider":"openai"},
		{"name":"GITHUB","source":"oauth"}
	]}}`
	var root struct {
		Config godo.HostedAgentConfig `json:"config"`
	}
	require.NoError(t, json.Unmarshal([]byte(raw), &root))
	assert.Equal(t, []any{
		map[string]any{"name": "OPENAI_API_KEY", "source": "tenantSecret", "provider": "openai"},
		map[string]any{"name": "GITHUB", "source": "oauth", "provider": ""},
	}, hostedAgentCredentialDicts(root.Config.Credentials))
	assert.Equal(t, []any{}, hostedAgentCredentialDicts(nil))
}

func TestHostedAgentTriggerArgs_Webhook(t *testing.T) {
	raw := `{
		"trigger_id": "t-1",
		"kind": "webhook",
		"name": "on-push",
		"status": "active",
		"session_mode": "fresh",
		"agent_kind": "AGENT_KIND_CLAUDE_CODE",
		"prompt_template": "review {{.payload}}",
		"output": {"mode": "slack", "slack_configured": true},
		"webhook": {"provider": "github", "webhook_url": "https://hooks.example.com/t-1"},
		"created_at": "2026-05-01T10:00:00Z"
	}`
	var tr godo.HostedAgentTrigger
	require.NoError(t, json.Unmarshal([]byte(raw), &tr))
	args, err := hostedAgentTriggerArgs(&tr)
	require.NoError(t, err)

	assert.Equal(t, "digitalocean.hostedAgentTrigger/t-1", args["__id"].Value)
	assert.Equal(t, "webhook", args["kind"].Value)
	assert.Equal(t, "active", args["status"].Value)
	assert.Equal(t, "fresh", args["sessionMode"].Value)
	assert.Equal(t, "AGENT_KIND_CLAUDE_CODE", args["agentKind"].Value)
	assert.Equal(t, "github", args["webhookProvider"].Value)
	assert.Equal(t, "", args["cronExpression"].Value)
	assert.Nil(t, args["nextRunAt"].Value)
	assert.Equal(t, "slack", args["outputMode"].Value)
	assert.Equal(t, true, args["outputSlackConfigured"].Value)
	assert.Equal(t, false, args["outputEmailConfigured"].Value)
	assert.NotNil(t, args["createdAt"].Value)
	assert.Nil(t, args["updatedAt"].Value)

	// Workload content and delivery endpoints are not exposed.
	for _, k := range []string{"promptTemplate", "sessionTemplate", "webhookUrl", "boundSessionId"} {
		_, ok := args[k]
		assert.False(t, ok, k)
	}
}

func TestHostedAgentTriggerArgs_CronWithoutOutput(t *testing.T) {
	raw := `{
		"trigger_id": "t-2",
		"kind": "cron",
		"status": "paused",
		"session_mode": "reuse",
		"cron": {"cron_expr": "0 3 * * *", "timezone": "UTC", "next_run_at": "2026-05-03T03:00:00Z"}
	}`
	var tr godo.HostedAgentTrigger
	require.NoError(t, json.Unmarshal([]byte(raw), &tr))
	args, err := hostedAgentTriggerArgs(&tr)
	require.NoError(t, err)

	assert.Equal(t, "cron", args["kind"].Value)
	assert.Equal(t, "paused", args["status"].Value)
	assert.Equal(t, "reuse", args["sessionMode"].Value)
	assert.Equal(t, "", args["webhookProvider"].Value)
	assert.Equal(t, "0 3 * * *", args["cronExpression"].Value)
	assert.Equal(t, "UTC", args["cronTimezone"].Value)
	assert.NotNil(t, args["nextRunAt"].Value)
	// No output block means nothing is delivered anywhere.
	assert.Equal(t, "none", args["outputMode"].Value)
	assert.Equal(t, false, args["outputEmailConfigured"].Value)
	assert.Equal(t, false, args["outputSlackConfigured"].Value)
}

func TestHostedAgentTriggerArgs_EmptyIDRejected(t *testing.T) {
	_, err := hostedAgentTriggerArgs(&godo.HostedAgentTrigger{Name: "no-id"})
	require.Error(t, err)
}
