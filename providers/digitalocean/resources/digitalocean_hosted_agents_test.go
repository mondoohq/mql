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
	"strings"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
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
		assert.Equal(t, "/v2/harness-runtime/triggers", r.URL.Path)
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
		assert.Equal(t, "/v2/harness-runtime/configs", r.URL.Path)
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
		"updated_at": "2026-05-02T10:00:00Z",
		"region": "ric1"
	}`
	var c godo.HostedAgentConfigSummary
	require.NoError(t, json.Unmarshal([]byte(raw), &c))
	args, err := hostedAgentConfigArgs(&c)
	require.NoError(t, err)
	assert.Equal(t, "digitalocean.hostedAgentConfig/cfg-1", args["__id"].Value)
	assert.Equal(t, "ric1", args["region"].Value)
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
	// Synthetic: a team without regional placement gets no region field;
	// it stays null rather than an empty slug.
	assert.Nil(t, args["region"].Value)

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

func TestHostedAgentConnectionProviders_DropsCustomAndDuplicates(t *testing.T) {
	// Synthetic: response shape from godo's webhook provider registry type.
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/harness-runtime/webhook-providers", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"providers":[{"key":"github"},{"key":"custom"},{"key":"gitlab"},{"key":"github"},{"key":""}]}`)
	})
	got, err := hostedAgentConnectionProviders(context.Background(), client.HostedAgentTriggers)
	require.NoError(t, err)
	assert.Equal(t, []string{"github", "gitlab"}, got)
}

func TestListHostedAgentConnections_FollowsPages(t *testing.T) {
	// Synthetic: page/per_page pagination with a reported total.
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/harness-runtime/auth/github/connections", r.URL.Path)
		assert.Equal(t, "100", r.URL.Query().Get("per_page"))
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "1":
			fmt.Fprint(w, `{"connections":[{"id":"c-1"},{"id":"c-2"}],"pagination":{"page":1,"per_page":2,"total":3}}`)
		case "2":
			fmt.Fprint(w, `{"connections":[{"id":"c-3"}],"pagination":{"page":2,"per_page":2,"total":3}}`)
		default:
			t.Fatalf("unexpected page %q", r.URL.Query().Get("page"))
		}
	})
	conns, err := listHostedAgentConnections(context.Background(), client.HostedAgents, "github")
	require.NoError(t, err)
	ids := []string{}
	for _, c := range conns {
		ids = append(ids, c.ID)
	}
	assert.Equal(t, []string{"c-1", "c-2", "c-3"}, ids)
}

func TestListHostedAgentConnections_StuckPageFails(t *testing.T) {
	// Synthetic: an endpoint that ignores the page parameter and keeps
	// answering the first page must not loop forever.
	calls := 0
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"connections":[{"id":"c-1"}],"pagination":{"page":1,"per_page":1,"total":3}}`)
	})
	_, err := listHostedAgentConnections(context.Background(), client.HostedAgents, "github")
	require.Error(t, err)
	assert.Equal(t, 2, calls)
}

func TestListHostedAgentConnections_NotFoundPropagates(t *testing.T) {
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"id":"not_found","message":"provider not found"}`)
	})
	_, err := listHostedAgentConnections(context.Background(), client.HostedAgents, "gitlab")
	require.Error(t, err)
	assert.True(t, isDoNotFound(err))
}

func TestHostedAgentConnectionArgs_OAuth(t *testing.T) {
	// Synthetic: fields from godo's HostedAgentConnection json tags.
	raw := `{
		"id": "conn-1",
		"provider": "github",
		"provider_display_name": "GitHub",
		"user_id": "reviewer-bot",
		"status": "active",
		"owning_user_id": "6e1f0c1a-0000-4000-8000-000000000001",
		"deletion_protected": true,
		"created_at": "2026-05-01T10:00:00Z",
		"oauth": {"scopes": ["repo", "read:org"], "granted_at": "2026-05-01T10:05:00Z"}
	}`
	var c godo.HostedAgentConnection
	require.NoError(t, json.Unmarshal([]byte(raw), &c))
	args, err := hostedAgentConnectionArgs(&c)
	require.NoError(t, err)
	assert.Equal(t, "digitalocean.hostedAgentConnection/github/conn-1", args["__id"].Value)
	assert.Equal(t, "reviewer-bot", args["actorId"].Value)
	assert.Equal(t, "GitHub", args["providerDisplayName"].Value)
	assert.Equal(t, "active", args["status"].Value)
	assert.Equal(t, "6e1f0c1a-0000-4000-8000-000000000001", args["owningUserUuid"].Value)
	assert.Equal(t, true, args["deletionProtected"].Value)
	assert.Equal(t, []any{"repo", "read:org"}, args["oauthScopes"].Value)
	assert.NotNil(t, args["grantedAt"].Value)
	assert.NotNil(t, args["createdAt"].Value)
	assert.Nil(t, args["updatedAt"].Value)
}

func TestHostedAgentConnectionArgs_NoOAuth(t *testing.T) {
	// Synthetic: an API-key connection carries no oauth block.
	c := godo.HostedAgentConnection{ID: "conn-2", Provider: "github", Status: "pending"}
	args, err := hostedAgentConnectionArgs(&c)
	require.NoError(t, err)
	assert.Equal(t, []any{}, args["oauthScopes"].Value)
	assert.Nil(t, args["grantedAt"].Value)
	assert.Equal(t, false, args["deletionProtected"].Value)
}

func TestHostedAgentConnectionArgs_EmptyIDRejected(t *testing.T) {
	_, err := hostedAgentConnectionArgs(&godo.HostedAgentConnection{Provider: "github"})
	require.Error(t, err)
}

func TestListHostedAgentConnections_NoPaginationBlock(t *testing.T) {
	// Synthetic: a response without a pagination block (total 0) must not
	// stop after a full first page.
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Query().Get("page") == "1" {
			conns := make([]string, 0, hostedAgentConnectionPageSize)
			for i := 0; i < hostedAgentConnectionPageSize; i++ {
				conns = append(conns, fmt.Sprintf(`{"id":"c-%d"}`, i))
			}
			fmt.Fprintf(w, `{"connections":[%s]}`, strings.Join(conns, ","))
			return
		}
		fmt.Fprint(w, `{"connections":[{"id":"last"}]}`)
	})
	conns, err := listHostedAgentConnections(context.Background(), client.HostedAgents, "github")
	require.NoError(t, err)
	assert.Len(t, conns, hostedAgentConnectionPageSize+1)
}

func TestListHostedAgentConnections_NoPaginationShortPage(t *testing.T) {
	// Synthetic: without a total, a short page is the last one.
	calls := 0
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"connections":[{"id":"c-1"}]}`)
	})
	conns, err := listHostedAgentConnections(context.Background(), client.HostedAgents, "github")
	require.NoError(t, err)
	assert.Len(t, conns, 1)
	assert.Equal(t, 1, calls)
}

// Synthetic: consent records in the shape of godo's SignalsListConsentsResponse JSON; no live account was checked.
func TestSignalsConsentLookups(t *testing.T) {
	var list godo.SignalsListConsentsResponse
	require.NoError(t, json.Unmarshal([]byte(`{"team_id":7,"consents":[
		{"id":1,"team_id":7,"source":"agent","agent_id":"","environment_id":"env-on","enabled":true},
		{"id":2,"team_id":7,"source":"agent","agent_id":"env-legacy","enabled":false},
		{"id":3,"team_id":7,"source":"inference","agent_id":"","enabled":true},
		{"id":4,"team_id":7,"source":"inference","agent_id":"","environment_id":"env-off","enabled":true}
	]}`), &list))

	on := agentSignalsConsent(&list, "env-on")
	require.NotNil(t, on)
	assert.True(t, *on)

	// Older records name the environment only through the deprecated agent_id.
	legacy := agentSignalsConsent(&list, "env-legacy")
	require.NotNil(t, legacy)
	assert.False(t, *legacy)

	// An inference record naming an environment is not an agent consent.
	assert.Nil(t, agentSignalsConsent(&list, "env-off"))
	assert.Nil(t, agentSignalsConsent(&list, "env-unknown"))
	assert.Nil(t, agentSignalsConsent(nil, "env-on"))

	inf := inferenceSignalsConsent(&list)
	require.NotNil(t, inf)
	assert.True(t, *inf)

	// Synthetic: a team with only agent records has no inference consent.
	assert.Nil(t, inferenceSignalsConsent(&godo.SignalsListConsentsResponse{Consents: list.Consents[:2]}))
}

// Synthetic: the consent listing read through the API, then a team without consent records (404); no live account was checked.
func TestSignalsConsentFields(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v1/consent": {200, `{"team_id":7,"consents":[{"source":"inference","enabled":false},{"source":"agent","environment_id":"cfg-1","enabled":true}]}`},
	})
	cfg := &mqlDigitaloceanHostedAgentConfig{MqlRuntime: rt, Id: strVal("cfg-1")}
	v, err := cfg.signalsConsentEnabled()
	require.NoError(t, err)
	assert.True(t, v)

	root, err := parentDigitalocean(rt)
	require.NoError(t, err)
	inf, err := root.inferenceSignalsConsentEnabled()
	require.NoError(t, err)
	assert.False(t, inf)
	assert.Equal(t, plugin.State(0), root.InferenceSignalsConsentEnabled.State, "a read false must not be null")

	rt = statusRuntime(t, map[string]route{})
	cfg = &mqlDigitaloceanHostedAgentConfig{MqlRuntime: rt, Id: strVal("cfg-1")}
	_, err = cfg.signalsConsentEnabled()
	require.NoError(t, err)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, cfg.SignalsConsentEnabled.State)
}
