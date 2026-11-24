// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"testing"

	"github.com/digitalocean/godo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Synthetic: a connection in the shape of godo's ActionGatewayConnection JSON, with an API key and connection parameters that must not surface; no live account was checked.
func TestActionGatewayConnectionArgs(t *testing.T) {
	var c godo.ActionGatewayConnection
	require.NoError(t, json.Unmarshal([]byte(`{
		"id":"conn-1","provider":"github","provider_display_name":"GitHub","user_id":"alice","status":"active",
		"created_at":"2026-10-01T10:00:00Z","revoked_at":null,
		"connection_parameters":{"webhook_secret":"param-secret"},
		"credential_kind":"team_credential","credential_id":"cred-1",
		"network":{"vpc":{"vpc_uuid":"vpc-1","region":"nyc3","destinations":[{"host":"10.0.0.5","port":443,"allowed_ip_cidrs":["10.0.0.0/24"]}]}},
		"api_key":{"value":"sk-live-secret"},
		"scopes":["repo","read:org"],"granted_at":"2026-10-02T10:00:00Z","owning_user_id":"u-1"
	}`), &c))

	args, err := actionGatewayConnectionArgs(&c)
	require.NoError(t, err)
	assert.Equal(t, "alice", args["userId"].Value)
	assert.Equal(t, "team_credential", args["credentialKind"].Value)
	assert.Equal(t, []any{"repo", "read:org"}, args["scopes"].Value)
	assert.NotNil(t, args["grantedAt"].Value)
	assert.Nil(t, args["revokedAt"].Value, "a connection that is not revoked has no revocation time")
	assert.Equal(t, []any{map[string]any{"host": "10.0.0.5", "port": int64(443), "allowedIpCidrs": []any{"10.0.0.0/24"}}}, args["vpcDestinations"].Value)

	raw, err := json.Marshal(func() map[string]any {
		m := map[string]any{}
		for k, v := range args {
			m[k] = v.Value
		}
		return m
	}())
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "sk-live-secret")
	assert.NotContains(t, string(raw), "param-secret")
}

// Synthetic: an older connection that carries its grant only in the oauth block, and no network; no live account was checked.
func TestActionGatewayConnectionArgsOAuthFallback(t *testing.T) {
	var c godo.ActionGatewayConnection
	require.NoError(t, json.Unmarshal([]byte(`{"id":"conn-2","oauth":{"scopes":["user:email"],"granted_at":"2026-10-02T10:00:00Z"}}`), &c))
	args, err := actionGatewayConnectionArgs(&c)
	require.NoError(t, err)
	assert.Equal(t, []any{"user:email"}, args["scopes"].Value)
	assert.NotNil(t, args["grantedAt"].Value)
	assert.Equal(t, []any{}, args["vpcDestinations"].Value)
}

// Synthetic: offset pagination of the connection list with a reported total; no live account was checked.
func TestListActionGatewayConnectionsFollowsPages(t *testing.T) {
	var pages []string
	client := newTestGodoClient(t, func(w http.ResponseWriter, r *http.Request) {
		page := r.URL.Query().Get("page")
		pages = append(pages, page)
		n, _ := strconv.Atoi(page)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"connections":[{"id":"c-%d"}],"pagination":{"page":%d,"per_page":1,"total":2}}`, n, n)
	})
	conns, err := listActionGatewayConnections(context.Background(), client.ActionGateway.Connections)
	require.NoError(t, err)
	require.Len(t, conns, 2)
	assert.Equal(t, "c-2", conns[1].ID)
	assert.Equal(t, []string{"1", "2"}, pages)
}

// Synthetic: a provider credential in the shape of godo's ActionGatewayProviderCredential JSON; no live account was checked.
func TestActionGatewayProviderCredentialArgs(t *testing.T) {
	var c godo.ActionGatewayProviderCredential
	require.NoError(t, json.Unmarshal([]byte(`{
		"id":"cred-1","provider":"jira","display_name":"Jira","kind":"PROVIDER_CREDENTIAL_KIND_OAUTH_CLIENT",
		"base_url":"https://svc:hunter2@jira.example.com","status":"PROVIDER_CREDENTIAL_STATUS_ACTIVE",
		"owning_user_id":"u-1","reusable_by_team":true,"scope":"read",
		"discovery":{"status":"consented","consented_at":"2026-10-03T10:00:00Z","authorization_url":"https://auth.example.com/?state=s3cr3t"}
	}`), &c))
	args, err := actionGatewayProviderCredentialArgs(&c)
	require.NoError(t, err)
	assert.Equal(t, true, args["reusableByTeam"].Value)
	assert.Equal(t, "https://svc@jira.example.com", args["baseUrl"].Value, "a password in the base URL is removed")
	assert.Equal(t, "consented", args["discoveryStatus"].Value)
	assert.NotNil(t, args["discoveryConsentedAt"].Value)
	for k, v := range args {
		assert.NotContains(t, fmt.Sprint(v.Value), "s3cr3t", k)
	}

	// Synthetic: no discovery block leaves its fields empty and null.
	args, err = actionGatewayProviderCredentialArgs(&godo.ActionGatewayProviderCredential{ID: "cred-2"})
	require.NoError(t, err)
	assert.Equal(t, "", args["discoveryStatus"].Value)
	assert.Nil(t, args["discoveryConsentedAt"].Value)
}

// Synthetic: an MCP server in the shape of godo's ActionGatewayMCPServer JSON; no live account was checked.
func TestActionGatewayMcpServerArgs(t *testing.T) {
	var s godo.ActionGatewayMCPServer
	require.NoError(t, json.Unmarshal([]byte(`{
		"serverRef":"docs","endpoint":"https://u:pw123@mcp.example.com/mcp","transport":"streamable-http",
		"credentialRefSource":"team","credentialRef":"cred-1","syncStatus":"synced","toolCount":4,
		"lastSyncedAt":"2026-10-04T10:00:00Z","createdAt":"2026-10-01T10:00:00Z",
		"oauth_scopes":["docs.read"],"oauth_authorization_ttl_seconds":"3600"
	}`), &s))
	args, err := actionGatewayMcpServerArgs(&s)
	require.NoError(t, err)
	assert.Equal(t, "docs", args["name"].Value)
	assert.Equal(t, "https://u@mcp.example.com/mcp", args["endpoint"].Value)
	assert.Equal(t, int64(3600), args["oauthAuthorizationTtlSeconds"].Value)
	assert.Equal(t, int64(4), args["toolCount"].Value)
	assert.NotNil(t, args["lastSyncedAt"].Value)
	assert.Nil(t, args["updatedAt"].Value, "an absent time is null")

	// Synthetic: an unset lifetime is null, not zero seconds.
	args, err = actionGatewayMcpServerArgs(&godo.ActionGatewayMCPServer{ServerRef: "x"})
	require.NoError(t, err)
	assert.Nil(t, args["oauthAuthorizationTtlSeconds"].Value)
}

// Synthetic: a connection resolves its provider credential from the credential listing; no live account was checked.
func TestActionGatewayConnectionProviderCredential(t *testing.T) {
	rt := statusRuntime(t, map[string]route{
		"/v2/action-gateway/provider-credentials": {200, `{"credentials":[{"id":"cred-1","provider":"jira"}]}`},
	})
	c := &mqlDigitaloceanActionGatewayConnection{MqlRuntime: rt}
	c.cacheCredentialID = "cred-1"
	cred, err := c.providerCredential()
	require.NoError(t, err)
	require.NotNil(t, cred)
	assert.Equal(t, "jira", cred.Provider.Data)

	gone := &mqlDigitaloceanActionGatewayConnection{MqlRuntime: rt}
	gone.cacheCredentialID = "cred-deleted"
	cred, err = gone.providerCredential()
	require.NoError(t, err)
	assert.Nil(t, cred)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, gone.ProviderCredential.State)
}
