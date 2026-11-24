// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"strings"
	"testing"

	observability "github.com/stackitcloud/stackit-sdk-go/services/observability/v1api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeReceiver(t *testing.T, payload string) *observability.Receivers {
	t.Helper()
	var r observability.Receivers
	require.NoError(t, json.Unmarshal([]byte(payload), &r))
	return &r
}

func TestAlertReceiverArgs(t *testing.T) {
	// Synthetic: receivers shaped after the SDK's Receivers model; no live account was checked.
	t.Run("webhook keeps only the scheme", func(t *testing.T) {
		secretURL := "http://hooks.example.com/services/T000/B000/s3cr3t-token"
		rcv := decodeReceiver(t, `{"name":"ops","webHookConfigs":[{"url":"`+secretURL+`"},`+
			`{"url":"HTTPS://teams.example.com/x","msTeams":true,"sendResolved":false}]}`)
		args := alertReceiverArgs("inst-1", rcv)

		assert.Equal(t, []any{"http", "https"}, args["webhookSchemes"].Value)
		assert.Equal(t, []any{"webhook", "msTeams"}, args["types"].Value)
		assert.Equal(t, false, args["sendResolved"].Value)
		for k, v := range args {
			if s, ok := v.Value.(string); ok {
				assert.NotContains(t, s, "s3cr3t", "field %s carries the webhook URL", k)
			}
			if l, ok := v.Value.([]any); ok {
				for _, e := range l {
					assert.False(t, strings.Contains(e.(string), "s3cr3t"), "field %s carries the webhook URL", k)
				}
			}
		}
	})

	t.Run("email and opsgenie, any true sendResolved wins", func(t *testing.T) {
		rcv := decodeReceiver(t, `{"name":"mail","emailConfigs":[{"to":"a@example.com","sendResolved":false,"authPassword":"pw"},`+
			`{"to":"b@example.com"}],"opsgenieConfigs":[{"apiKey":"k","sendResolved":true}]}`)
		args := alertReceiverArgs("inst-1", rcv)

		assert.Equal(t, []any{"a@example.com", "b@example.com"}, args["emailTo"].Value)
		assert.Equal(t, []any{"email", "opsgenie"}, args["types"].Value)
		assert.Equal(t, true, args["sendResolved"].Value)
		assert.Equal(t, []any{}, args["webhookSchemes"].Value)
	})

	t.Run("no notifier reports sendResolved", func(t *testing.T) {
		args := alertReceiverArgs("inst-1", decodeReceiver(t, `{"name":"null-route"}`))
		assert.Nil(t, args["sendResolved"].Value)
		assert.Equal(t, []any{}, args["types"].Value)
	})

	t.Run("receivers of two instances do not share a cache key", func(t *testing.T) {
		rcv := decodeReceiver(t, `{"name":"ops"}`)
		assert.NotEqual(t, alertReceiverArgs("inst-1", rcv)["__id"].Value, alertReceiverArgs("inst-2", rcv)["__id"].Value)
	})
}

func TestUrlScheme(t *testing.T) {
	// Synthetic: no live account was checked.
	assert.Equal(t, "https", urlScheme("HTTPS://example.com/a?token=x"))
	assert.Equal(t, "", urlScheme("example.com/no-scheme"))
	assert.Equal(t, "", urlScheme("http://[::1"))
}

func TestAlertRuleTotal(t *testing.T) {
	// Synthetic: two groups with three rules between them; no live account was checked.
	var groups []observability.AlertGroup
	require.NoError(t, json.Unmarshal([]byte(`[`+
		`{"name":"a","rules":[{"alert":"x","expr":"up == 0"},{"alert":"y","expr":"up == 0"}]},`+
		`{"name":"b","rules":[{"alert":"z","expr":"up == 0"}]},{"name":"c","rules":[]}]`), &groups))
	assert.Equal(t, int64(3), alertRuleTotal(groups))
	assert.Equal(t, int64(0), alertRuleTotal(nil))
}

func TestGenericOauthFlag(t *testing.T) {
	// Synthetic: Grafana configurations after the SDK's GrafanaConfigs model; no live account was checked.
	decode := func(payload string) *observability.GrafanaConfigs {
		var g observability.GrafanaConfigs
		require.NoError(t, json.Unmarshal([]byte(payload), &g))
		return &g
	}
	oauth := `"genericOauth":{"apiUrl":"a","authUrl":"b","enabled":true,"oauthClientId":"c","oauthClientSecret":"d",` +
		`"roleAttributePath":"e","tokenUrl":"f","roleAttributeStrict":true,"usePkce":false}`
	g := decode(`{"message":"ok","publicReadAccess":false,"useStackitSso":true,` + oauth + `}`)
	strict := genericOauthFlag(g, (*observability.GrafanaOauth).GetRoleAttributeStrictOk)
	pkce := genericOauthFlag(g, (*observability.GrafanaOauth).GetUsePkceOk)
	require.NotNil(t, strict)
	require.NotNil(t, pkce)
	assert.True(t, *strict)
	assert.False(t, *pkce)

	noOauth := decode(`{"message":"ok","publicReadAccess":false,"useStackitSso":true}`)
	assert.Nil(t, genericOauthFlag(noOauth, (*observability.GrafanaOauth).GetUsePkceOk))
	assert.Nil(t, genericOauthFlag(nil, (*observability.GrafanaOauth).GetUsePkceOk))
}
