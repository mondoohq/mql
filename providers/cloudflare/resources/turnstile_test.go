// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const turnstileWidgetsResponse = `{"success":true,"errors":[],"messages":[],
	"result":[{
		"sitekey":"0x4AAF00AAAABn0R22HWm098",
		"name":"login-form",
		"mode":"managed",
		"region":"world",
		"clearance_level":"no_clearance",
		"domains":["example.com","staging.example.com"],
		"bot_fight_mode":false,
		"ephemeral_id":true,
		"offlabel":false,
		"secret":"0x4AAF00AAAABn0R22HWm098SUPERSECRET",
		"created_on":"2026-07-20T12:00:00Z",
		"modified_on":"2026-07-21T12:00:00Z"
	}],
	"result_info":{"page":1,"per_page":100,"total_pages":1}}`

func TestTurnstileWidgets(t *testing.T) {
	env := setupTestEnv(t)
	account := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/challenges/widgets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, turnstileWidgetsResponse)
	})

	widgets, err := account.turnstileWidgets()
	require.NoError(t, err)
	require.Len(t, widgets, 1)

	widget := widgets[0].(*mqlCloudflareTurnstileWidget)
	assert.Equal(t, "0x4AAF00AAAABn0R22HWm098", widget.Sitekey.Data)
	assert.Equal(t, "login-form", widget.Name.Data)
	assert.Equal(t, "managed", widget.Mode.Data)
	assert.Equal(t, "world", widget.Region.Data)
	assert.Equal(t, "no_clearance", widget.ClearanceLevel.Data)
	assert.Equal(t, []any{"example.com", "staging.example.com"}, widget.Domains.Data)
	assert.False(t, widget.BotFightMode.Data)
	assert.True(t, widget.EphemeralIdEnabled.Data)
	assert.False(t, widget.Offlabel.Data)

	require.NotNil(t, widget.CreatedOn.Data)
	assert.Equal(t, 2026, widget.CreatedOn.Data.Year())
	require.NotNil(t, widget.ModifiedOn.Data)
	assert.Equal(t, 21, widget.ModifiedOn.Data.Day())
}

// The widgets endpoint returns each widget's secret key. It must not reach the
// schema, so no query can ever surface it.
func TestTurnstileWidgetSecretNotExposed(t *testing.T) {
	env := setupTestEnv(t)
	account := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/challenges/widgets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, turnstileWidgetsResponse)
	})

	widgets, err := account.turnstileWidgets()
	require.NoError(t, err)
	require.Len(t, widgets, 1)

	// The decode target has no field for it, so the secret is dropped before it
	// can be mapped. Assert on the decoded shape to keep that true.
	var decoded struct {
		Result []turnstileWidget `json:"result"`
	}
	require.NoError(t, json.Unmarshal([]byte(turnstileWidgetsResponse), &decoded))
	require.Len(t, decoded.Result, 1)

	marshaled, err := json.Marshal(decoded.Result[0])
	require.NoError(t, err)
	assert.NotContains(t, string(marshaled), "SUPERSECRET",
		"the widget secret must never be carried into the resource")
}

func TestTurnstileWidgetsUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	account := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/challenges/widgets", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	widgets, err := account.turnstileWidgets()
	require.NoError(t, err, "a token without Turnstile read must degrade to an empty list")
	assert.Empty(t, widgets)
}
