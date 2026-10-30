// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func handleContentScanningSettings(env *testEnv, body string) {
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/content-upload-scan/settings", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, body)
	})
}

// The settings endpoint reports status as an enabled/disabled string, so the
// mapping to a bool is the only place a typo turns "off" into "on".
func TestContentScanningEnabledMapping(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  bool
	}{
		{"enabled", true},
		{"ENABLED", true},
		{"disabled", false},
		{"", false},
		{"unexpected", false},
	} {
		t.Run(tc.value, func(t *testing.T) {
			env := setupTestEnv(t)
			zone := createTestZone(t, env)
			handleContentScanningSettings(env, fmt.Sprintf(
				`{"success":true,"result":{"value":%q,"modified":"2026-07-20T12:00:00Z"}}`, tc.value))

			cs, err := zone.contentScanning()
			require.NoError(t, err)
			require.NotNil(t, cs)
			assert.Equal(t, tc.want, cs.Enabled.Data)
		})
	}
}

func TestContentScanningModifiedTime(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handleContentScanningSettings(env, `{"success":true,"result":{"value":"enabled","modified":"2026-07-20T12:00:00Z"}}`)

	cs, err := zone.contentScanning()
	require.NoError(t, err)
	require.NotNil(t, cs.Modified.Data)
	assert.Equal(t, 2026, cs.Modified.Data.Year())
}

func TestContentScanningPayloads(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)
	handleContentScanningSettings(env, `{"success":true,"result":{"value":"enabled","modified":""}}`)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/content-upload-scan/payloads", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"id":"payload-1","payload":"lookup_json_string(http.request.body.raw, \"file\")"}
		],"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	cs, err := zone.contentScanning()
	require.NoError(t, err)

	payloads, err := cs.payloads()
	require.NoError(t, err)
	require.Len(t, payloads, 1)

	p := payloads[0].(*mqlCloudflareZoneContentScanningPayload)
	assert.Equal(t, "payload-1", p.Id.Data)
	assert.Contains(t, p.Payload.Data, "lookup_json_string")

	// An absent modified timestamp must be null, not the zero time.
	assert.Nil(t, cs.Modified.Data)
}

func TestContentScanningUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/content-upload-scan/settings", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Not Found"}]}`)
	})

	cs, err := zone.contentScanning()
	require.NoError(t, err, "an unavailable add-on must surface as null, not error")
	assert.Nil(t, cs)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, zone.ContentScanning.State)
}
