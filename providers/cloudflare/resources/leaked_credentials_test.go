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

func TestLeakedCredentialChecks(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/leaked-credential-checks", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":{"enabled":true}}`)
	})
	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/leaked-credential-checks/detections", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":[
			{"id":"det-1","username":"lookup_json_string(http.request.body.raw, \"user\")","password":"lookup_json_string(http.request.body.raw, \"pass\")"}
		],"result_info":{"page":1,"per_page":100,"total_pages":1}}`)
	})

	checks, err := zone.leakedCredentialChecks()
	require.NoError(t, err)
	require.NotNil(t, checks)
	assert.True(t, checks.Enabled.Data)

	detections, err := checks.detections()
	require.NoError(t, err)
	require.Len(t, detections, 1)

	d := detections[0].(*mqlCloudflareZoneLeakedCredentialChecksDetection)
	assert.Equal(t, "det-1", d.Id.Data)
	// These are ruleset expressions locating the fields, never credential
	// values, which is why exposing them is safe.
	assert.Contains(t, d.Username.Data, "lookup_json_string")
	assert.Contains(t, d.Password.Data, "lookup_json_string")
}

func TestLeakedCredentialChecksDisabled(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/leaked-credential-checks", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, `{"success":true,"result":{"enabled":false}}`)
	})

	checks, err := zone.leakedCredentialChecks()
	require.NoError(t, err)
	require.NotNil(t, checks)
	assert.False(t, checks.Enabled.Data, "a disabled feature must read false, not null")
}

func TestLeakedCredentialChecksUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	zone := createTestZone(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/zones/%s/leaked-credential-checks", testZoneID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Forbidden"}]}`)
	})

	checks, err := zone.leakedCredentialChecks()
	require.NoError(t, err)
	assert.Nil(t, checks)
	assert.Equal(t, plugin.StateIsNull|plugin.StateIsSet, zone.LeakedCredentialChecks.State)
}
