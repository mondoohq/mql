// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cloudflare/cloudflare-go/v7/registrar"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func TestRegistrarDomainArgs(t *testing.T) {
	// Synthetic: an active registration, and a pending transfer whose expiry
	// the API reports as null; no live account was checked.
	t.Run("active", func(t *testing.T) {
		var reg registrar.Registration
		require.NoError(t, json.Unmarshal([]byte(`{"domain_name":"example.com","auto_renew":true,"locked":true,
			"privacy_mode":"redaction","status":"active",
			"created_at":"2020-05-06T07:08:09Z","expires_at":"2027-05-06T07:08:09Z"}`), &reg))

		args := registrarDomainArgs(testAccountID, reg)
		assert.Equal(t, "cloudflare.account.registrarDomain@"+testAccountID+"/example.com", args["__id"].Value)
		assert.Equal(t, "example.com", args["name"].Value)
		assert.Equal(t, true, args["locked"].Value)
		assert.Equal(t, true, args["autoRenew"].Value)
		assert.Equal(t, "redaction", args["privacyMode"].Value)
		assert.Equal(t, "active", args["status"].Value)
		expires, ok := args["expiresAt"].Value.(*time.Time)
		require.True(t, ok)
		assert.Equal(t, time.Date(2027, 5, 6, 7, 8, 9, 0, time.UTC), expires.UTC())
		created, ok := args["createdAt"].Value.(*time.Time)
		require.True(t, ok)
		assert.Equal(t, 2020, created.Year())
	})

	t.Run("pending transfer", func(t *testing.T) {
		var reg registrar.Registration
		require.NoError(t, json.Unmarshal([]byte(`{"domain_name":"moving.example","auto_renew":false,"locked":false,
			"privacy_mode":"off","status":"transfer_pending",
			"created_at":"2026-11-01T00:00:00Z","expires_at":null}`), &reg))

		args := registrarDomainArgs(testAccountID, reg)
		assert.Equal(t, false, args["locked"].Value)
		assert.Equal(t, false, args["autoRenew"].Value)
		assert.Equal(t, "transfer_pending", args["status"].Value)
		assert.Nil(t, args["expiresAt"].Value, "a pending transfer has no expiry yet")
	})
}

// Synthetic: two pages of registrations joined by a cursor; no live account
// was checked. Both pages must be read, and the domain with a zone in scope
// resolves to it while the other reads null.
func TestRegistrarDomainsPagination(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	requests := 0
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/registrar/registrations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Query().Get("cursor") {
		case "":
			jsonResponse(w, `{"success":true,"errors":[],"messages":[],"result":[
				{"domain_name":"example.com","auto_renew":true,"locked":true,"privacy_mode":"redaction",
				 "status":"active","created_at":"2020-01-01T00:00:00Z","expires_at":"2027-01-01T00:00:00Z"}
			],"result_info":{"count":1,"per_page":1,"cursor":"page-2"}}`)
		case "page-2":
			jsonResponse(w, `{"success":true,"errors":[],"messages":[],"result":[
				{"domain_name":"elsewhere.example","auto_renew":false,"locked":false,"privacy_mode":"off",
				 "status":"expired","created_at":"2019-01-01T00:00:00Z","expires_at":"2025-01-01T00:00:00Z"}
			],"result_info":{"count":1,"per_page":1,"cursor":""}}`)
		default:
			t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
		}
	})
	env.Mux.HandleFunc("/zones", pagedFixture("zones"))

	result, err := acc.registrarDomains()
	require.NoError(t, err)
	require.Len(t, result, 2)
	assert.Equal(t, 2, requests)

	first := result[0].(*mqlCloudflareAccountRegistrarDomain)
	second := result[1].(*mqlCloudflareAccountRegistrarDomain)
	assert.Equal(t, "example.com", first.Name.Data)
	assert.Equal(t, "elsewhere.example", second.Name.Data)
	assert.NotEqual(t, first.MqlID(), second.MqlID())

	zone, err := first.zone()
	require.NoError(t, err)
	require.NotNil(t, zone)
	assert.Equal(t, testZoneID, zone.Id.Data)

	none, err := second.zone()
	require.NoError(t, err)
	assert.Nil(t, none)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, second.Zone.State)
}

// Synthetic: an account without Registrar access answers 403 with the
// generic code; no live account was checked. The list degrades to empty.
func TestRegistrarDomainsUnavailable(t *testing.T) {
	env := setupTestEnv(t)
	acc := createTestAccount(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/registrar/registrations", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"result":null}`)
	})

	result, err := acc.registrarDomains()
	require.NoError(t, err)
	assert.Empty(t, result)
}
