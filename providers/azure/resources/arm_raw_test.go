// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"github.com/stretchr/testify/require"
)

type armRawTestRow struct {
	armTrackedResource
	Properties *struct {
		State *string `json:"state"`
	} `json:"properties"`
}

func TestArmJSONPager(t *testing.T) {
	// Synthetic: two pages joined by a nextLink.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Query().Get("page") {
		case "":
			assert.Equal(t, "2025-04-01", r.URL.Query().Get("api-version"))
			_, _ = w.Write([]byte(`{"value":[{"id":"/subscriptions/s/resourceGroups/rg/providers/P/t/a","name":"a","location":"eastus","tags":{"env":"prod"},
				"identity":{"type":"SystemAssigned, UserAssigned","principalId":"p","tenantId":"t","userAssignedIdentities":{"/x/uai":{"principalId":"q"}}},
				"properties":{"state":"on"}}, null],"nextLink":"` + srv.URL + `/next?page=2"}`))
		case "2":
			_, _ = w.Write([]byte(`{"value":[{"id":"b-id","name":"b"}]}`))
		}
	}))
	defer srv.Close()

	client := testArmClient(t, srv)
	p := newArmJSONPager[armRawTestRow](client, "rows", armResourceURL(client, "/subscriptions/s/providers/P/t", "2025-04-01"))
	var got []*armRawTestRow
	for p.More() {
		page, err := p.NextPage(context.Background())
		require.NoError(t, err)
		got = append(got, page.Value...)
	}
	require.Len(t, got, 3)
	assert.Equal(t, "a", *got[0].Name)
	assert.Equal(t, "prod", *got[0].Tags["env"])
	assert.Equal(t, "on", *got[0].Properties.State)
	assert.Equal(t, "SystemAssigned, UserAssigned", *got[0].Identity.Type)
	assert.Equal(t, []string{"/x/uai"}, sortedUserAssignedIdentityIDs(got[0].Identity.UserAssignedIdentities))
	assert.Nil(t, got[1], "a null row stays nil for listPaged to skip")
	assert.Nil(t, got[2].Properties)
	assert.Nil(t, got[2].Identity)
}

func TestArmJSONPagerDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed","message":"denied"}}`))
	}))
	defer srv.Close()

	p := newArmJSONPager[armRawTestRow](testArmClient(t, srv), "rows", srv.URL+"/list")
	_, err := p.NextPage(context.Background())
	require.Error(t, err)
	// listPaged reports null only for a 403 ResponseError.
	assert.Equal(t, faultDenied, azureFault(err))
}

func TestArmJSONPagerCycle(t *testing.T) {
	// Synthetic: a nextLink that points back at an earlier page.
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/list" {
			_, _ = w.Write([]byte(`{"value":[],"nextLink":"` + srv.URL + `/two"}`))
			return
		}
		_, _ = w.Write([]byte(`{"value":[],"nextLink":"` + srv.URL + `/list"}`))
	}))
	defer srv.Close()

	p := newArmJSONPager[armRawTestRow](testArmClient(t, srv), "rows", srv.URL+"/list")
	_, err := p.NextPage(context.Background())
	require.NoError(t, err)
	_, err = p.NextPage(context.Background())
	require.NoError(t, err)
	_, err = p.NextPage(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cycled")
}

func TestArmGetJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/missing" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"NotFound"}}`))
			return
		}
		assert.Equal(t, "2025-09-01", r.URL.Query().Get("api-version"))
		_, _ = w.Write([]byte(`{"name":"ws"}`))
	}))
	defer srv.Close()

	client := testArmClient(t, srv)
	var out armTrackedResource
	require.NoError(t, armGetJSON(context.Background(), client, "/subscriptions/s/ws", "2025-09-01", &out))
	assert.Equal(t, "ws", *out.Name)

	err := armGetJSON(context.Background(), client, "/missing", "2025-09-01", &out)
	require.Error(t, err)
	assert.Equal(t, faultAbsent, azureFault(err))
}

func TestOrDefault(t *testing.T) {
	assert.Equal(t, "Enabled", orDefault(nil, "Enabled"))
	assert.Equal(t, "Enabled", orDefault(new(""), "Enabled"))
	assert.Equal(t, "Disabled", orDefault(new("Disabled"), "Enabled"))
}

func TestIsUserAssignedIdentityID(t *testing.T) {
	assert.True(t, isUserAssignedIdentityID("/subscriptions/s/resourceGroups/rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/mi"))
	assert.True(t, isUserAssignedIdentityID("/subscriptions/s/resourcegroups/rg/providers/microsoft.managedidentity/userassignedidentities/mi"))
	assert.False(t, isUserAssignedIdentityID("SystemAssigned"))
	assert.False(t, isUserAssignedIdentityID(""))
	assert.False(t, isUserAssignedIdentityID("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"))
}

func TestUserAssignedIdentityRefNull(t *testing.T) {
	// Synthetic: no identity, or a marker that names no user-assigned
	// identity, resolves to a set null rather than an unset field.
	for _, id := range []string{"", "SystemAssigned"} {
		var field plugin.TValue[*mqlAzureSubscriptionManagedIdentity]
		res, err := userAssignedIdentityRef(nil, id, &field)
		require.NoError(t, err)
		assert.Nil(t, res)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, field.State, id)
	}
}
