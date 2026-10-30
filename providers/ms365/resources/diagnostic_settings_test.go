// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// entraPayload is shaped like a real microsoft.aadiam/diagnosticSettings
// response: one setting exporting three of the categories it lists, with a Log
// Analytics destination and no storage or Event Hub.
const entraPayload = `{
  "value": [
    {
      "id": "/providers/microsoft.aadiam/diagnosticSettings/entra-to-la",
      "name": "entra-to-la",
      "type": "microsoft.aadiam/diagnosticSettings",
      "properties": {
        "workspaceId": "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/logs/providers/Microsoft.OperationalInsights/workspaces/tenant-logs",
        "logs": [
          {"category": "AuditLogs", "enabled": true, "retentionPolicy": {"days": 0, "enabled": false}},
          {"category": "SignInLogs", "enabled": true, "retentionPolicy": {"days": 0, "enabled": false}},
          {"category": "MicrosoftGraphActivityLogs", "enabled": true, "retentionPolicy": {"days": 0, "enabled": false}},
          {"category": "ProvisioningLogs", "enabled": false, "retentionPolicy": {"days": 0, "enabled": false}}
        ]
      }
    }
  ]
}`

func TestArmDiagnosticSettingDecode(t *testing.T) {
	list := &armDiagnosticSettingsList{}
	require.NoError(t, json.Unmarshal([]byte(entraPayload), list))
	require.Len(t, list.Value, 1)

	got := list.Value[0]
	assert.Equal(t, "/providers/microsoft.aadiam/diagnosticSettings/entra-to-la", got.Id)
	assert.Equal(t, "entra-to-la", got.Name)
	assert.Equal(t, "microsoft.aadiam/diagnosticSettings", got.Type)

	// A mistyped destination tag decodes to "", which reads as "no destination
	// configured" on a setting that has one. Pin each destination tag.
	assert.Equal(t,
		"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/logs/providers/Microsoft.OperationalInsights/workspaces/tenant-logs",
		got.Properties.WorkspaceId)
	assert.Empty(t, got.Properties.StorageAccountId)
	assert.Empty(t, got.Properties.EventHubName)
	assert.Empty(t, got.Properties.EventHubAuthorizationRuleId)

	require.Len(t, got.Properties.Logs, 4)
	assert.Equal(t, "AuditLogs", got.Properties.Logs[0].Category)
	assert.True(t, got.Properties.Logs[0].Enabled)
	assert.False(t, got.Properties.Logs[3].Enabled)
}

func TestEnabledLogCategories(t *testing.T) {
	t.Run("returns only the categories that are switched on", func(t *testing.T) {
		list := &armDiagnosticSettingsList{}
		require.NoError(t, json.Unmarshal([]byte(entraPayload), list))

		// ProvisioningLogs is listed but disabled. A setting names every category
		// it knows about, so taking the list at face value would report a stream
		// as exported when it is switched off.
		assert.Equal(t,
			[]string{"AuditLogs", "SignInLogs", "MicrosoftGraphActivityLogs"},
			list.Value[0].Properties.enabledLogCategories())
	})

	t.Run("a setting that exports nothing reports an empty list", func(t *testing.T) {
		props := armDiagnosticSettingProperties{Logs: []armDiagnosticLogSetting{
			{Category: "AuditLogs", Enabled: false},
			{Category: "SignInLogs", Enabled: false},
		}}
		got := props.enabledLogCategories()
		assert.NotNil(t, got, "must be an empty list, not nil, so contains is answerable")
		assert.Empty(t, got)
	})

	t.Run("a setting with no logs at all reports an empty list", func(t *testing.T) {
		got := armDiagnosticSettingProperties{}.enabledLogCategories()
		assert.NotNil(t, got)
		assert.Empty(t, got)
	})

	// An unnamed category names no log stream. Keeping it would put "" into a
	// list that checks test with contains.
	t.Run("drops an entry with no category name", func(t *testing.T) {
		props := armDiagnosticSettingProperties{Logs: []armDiagnosticLogSetting{
			{Category: "", Enabled: true},
			{Category: "AuditLogs", Enabled: true},
		}}
		assert.Equal(t, []string{"AuditLogs"}, props.enabledLogCategories())
	})
}

func TestArmGet(t *testing.T) {
	t.Run("decodes a successful response and sends the bearer token", func(t *testing.T) {
		var gotAuth string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(entraPayload))
		}))
		defer srv.Close()

		list, err := armGet(context.Background(), "a-token", srv.URL)
		require.NoError(t, err)
		require.Len(t, list.Value, 1)
		assert.Equal(t, "Bearer a-token", gotAuth)
	})

	// A tenant with nothing configured answers 200 with an empty array. That is
	// a real finding and must not be confused with a failure.
	t.Run("an empty collection is not an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`{"value": []}`))
		}))
		defer srv.Close()

		list, err := armGet(context.Background(), "a-token", srv.URL)
		require.NoError(t, err)
		assert.Empty(t, list.Value)
	})

	// The failure that matters: credentials without the role get a 403. Reading
	// that as an empty collection would report "no diagnostic settings are
	// configured" for a tenant nobody was allowed to look at, and every check
	// over the categories would pass vacuously.
	t.Run("a forbidden response is an error, not an empty collection", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"AuthorizationFailed","message":"does not have authorization to perform action 'Microsoft.Intune/diagnosticSettings/read'"}}`))
		}))
		defer srv.Close()

		list, err := armGet(context.Background(), "a-token", srv.URL)
		require.Error(t, err)
		assert.Nil(t, list)
		assert.Contains(t, err.Error(), "403")
		assert.Contains(t, err.Error(), "AuthorizationFailed")
	})

	t.Run("a body that is not the expected shape is an error", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte(`not json`))
		}))
		defer srv.Close()

		_, err := armGet(context.Background(), "a-token", srv.URL)
		require.Error(t, err)
	})
}
