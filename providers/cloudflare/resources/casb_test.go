// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

const casbPolicyRemediating = `{
  "id": "11111111-1111-1111-1111-111111111111",
  "display_name": "Revoke public sharing",
  "description": "Removes public links from shared files",
  "enabled": true,
  "finding_type_id": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
  "applies_to_all_integrations": false,
  "integration_ids": ["int-1", "int-2"],
  "actions": {
    "remediation_types": [
      {"remediation_type_id": "rt-1", "remediation_type": "remove_public_link", "display_name": "Remove public link"}
    ],
    "webhook_configs": [
      {"webhook_config_id": "wh-1", "display_name": "SOC channel"}
    ]
  },
  "created_at": "2026-01-02T03:04:05Z",
  "updated_at": "2026-02-03T04:05:06Z",
  "last_triggered_at": "2026-03-04T05:06:07Z"
}`

const casbPolicyReportOnly = `{
  "id": "22222222-2222-2222-2222-222222222222",
  "display_name": "Notify only",
  "description": "",
  "enabled": false,
  "finding_type_id": "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb",
  "applies_to_all_integrations": true,
  "integration_ids": [],
  "actions": {"remediation_types": [], "webhook_configs": []},
  "created_at": "2026-01-02T03:04:05Z",
  "updated_at": "2026-01-02T03:04:05Z"
}`

func casbPage(result string, resultInfo string) string {
	return `{"success":true,"errors":[],"messages":[],"result":[` + result + `],"result_info":` + resultInfo + `}`
}

func TestCasbPosturePoliciesFields(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/data-security/posture/policies", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		jsonResponse(w, casbPage(casbPolicyRemediating+","+casbPolicyReportOnly, `{"cursors":{"after":""}}`))
	})

	result, err := one.casbPosturePolicies()
	require.NoError(t, err)
	require.Len(t, result, 2)

	p := result[0].(*mqlCloudflareOneCasbPosturePolicy)
	assert.Equal(t, "11111111-1111-1111-1111-111111111111", p.Id.Data)
	assert.Equal(t, "Revoke public sharing", p.DisplayName.Data)
	assert.Equal(t, "Removes public links from shared files", p.Description.Data)
	assert.True(t, p.Enabled.Data)
	assert.Equal(t, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", p.FindingTypeId.Data)
	assert.False(t, p.AppliesToAllIntegrations.Data)
	assert.Equal(t, []any{"int-1", "int-2"}, p.IntegrationIds.Data)
	assert.Equal(t, 2026, p.LastTriggeredAt.Data.Year())
	assert.Equal(t, 3, int(p.LastTriggeredAt.Data.Month()))
	assert.Equal(t, 2, int(p.UpdatedAt.Data.Month()))

	require.Len(t, p.Remediations.Data, 1)
	rem := p.Remediations.Data[0].(*mqlCloudflareOneCasbPosturePolicyRemediation)
	assert.Equal(t, "rt-1", rem.Id.Data)
	assert.Equal(t, "remove_public_link", rem.Type.Data)
	assert.Equal(t, "Remove public link", rem.DisplayName.Data)

	require.Len(t, p.Webhooks.Data, 1)
	wh := p.Webhooks.Data[0].(*mqlCloudflareOneCasbPosturePolicyWebhook)
	assert.Equal(t, "wh-1", wh.Id.Data)
	assert.Equal(t, "SOC channel", wh.DisplayName.Data)

	q := result[1].(*mqlCloudflareOneCasbPosturePolicy)
	assert.False(t, q.Enabled.Data)
	assert.True(t, q.AppliesToAllIntegrations.Data)
	assert.Empty(t, q.Remediations.Data)
	assert.Empty(t, q.Webhooks.Data)
	assert.True(t, q.LastTriggeredAt.State&plugin.StateIsNull != 0,
		"a policy that never ran must report a null lastTriggeredAt, not year 1")
}

// The endpoint documents its cursor as result_info.cursor while the SDK
// paginator reads result_info.cursors.after. Both spellings must reach the
// second page, or policies past the first page silently disappear.
func TestCasbPosturePoliciesPagination(t *testing.T) {
	for _, tc := range []struct {
		name     string
		nextInfo string
	}{
		{name: "cursors.after", nextInfo: `{"cursors":{"after":"page2"}}`},
		{name: "cursor", nextInfo: `{"cursor":"page2"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := setupTestEnv(t)
			one := createTestOne(t, env)

			env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/data-security/posture/policies", testAccountID), func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Query().Get("cursor") {
				case "":
					jsonResponse(w, casbPage(casbPolicyRemediating, tc.nextInfo))
				case "page2":
					jsonResponse(w, casbPage(casbPolicyReportOnly, `{}`))
				default:
					t.Errorf("unexpected cursor %q", r.URL.Query().Get("cursor"))
				}
			})

			result, err := one.casbPosturePolicies()
			require.NoError(t, err)
			require.Len(t, result, 2)
			assert.Equal(t, "22222222-2222-2222-2222-222222222222", result[1].(*mqlCloudflareOneCasbPosturePolicy).Id.Data)
		})
	}
}

// A server that keeps returning the cursor it was just given must not loop
// the walk forever.
func TestCasbPosturePoliciesStuckCursor(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	var calls atomic.Int32
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/data-security/posture/policies", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) > 5 {
			t.Error("pagination did not stop on a repeated cursor")
			jsonResponse(w, casbPage("", `{}`))
			return
		}
		jsonResponse(w, casbPage(casbPolicyRemediating, `{"cursors":{"after":"same"}}`))
	})

	_, err := one.casbPosturePolicies()
	require.NoError(t, err)
	assert.Equal(t, int32(2), calls.Load())
}

func TestCasbPosturePoliciesForbiddenIsEmpty(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/data-security/posture/policies", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":10000,"message":"Authentication error"}],"messages":[],"result":null}`))
	})

	result, err := one.casbPosturePolicies()
	require.NoError(t, err)
	assert.Empty(t, result)
}
