// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestIsAdminToken(t *testing.T) {
	tests := []struct {
		token string
		want  bool
	}{
		{"sk-admin-abc123", true},
		{"sk-proj-abc123", false},
		{"sk-abc123", false},
		{"", false},
	}
	for _, tc := range tests {
		assert.Equal(t, tc.want, isAdminToken(tc.token), tc.token)
	}
}

func TestFetchAccountInfo(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantOrgID string
		wantName  string
	}{
		{
			name:      "single org",
			body:      `{"orgs":{"data":[{"id":"org-1","name":"Acme","is_default":true}]}}`,
			wantOrgID: "org-1",
			wantName:  "Acme",
		},
		{
			name:      "prefers the default org over the first",
			body:      `{"orgs":{"data":[{"id":"org-1","name":"First","is_default":false},{"id":"org-2","name":"Default","is_default":true}]}}`,
			wantOrgID: "org-2",
			wantName:  "Default",
		},
		{
			name:      "falls back to the first org when none is default",
			body:      `{"orgs":{"data":[{"id":"org-1","name":"First","is_default":false},{"id":"org-2","name":"Second","is_default":false}]}}`,
			wantOrgID: "org-1",
			wantName:  "First",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				assert.Equal(t, "/v1/me", r.URL.Path)
				assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			info, err := fetchAccountInfo(srv.URL, "test-token")
			require.NoError(t, err)
			assert.Equal(t, tc.wantOrgID, info.OrgID)
			assert.Equal(t, tc.wantName, info.OrgName)
		})
	}
}

// /v1/me is undocumented, so its response size is not a contract we control.
// A body past the cap must stop the read rather than let connect-time org
// detection allocate whatever the endpoint sends.
func TestFetchAccountInfoCapsTheBody(t *testing.T) {
	padding := strings.Repeat("x", maxAccountInfoBody)
	body := `{"orgs":{"data":[{"id":"org-abc","name":"` + padding + `","is_default":true}]}}`
	require.Greater(t, len(body), maxAccountInfoBody, "the test body has to exceed the cap to exercise it")

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	info, err := fetchAccountInfo(srv.URL, "sk-test")
	require.Error(t, err, "the read stopped at the cap")
	assert.Contains(t, err.Error(), "exceeded the 1048576 byte limit",
		"a capped read has to name itself: the truncated JSON would otherwise fail with a generic syntax error that reads like a malformed response")
	assert.Nil(t, info)
}

func TestResolveTokens(t *testing.T) {
	tests := []struct {
		name       string
		tokenFlag  string
		adminFlag  string
		tokenEnv   string
		adminEnv   string
		wantProj   string
		wantAdmin  string
		reasonNote string
	}{
		{
			name: "no credentials", wantProj: "", wantAdmin: "",
		},
		{
			name:      "a project key stays on the data plane",
			tokenFlag: "sk-proj-one", wantProj: "sk-proj-one", wantAdmin: "",
		},
		{
			name:      "an admin key passed to --token is still detected by its prefix",
			tokenFlag: "sk-admin-one", wantProj: "", wantAdmin: "sk-admin-one",
			reasonNote: "sending an admin key to the data-plane endpoints would fail every call",
		},
		{
			name:      "both flags fill both planes",
			tokenFlag: "sk-proj-one", adminFlag: "sk-admin-one",
			wantProj: "sk-proj-one", wantAdmin: "sk-admin-one",
		},
		{
			name:     "both environment variables fill both planes",
			tokenEnv: "sk-proj-one", adminEnv: "sk-admin-one",
			wantProj: "sk-proj-one", wantAdmin: "sk-admin-one",
		},
		{
			name:      "flags win over the environment",
			tokenFlag: "sk-proj-flag", adminFlag: "sk-admin-flag",
			tokenEnv: "sk-proj-env", adminEnv: "sk-admin-env",
			wantProj: "sk-proj-flag", wantAdmin: "sk-admin-flag",
		},
		{
			name:      "--admin-token names the plane whatever the prefix",
			adminFlag: "sk-one", wantProj: "", wantAdmin: "sk-one",
		},
		{
			name:      "an admin key in --token does not displace an explicit admin token",
			tokenFlag: "sk-admin-one", adminFlag: "sk-admin-two",
			wantProj: "", wantAdmin: "sk-admin-two",
		},
		{
			name:     "a project key from the environment pairs with an admin flag",
			tokenEnv: "sk-proj-one", adminFlag: "sk-admin-one",
			wantProj: "sk-proj-one", wantAdmin: "sk-admin-one",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			proj, admin := resolveTokens(tc.tokenFlag, tc.adminFlag, tc.tokenEnv, tc.adminEnv)
			assert.Equal(t, tc.wantProj, proj, tc.reasonNote)
			assert.Equal(t, tc.wantAdmin, admin, tc.reasonNote)
		})
	}
}

func newTestConnection(t *testing.T, options map[string]string) *OpenaiConnection {
	t.Helper()
	// Clear the environment so an ambient key cannot leak in, and set an
	// organization so the constructor skips its best-effort /v1/me call.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENAI_ADMIN_KEY", "")
	t.Setenv("OPENAI_ORG_ID", "")
	t.Setenv("OPENAI_PROJECT_ID", "")
	opts := map[string]string{OrganizationOption: "org-test"}
	maps.Copy(opts, options)
	conn, err := NewOpenaiConnection(0, &inventory.Asset{}, &inventory.Config{Options: opts})
	require.NoError(t, err)
	return conn
}

func TestConnectionPlanes(t *testing.T) {
	projectOnly := newTestConnection(t, map[string]string{TokenOption: "sk-proj-one"})
	assert.NotNil(t, projectOnly.Client())
	assert.Nil(t, projectOnly.AdminClient(), "a project key cannot read organization resources")
	assert.False(t, projectOnly.IsAdminKey())

	adminOnly := newTestConnection(t, map[string]string{TokenOption: "sk-admin-one"})
	assert.Nil(t, adminOnly.Client(), "an admin key cannot read data-plane resources")
	assert.NotNil(t, adminOnly.AdminClient())
	assert.True(t, adminOnly.IsAdminKey())

	// Both keys on one connection is what lets a query cross the two planes,
	// such as a fine-tuning checkpoint (project key) and the projects it is
	// shared into (admin key).
	both := newTestConnection(t, map[string]string{
		TokenOption:      "sk-proj-one",
		AdminTokenOption: "sk-admin-one",
	})
	require.NotNil(t, both.Client())
	require.NotNil(t, both.AdminClient())
	assert.True(t, both.IsAdminKey())

	none := newTestConnection(t, nil)
	assert.Nil(t, none.Client())
	assert.Nil(t, none.AdminClient())
}

func TestConnectionIdentityIsUnchangedByTheAdminToken(t *testing.T) {
	// The platform id keys the asset. Adding a second credential to an
	// existing connection must not re-key the asset it already scanned.
	t.Setenv("OPENAI_API_KEY", "")
	t.Setenv("OPENAI_ADMIN_KEY", "")
	t.Setenv("OPENAI_ORG_ID", "")
	t.Setenv("OPENAI_PROJECT_ID", "")

	projectOnly, err := NewOpenaiConnection(0, &inventory.Asset{}, &inventory.Config{Options: map[string]string{
		TokenOption: "sk-proj-one",
	}})
	require.NoError(t, err)

	withAdmin, err := NewOpenaiConnection(0, &inventory.Asset{}, &inventory.Config{Options: map[string]string{
		TokenOption:      "sk-proj-one",
		AdminTokenOption: "sk-admin-one",
	}})
	require.NoError(t, err)

	assert.Equal(t, projectOnly.PlatformId(), withAdmin.PlatformId())
}
