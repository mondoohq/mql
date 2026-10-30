// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"encoding/json"
	"testing"

	"github.com/portainer/client-api-go/v2/pkg/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
)

func TestGrantedAuthorizations(t *testing.T) {
	t.Run("nil map is not an empty grant", func(t *testing.T) {
		// An instance that computes no authorizations reports nothing, which is
		// not the same as an account holding none.
		got, ok := grantedAuthorizations(nil)
		assert.False(t, ok)
		assert.Nil(t, got)
	})

	t.Run("empty map is an empty grant", func(t *testing.T) {
		got, ok := grantedAuthorizations(map[string]bool{})
		assert.True(t, ok)
		assert.Equal(t, []any{}, got)
	})

	t.Run("revoked entries are dropped and the rest sorted", func(t *testing.T) {
		got, ok := grantedAuthorizations(map[string]bool{
			"DockerContainerCreate":  true,
			"DockerContainerDelete":  false,
			"PortainerEndpointizeIt": true,
		})
		assert.True(t, ok)
		assert.Equal(t, []any{"DockerContainerCreate", "PortainerEndpointizeIt"}, got)
	})
}

func TestAutoUpdateFields(t *testing.T) {
	t.Run("no auto-update leaves every detail null", func(t *testing.T) {
		got := autoUpdateFields(nil)
		assert.Equal(t, llx.BoolData(false), got["autoUpdateEnabled"])
		for _, key := range []string{
			"autoUpdateInterval", "autoUpdateWebhook",
			"autoUpdateForcePullImage", "autoUpdateForceUpdate",
		} {
			assert.Equal(t, llx.NilData, got[key], key)
		}
	})

	t.Run("scheduled auto-update", func(t *testing.T) {
		got := autoUpdateFields(&models.PortainerAutoUpdateSettings{
			Interval:       "5m",
			ForcePullImage: true,
			ForceUpdate:    true,
		})
		assert.Equal(t, llx.BoolData(true), got["autoUpdateEnabled"])
		assert.Equal(t, llx.StringData("5m"), got["autoUpdateInterval"])
		assert.Equal(t, llx.BoolData(false), got["autoUpdateWebhook"])
		assert.Equal(t, llx.BoolData(true), got["autoUpdateForcePullImage"])
		assert.Equal(t, llx.BoolData(true), got["autoUpdateForceUpdate"])
	})

	t.Run("webhook-driven auto-update reports no interval", func(t *testing.T) {
		got := autoUpdateFields(&models.PortainerAutoUpdateSettings{
			Webhook: "00000000-0000-4000-8000-000000000000",
		})
		assert.Equal(t, llx.BoolData(true), got["autoUpdateEnabled"])
		// An empty interval must not be reported as "redeploys immediately".
		assert.Equal(t, llx.NilData, got["autoUpdateInterval"])
		assert.Equal(t, llx.BoolData(true), got["autoUpdateWebhook"])
		assert.Equal(t, llx.BoolData(false), got["autoUpdateForcePullImage"])
	})
}

func TestGitFields(t *testing.T) {
	t.Run("no repository leaves every detail null", func(t *testing.T) {
		got := gitFields(nil)
		for _, key := range []string{
			"gitUrl", "gitReferenceName", "gitConfigFilePath",
			"gitTlsSkipVerify", "gitAuthenticationConfigured",
		} {
			assert.Equal(t, llx.NilData, got[key], key)
		}
	})

	t.Run("repository without credentials", func(t *testing.T) {
		got := gitFields(&models.GittypesRepoConfig{
			URL:            "https://git.example.invalid/app.git",
			ReferenceName:  "refs/heads/main",
			ConfigFilePath: "compose.yaml",
			TlsskipVerify:  true,
		})
		assert.Equal(t, llx.StringData("https://git.example.invalid/app.git"), got["gitUrl"])
		assert.Equal(t, llx.StringData("refs/heads/main"), got["gitReferenceName"])
		assert.Equal(t, llx.StringData("compose.yaml"), got["gitConfigFilePath"])
		assert.Equal(t, llx.BoolData(true), got["gitTlsSkipVerify"])
		assert.Equal(t, llx.BoolData(false), got["gitAuthenticationConfigured"])
	})

	t.Run("repository with credentials reports presence only", func(t *testing.T) {
		got := gitFields(&models.GittypesRepoConfig{
			URL:            "https://git.example.invalid/app.git",
			Authentication: &models.GittypesGitAuthentication{},
		})
		assert.Equal(t, llx.BoolData(true), got["gitAuthenticationConfigured"])
		// the credential itself must never reach the schema
		for _, v := range got {
			assert.NotContains(t, v.String(), "password")
		}
	})
}

func TestFindStackCreator(t *testing.T) {
	users := []*models.PortainereeUser{
		{ID: 1, Username: "admin"},
		{ID: 2, Username: "operator"},
	}

	t.Run("resolves by id", func(t *testing.T) {
		got := findStackCreator(users, "2", "operator")
		require.NotNil(t, got)
		assert.Equal(t, int64(2), got.ID)
	})

	t.Run("an id that no longer resolves does not fall back to the name", func(t *testing.T) {
		// A recreated account can reuse a login name, so attributing the stack
		// by name here would name the wrong account.
		assert.Nil(t, findStackCreator(users, "9", "operator"))
	})

	t.Run("falls back to the login name when no id was recorded", func(t *testing.T) {
		got := findStackCreator(users, "", "admin")
		require.NotNil(t, got)
		assert.Equal(t, int64(1), got.ID)
	})

	t.Run("a zero id is treated as unrecorded", func(t *testing.T) {
		got := findStackCreator(users, "0", "admin")
		require.NotNil(t, got)
		assert.Equal(t, int64(1), got.ID)
	})

	t.Run("nothing to match on", func(t *testing.T) {
		assert.Nil(t, findStackCreator(users, "", ""))
		assert.Nil(t, findStackCreator(users, "", "ghost"))
	})
}

func TestRegistryAccessEndpointIDs(t *testing.T) {
	got := registryAccessEndpointIDs(models.PortainerRegistryAccesses{
		"10":     {},
		"2":      {},
		"broken": {},
	})
	// sorted numerically, not lexically, and the unparseable key is dropped
	// rather than attributed to some environment
	assert.Equal(t, []int64{2, 10}, got)
	assert.Empty(t, registryAccessEndpointIDs(nil))
}

func TestEdgeJobEndpointIDs(t *testing.T) {
	got := edgeJobEndpointIDs(map[string]models.PortainerEdgeJobEndpointMeta{
		"10": {},
		"2":  {},
		"":   {},
	})
	assert.Equal(t, []int64{2, 10}, got)
	assert.Empty(t, edgeJobEndpointIDs(nil))
}

func TestUserEnvironmentAuthorizationIDs(t *testing.T) {
	got := userEnvironmentAuthorizationIDs(models.PortainerEndpointAuthorizations{
		"10":  {},
		"2":   {},
		"n/a": {},
	})
	assert.Equal(t, []int64{2, 10}, got)
	assert.Empty(t, userEnvironmentAuthorizationIDs(nil))
}

// TestDecodeStackPayload pins the decoding of a stack against the key casing a
// Portainer server actually sends, which differs from the SDK's struct tags for
// several security-relevant fields.
func TestDecodeStackPayload(t *testing.T) {
	// Shaped like a GET /stacks entry, with zero-entropy placeholder values.
	raw := `{
		"Id": 3,
		"Name": "git-stack",
		"Type": 2,
		"Status": 1,
		"EndpointId": 1,
		"EntryPoint": "compose.yaml",
		"CreatedBy": "admin",
		"createdByUserId": "1",
		"creationDate": 1700000000,
		"AutoUpdate": {
			"Interval": "",
			"Webhook": "00000000-0000-4000-8000-000000000000",
			"ForceUpdate": true,
			"ForcePullImage": true
		},
		"GitConfig": {
			"URL": "https://git.example.invalid/app.git",
			"ReferenceName": "refs/heads/main",
			"ConfigFilePath": "compose.yaml",
			"Authentication": null,
			"TLSSkipVerify": true
		},
		"webhook": "00000000-0000-4000-8000-000000000001"
	}`

	var s models.PortainereeStack
	require.NoError(t, json.Unmarshal([]byte(raw), &s))

	assert.Equal(t, int64(3), s.ID)
	assert.Equal(t, int64(2), s.Type)
	assert.Equal(t, int64(1), s.Status)
	assert.Equal(t, int64(1), s.EndpointID)
	assert.Equal(t, "1", s.CreatedByUserID)
	assert.Equal(t, int64(1700000000), s.CreationDate)
	require.NotNil(t, s.AutoUpdate)
	assert.True(t, s.AutoUpdate.ForcePullImage, "a redeploy that re-resolves a mutable tag must not read as false")
	assert.True(t, s.AutoUpdate.ForceUpdate)
	require.NotNil(t, s.GitConfig)
	assert.True(t, s.GitConfig.TlsskipVerify, "the server sends TLSSkipVerify; a skipped check must not read as false")
	assert.Nil(t, s.GitConfig.Authentication)
	assert.NotEmpty(t, s.Webhook)

	// and the mapping derived from it
	auto := autoUpdateFields(s.AutoUpdate)
	assert.Equal(t, llx.BoolData(true), auto["autoUpdateWebhook"])
	assert.Equal(t, llx.NilData, auto["autoUpdateInterval"])
	git := gitFields(s.GitConfig)
	assert.Equal(t, llx.BoolData(true), git["gitTlsSkipVerify"])
}

// TestDecodeRegistryPayload pins the decoding of a registry, including that the
// list response carries no password for the schema to leak.
func TestDecodeRegistryPayload(t *testing.T) {
	raw := `{
		"Id": 1,
		"Type": 3,
		"Name": "internal-registry",
		"URL": "registry.example.invalid:5000",
		"BaseURL": "",
		"Authentication": true,
		"Username": "puller",
		"Password": "",
		"RegistryAccesses": {
			"1": {
				"UserAccessPolicies": {"2": {"RoleId": 3}},
				"TeamAccessPolicies": {"1": {"RoleId": 4}},
				"Namespaces": null
			}
		}
	}`

	var r models.PortainereeRegistry
	require.NoError(t, json.Unmarshal([]byte(raw), &r))

	assert.Equal(t, int64(3), r.Type)
	assert.True(t, r.Authentication, "a registry Portainer holds a credential for must not read as unauthenticated")
	assert.Equal(t, "puller", r.Username)
	require.Len(t, r.RegistryAccesses, 1)
	access := r.RegistryAccesses["1"]
	assert.Equal(t, int64(4), access.TeamAccessPolicies["1"].RoleID)
	assert.Equal(t, int64(3), access.UserAccessPolicies["2"].RoleID)
	assert.Equal(t, []int64{1}, registryAccessEndpointIDs(r.RegistryAccesses))
}

// TestDecodeWebhookPayload pins the decoding of a webhook, whose keys are all
// capitalized on the wire.
func TestDecodeWebhookPayload(t *testing.T) {
	raw := `{"Id":1,"Token":"00000000-0000-4000-8000-000000000000","ResourceId":"deadbeef","EndpointId":1,"RegistryId":2,"Type":1}`

	var w models.PortainerWebhook
	require.NoError(t, json.Unmarshal([]byte(raw), &w))

	assert.Equal(t, int64(1), w.ID)
	assert.Equal(t, "deadbeef", w.ResourceID)
	assert.Equal(t, int64(1), w.EndpointID)
	assert.Equal(t, int64(2), w.RegistryID)
	assert.Equal(t, int64(1), w.Type)
}

// TestDecodeEndpointMTLS pins the mutual-TLS block on an environment, which is
// absent on instances that do not report it.
func TestDecodeEndpointMTLS(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		var e models.PortainereeEndpoint
		require.NoError(t, json.Unmarshal([]byte(`{"Id":1,"Name":"local"}`), &e))
		assert.Nil(t, e.MTLSStatus)

		enabled, ok := mtlsFields(e.MTLSStatus)
		// "not reported" must stay null; a fabricated false would let a
		// null-tolerant assertion pass on an unverified environment.
		assert.Equal(t, llx.NilData, enabled)
		assert.Equal(t, llx.NilData, ok)
	})

	t.Run("reported", func(t *testing.T) {
		var e models.PortainereeEndpoint
		require.NoError(t, json.Unmarshal([]byte(`{"Id":1,"MTLSStatus":{"enabled":true,"ok":false}}`), &e))
		require.NotNil(t, e.MTLSStatus)

		enabled, ok := mtlsFields(e.MTLSStatus)
		assert.Equal(t, llx.BoolData(true), enabled)
		assert.Equal(t, llx.BoolData(false), ok)
	})
}

// TestDecodeAPIKeyPayload pins an API key, whose lastUsed is 0 for a key that
// has never authenticated a request.
func TestDecodeAPIKeyPayload(t *testing.T) {
	raw := `[{"id":2,"userId":2,"description":"never-used-key","prefix":"ptr_000","dateCreated":1700000000,"lastUsed":0}]`

	var keys []*models.PortainerAPIKey
	require.NoError(t, json.Unmarshal([]byte(raw), &keys))
	require.Len(t, keys, 1)

	assert.Equal(t, int64(2), keys[0].ID)
	assert.Equal(t, int64(2), keys[0].UserID)
	assert.Equal(t, "ptr_000", keys[0].Prefix)
	assert.Equal(t, int64(1700000000), keys[0].DateCreated)
	// a key that has never been used must read as null, not as the 1970 epoch
	assert.Nil(t, unixTimePtr(keys[0].LastUsed))
}

// TestDecodeEdgeJobPayload pins an Edge job, whose targeted environments arrive
// as a map keyed by environment id.
func TestDecodeEdgeJobPayload(t *testing.T) {
	raw := `{"Id":1,"Created":1700000000,"CronExpression":"0 2 * * *","Endpoints":{"2":{"LogsStatus":0,"CollectLogs":false}},"EdgeGroups":[1],"Name":"nightly-audit","ScriptPath":"/data/edge_jobs/1/job_1.sh","Recurring":true,"Version":1}`

	var j models.PortainerEdgeJob
	require.NoError(t, json.Unmarshal([]byte(raw), &j))

	assert.Equal(t, "0 2 * * *", j.CronExpression)
	assert.True(t, j.Recurring)
	assert.Equal(t, []int64{1}, j.EdgeGroups)
	assert.Equal(t, []int64{2}, edgeJobEndpointIDs(j.Endpoints))
}

// TestDecodeRolePayload pins a role definition, whose authorizations decide what
// a role named readonly_user may actually do.
func TestDecodeRolePayload(t *testing.T) {
	raw := `{"Id":4,"Name":"readonly_user","Description":"Read-only access","Priority":4,"Authorizations":{"DockerContainerList":true,"DockerContainerCreate":false},"Scope":{}}`

	var r models.PortainereeRole
	require.NoError(t, json.Unmarshal([]byte(raw), &r))

	require.NotNil(t, r.ID)
	assert.Equal(t, int64(4), *r.ID)
	require.NotNil(t, r.Name)
	assert.Equal(t, "readonly_user", *r.Name)

	names, ok := grantedAuthorizations(r.Authorizations)
	assert.True(t, ok)
	assert.Equal(t, []any{"DockerContainerList"}, names)
}
