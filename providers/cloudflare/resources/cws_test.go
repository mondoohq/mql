// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/cloudflare/cloudflare-go/v7/packages/pagination"
	"github.com/cloudflare/cloudflare-go/v7/zero_trust"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// All CWS fixtures are synthetic: no account with Cloud Web Security was
// available. The shapes follow the cloudflare-go v7.14.0 response types.

func cwsPage(result, cursor string) string {
	return `{"success":true,"errors":[],"messages":[],"result":[` + result + `],"result_info":{"count":1,"per_page":100,"cursor":"` + cursor + `"}}`
}

func cwsHandle(env *testEnv, path, body string) {
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cws/%s", testAccountID, path), func(w http.ResponseWriter, r *http.Request) {
		jsonResponse(w, body)
	})
}

const (
	cwsDeploymentProd = `{
		"id":"d0000000-0000-0000-0000-000000000001","name":"prod","description":"production egress",
		"default_mode":"BLOCK","on_error_action":"SKIP","rego_raise_error":true,
		"policy_set_ids":["s0000000-0000-0000-0000-000000000001"],
		"domain_acl_id":"a0000000-0000-0000-0000-000000000001",
		"basic_auth_credential_ids":["c0000000-0000-0000-0000-000000000001"],
		"tags":{"env":"prod"},
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-02T00:00:00Z"}`
	cwsDeploymentBare = `{
		"id":"d0000000-0000-0000-0000-000000000002","name":"open",
		"default_mode":"ALLOW","on_error_action":"BLOCK","rego_raise_error":false,
		"policy_set_ids":null,"basic_auth_credential_ids":null,"tags":{},
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsPolicySet = `{
		"id":"s0000000-0000-0000-0000-000000000001","name":"baseline",
		"policies":[{"policy_id":"p0000000-0000-0000-0000-000000000001","enforce":true},
		            {"policy_id":"p0000000-0000-0000-0000-000000000002","enforce":false}],
		"include_workload_ids":["w0000000-0000-0000-0000-000000000001"],
		"exclude_workload_ids":["w0000000-0000-0000-0000-000000000002"],
		"tags":{},"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsPolicyEnforced = `{
		"id":"p0000000-0000-0000-0000-000000000001","name":"deny-uploads","description":"block uploads",
		"entrypoint":"deny","filter":"http.request.method == \"POST\"","package_path":"policy.uploads",
		"rego_source":"package policy.uploads\ndeny := true","tags":{"owner":"sec"},
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-03T00:00:00Z"}`
	cwsPolicyMonitor = `{
		"id":"p0000000-0000-0000-0000-000000000002","name":"audit-only",
		"entrypoint":"allow","filter":"true","package_path":"policy.audit",
		"rego_source":"package policy.audit\nallow := true","tags":{},
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsPolicyOrphan = `{
		"id":"p0000000-0000-0000-0000-000000000003","name":"orphan",
		"entrypoint":"deny","filter":"true","package_path":"policy.orphan",
		"rego_source":"package policy.orphan\ndeny := false","tags":{},
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsWorkloadA = `{"id":"w0000000-0000-0000-0000-000000000001","name":"ci","filter":"ip.src in {10.0.0.0/8}","tags":{},
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsWorkloadB = `{"id":"w0000000-0000-0000-0000-000000000002","name":"healthchecks","filter":"http.request.uri.path == \"/health\"","tags":{},
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsDomainACL = `{"id":"a0000000-0000-0000-0000-000000000001","name":"allowlist","default_action":"BLOCK",
		"entries":[{"domain":"github.com","action":"ALLOW"},{"domain":"evil.example","action":"BLOCK"}],
		"created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsCredentialUsed   = `{"id":"c0000000-0000-0000-0000-000000000001","username":"ci-bot","created_at":"2026-10-01T00:00:00Z","updated_at":"2026-10-01T00:00:00Z"}`
	cwsCredentialUnused = `{"id":"c0000000-0000-0000-0000-000000000002","username":"old-bot","created_at":"2025-01-01T00:00:00Z","updated_at":"2025-01-01T00:00:00Z"}`
)

func setupCws(t *testing.T) (*testEnv, *mqlCloudflareOneCws) {
	t.Helper()
	env := setupTestEnv(t)
	one := createTestOne(t, env)

	cwsHandle(env, "deployments", cwsPage(cwsDeploymentProd+","+cwsDeploymentBare, ""))
	cwsHandle(env, "policy-sets", cwsPage(cwsPolicySet, ""))
	cwsHandle(env, "policies", cwsPage(cwsPolicyEnforced+","+cwsPolicyMonitor+","+cwsPolicyOrphan, ""))
	cwsHandle(env, "workloads", cwsPage(cwsWorkloadA+","+cwsWorkloadB, ""))
	cwsHandle(env, "domain-acls", cwsPage(cwsDomainACL, ""))
	cwsHandle(env, "basic-auth-credentials", cwsPage(cwsCredentialUsed+","+cwsCredentialUnused, ""))
	// Anything below a credential is its secrets, which must never be read.
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cws/basic-auth-credentials/", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("credential secrets endpoint was called: %s", r.URL.Path)
		w.WriteHeader(http.StatusTeapot)
	})

	cws, err := one.cws()
	require.NoError(t, err)
	return env, cws
}

func cwsByName[T any](t *testing.T, list []any, name func(T) string, want string) T {
	t.Helper()
	for _, r := range list {
		if v := r.(T); name(v) == want {
			return v
		}
	}
	t.Fatalf("no resource named %q", want)
	var zero T
	return zero
}

func TestCwsDeployments(t *testing.T) {
	_, cws := setupCws(t)

	list, err := cws.deployments()
	require.NoError(t, err)
	require.Len(t, list, 2)

	prod := list[0].(*mqlCloudflareOneCwsDeployment)
	assert.Equal(t, "prod", prod.Name.Data)
	assert.Equal(t, "production egress", prod.Description.Data)
	assert.Equal(t, "BLOCK", prod.DefaultMode.Data)
	assert.Equal(t, "SKIP", prod.OnErrorAction.Data)
	assert.True(t, prod.RegoRaiseError.Data)
	assert.Equal(t, map[string]any{"env": "prod"}, prod.Tags.Data)
	assert.Equal(t, 2, prod.UpdatedAt.Data.Day())

	sets, err := prod.policySets()
	require.NoError(t, err)
	require.Len(t, sets, 1)
	assert.Equal(t, "baseline", sets[0].(*mqlCloudflareOneCwsPolicySet).Name.Data)

	acl, err := prod.domainAcl()
	require.NoError(t, err)
	require.NotNil(t, acl)
	assert.Equal(t, "allowlist", acl.Name.Data)

	creds, err := prod.basicAuthCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "ci-bot", creds[0].(*mqlCloudflareOneCwsBasicAuthCredential).Username.Data)

	// A deployment that passes unmatched traffic and has nothing attached: no
	// description, no domain ACL, empty attachments.
	open := list[1].(*mqlCloudflareOneCwsDeployment)
	assert.Equal(t, "ALLOW", open.DefaultMode.Data)
	assert.True(t, open.Description.IsNull(), "an absent description must read null, not empty")
	acl, err = open.domainAcl()
	require.NoError(t, err)
	assert.Nil(t, acl)
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, open.DomainAcl.State)
	sets, err = open.policySets()
	require.NoError(t, err)
	assert.Empty(t, sets)
}

func TestCwsPolicySetMembersAndWorkloads(t *testing.T) {
	_, cws := setupCws(t)

	list, err := cws.policySets()
	require.NoError(t, err)
	require.Len(t, list, 1)
	set := list[0].(*mqlCloudflareOneCwsPolicySet)
	assert.True(t, set.Description.IsNull())

	members, err := set.members()
	require.NoError(t, err)
	require.Len(t, members, 2)
	m0 := members[0].(*mqlCloudflareOneCwsPolicySetMember)
	m1 := members[1].(*mqlCloudflareOneCwsPolicySetMember)
	assert.True(t, m0.Enforce.Data)
	assert.False(t, m1.Enforce.Data, "a monitor-only membership must not read as enforcing")
	assert.NotEqual(t, m0.MqlID(), m1.MqlID())

	p0, err := m0.policy()
	require.NoError(t, err)
	assert.Equal(t, "deny-uploads", p0.Name.Data)
	p1, err := m1.policy()
	require.NoError(t, err)
	assert.Equal(t, "audit-only", p1.Name.Data)

	inc, err := set.includeWorkloads()
	require.NoError(t, err)
	require.Len(t, inc, 1)
	assert.Equal(t, "ci", inc[0].(*mqlCloudflareOneCwsWorkload).Name.Data)
	exc, err := set.excludeWorkloads()
	require.NoError(t, err)
	require.Len(t, exc, 1)
	assert.Equal(t, "healthchecks", exc[0].(*mqlCloudflareOneCwsWorkload).Name.Data)

	deps, err := set.deployments()
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "prod", deps[0].(*mqlCloudflareOneCwsDeployment).Name.Data)
}

func TestCwsPolicies(t *testing.T) {
	_, cws := setupCws(t)

	list, err := cws.policies()
	require.NoError(t, err)
	require.Len(t, list, 3)

	name := func(p *mqlCloudflareOneCwsPolicy) string { return p.Name.Data }
	p := cwsByName(t, list, name, "deny-uploads")
	assert.Equal(t, "block uploads", p.Description.Data)
	assert.Equal(t, "deny", p.Entrypoint.Data)
	assert.Equal(t, `http.request.method == "POST"`, p.Filter.Data)
	assert.Equal(t, "policy.uploads", p.PackagePath.Data)
	assert.Contains(t, p.RegoSource.Data, "package policy.uploads")
	assert.Equal(t, map[string]any{"owner": "sec"}, p.Tags.Data)

	sets, err := p.policySets()
	require.NoError(t, err)
	require.Len(t, sets, 1)

	// A policy that no set references never runs.
	orphan := cwsByName(t, list, name, "orphan")
	sets, err = orphan.policySets()
	require.NoError(t, err)
	assert.Empty(t, sets)
}

func TestCwsDomainAclsAndCredentials(t *testing.T) {
	_, cws := setupCws(t)

	acls, err := cws.domainAcls()
	require.NoError(t, err)
	require.Len(t, acls, 1)
	acl := acls[0].(*mqlCloudflareOneCwsDomainAcl)
	assert.Equal(t, "BLOCK", acl.DefaultAction.Data)
	assert.Equal(t, map[string]any{"github.com": "ALLOW", "evil.example": "BLOCK"}, acl.Entries.Data)
	deps, err := acl.deployments()
	require.NoError(t, err)
	require.Len(t, deps, 1)

	creds, err := cws.basicAuthCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 2)
	name := func(c *mqlCloudflareOneCwsBasicAuthCredential) string { return c.Username.Data }

	used := cwsByName(t, creds, name, "ci-bot")
	deps, err = used.deployments()
	require.NoError(t, err)
	require.Len(t, deps, 1)
	assert.Equal(t, "prod", deps[0].(*mqlCloudflareOneCwsDeployment).Name.Data)

	unused := cwsByName(t, creds, name, "old-bot")
	deps, err = unused.deployments()
	require.NoError(t, err)
	assert.Empty(t, deps, "a credential no deployment accepts must report no deployments")
}

func TestCwsUnavailableDegradesToEmpty(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cws/policies", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10000,"message":"not entitled"}]}`)
	})
	cws, err := one.cws()
	require.NoError(t, err)

	list, err := cws.policies()
	require.NoError(t, err)
	assert.Empty(t, list)
}

func TestCwsCredentialScopeFailureSurfaces(t *testing.T) {
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cws/deployments", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		jsonResponse(w, `{"success":false,"errors":[{"code":10002,"message":"Authorization Failure"}]}`)
	})
	cws, err := one.cws()
	require.NoError(t, err)

	_, err = cws.deployments()
	assert.Error(t, err, "a credential failure must not read as an account without deployments")
}

func TestCwsListAllFollowsCursorOverHTTP(t *testing.T) {
	// Synthetic: two pages joined by a cursor.
	var cursors []string
	env := setupTestEnv(t)
	one := createTestOne(t, env)
	env.Mux.HandleFunc(fmt.Sprintf("/accounts/%s/cws/workloads", testAccountID), func(w http.ResponseWriter, r *http.Request) {
		cursors = append(cursors, r.URL.Query().Get("cursor"))
		assert.Equal(t, "100", r.URL.Query().Get("per_page"))
		switch r.URL.Query().Get("cursor") {
		case "":
			jsonResponse(w, cwsPage(cwsWorkloadA, "next-1"))
		default:
			jsonResponse(w, cwsPage(cwsWorkloadB, ""))
		}
	})
	cws, err := one.cws()
	require.NoError(t, err)
	list, err := cws.workloads()
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, []string{"", "next-1"}, cursors)
}

func fakeCursorPage(ids []string, cursor string) *pagination.CursorPagination[zero_trust.Workload] {
	page := &pagination.CursorPagination[zero_trust.Workload]{}
	for _, id := range ids {
		page.Result = append(page.Result, zero_trust.Workload{ID: id})
	}
	page.ResultInfo.Cursor = cursor
	return page
}

func TestCwsListAll(t *testing.T) {
	t.Run("stops on a repeated cursor", func(t *testing.T) {
		// Synthetic: a server that keeps returning the same cursor.
		calls := 0
		got, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.Workload], error) {
			calls++
			if calls > 10 {
				t.Fatal("walk did not stop on a repeated cursor")
			}
			return fakeCursorPage([]string{"w" + cursor}, "same"), nil
		})
		require.NoError(t, err)
		assert.Len(t, got, 2)
		assert.Equal(t, 2, calls)
	})

	t.Run("stops on an empty page even with a cursor", func(t *testing.T) {
		calls := 0
		got, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.Workload], error) {
			calls++
			if cursor == "" {
				return fakeCursorPage([]string{"a"}, "c1"), nil
			}
			return fakeCursorPage(nil, "c2"), nil
		})
		require.NoError(t, err)
		assert.Len(t, got, 1)
		assert.Equal(t, 2, calls)
	})

	t.Run("propagates an error", func(t *testing.T) {
		_, err := cwsListAll(func(cursor string) (*pagination.CursorPagination[zero_trust.Workload], error) {
			return nil, errors.New("boom")
		})
		assert.Error(t, err)
	})
}

func TestCwsResolve(t *testing.T) {
	id := func(r any) string { return r.(string) }
	list := []any{"a", "b", "c"}

	assert.Equal(t, []any{"c", "a"}, cwsResolve([]string{"c", "a"}, list, id), "order follows the reference list")
	assert.Equal(t, []any{"b"}, cwsResolve([]string{"missing", "b"}, list, id), "an unknown id is skipped")
	assert.Empty(t, cwsResolve(nil, list, id))
}

func TestCwsDomainACLEntries(t *testing.T) {
	got := cwsDomainACLEntries([]zero_trust.DomainACLEntry{
		{Domain: "a.example", Action: zero_trust.DomainACLEntriesActionAllow},
		{Domain: "*.b.example", Action: zero_trust.DomainACLEntriesActionBlock},
	})
	assert.Equal(t, map[string]any{"a.example": "ALLOW", "*.b.example": "BLOCK"}, got)
	assert.Empty(t, cwsDomainACLEntries(nil))
}
