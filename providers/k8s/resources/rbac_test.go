// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/utils/syncx"
	rbacv1 "k8s.io/api/rbac/v1"
)

func rbacRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile("./testdata/rbac-rules.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func clusterRoleByName(t *testing.T, k8s *mqlK8s, name string) *mqlK8sRbacClusterrole {
	t.Helper()
	roles := k8s.GetClusterroles()
	require.NoError(t, roles.Error)
	for i := range roles.Data {
		r := roles.Data[i].(*mqlK8sRbacClusterrole)
		if r.GetName().Data == name {
			return r
		}
	}
	require.FailNowf(t, "clusterrole not found", "clusterrole %q not found", name)
	return nil
}

func roleByName(t *testing.T, k8s *mqlK8s, name string) *mqlK8sRbacRole {
	t.Helper()
	roles := k8s.GetRoles()
	require.NoError(t, roles.Error)
	for i := range roles.Data {
		r := roles.Data[i].(*mqlK8sRbacRole)
		if r.GetName().Data == name {
			return r
		}
	}
	require.FailNowf(t, "role not found", "role %q not found", name)
	return nil
}

func TestRbacPolicyRules_TypedView(t *testing.T) {
	k8sObj, err := NewResource(rbacRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	cr := clusterRoleByName(t, k8s, "secret-reader")
	rules := cr.GetPolicyRules()
	require.NoError(t, rules.Error)
	require.Len(t, rules.Data, 1)

	rule := rules.Data[0].(*mqlK8sRbacPolicyRule)
	assert.ElementsMatch(t, []any{"get", "list", "watch"}, rule.GetVerbs().Data)
	assert.ElementsMatch(t, []any{""}, rule.GetApiGroups().Data)
	assert.ElementsMatch(t, []any{"secrets"}, rule.GetResources().Data)
	assert.Empty(t, rule.GetResourceNames().Data)
	assert.Empty(t, rule.GetNonResourceURLs().Data)

	// resourceNames are preserved when set
	configmapReader := roleByName(t, k8s, "configmap-reader")
	crRules := configmapReader.GetPolicyRules()
	require.NoError(t, crRules.Error)
	require.Len(t, crRules.Data, 1)
	assert.ElementsMatch(t, []any{"app-config"},
		crRules.Data[0].(*mqlK8sRbacPolicyRule).GetResourceNames().Data)
}

func TestRbacClusterRolePredicates(t *testing.T) {
	k8sObj, err := NewResource(rbacRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	tests := []struct {
		name          string
		wildcard      bool
		privEscalates bool
		readsSecrets  bool
	}{
		// wildcard "*" verbs/resources/groups: wildcard true; it also covers
		// escalate and secret reads, so both derived predicates are true.
		{name: "wildcard-admin", wildcard: true, privEscalates: true, readsSecrets: true},
		{name: "secret-reader", wildcard: false, privEscalates: false, readsSecrets: true},
		{name: "escalator", wildcard: false, privEscalates: true, readsSecrets: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cr := clusterRoleByName(t, k8s, tc.name)
			assert.Equal(t, tc.wildcard, cr.GetHasWildcardRule().Data, "hasWildcardRule")
			assert.Equal(t, tc.privEscalates, cr.GetAllowsPrivilegeEscalation().Data, "allowsPrivilegeEscalation")
			assert.Equal(t, tc.readsSecrets, cr.GetCanReadSecrets().Data, "canReadSecrets")
		})
	}
}

func TestRbacRolePredicates(t *testing.T) {
	k8sObj, err := NewResource(rbacRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	// benign read-only role
	reader := roleByName(t, k8s, "configmap-reader")
	assert.False(t, reader.GetHasWildcardRule().Data)
	assert.False(t, reader.GetAllowsPrivilegeEscalation().Data)
	assert.False(t, reader.GetCanReadSecrets().Data)

	// role that can bind roles escalates privileges
	binder := roleByName(t, k8s, "binder")
	assert.False(t, binder.GetHasWildcardRule().Data)
	assert.True(t, binder.GetAllowsPrivilegeEscalation().Data)
	assert.False(t, binder.GetCanReadSecrets().Data)
}

func TestRbacResourceMatches(t *testing.T) {
	tests := []struct {
		name          string
		ruleResources []string
		resource      string
		want          bool
	}{
		{"exact resource", []string{"pods"}, "pods", true},
		{"exact subresource", []string{"pods/exec"}, "pods/exec", true},
		{"wildcard covers subresource", []string{"*"}, "pods/exec", true},
		{"any-resource subresource form", []string{"*/approval"}, "certificatesigningrequests/approval", true},
		{"any-resource form, other subresource", []string{"*/approval"}, "certificatesigningrequests/status", false},
		{"any-resource form does not cover the bare resource", []string{"*/approval"}, "approval", false},
		{"any-resource form does not cover a parent resource", []string{"*/approval"}, "certificatesigningrequests", false},
		{"resource does not cover its subresources", []string{"pods"}, "pods/exec", false},
		{"resource/* is not a wildcard", []string{"certificatesigningrequests/*"}, "certificatesigningrequests/approval", false},
		{"empty subresource", []string{"*/"}, "pods/", false},
		{"no rule resources", nil, "pods", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, rbacResourceMatches(tt.ruleResources, tt.resource))
		})
	}
}

func TestRbacRuleGrants_SubresourceWildcard(t *testing.T) {
	rule := rbacv1.PolicyRule{
		APIGroups: []string{"certificates.k8s.io"},
		Resources: []string{"*/approval"},
		Verbs:     []string{"update"},
	}
	assert.True(t, rbacRuleGrants(rule, "certificates.k8s.io", "certificatesigningrequests/approval", "update", ""))
	assert.False(t, rbacRuleGrants(rule, "certificates.k8s.io", "certificatesigningrequests/approval", "delete", ""))
	assert.False(t, rbacRuleGrants(rule, "", "pods/approval", "update", ""))
}
