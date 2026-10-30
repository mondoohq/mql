// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/utils/syncx"
)

func rbacSubjectsRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile("./testdata/rbac-subjects.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func subjectKey(s *mqlK8sRbacSubject) string {
	return s.GetKind().Data + "/" + s.GetNamespace().Data + "/" + s.GetName().Data
}

func subjectsByKey(t *testing.T, k8s *mqlK8s) map[string]*mqlK8sRbacSubject {
	t.Helper()
	res := k8s.GetRbacSubjects()
	require.NoError(t, res.Error)
	out := map[string]*mqlK8sRbacSubject{}
	for i := range res.Data {
		s := res.Data[i].(*mqlK8sRbacSubject)
		out[subjectKey(s)] = s
	}
	return out
}

func TestRbacSubjects_Enumeration(t *testing.T) {
	k8sObj, err := NewResource(rbacSubjectsRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	subjects := subjectsByKey(t, k8s)

	// alice is named in two bindings but must appear once (dedup).
	assert.Len(t, subjects, 6)
	for _, want := range []string{
		"User//alice",
		"Group//ops-admins",
		"User//bob",
		"ServiceAccount/default/secret-sa",
		"ServiceAccount/default/reader-sa",
		"ServiceAccount/default/named-sa",
	} {
		assert.Contains(t, subjects, want)
	}
}

func TestRbacSubjects_Predicates(t *testing.T) {
	k8sObj, err := NewResource(rbacSubjectsRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	subjects := subjectsByKey(t, k8s)

	tests := []struct {
		key          string
		clusterAdmin bool
		readSecrets  bool
		escalate     bool
		wildcard     bool
	}{
		// wildcard-admin confers everything; alice keeps it despite her second,
		// benign binding.
		{"User//alice", true, true, true, true},
		{"Group//ops-admins", true, true, true, true},
		// secret-reader: reads secrets only.
		{"ServiceAccount/default/secret-sa", false, true, false, false},
		// binder: escalation via the bind verb, nothing else.
		{"User//bob", false, false, true, false},
		// configmap-reader: benign.
		{"ServiceAccount/default/reader-sa", false, false, false, false},
		// named-secret-reader: reads secrets (the capability predicate is
		// name-agnostic, so a ResourceNames-scoped grant still counts).
		{"ServiceAccount/default/named-sa", false, true, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			s, ok := subjects[tt.key]
			require.True(t, ok, "subject %q not enumerated", tt.key)

			ca := s.GetIsClusterAdmin()
			require.NoError(t, ca.Error)
			assert.Equal(t, tt.clusterAdmin, ca.Data, "isClusterAdmin")

			rs := s.GetCanReadSecrets()
			require.NoError(t, rs.Error)
			assert.Equal(t, tt.readSecrets, rs.Data, "canReadSecrets")

			esc := s.GetCanEscalatePrivileges()
			require.NoError(t, esc.Error)
			assert.Equal(t, tt.escalate, esc.Data, "canEscalatePrivileges")

			wc := s.GetHasWildcardPermissions()
			require.NoError(t, wc.Error)
			assert.Equal(t, tt.wildcard, wc.Data, "hasWildcardPermissions")
		})
	}
}

func TestRbacSubjects_ServiceAccountResolution(t *testing.T) {
	k8sObj, err := NewResource(rbacSubjectsRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	subjects := subjectsByKey(t, k8s)

	// A ServiceAccount subject resolves to its object.
	sa := subjects["ServiceAccount/default/secret-sa"].GetServiceAccount()
	require.NoError(t, sa.Error)
	require.NotNil(t, sa.Data)
	assert.Equal(t, "secret-sa", sa.Data.GetName().Data)

	// A user subject has no backing ServiceAccount.
	none := subjects["User//alice"].GetServiceAccount()
	require.NoError(t, none.Error)
	assert.Nil(t, none.Data)
}

func TestRbacSubjects_Bindings(t *testing.T) {
	k8sObj, err := NewResource(rbacSubjectsRuntime(t), "k8s", nil)
	require.NoError(t, err)
	k8s := k8sObj.(*mqlK8s)

	subjects := subjectsByKey(t, k8s)

	alice := subjects["User//alice"]
	crbs := alice.GetClusterRoleBindings()
	require.NoError(t, crbs.Error)
	require.Len(t, crbs.Data, 1)
	assert.Equal(t, "crb-admins", crbs.Data[0].(*mqlK8sRbacClusterrolebinding).GetName().Data)

	rbs := alice.GetRoleBindings()
	require.NoError(t, rbs.Error)
	require.Len(t, rbs.Data, 1)
	assert.Equal(t, "rb-alice-config", rbs.Data[0].(*mqlK8sRbacRolebinding).GetName().Data)

	// secret-sa is granted only through a RoleBinding.
	secretSA := subjects["ServiceAccount/default/secret-sa"]
	secretRBs := secretSA.GetRoleBindings()
	require.NoError(t, secretRBs.Error)
	require.Len(t, secretRBs.Data, 1)
	assert.Equal(t, "rb-secrets", secretRBs.Data[0].(*mqlK8sRbacRolebinding).GetName().Data)
}

func whoCanKeys(t *testing.T, runtime *plugin.Runtime, args map[string]*llx.RawData) []string {
	t.Helper()
	r, err := NewResource(runtime, "k8s.rbac.whoCan", args)
	require.NoError(t, err)
	res := r.(*mqlK8sRbacWhoCan).GetSubjects()
	require.NoError(t, res.Error)
	keys := []string{}
	for i := range res.Data {
		keys = append(keys, subjectKey(res.Data[i].(*mqlK8sRbacSubject)))
	}
	return keys
}

func TestRbacWhoCan(t *testing.T) {
	runtime := rbacSubjectsRuntime(t)

	// Cluster-wide secret read: wildcard admins plus the namespaced secret-sa
	// (an empty namespace selector considers every namespace).
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins", "ServiceAccount/default/secret-sa"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":     llx.StringData("list"),
			"resource": llx.StringData("secrets"),
		}))

	// Scoped to kube-system: only the cluster-wide grants apply; the default
	// RoleBinding for secret-sa is excluded.
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":      llx.StringData("list"),
			"resource":  llx.StringData("secrets"),
			"namespace": llx.StringData("kube-system"),
		}))

	// Scoped to default: cluster-wide grants plus the default RoleBinding.
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins", "ServiceAccount/default/secret-sa"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":      llx.StringData("list"),
			"resource":  llx.StringData("secrets"),
			"namespace": llx.StringData("default"),
		}))

	// Privilege escalation by binding roles: wildcard admins plus bob.
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins", "User//bob"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":     llx.StringData("bind"),
			"resource": llx.StringData("roles"),
			"group":    llx.StringData("rbac.authorization.k8s.io"),
		}))

	// An action only the wildcard role covers.
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":     llx.StringData("delete"),
			"resource": llx.StringData("pods"),
		}))
}

func TestRbacWhoCan_ResourceName(t *testing.T) {
	runtime := rbacSubjectsRuntime(t)

	// Unscoped get on secrets: wildcard admins, secret-sa (unrestricted secret
	// read), and named-sa (its grant is ResourceNames-scoped but still counts
	// when no specific object is queried).
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins", "ServiceAccount/default/secret-sa", "ServiceAccount/default/named-sa"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":     llx.StringData("get"),
			"resource": llx.StringData("secrets"),
		}))

	// Scoped to the object named-sa is allowed: named-sa is included.
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins", "ServiceAccount/default/secret-sa", "ServiceAccount/default/named-sa"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":     llx.StringData("get"),
			"resource": llx.StringData("secrets"),
			"name":     llx.StringData("app-secret"),
		}))

	// Scoped to a different object: named-sa's ResourceNames-restricted grant no
	// longer matches, but the unrestricted secret-reader and wildcard admins do.
	assert.ElementsMatch(t,
		[]string{"User//alice", "Group//ops-admins", "ServiceAccount/default/secret-sa"},
		whoCanKeys(t, runtime, map[string]*llx.RawData{
			"verb":     llx.StringData("get"),
			"resource": llx.StringData("secrets"),
			"name":     llx.StringData("other-secret"),
		}))
}
