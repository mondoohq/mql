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
)

func namespaceByName(t *testing.T, runtime *plugin.Runtime, name string) *mqlK8sNamespace {
	t.Helper()
	obj, err := NewResource(runtime, "k8s", nil)
	require.NoError(t, err)
	namespaces := obj.(*mqlK8s).GetNamespaces()
	require.NoError(t, namespaces.Error)

	for i := range namespaces.Data {
		ns := namespaces.Data[i].(*mqlK8sNamespace)
		if ns.GetName().Data == name {
			return ns
		}
	}
	require.FailNowf(t, "namespace not found", "namespace %q not returned by k8s.namespaces", name)
	return nil
}

func newManifestRuntime(t *testing.T, manifestFile string) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{{}},
	}, manifest.WithManifestFile(manifestFile))
	require.NoError(t, err)
	require.NotNil(t, conn)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func TestNamespacePodSecurity(t *testing.T) {
	runtime := newManifestRuntime(t, "./testdata/podsecurity-vap.yaml")

	// End-to-end: the manifest parser surfaces the standalone Namespace object
	// with its Pod Security admission labels, which the accessors then read.
	ns := namespaceByName(t, runtime, "secured")

	assert.Equal(t, "restricted", ns.GetPodSecurityEnforce().Data)
	assert.Equal(t, "v1.30", ns.GetPodSecurityEnforceVersion().Data)
	assert.Equal(t, "baseline", ns.GetPodSecurityWarn().Data)
	// labels that are not set resolve to empty strings
	assert.Equal(t, "", ns.GetPodSecurityAudit().Data)
	assert.Equal(t, "", ns.GetPodSecurityAuditVersion().Data)
	assert.Equal(t, "", ns.GetPodSecurityWarnVersion().Data)
}

func TestNamespacePodSecurity_Unset(t *testing.T) {
	runtime := newManifestRuntime(t, "./testdata/podsecurity-vap.yaml")

	// A namespace that exists only because a workload references it has no Pod
	// Security labels, so every PSA accessor must resolve to an empty string
	// rather than erroring.
	ns := namespaceByName(t, runtime, "guarded-workloads")

	assert.Equal(t, "", ns.GetPodSecurityEnforce().Data)
	assert.Equal(t, "", ns.GetPodSecurityEnforceVersion().Data)
	assert.Equal(t, "", ns.GetPodSecurityAudit().Data)
	assert.Equal(t, "", ns.GetPodSecurityAuditVersion().Data)
	assert.Equal(t, "", ns.GetPodSecurityWarn().Data)
	assert.Equal(t, "", ns.GetPodSecurityWarnVersion().Data)
}

func TestManifest_ValidatingAdmissionPolicy(t *testing.T) {
	runtime := newManifestRuntime(t, "./testdata/podsecurity-vap.yaml")

	obj, err := NewResource(runtime, "k8s", nil)
	require.NoError(t, err)
	k8s := obj.(*mqlK8s)

	policies := k8s.GetValidatingAdmissionPolicies()
	require.NoError(t, policies.Error)
	require.Len(t, policies.Data, 1)

	vap := policies.Data[0].(*mqlK8sAdmissionValidatingadmissionpolicy)
	assert.Equal(t, "demo-policy", vap.GetName().Data)
	assert.Equal(t, "Fail", vap.GetFailurePolicy().Data)
	assert.Len(t, vap.GetValidations().Data, 1)

	// the policy resolves the bindings that reference it by name
	bindings := vap.GetBindings()
	require.NoError(t, bindings.Error)
	require.Len(t, bindings.Data, 1)
	binding := bindings.Data[0].(*mqlK8sAdmissionValidatingadmissionpolicybinding)
	assert.Equal(t, "demo-binding", binding.GetName().Data)
	assert.Equal(t, []any{"Deny", "Audit"}, binding.GetValidationActions().Data)

	// the binding resolves back to its typed policy
	policy := binding.GetPolicy()
	require.NoError(t, policy.Error)
	require.NotNil(t, policy.Data)
	assert.Equal(t, "demo-policy", policy.Data.GetName().Data)
}

func vapByName(t *testing.T, k8s *mqlK8s, name string) *mqlK8sAdmissionValidatingadmissionpolicy {
	t.Helper()
	policies := k8s.GetValidatingAdmissionPolicies()
	require.NoError(t, policies.Error)
	for i := range policies.Data {
		p := policies.Data[i].(*mqlK8sAdmissionValidatingadmissionpolicy)
		if p.GetName().Data == name {
			return p
		}
	}
	require.FailNowf(t, "policy not found", "policy %q not found", name)
	return nil
}

func bindingByName(t *testing.T, k8s *mqlK8s, name string) *mqlK8sAdmissionValidatingadmissionpolicybinding {
	t.Helper()
	bindings := k8s.GetValidatingAdmissionPolicyBindings()
	require.NoError(t, bindings.Error)
	for i := range bindings.Data {
		b := bindings.Data[i].(*mqlK8sAdmissionValidatingadmissionpolicybinding)
		if b.GetName().Data == name {
			return b
		}
	}
	require.FailNowf(t, "binding not found", "binding %q not found", name)
	return nil
}

func TestManifest_ValidatingAdmissionPolicy_CrossReferences(t *testing.T) {
	runtime := newManifestRuntime(t, "./testdata/vap-multi.yaml")

	obj, err := NewResource(runtime, "k8s", nil)
	require.NoError(t, err)
	k8s := obj.(*mqlK8s)

	policies := k8s.GetValidatingAdmissionPolicies()
	require.NoError(t, policies.Error)
	require.Len(t, policies.Data, 2)

	bindings := k8s.GetValidatingAdmissionPolicyBindings()
	require.NoError(t, bindings.Error)
	require.Len(t, bindings.Data, 3)

	// policy-a is activated by exactly its two bindings
	policyA := vapByName(t, k8s, "policy-a")
	assert.Equal(t, "Ignore", policyA.GetFailurePolicy().Data)
	assert.Len(t, policyA.GetValidations().Data, 2)
	aBindings := policyA.GetBindings()
	require.NoError(t, aBindings.Error)
	aBindingNames := make([]string, 0, len(aBindings.Data))
	for i := range aBindings.Data {
		aBindingNames = append(aBindingNames, aBindings.Data[i].(*mqlK8sAdmissionValidatingadmissionpolicybinding).GetName().Data)
	}
	assert.ElementsMatch(t, []string{"binding-a1", "binding-a2"}, aBindingNames)

	// policy-b has no bindings; failurePolicy defaults to empty when unset
	policyB := vapByName(t, k8s, "policy-b")
	assert.Equal(t, "", policyB.GetFailurePolicy().Data)
	bBindings := policyB.GetBindings()
	require.NoError(t, bBindings.Error)
	assert.Empty(t, bBindings.Data)

	// a binding pointing at a missing policy resolves to null, not an error
	orphan := bindingByName(t, k8s, "orphan-binding")
	assert.Equal(t, "ghost", orphan.GetPolicyName().Data)
	orphanPolicy := orphan.GetPolicy()
	require.NoError(t, orphanPolicy.Error)
	assert.Nil(t, orphanPolicy.Data)
}
