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
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	"go.mondoo.com/mql/utils/syncx"
	corev1 "k8s.io/api/core/v1"
)

func workloadSecurityK8s(t *testing.T) *mqlK8s {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{shared.OPTION_NAMESPACE: "default"}},
		},
	}, manifest.WithManifestFile("./testdata/workload-security.yaml"))
	require.NoError(t, err)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn

	obj, err := NewResource(runtime, "k8s", nil)
	require.NoError(t, err)
	return obj.(*mqlK8s)
}

func deploymentByName(t *testing.T, k8s *mqlK8s, name string) *mqlK8sDeployment {
	t.Helper()
	deployments := k8s.GetDeployments()
	require.NoError(t, deployments.Error)
	for i := range deployments.Data {
		d := deployments.Data[i].(*mqlK8sDeployment)
		if d.GetName().Data == name {
			return d
		}
	}
	require.FailNowf(t, "deployment not found", "deployment %q not found", name)
	return nil
}

// TestWorkloadSecurityRollups_NilSpec guards against panics when the pod spec
// is nil (e.g. a malformed manifest yields (nil, nil)). Every helper must treat
// a nil spec as "nothing configured" rather than dereferencing it.
func TestWorkloadSecurityRollups_NilSpec(t *testing.T) {
	assert.NotPanics(t, func() {
		// With no containers, the "any container" predicates report false.
		assert.False(t, specRunsPrivileged(nil), "runsPrivileged")
		assert.False(t, specAllowsPrivilegeEscalation(nil), "allowsPrivilegeEscalation")
		assert.False(t, specRunsAsRoot(nil), "runsAsRoot")
		assert.False(t, specHasWritableRootFilesystem(nil), "hasWritableRootFilesystem")
		assert.False(t, specDropsAllCapabilities(nil), "dropsAllCapabilities")
		assert.Empty(t, specAddedCapabilities(nil), "addedCapabilities")
		assert.False(t, specUsesHostNamespaces(nil), "usesHostNamespaces")
		assert.False(t, specUsesHostPath(nil), "usesHostPath")
		// The automount decision now also consults the ServiceAccount; the part
		// that reads the spec must still tolerate a nil one.
		assert.Equal(t, "default", podServiceAccountName(nil), "podServiceAccountName")
		assert.False(t, specUsesUnconfinedSeccomp(nil), "usesUnconfinedSeccomp")
		assert.False(t, specHasSeccompProfile(nil), "hasSeccompProfile")
	})

	// dictFromSpec must not dereference a nil spec.
	dict, err := dictFromSpec(nil, nil)
	require.NoError(t, err)
	assert.Nil(t, dict)
}

func TestWorkloadSecurityRollups(t *testing.T) {
	k8s := workloadSecurityK8s(t)

	t.Run("hardened workload", func(t *testing.T) {
		d := deploymentByName(t, k8s, "hardened")
		assert.False(t, d.GetRunsPrivileged().Data, "runsPrivileged")
		assert.False(t, d.GetAllowsPrivilegeEscalation().Data, "allowsPrivilegeEscalation")
		assert.False(t, d.GetRunsAsRoot().Data, "runsAsRoot")
		assert.False(t, d.GetHasWritableRootFilesystem().Data, "hasWritableRootFilesystem")
		assert.True(t, d.GetDropsAllCapabilities().Data, "dropsAllCapabilities")
		assert.Equal(t, []any{"NET_BIND_SERVICE"}, d.GetAddedCapabilities().Data, "addedCapabilities")
		assert.False(t, d.GetUsesHostNamespaces().Data, "usesHostNamespaces")
		assert.False(t, d.GetUsesHostPath().Data, "usesHostPath")
		assert.False(t, d.GetAutomountServiceAccountToken().Data, "automountServiceAccountToken")
		assert.False(t, d.GetHostNetwork().Data, "hostNetwork")
		// Pod-level RuntimeDefault profile applies to the container.
		assert.False(t, d.GetUsesUnconfinedSeccomp().Data, "usesUnconfinedSeccomp")
		assert.True(t, d.GetHasSeccompProfile().Data, "hasSeccompProfile")
	})

	t.Run("risky workload", func(t *testing.T) {
		d := deploymentByName(t, k8s, "risky")
		assert.True(t, d.GetRunsPrivileged().Data, "runsPrivileged")
		assert.True(t, d.GetAllowsPrivilegeEscalation().Data, "allowsPrivilegeEscalation")
		assert.True(t, d.GetRunsAsRoot().Data, "runsAsRoot")
		assert.True(t, d.GetHasWritableRootFilesystem().Data, "hasWritableRootFilesystem")
		assert.False(t, d.GetDropsAllCapabilities().Data, "dropsAllCapabilities")
		// union across init + main containers, deduplicated
		assert.ElementsMatch(t, []any{"NET_RAW", "SYS_ADMIN"}, d.GetAddedCapabilities().Data, "addedCapabilities")
		assert.True(t, d.GetUsesHostNamespaces().Data, "usesHostNamespaces")
		assert.True(t, d.GetUsesHostPath().Data, "usesHostPath")
		assert.True(t, d.GetHostNetwork().Data, "hostNetwork")
		assert.True(t, d.GetHostPID().Data, "hostPID")
		assert.False(t, d.GetHostIPC().Data, "hostIPC")
		// automountServiceAccountToken defaults to true when unset
		assert.True(t, d.GetAutomountServiceAccountToken().Data, "automountServiceAccountToken")
		// The main container explicitly sets the Unconfined seccomp profile.
		assert.True(t, d.GetUsesUnconfinedSeccomp().Data, "usesUnconfinedSeccomp")
		assert.False(t, d.GetHasSeccompProfile().Data, "hasSeccompProfile")
	})

	t.Run("pod-level runAsNonRoot is folded into runsAsRoot", func(t *testing.T) {
		d := deploymentByName(t, k8s, "podlevelnonroot")
		assert.False(t, d.GetRunsAsRoot().Data, "runsAsRoot")
		assert.False(t, d.GetRunsPrivileged().Data, "runsPrivileged")
		assert.True(t, d.GetDropsAllCapabilities().Data, "dropsAllCapabilities")
	})

	t.Run("securityContext dict surfaces the pod-level context", func(t *testing.T) {
		d := deploymentByName(t, k8s, "podlevelnonroot")
		sc := d.GetSecurityContext()
		require.NoError(t, sc.Error)
		scMap, ok := sc.Data.(map[string]any)
		require.True(t, ok, "securityContext is a dict")
		assert.Equal(t, true, scMap["runAsNonRoot"], "securityContext.runAsNonRoot")
	})
}

// TestSpecDropsAllCapabilities_Case pins ALL to the runtimes' behavior:
// containerd and CRI-O match it case-insensitively, so "all" drops every
// capability even though Pod Security Admission's restricted profile only
// accepts the uppercase spelling.
func TestSpecDropsAllCapabilities_Case(t *testing.T) {
	spec := func(drops ...[]corev1.Capability) *corev1.PodSpec {
		s := &corev1.PodSpec{}
		for _, d := range drops {
			s.Containers = append(s.Containers, corev1.Container{
				SecurityContext: &corev1.SecurityContext{
					Capabilities: &corev1.Capabilities{Drop: d},
				},
			})
		}
		return s
	}

	tests := []struct {
		name string
		spec *corev1.PodSpec
		want bool
	}{
		{"uppercase", spec([]corev1.Capability{"ALL"}), true},
		{"lowercase", spec([]corev1.Capability{"all"}), true},
		{"mixed case", spec([]corev1.Capability{"NET_RAW", "All"}), true},
		{"one container drops only NET_RAW", spec([]corev1.Capability{"all"}, []corev1.Capability{"NET_RAW"}), false},
		{"prefix is not ALL", spec([]corev1.Capability{"ALLOW"}), false},
		{"empty drop list", spec([]corev1.Capability{}), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, specDropsAllCapabilities(tt.spec))
		})
	}
}

// TestWorkloadSecurityRollups_Pod exercises the pod accessor path, which uses
// podSpecTyped() rather than the controller securitySpec() helper.
func TestWorkloadSecurityRollups_Pod(t *testing.T) {
	k8s := workloadSecurityK8s(t)

	pods := k8s.GetPods()
	require.NoError(t, pods.Error)
	var pod *mqlK8sPod
	for i := range pods.Data {
		p := pods.Data[i].(*mqlK8sPod)
		if p.GetName().Data == "risky-pod" {
			pod = p
			break
		}
	}
	require.NotNil(t, pod, "risky-pod not found")

	assert.True(t, pod.GetRunsPrivileged().Data, "runsPrivileged")
	assert.True(t, pod.GetAllowsPrivilegeEscalation().Data, "allowsPrivilegeEscalation")
	assert.True(t, pod.GetRunsAsRoot().Data, "runsAsRoot")
	assert.True(t, pod.GetHasWritableRootFilesystem().Data, "hasWritableRootFilesystem")
	assert.False(t, pod.GetDropsAllCapabilities().Data, "dropsAllCapabilities")
	assert.Equal(t, []any{"SYS_ADMIN"}, pod.GetAddedCapabilities().Data, "addedCapabilities")
	assert.True(t, pod.GetUsesHostNamespaces().Data, "usesHostNamespaces (hostIPC)")
	assert.True(t, pod.GetUsesHostPath().Data, "usesHostPath")
}

// rollupReader is the common accessor surface every workload-bearing resource
// implements; it lets one table verify per-kind wiring of every predicate.
type rollupReader interface {
	GetName() *plugin.TValue[string]
	GetRunsPrivileged() *plugin.TValue[bool]
	GetAllowsPrivilegeEscalation() *plugin.TValue[bool]
	GetRunsAsRoot() *plugin.TValue[bool]
	GetHasWritableRootFilesystem() *plugin.TValue[bool]
	GetDropsAllCapabilities() *plugin.TValue[bool]
	GetAddedCapabilities() *plugin.TValue[[]any]
	GetUsesHostNamespaces() *plugin.TValue[bool]
	GetUsesHostPath() *plugin.TValue[bool]
	GetAutomountServiceAccountToken() *plugin.TValue[bool]
	GetHostNetwork() *plugin.TValue[bool]
	GetHostPID() *plugin.TValue[bool]
	GetHostIPC() *plugin.TValue[bool]
	GetUsesUnconfinedSeccomp() *plugin.TValue[bool]
	GetHasSeccompProfile() *plugin.TValue[bool]
	GetSecurityContext() *plugin.TValue[any]
}

// TestWorkloadSecurityRollups_AllKinds confirms every controller workload wires
// each predicate (and the securityContext dict) to its own object getter. The
// *-privileged fixtures each have a single privileged container and nothing
// else set, so every kind shares the same expected predicate vector.
func TestWorkloadSecurityRollups_AllKinds(t *testing.T) {
	k8s := workloadSecurityK8s(t)

	find := func(t *testing.T, list *plugin.TValue[[]any], name string) rollupReader {
		t.Helper()
		require.NoError(t, list.Error)
		for i := range list.Data {
			r := list.Data[i].(rollupReader)
			if r.GetName().Data == name {
				return r
			}
		}
		require.FailNowf(t, "workload not found", "%q not found", name)
		return nil
	}

	cases := []struct {
		name string
		list *plugin.TValue[[]any]
	}{
		{"ds-privileged", k8s.GetDaemonsets()},
		{"ss-privileged", k8s.GetStatefulsets()},
		{"rs-privileged", k8s.GetReplicasets()},
		{"job-privileged", k8s.GetJobs()},
		{"cronjob-privileged", k8s.GetCronjobs()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := find(t, tc.list, tc.name)
			// A lone privileged container, nothing else set.
			assert.True(t, r.GetRunsPrivileged().Data, "runsPrivileged")
			// allowPrivilegeEscalation is unset, which defaults to permitted.
			assert.True(t, r.GetAllowsPrivilegeEscalation().Data, "allowsPrivilegeEscalation")
			assert.True(t, r.GetRunsAsRoot().Data, "runsAsRoot")
			assert.True(t, r.GetHasWritableRootFilesystem().Data, "hasWritableRootFilesystem")
			assert.False(t, r.GetDropsAllCapabilities().Data, "dropsAllCapabilities")
			assert.Empty(t, r.GetAddedCapabilities().Data, "addedCapabilities")
			assert.False(t, r.GetUsesHostNamespaces().Data, "usesHostNamespaces")
			assert.False(t, r.GetUsesHostPath().Data, "usesHostPath")
			// automountServiceAccountToken is unset, which defaults to true.
			assert.True(t, r.GetAutomountServiceAccountToken().Data, "automountServiceAccountToken")
			assert.False(t, r.GetHostNetwork().Data, "hostNetwork")
			assert.False(t, r.GetHostPID().Data, "hostPID")
			assert.False(t, r.GetHostIPC().Data, "hostIPC")
			// No seccomp profile is set, so it is neither Unconfined nor confined.
			assert.False(t, r.GetUsesUnconfinedSeccomp().Data, "usesUnconfinedSeccomp")
			assert.False(t, r.GetHasSeccompProfile().Data, "hasSeccompProfile")
			// securityContext resolves without error even when unset.
			assert.NoError(t, r.GetSecurityContext().Error, "securityContext")
		})
	}
}
