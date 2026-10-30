// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/utils/syncx"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

const crossRefFixture = "testdata/cross_references.yaml"

// loadCrossRefRuntime loads the cross-reference fixture and returns a runtime
// wired against the resulting manifest connection. The connection is left
// namespace-scopeless so cluster-wide queries traverse every fixture object.
func loadCrossRefRuntime(t *testing.T) *plugin.Runtime {
	t.Helper()
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{Options: map[string]string{}},
		},
	}, manifest.WithManifestFile(crossRefFixture))
	require.NoError(t, err)
	require.NotNil(t, conn)

	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	runtime.Connection = conn
	return runtime
}

func mqlResourceNames(t *testing.T, items []any) []string {
	t.Helper()
	out := make([]string, 0, len(items))
	for _, it := range items {
		switch v := it.(type) {
		case *mqlK8sPod:
			out = append(out, v.Name.Data)
		case *mqlK8sDeployment:
			out = append(out, v.Name.Data)
		case *mqlK8sStatefulset:
			out = append(out, v.Name.Data)
		case *mqlK8sDaemonset:
			out = append(out, v.Name.Data)
		case *mqlK8sReplicaset:
			out = append(out, v.Name.Data)
		case *mqlK8sJob:
			out = append(out, v.Name.Data)
		case *mqlK8sCronjob:
			out = append(out, v.Name.Data)
		case *mqlK8sService:
			out = append(out, v.Name.Data)
		case *mqlK8sEndpointslice:
			out = append(out, v.Name.Data)
		case *mqlK8sSecret:
			out = append(out, v.Name.Data)
		case *mqlK8sConfigmap:
			out = append(out, v.Name.Data)
		case *mqlK8sServiceaccount:
			out = append(out, v.Name.Data)
		case *mqlK8sRbacRole:
			out = append(out, v.Name.Data)
		case *mqlK8sRbacRolebinding:
			out = append(out, v.Name.Data)
		case *mqlK8sRbacClusterrole:
			out = append(out, v.Name.Data)
		case *mqlK8sRbacClusterrolebinding:
			out = append(out, v.Name.Data)
		default:
			t.Fatalf("mqlResourceNames: unhandled type %T", v)
		}
	}
	sort.Strings(out)
	return out
}

// -----------------------------------------------------------------------------
// Pure-function tests for the multi-arm reference predicates.
// These walk a constructed *corev1.Pod and don't need the MQL runtime.
// -----------------------------------------------------------------------------

func TestPodReferencesSecret(t *testing.T) {
	// One pod that references "target" through every supported path, plus a
	// no-match secret to assert false-positives aren't introduced.
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "v-secret", Secret: &corev1.SecretVolumeSource{SecretName: "target"}},
				{Name: "v-projected", Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{Secret: &corev1.SecretProjection{Name: "target"}},
					},
				}},
			},
			ImagePullSecrets: []corev1.LocalObjectReference{{Name: "target"}},
			Containers: []corev1.Container{
				{
					Name: "main",
					Env: []corev1.EnvVar{
						{Name: "X", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
							Name: "target", Key: "k",
						}}},
					},
					EnvFrom: []corev1.EnvFromSource{
						{SecretRef: &corev1.SecretEnvSource{Name: "target"}},
					},
				},
			},
			InitContainers: []corev1.Container{
				{Name: "init", Env: []corev1.EnvVar{{Name: "Y", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					Name: "target", Key: "k",
				}}}}},
			},
			EphemeralContainers: []corev1.EphemeralContainer{
				{
					Name: "debug",
					EnvFrom: []corev1.EnvFromSource{
						{SecretRef: &corev1.SecretEnvSource{Name: "target"}},
					}},
			},
		},
	}
	assert.True(t, podReferencesSecret(pod, "target"), "should detect target via any of the configured paths")
	assert.False(t, podReferencesSecret(pod, "no-such-secret"), "must not false-positive on a name nothing references")

	// Empty pod — no false-positive on the empty string.
	assert.False(t, podReferencesSecret(&corev1.Pod{}, "anything"))
	assert.False(t, podReferencesSecret(&corev1.Pod{}, ""))

	// Per-path coverage: each branch should be the sole signal that flips the result.
	t.Run("volume.secret only", func(t *testing.T) {
		p := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{
			{Name: "v", Secret: &corev1.SecretVolumeSource{SecretName: "s"}},
		}}}
		assert.True(t, podReferencesSecret(p, "s"))
		assert.False(t, podReferencesSecret(p, "other"))
	})
	t.Run("projected.secret only", func(t *testing.T) {
		p := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{
			{Name: "v", Projected: &corev1.ProjectedVolumeSource{
				Sources: []corev1.VolumeProjection{{Secret: &corev1.SecretProjection{Name: "s"}}},
			}},
		}}}
		assert.True(t, podReferencesSecret(p, "s"))
	})
	t.Run("imagePullSecrets only", func(t *testing.T) {
		p := &corev1.Pod{Spec: corev1.PodSpec{ImagePullSecrets: []corev1.LocalObjectReference{{Name: "s"}}}}
		assert.True(t, podReferencesSecret(p, "s"))
	})
	t.Run("container env only", func(t *testing.T) {
		p := &corev1.Pod{Spec: corev1.PodSpec{Containers: []corev1.Container{
			{Env: []corev1.EnvVar{{ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
				Name: "s"}}}}},
		}}}
		assert.True(t, podReferencesSecret(p, "s"))
	})
	t.Run("init container envFrom only", func(t *testing.T) {
		p := &corev1.Pod{Spec: corev1.PodSpec{InitContainers: []corev1.Container{
			{EnvFrom: []corev1.EnvFromSource{{SecretRef: &corev1.SecretEnvSource{Name: "s"}}}},
		}}}
		assert.True(t, podReferencesSecret(p, "s"))
	})
	t.Run("ephemeral container only", func(t *testing.T) {
		p := &corev1.Pod{Spec: corev1.PodSpec{EphemeralContainers: []corev1.EphemeralContainer{
			{Env: []corev1.EnvVar{
				{ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
					Name: "s"}}},
			}},
		}}}
		assert.True(t, podReferencesSecret(p, "s"))
	})
}

func TestPodReferencesConfigMap(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Volumes: []corev1.Volume{
				{Name: "v-cm", ConfigMap: &corev1.ConfigMapVolumeSource{
					Name: "target",
				}},
				{Name: "v-projected", Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{ConfigMap: &corev1.ConfigMapProjection{Name: "target"}},
					},
				}},
			},
			Containers: []corev1.Container{
				{Env: []corev1.EnvVar{{ValueFrom: &corev1.EnvVarSource{
					ConfigMapKeyRef: &corev1.ConfigMapKeySelector{Name: "target"},
				}}}},
				{EnvFrom: []corev1.EnvFromSource{{ConfigMapRef: &corev1.ConfigMapEnvSource{
					Name: "target"}}}},
			},
		},
	}
	assert.True(t, podReferencesConfigMap(pod, "target"))
	assert.False(t, podReferencesConfigMap(pod, "no-such-cm"))
	// Secret references must not be confused for ConfigMap references.
	secretOnly := &corev1.Pod{Spec: corev1.PodSpec{Volumes: []corev1.Volume{
		{Name: "v", Secret: &corev1.SecretVolumeSource{SecretName: "target"}},
	}}}
	assert.False(t, podReferencesConfigMap(secretOnly, "target"),
		"a secret named 'target' must not satisfy a configmap lookup")
}

// -----------------------------------------------------------------------------
// Fixture-driven integration tests for cross-reference resolvers.
// -----------------------------------------------------------------------------

func TestPodOwnerRefs(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("pod owned by ReplicaSet resolves replicaSet and 2-hop deployment", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
			"name":      llx.StringData("api-7d4f-xyz"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pod := obj.(*mqlK8sPod)

		rs := pod.GetReplicaSet()
		require.NoError(t, rs.Error)
		require.NotNil(t, rs.Data)
		assert.Equal(t, "api-7d4f", rs.Data.Name.Data)

		dep := pod.GetDeployment()
		require.NoError(t, dep.Error)
		require.NotNil(t, dep.Data, "deployment should resolve via Pod → RS → Deployment ownerReferences")
		assert.Equal(t, "api", dep.Data.Name.Data)

		// Non-matching kinds must be null and have StateIsNull set.
		assertNullOwner(t, pod.GetStatefulSet().State, pod.GetStatefulSet().Data == nil)
		assertNullOwner(t, pod.GetDaemonSet().State, pod.GetDaemonSet().Data == nil)
		assertNullOwner(t, pod.GetJob().State, pod.GetJob().Data == nil)
	})

	t.Run("pod owned by ReplicaSet with no Deployment owner has null deployment", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
			"name":      llx.StringData("standalone-pod"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pod := obj.(*mqlK8sPod)

		rs := pod.GetReplicaSet()
		require.NoError(t, rs.Error)
		require.NotNil(t, rs.Data, "the orphan ReplicaSet should still resolve")
		assert.Equal(t, "standalone-rs", rs.Data.Name.Data)

		dep := pod.GetDeployment()
		require.NoError(t, dep.Error)
		assert.Nil(t, dep.Data, "ReplicaSet without a Deployment owner must surface as null deployment")
		assert.True(t, dep.State&plugin.StateIsNull != 0, "expected StateIsNull on the null deployment")
	})

	t.Run("pod owned by StatefulSet", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
			"name":      llx.StringData("db-0"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pod := obj.(*mqlK8sPod)
		ss := pod.GetStatefulSet()
		require.NoError(t, ss.Error)
		require.NotNil(t, ss.Data)
		assert.Equal(t, "db", ss.Data.Name.Data)
		assert.Nil(t, pod.GetReplicaSet().Data)
		assert.Nil(t, pod.GetJob().Data)
	})

	t.Run("pod owned by DaemonSet", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
			"name":      llx.StringData("fluentd-abc"),
			"namespace": llx.StringData("kube-system"),
		})
		require.NoError(t, err)
		pod := obj.(*mqlK8sPod)
		ds := pod.GetDaemonSet()
		require.NoError(t, ds.Error)
		require.NotNil(t, ds.Data)
		assert.Equal(t, "fluentd", ds.Data.Name.Data)
	})

	t.Run("pod owned by Job", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
			"name":      llx.StringData("importer-pod"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pod := obj.(*mqlK8sPod)
		j := pod.GetJob()
		require.NoError(t, j.Error)
		require.NotNil(t, j.Data)
		assert.Equal(t, "importer", j.Data.Name.Data)
	})

	t.Run("bare pod has all-null typed owner refs", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.pod", map[string]*llx.RawData{
			"name":      llx.StringData("bare-pod"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pod := obj.(*mqlK8sPod)
		assert.Nil(t, pod.GetReplicaSet().Data)
		assert.Nil(t, pod.GetStatefulSet().Data)
		assert.Nil(t, pod.GetDaemonSet().Data)
		assert.Nil(t, pod.GetJob().Data)
		assert.Nil(t, pod.GetDeployment().Data)
	})
}

func assertNullOwner(t *testing.T, state plugin.State, dataIsNil bool) {
	t.Helper()
	assert.True(t, dataIsNil, "expected data to be nil for non-matching owner kind")
	assert.True(t, state&plugin.StateIsNull != 0, "expected StateIsNull bit on non-matching owner kind")
}

func TestWorkloadPodsSelector(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("deployment with matchLabels selector", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.deployment", map[string]*llx.RawData{
			"name":      llx.StringData("api"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sDeployment).GetPods()
		require.NoError(t, pods.Error)
		assert.Equal(t, []string{"api-7d4f-xyz"}, mqlResourceNames(t, pods.Data),
			"deployment.pods must match the app=api selector and exclude pods in other namespaces or with different labels")
	})

	t.Run("statefulset with matchLabels selector", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.statefulset", map[string]*llx.RawData{
			"name":      llx.StringData("db"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sStatefulset).GetPods()
		require.NoError(t, pods.Error)
		assert.Equal(t, []string{"db-0"}, mqlResourceNames(t, pods.Data))
	})

	t.Run("daemonset namespace scope", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.daemonset", map[string]*llx.RawData{
			"name":      llx.StringData("fluentd"),
			"namespace": llx.StringData("kube-system"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sDaemonset).GetPods()
		require.NoError(t, pods.Error)
		assert.Equal(t, []string{"fluentd-abc"}, mqlResourceNames(t, pods.Data),
			"daemonset.pods must scope to the daemonset's namespace even with matching labels elsewhere")
	})

	t.Run("job with matchExpressions selector", func(t *testing.T) {
		// Exercises the matchExpressions code path in podsMatchingSelector.
		obj, err := NewResource(runtime, "k8s.job", map[string]*llx.RawData{
			"name":      llx.StringData("importer"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sJob).GetPods()
		require.NoError(t, pods.Error)
		assert.Equal(t, []string{"importer-pod"}, mqlResourceNames(t, pods.Data))
	})
}

func TestPodsMatchingSelectorHelper(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	// nil selector returns an empty list rather than every pod.
	out, err := podsMatchingSelector(runtime, nil, "prod")
	require.NoError(t, err)
	assert.Empty(t, out, "nil selector must not return any pods")

	// Empty selector matches nothing-specific — k8s semantics treat it as "match all"
	// for an actual selector object, but here we cover the nil-vs-empty distinction
	// via the workload tests above. The pure helper test focuses on its contract.

	// Mismatched namespace returns nothing even when labels would otherwise match.
	sel := &metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}}
	out, err = podsMatchingSelector(runtime, sel, "nonexistent-ns")
	require.NoError(t, err)
	assert.Empty(t, out)
}

func TestCronJobActiveJobsAndJobs(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.cronjob", map[string]*llx.RawData{
		"name":      llx.StringData("weekly-cleanup"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	cj := obj.(*mqlK8sCronjob)

	active := cj.GetActiveJobs()
	require.NoError(t, active.Error)
	assert.Equal(t, []string{"weekly-cleanup-active"}, mqlResourceNames(t, active.Data),
		"activeJobs must resolve status.active ObjectReferences and exclude completed/unrelated jobs")

	owned := cj.GetJobs()
	require.NoError(t, owned.Error)
	assert.Equal(t,
		[]string{"weekly-cleanup-active", "weekly-cleanup-completed"},
		mqlResourceNames(t, owned.Data),
		"jobs must include every Job with an ownerReference UID matching the CronJob, regardless of status")
}

func TestServiceEndpointSlices(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.service", map[string]*llx.RawData{
		"name":      llx.StringData("api"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	slices := obj.(*mqlK8sService).GetEndpointSlices()
	require.NoError(t, slices.Error)
	assert.Equal(t, []string{"api-slice"}, mqlResourceNames(t, slices.Data),
		"endpointSlices must filter on kubernetes.io/service-name + namespace and exclude orphan-slice")
}

func TestEndpointSliceService(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("slice with service-name label resolves typed Service", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.endpointslice", map[string]*llx.RawData{
			"name":      llx.StringData("api-slice"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		svc := obj.(*mqlK8sEndpointslice).GetService()
		require.NoError(t, svc.Error)
		require.NotNil(t, svc.Data)
		assert.Equal(t, "api", svc.Data.Name.Data)
	})

	t.Run("slice without service-name label has null service", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.endpointslice", map[string]*llx.RawData{
			"name":      llx.StringData("orphan-slice"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		svc := obj.(*mqlK8sEndpointslice).GetService()
		require.NoError(t, svc.Error)
		assert.Nil(t, svc.Data)
		assert.True(t, svc.State&plugin.StateIsNull != 0)
	})
}

func TestSecretUsedBy(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("secret referenced from every path is used by exactly one pod", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.secret", map[string]*llx.RawData{
			"name":      llx.StringData("db-creds"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sSecret).GetUsedBy()
		require.NoError(t, pods.Error)
		assert.Equal(t, []string{"api-7d4f-xyz"}, mqlResourceNames(t, pods.Data))
	})

	t.Run("imagePullSecret target only is still detected", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.secret", map[string]*llx.RawData{
			"name":      llx.StringData("regcred"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sSecret).GetUsedBy()
		require.NoError(t, pods.Error)
		assert.Equal(t, []string{"api-7d4f-xyz"}, mqlResourceNames(t, pods.Data))
	})

	t.Run("orphan secret has empty usedBy", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.secret", map[string]*llx.RawData{
			"name":      llx.StringData("orphan-secret"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sSecret).GetUsedBy()
		require.NoError(t, pods.Error)
		assert.Empty(t, pods.Data, "unused secrets must report an empty usedBy list")
	})
}

func TestConfigMapUsedBy(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("configmap referenced from volume+env+envFrom+init", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.configmap", map[string]*llx.RawData{
			"name":      llx.StringData("app-config"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sConfigmap).GetUsedBy()
		require.NoError(t, pods.Error)
		assert.Equal(t, []string{"api-7d4f-xyz"}, mqlResourceNames(t, pods.Data))
	})

	t.Run("orphan configmap has empty usedBy", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.configmap", map[string]*llx.RawData{
			"name":      llx.StringData("orphan-config"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		pods := obj.(*mqlK8sConfigmap).GetUsedBy()
		require.NoError(t, pods.Error)
		assert.Empty(t, pods.Data)
	})
}

// -----------------------------------------------------------------------------
// RBAC traversal: subject resolution + roleRef kind dispatch + boundBy reverse.
// -----------------------------------------------------------------------------

func TestResolveServiceAccountSubjects(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("explicit subject namespace is used", func(t *testing.T) {
		out, err := resolveServiceAccountSubjects(runtime, []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "api-sa", Namespace: "prod"},
		}, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"api-sa"}, mqlResourceNames(t, out))
	})

	t.Run("missing namespace falls back to binding namespace", func(t *testing.T) {
		out, err := resolveServiceAccountSubjects(runtime, []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "api-sa"}, // namespace omitted
		}, "prod")
		require.NoError(t, err)
		assert.Equal(t, []string{"api-sa"}, mqlResourceNames(t, out))
	})

	t.Run("non-ServiceAccount subjects are skipped", func(t *testing.T) {
		out, err := resolveServiceAccountSubjects(runtime, []rbacv1.Subject{
			{Kind: "User", Name: "alice@example.com"},
			{Kind: "Group", Name: "devs"},
			{Kind: "ServiceAccount", Name: "api-sa", Namespace: "prod"},
		}, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"api-sa"}, mqlResourceNames(t, out),
			"User and Group subjects must be filtered out")
	})

	t.Run("missing namespace and no fallback skips the subject", func(t *testing.T) {
		out, err := resolveServiceAccountSubjects(runtime, []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "api-sa"}, // no namespace, no fallback
		}, "")
		require.NoError(t, err)
		assert.Empty(t, out, "ServiceAccount with neither explicit namespace nor fallback must be skipped, not error")
	})

	t.Run("subject pointing at a deleted SA is skipped, not surfaced as an error", func(t *testing.T) {
		// "not found" is the only error class the resolver swallows — it represents
		// a binding that still references a SA that was deleted. Any other error
		// (transient, auth, etc.) must propagate. This test pins the deleted-SA
		// behavior alongside a real SA in the same call, asserting the live one
		// is still returned.
		out, err := resolveServiceAccountSubjects(runtime, []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "deleted-sa", Namespace: "prod"},
			{Kind: "ServiceAccount", Name: "api-sa", Namespace: "prod"},
		}, "")
		require.NoError(t, err, "missing SA must not break resolution of valid subjects in the same list")
		assert.Equal(t, []string{"api-sa"}, mqlResourceNames(t, out))
	})
}

func TestRoleBindingResolvers(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("RoleBinding referencing a Role", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.rbac.rolebinding", map[string]*llx.RawData{
			"name":      llx.StringData("read-secrets"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		rb := obj.(*mqlK8sRbacRolebinding)

		role := rb.GetRole()
		require.NoError(t, role.Error)
		require.NotNil(t, role.Data)
		assert.Equal(t, "secret-reader", role.Data.Name.Data)

		// roleRef.kind=Role implies clusterRole() is null.
		cr := rb.GetClusterRole()
		require.NoError(t, cr.Error)
		assert.Nil(t, cr.Data)
		assert.True(t, cr.State&plugin.StateIsNull != 0)

		sas := rb.GetServiceAccounts()
		require.NoError(t, sas.Error)
		assert.Equal(t, []string{"api-sa"}, mqlResourceNames(t, sas.Data),
			"subject without explicit namespace must fall back to the binding's namespace")
	})

	t.Run("RoleBinding referencing a ClusterRole", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.rbac.rolebinding", map[string]*llx.RawData{
			"name":      llx.StringData("read-pods-in-prod"),
			"namespace": llx.StringData("prod"),
		})
		require.NoError(t, err)
		rb := obj.(*mqlK8sRbacRolebinding)

		// Mutually exclusive: role() is null when roleRef points at a ClusterRole.
		role := rb.GetRole()
		require.NoError(t, role.Error)
		assert.Nil(t, role.Data)
		assert.True(t, role.State&plugin.StateIsNull != 0)

		cr := rb.GetClusterRole()
		require.NoError(t, cr.Error)
		require.NotNil(t, cr.Data)
		assert.Equal(t, "pod-reader", cr.Data.Name.Data)
	})
}

func TestClusterRoleBindingResolvers(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.rbac.clusterrolebinding", map[string]*llx.RawData{
		"name": llx.StringData("read-pods-everywhere"),
	})
	require.NoError(t, err)
	crb := obj.(*mqlK8sRbacClusterrolebinding)

	cr := crb.GetClusterRole()
	require.NoError(t, cr.Error)
	require.NotNil(t, cr.Data)
	assert.Equal(t, "pod-reader", cr.Data.Name.Data)

	// User subject must be filtered out; only ServiceAccount remains.
	sas := crb.GetServiceAccounts()
	require.NoError(t, sas.Error)
	assert.Equal(t, []string{"api-sa"}, mqlResourceNames(t, sas.Data))
}

func TestRoleBoundBy(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.rbac.role", map[string]*llx.RawData{
		"name":      llx.StringData("secret-reader"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	r := obj.(*mqlK8sRbacRole)
	rbs := r.GetBoundBy()
	require.NoError(t, rbs.Error)
	assert.Equal(t, []string{"read-secrets"}, mqlResourceNames(t, rbs.Data),
		"Role.boundBy must return only RoleBindings whose roleRef.kind=Role and name matches; "+
			"read-pods-in-prod targets the same namespace but references a ClusterRole and must be excluded")
}

func TestClusterRoleBoundBy(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.rbac.clusterrole", map[string]*llx.RawData{
		"name": llx.StringData("pod-reader"),
	})
	require.NoError(t, err)
	cr := obj.(*mqlK8sRbacClusterrole)
	crbs := cr.GetBoundBy()
	require.NoError(t, crbs.Error)
	assert.Equal(t, []string{"read-pods-everywhere"}, mqlResourceNames(t, crbs.Data),
		"ClusterRole.boundBy must only walk ClusterRoleBindings, not RoleBindings that also reference the role")
}

// -----------------------------------------------------------------------------
// Namespace accessors (filterByNamespace helper, used by 21 accessors).
// -----------------------------------------------------------------------------

func TestNamespaceAccessors(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	prod, err := NewResource(runtime, "k8s.namespace", map[string]*llx.RawData{
		"name": llx.StringData("prod"),
	})
	require.NoError(t, err)
	ns := prod.(*mqlK8sNamespace)

	pods := ns.GetPods()
	require.NoError(t, pods.Error)
	prodPodNames := mqlResourceNames(t, pods.Data)
	assert.ElementsMatch(t,
		[]string{"api-7d4f-xyz", "bare-pod", "db-0", "importer-pod", "standalone-pod"},
		prodPodNames,
		"namespace.pods must include every Pod in 'prod' and exclude the kube-system one")
	for _, name := range prodPodNames {
		assert.NotEqual(t, "fluentd-abc", name, "kube-system pod must not appear in prod.pods")
	}

	secrets := ns.GetSecrets()
	require.NoError(t, secrets.Error)
	assert.ElementsMatch(t, []string{"db-creds", "orphan-secret", "regcred"}, mqlResourceNames(t, secrets.Data))

	cfgs := ns.GetConfigmaps()
	require.NoError(t, cfgs.Error)
	assert.ElementsMatch(t, []string{"app-config", "orphan-config"}, mqlResourceNames(t, cfgs.Data))

	deps := ns.GetDeployments()
	require.NoError(t, deps.Error)
	assert.Equal(t, []string{"api"}, mqlResourceNames(t, deps.Data))

	cronjobs := ns.GetCronjobs()
	require.NoError(t, cronjobs.Error)
	assert.Equal(t, []string{"weekly-cleanup"}, mqlResourceNames(t, cronjobs.Data))

	// kube-system must see the daemonset, not the prod resources.
	kubeSys, err := NewResource(runtime, "k8s.namespace", map[string]*llx.RawData{
		"name": llx.StringData("kube-system"),
	})
	require.NoError(t, err)
	ksDS := kubeSys.(*mqlK8sNamespace).GetDaemonsets()
	require.NoError(t, ksDS.Error)
	assert.Equal(t, []string{"fluentd"}, mqlResourceNames(t, ksDS.Data))
	ksPods := kubeSys.(*mqlK8sNamespace).GetPods()
	require.NoError(t, ksPods.Error)
	assert.Equal(t, []string{"fluentd-abc"}, mqlResourceNames(t, ksPods.Data))
}

// -----------------------------------------------------------------------------
// Job/CronJob nullable defaults — the bot reviewer caught two of these on
// the original PR (completions, completionMode), so these are sentinels.
// -----------------------------------------------------------------------------

func TestJobDefaults(t *testing.T) {
	runtime := loadCrossRefRuntime(t)
	obj, err := NewResource(runtime, "k8s.job", map[string]*llx.RawData{
		"name":      llx.StringData("importer"),
		"namespace": llx.StringData("prod"),
	})
	require.NoError(t, err)
	j := obj.(*mqlK8sJob)

	// completionMode unset in the fixture → must default to "NonIndexed", not "".
	cm := j.GetCompletionMode()
	require.NoError(t, cm.Error)
	assert.Equal(t, "NonIndexed", cm.Data,
		"completionMode default regressed if this is empty — k8s API default is NonIndexed")

	// completions unset → must fall back to parallelism, not 0.
	completions := j.GetCompletions()
	require.NoError(t, completions.Error)
	parallelism := j.GetParallelism()
	require.NoError(t, parallelism.Error)
	assert.Equal(t, parallelism.Data, completions.Data,
		"completions default regressed if this is 0 — k8s API default is one completion per parallelism")

	// backoffLimit unset → must default to 6, not 0.
	bl := j.GetBackoffLimit()
	require.NoError(t, bl.Error)
	assert.Equal(t, int64(6), bl.Data, "backoffLimit default must be the k8s API default of 6")
}

// -----------------------------------------------------------------------------
// Webhook configuration singular-lookup regression.
// Before the init functions were added, k8s.admission.{validating,mutating}-
// webhookconfiguration(name: "X") returned a resource with obj=nil, so every
// field that dereferenced k.obj panicked with nil pointer deref. This test
// asserts the lookup actually populates obj and the fields are reachable.
// -----------------------------------------------------------------------------

func TestWebhookConfigurationSingularLookup(t *testing.T) {
	runtime := loadCrossRefRuntime(t)

	t.Run("ValidatingWebhookConfiguration", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.admission.validatingwebhookconfiguration", map[string]*llx.RawData{
			"name": llx.StringData("regression-validator"),
		})
		require.NoError(t, err)
		vwc := obj.(*mqlK8sAdmissionValidatingwebhookconfiguration)
		require.NotNil(t, vwc, "lookup must return a populated resource, not nil")

		// Each of these accessors used to panic when init was missing.
		hooks := vwc.GetWebhooks()
		require.NoError(t, hooks.Error)
		assert.Len(t, hooks.Data, 1, "webhooks list must round-trip the single configured webhook")

		labels := vwc.GetLabels()
		require.NoError(t, labels.Error)
		assert.Equal(t, "cross-references", labels.Data["test"])

		manifest := vwc.GetManifest()
		require.NoError(t, manifest.Error)
		require.NotNil(t, manifest.Data)
	})

	t.Run("MutatingWebhookConfiguration", func(t *testing.T) {
		obj, err := NewResource(runtime, "k8s.admission.mutatingwebhookconfiguration", map[string]*llx.RawData{
			"name": llx.StringData("regression-mutator"),
		})
		require.NoError(t, err)
		mwc := obj.(*mqlK8sAdmissionMutatingwebhookconfiguration)
		require.NotNil(t, mwc)

		hooks := mwc.GetWebhooks()
		require.NoError(t, hooks.Error)
		assert.Len(t, hooks.Data, 1)

		labels := mwc.GetLabels()
		require.NoError(t, labels.Error)
		assert.Equal(t, "cross-references", labels.Data["test"])

		manifest := mwc.GetManifest()
		require.NoError(t, manifest.Error)
		require.NotNil(t, manifest.Data)
	})
}
