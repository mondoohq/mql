// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func clusterScopedApiResource(kind string) *ApiResource {
	return &ApiResource{
		Resource:     metav1.APIResource{Kind: kind, Namespaced: false},
		GroupVersion: schema.GroupVersion{Group: "storage.k8s.io", Version: "v1"},
	}
}

func namespacedApiResource(kind string) *ApiResource {
	return &ApiResource{
		Resource:     metav1.APIResource{Kind: kind, Namespaced: true},
		GroupVersion: schema.GroupVersion{Group: "", Version: "v1"},
	}
}

func storageClass(name string) runtime.Object {
	sc := &storagev1.StorageClass{ObjectMeta: metav1.ObjectMeta{Name: name}}
	sc.SetGroupVersionKind(schema.GroupVersionKind{
		Group: "storage.k8s.io", Version: "v1", Kind: "StorageClass",
	})
	return sc
}

func configMap(namespace, name string) runtime.Object {
	cm := &corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: name}}
	cm.SetGroupVersionKind(schema.GroupVersionKind{Version: "v1", Kind: "ConfigMap"})
	return cm
}

// Staged discovery sets a namespace on every namespace asset. A cluster-scoped
// object has no namespace to match, so applying the filter to one silently
// empties the list and every policy over it passes vacuously.
func TestFilterResourceKeepsClusterScopedKindsUnderNamespaceScope(t *testing.T) {
	objs := []runtime.Object{storageClass("standard"), storageClass("fast")}

	got, err := FilterResource(clusterScopedApiResource("StorageClass"), objs, "", "kube-system")
	require.NoError(t, err)
	assert.Len(t, got, 2, "a namespace scope must not hide cluster-scoped objects")
}

func TestFilterResourceStillScopesNamespacedKinds(t *testing.T) {
	objs := []runtime.Object{
		configMap("kube-system", "wanted"),
		configMap("default", "other"),
	}

	got, err := FilterResource(namespacedApiResource("ConfigMap"), objs, "", "kube-system")
	require.NoError(t, err)
	require.Len(t, got, 1, "a namespaced kind must still be filtered by namespace")

	cm, ok := got[0].(*corev1.ConfigMap)
	require.True(t, ok)
	assert.Equal(t, "wanted", cm.Name)
}

// Name filtering has to keep working for both scopes, or the guard above would
// turn a single-object lookup into "every object of that kind".
func TestFilterResourceByNameAcrossScopes(t *testing.T) {
	cluster, err := FilterResource(clusterScopedApiResource("StorageClass"),
		[]runtime.Object{storageClass("standard"), storageClass("fast")}, "fast", "kube-system")
	require.NoError(t, err)
	require.Len(t, cluster, 1)
	sc, ok := cluster[0].(*storagev1.StorageClass)
	require.True(t, ok)
	assert.Equal(t, "fast", sc.Name)

	namespaced, err := FilterResource(namespacedApiResource("ConfigMap"),
		[]runtime.Object{configMap("kube-system", "a"), configMap("kube-system", "b")}, "b", "kube-system")
	require.NoError(t, err)
	require.Len(t, namespaced, 1)
	cm, ok := namespaced[0].(*corev1.ConfigMap)
	require.True(t, ok)
	assert.Equal(t, "b", cm.Name)
}
