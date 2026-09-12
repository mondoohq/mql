// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

func testObject(kind, namespace, name string) runtime.Object {
	u := &unstructured.Unstructured{Object: map[string]any{}}
	u.SetGroupVersionKind(schema.GroupVersionKind{Kind: kind, Version: "v1"})
	u.SetName(name)
	if namespace != "" {
		u.SetNamespace(namespace)
	}
	return u
}

func apiResource(kind string, namespaced bool) *ApiResource {
	return &ApiResource{
		Resource: metav1.APIResource{Kind: kind, Name: kind + "s", Namespaced: namespaced},
	}
}

func names(objs []runtime.Object) []string {
	out := make([]string, 0, len(objs))
	for _, o := range objs {
		out = append(out, o.(*unstructured.Unstructured).GetName())
	}
	return out
}

// TestFilterResourceClusterScoped pins that a namespace filter never applies to
// cluster-scoped kinds. Those objects have an empty metadata.namespace, so
// comparing it to a requested namespace used to drop all of them and report the
// kind as empty — a scan scoped to a namespace saw zero Nodes, zero
// ClusterRoles and zero PersistentVolumes rather than the real ones.
func TestFilterResourceClusterScoped(t *testing.T) {
	objs := []runtime.Object{
		testObject("Node", "", "node-a"),
		testObject("Node", "", "node-b"),
	}

	res, err := FilterResource(apiResource("Node", false), objs, "", "prod")
	require.NoError(t, err)
	assert.Equal(t, []string{"node-a", "node-b"}, names(res),
		"cluster-scoped objects must survive a namespace filter")
}

// TestFilterResourceNamespaced pins that namespaced kinds still honor the
// namespace filter, so the cluster-scoped carve-out does not widen the scope of
// a namespaced scan.
func TestFilterResourceNamespaced(t *testing.T) {
	objs := []runtime.Object{
		testObject("Pod", "prod", "web"),
		testObject("Pod", "staging", "web"),
		testObject("Pod", "prod", "db"),
	}

	res, err := FilterResource(apiResource("Pod", true), objs, "", "prod")
	require.NoError(t, err)
	assert.Equal(t, []string{"web", "db"}, names(res))
}

func TestFilterResourceByName(t *testing.T) {
	tests := []struct {
		name       string
		kind       string
		namespaced bool
		objs       []runtime.Object
		wantName   string
		namespace  string
		expected   []string
	}{
		{
			name:       "name filter on a namespaced kind",
			kind:       "Pod",
			namespaced: true,
			objs: []runtime.Object{
				testObject("Pod", "prod", "web"),
				testObject("Pod", "prod", "db"),
			},
			wantName:  "web",
			namespace: "prod",
			expected:  []string{"web"},
		},
		{
			name:       "name filter on a cluster-scoped kind ignores the namespace",
			kind:       "ClusterRole",
			namespaced: false,
			objs: []runtime.Object{
				testObject("ClusterRole", "", "admin"),
				testObject("ClusterRole", "", "viewer"),
			},
			wantName:  "admin",
			namespace: "prod",
			expected:  []string{"admin"},
		},
		{
			name:       "other kinds are never returned",
			kind:       "Pod",
			namespaced: true,
			objs: []runtime.Object{
				testObject("Pod", "prod", "web"),
				testObject("Service", "prod", "web"),
			},
			namespace: "prod",
			expected:  []string{"web"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := FilterResource(apiResource(tt.kind, tt.namespaced), tt.objs, tt.wantName, tt.namespace)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, names(res))
		})
	}
}
