// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/api/meta"
)

const defaultNamespaceManifest = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.27
---
apiVersion: v1
kind: Pod
metadata:
  name: api
  namespace: default
spec:
  containers:
  - name: api
    image: nginx:1.27
---
apiVersion: v1
kind: Pod
metadata:
  name: worker
  namespace: jobs
spec:
  containers:
  - name: worker
    image: nginx:1.27
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
---
apiVersion: apiextensions.k8s.io/v1
kind: CustomResourceDefinition
metadata:
  name: widgets.example.com
spec:
  group: example.com
  scope: Namespaced
  names:
    kind: Widget
    plural: widgets
  versions:
  - name: v1
    served: true
    storage: true
---
apiVersion: example.com/v1
kind: Widget
metadata:
  name: blue
---
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: legacy
spec:
  template:
    spec:
      containers:
      - name: legacy
        image: nginx:1.27
---
apiVersion: example.com/v1
kind: Gadget
metadata:
  name: unknown-scope
`

func objectNamespaces(t *testing.T, p ManifestParser) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, o := range p.Objects {
		m, err := meta.Accessor(o)
		require.NoError(t, err)
		if m.GetName() == "" {
			continue
		}
		out[o.GetObjectKind().GroupVersionKind().Kind+"/"+m.GetName()] = m.GetNamespace()
	}
	return out
}

func TestSetDefaultNamespaces(t *testing.T) {
	p, err := NewManifestParser([]byte(defaultNamespaceManifest), "", "")
	require.NoError(t, err)

	// Without defaulting, objects keep the namespace they were written with.
	assert.Equal(t, "", objectNamespaces(t, p)["Deployment/web"])

	require.NoError(t, p.SetDefaultNamespaces())
	ns := objectNamespaces(t, p)

	// A namespaced object that names no namespace is placed in "default".
	assert.Equal(t, "default", ns["Deployment/web"])
	// One that names a namespace keeps it.
	assert.Equal(t, "default", ns["Pod/api"])
	assert.Equal(t, "jobs", ns["Pod/worker"])
	// So is one of a kind served under an older API group.
	assert.Equal(t, "default", ns["Deployment/legacy"])
	// Cluster-scoped objects have no namespace.
	assert.Equal(t, "", ns["ClusterRole/reader"])
	assert.Equal(t, "", ns["CustomResourceDefinition/widgets.example.com"])
	// A custom kind takes the scope its CustomResourceDefinition declares.
	assert.Equal(t, "default", ns["Widget/blue"])
	// A kind whose scope is not known is left as written.
	assert.Equal(t, "", ns["Gadget/unknown-scope"])

	// The namespace list includes the default namespace the Deployment is in.
	nss, err := p.Namespaces()
	require.NoError(t, err)
	names := []string{}
	for _, n := range nss {
		names = append(names, n.Name)
	}
	assert.ElementsMatch(t, []string{"default", "jobs"}, names)

	// The workload is found in the default namespace.
	res, err := p.Resources("deployment", "web", "default")
	require.NoError(t, err)
	assert.Len(t, res.Resources, 1)
	res, err = p.Resources("deployment", "legacy", "default")
	require.NoError(t, err)
	assert.Len(t, res.Resources, 1)
}

func TestEffectiveNamespace(t *testing.T) {
	p, err := NewManifestParser([]byte(defaultNamespaceManifest), "", "")
	require.NoError(t, err)

	// Before defaulting, the written namespace is returned unchanged.
	assert.Equal(t, "", p.EffectiveNamespace("apps/v1", "Deployment", ""))

	require.NoError(t, p.SetDefaultNamespaces())
	assert.Equal(t, "default", p.EffectiveNamespace("apps/v1", "Deployment", ""))
	assert.Equal(t, "default", p.EffectiveNamespace("extensions/v1beta1", "Deployment", ""))
	assert.Equal(t, "jobs", p.EffectiveNamespace("v1", "Pod", "jobs"))
	assert.Equal(t, "", p.EffectiveNamespace("rbac.authorization.k8s.io/v1", "ClusterRole", ""))
	assert.Equal(t, "default", p.EffectiveNamespace("example.com/v1", "Widget", ""))
	assert.Equal(t, "", p.EffectiveNamespace("example.com/v1", "Gadget", ""))

	// The source position of a namespace-less object is indexed under the
	// namespace it was defaulted to, and a cluster-scoped one under none.
	index := BuildManifestPositionIndex([]byte(defaultNamespaceManifest), "app.yaml", p.EffectiveNamespace)
	assert.Contains(t, index, ObjectID("Deployment", "default", "web"))
	assert.NotContains(t, index, ObjectID("Deployment", "", "web"))
	assert.Contains(t, index, ObjectID("ClusterRole", "", "reader"))
	assert.Contains(t, index, ObjectID("Pod", "jobs", "worker"))
}
