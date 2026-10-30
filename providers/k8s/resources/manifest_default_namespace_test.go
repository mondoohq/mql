// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/manifest"
	"go.mondoo.com/mql/utils/syncx"
)

// A Deployment that names no namespace, beside Pods in "default" and in
// another namespace, and a cluster-scoped ClusterRole.
const namespacelessManifest = `apiVersion: apps/v1
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
        securityContext:
          privileged: true
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
`

func namespacelessRuntime(t *testing.T, targets ...string) (*plugin.Runtime, string) {
	t.Helper()
	file := filepath.Join(t.TempDir(), "app.yaml")
	require.NoError(t, os.WriteFile(file, []byte(namespacelessManifest), 0o600))

	cfg := &inventory.Config{Type: "k8s", Options: map[string]string{}}
	if len(targets) > 0 {
		cfg.Discover = &inventory.Discovery{Targets: targets}
	}
	conn, err := manifest.NewConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{cfg},
	}, manifest.WithManifestFile(file))
	require.NoError(t, err)

	runtime := &plugin.Runtime{
		Resources:      &syncx.Map[plugin.Resource]{},
		Connection:     conn,
		CreateResource: CreateResource,
	}
	return runtime, file
}

func TestManifest_NamespacelessWorkloadIsInDefault(t *testing.T) {
	runtime, file := namespacelessRuntime(t)

	obj, err := NewResource(runtime, "k8s.deployment", map[string]*llx.RawData{
		"name":      llx.StringData("web"),
		"namespace": llx.StringData("default"),
	})
	require.NoError(t, err)
	d := obj.(*mqlK8sDeployment)
	assert.Equal(t, "default", d.GetNamespace().Data)

	// The object still points at where it was declared.
	ctx := d.GetContext()
	require.NoError(t, ctx.Error)
	require.NotNil(t, ctx.Data)
	assert.Equal(t, file, ctx.Data.Path.Data)

	// The namespace it is in is listed.
	obj, err = NewResource(runtime, "k8s", nil)
	require.NoError(t, err)
	nss := obj.(*mqlK8s).GetNamespaces()
	require.NoError(t, nss.Error)
	names := []string{}
	for _, n := range nss.Data {
		names = append(names, n.(*mqlK8sNamespace).GetName().Data)
	}
	assert.ElementsMatch(t, []string{"default", "jobs"}, names)
}

func TestManifest_DiscoversNamespacelessWorkload(t *testing.T) {
	for _, targets := range [][]string{{DiscoveryAuto}, {DiscoveryAll}, {DiscoveryDeployments}} {
		t.Run(targets[0], func(t *testing.T) {
			runtime, _ := namespacelessRuntime(t, targets...)
			inv, err := Discover(runtime, mql.Features{})
			require.NoError(t, err)

			names := map[string]*inventory.Asset{}
			for _, a := range inv.Spec.Assets {
				names[a.Name] = a
			}
			require.Contains(t, names, "default/web")
			web := names["default/web"]
			require.NotNil(t, web.Platform)
			assert.Equal(t, "k8s-deployment", web.Platform.Name)
			require.NotEmpty(t, web.PlatformIds)
			assert.Contains(t, web.PlatformIds[0], "/namespace/default/")
		})
	}
}
