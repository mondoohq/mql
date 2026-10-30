// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

func newTestRuntime() *plugin.Runtime {
	runtime := &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
	return runtime
}

func TestParseK8sResources(t *testing.T) {
	t.Run("single deployment", func(t *testing.T) {
		yaml := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: my-app
  namespace: production
  labels:
    app: my-app
    version: "1.0"
  annotations:
    description: "Test deployment"
spec:
  replicas: 3`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/deployment.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		assert.Equal(t, "apps/v1", res.ApiVersion.Data)
		assert.Equal(t, "Deployment", res.Kind.Data)
		assert.Equal(t, "my-app", res.Name.Data)
		assert.Equal(t, "production", res.Namespace.Data)
		assert.Equal(t, "mychart:templates/deployment.yaml", res.cacheTemplateKey)
	})

	t.Run("multi-document YAML", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: Service
metadata:
  name: svc-a
---
apiVersion: v1
kind: Service
metadata:
  name: svc-b
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: config-a`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/all.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 3)

		// Verify each has unique IDs (different docIndex)
		ids := map[string]bool{}
		for _, r := range resources {
			res := r.(*mqlHelmResource)
			ids[res.__id] = true
		}
		assert.Len(t, ids, 3, "all resources should have unique IDs")
	})

	t.Run("empty documents skipped", func(t *testing.T) {
		yaml := `---
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: test
---
---`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/sparse.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)
	})

	t.Run("non-k8s YAML skipped", func(t *testing.T) {
		yaml := `# This is a comment file
key: value
another: thing`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/notes.yaml", yaml, false)
		require.NoError(t, err)
		assert.Empty(t, resources)
	})

	t.Run("invalid YAML skipped", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: Service
metadata:
  name: valid-svc
---
this is not: valid: yaml: [[[
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: valid-cm`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/mixed.yaml", yaml, false)
		require.NoError(t, err)
		assert.Len(t, resources, 2, "should skip invalid YAML but parse valid docs")
	})

	t.Run("resource with no metadata", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: Namespace`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/ns.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		assert.Equal(t, "Namespace", res.Kind.Data)
		assert.Equal(t, "", res.Name.Data)
		assert.Equal(t, "", res.Namespace.Data)
	})

	t.Run("template key separator conversion", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: test`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "my-chart/templates/cm.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		// The "/" between chart name and template path should be converted to ":"
		assert.Equal(t, "my-chart:templates/cm.yaml", res.cacheTemplateKey)
	})

	t.Run("empty content", func(t *testing.T) {
		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/empty.yaml", "", false)
		require.NoError(t, err)
		assert.Empty(t, resources)
	})
}

func TestParseK8sResourcesEdgeCases(t *testing.T) {
	t.Run("resource with metadata but no labels or annotations", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: Service
metadata:
  name: no-labels-svc
  namespace: default`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/svc.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		assert.Equal(t, "Service", res.Kind.Data)
		assert.Equal(t, "no-labels-svc", res.Name.Data)
		assert.Equal(t, "default", res.Namespace.Data)
		// Labels and annotations should be empty maps, not nil
		assert.NotNil(t, res.Labels.Data)
		assert.Empty(t, res.Labels.Data)
		assert.NotNil(t, res.Annotations.Data)
		assert.Empty(t, res.Annotations.Data)
	})

	t.Run("resource with empty metadata block", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: Namespace
metadata: {}`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/ns.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		assert.Equal(t, "Namespace", res.Kind.Data)
		assert.Equal(t, "", res.Name.Data)
	})

	t.Run("YAML with only comments between separators", func(t *testing.T) {
		yaml := `---
# This is just a comment
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: after-comments
---
# Another comment block
# with multiple lines
---`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/comments.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		assert.Equal(t, "after-comments", res.Name.Data)
	})

	t.Run("YAML with only whitespace between separators", func(t *testing.T) {
		yaml := `---


---
apiVersion: v1
kind: Service
metadata:
  name: after-whitespace
---

---`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/ws.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		assert.Equal(t, "after-whitespace", res.Name.Data)
	})

	t.Run("large multi-document with mixed valid and invalid", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-1
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: cm-2
---
not: valid: yaml: [[[
---
apiVersion: v1
kind: Service
metadata:
  name: svc-1
---
key: value
no_kind: here
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: deploy-1
  namespace: staging
  labels:
    app: test
    tier: backend
  annotations:
    commit: abc123`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/large.yaml", yaml, false)
		require.NoError(t, err)
		assert.Len(t, resources, 4, "should parse 4 valid K8s resources, skipping invalid YAML and non-K8s docs")

		// Verify the Deployment has labels and annotations
		var deploy *mqlHelmResource
		for _, r := range resources {
			res := r.(*mqlHelmResource)
			if res.Kind.Data == "Deployment" {
				deploy = res
				break
			}
		}
		require.NotNil(t, deploy)
		assert.Equal(t, "deploy-1", deploy.Name.Data)
		assert.Equal(t, "staging", deploy.Namespace.Data)
		assert.Equal(t, "test", deploy.Labels.Data["app"])
		assert.Equal(t, "backend", deploy.Labels.Data["tier"])
		assert.Equal(t, "abc123", deploy.Annotations.Data["commit"])
	})

	t.Run("resource with non-string label values", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: non-string-labels
  labels:
    app: myapp
    numeric: 123
    bool_val: true`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/labels.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)

		res := resources[0].(*mqlHelmResource)
		// Only string labels should be preserved (numeric/bool are kept as strings by YAML parser)
		assert.Equal(t, "myapp", res.Labels.Data["app"])
	})

	t.Run("resource with only apiVersion no kind", func(t *testing.T) {
		yaml := `apiVersion: v1
metadata:
  name: no-kind`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/nokind.yaml", yaml, false)
		require.NoError(t, err)
		assert.Empty(t, resources, "should skip docs without a kind field")
	})

	t.Run("multiple templates produce unique IDs across different template keys", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: shared-name`

		runtime := newTestRuntime()
		res1, err := parseK8sResources(runtime, "chartA/templates/cm.yaml", yaml, false)
		require.NoError(t, err)
		res2, err := parseK8sResources(runtime, "chartB/templates/cm.yaml", yaml, false)
		require.NoError(t, err)

		id1 := res1[0].(*mqlHelmResource).__id
		id2 := res2[0].(*mqlHelmResource).__id
		assert.NotEqual(t, id1, id2, "same resource from different charts should have different IDs")
	})
}

func TestResourceIDUniqueness(t *testing.T) {
	t.Run("same kind and name in different namespaces", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: shared-config
  namespace: staging
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: shared-config
  namespace: production`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/cm.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 2)

		id0 := resources[0].(*mqlHelmResource).__id
		id1 := resources[1].(*mqlHelmResource).__id
		assert.NotEqual(t, id0, id1, "resources in different namespaces should have different IDs")
	})

	t.Run("same kind name and namespace get different docIndex", func(t *testing.T) {
		yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: duplicate
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: duplicate`

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/dup.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 2)

		id0 := resources[0].(*mqlHelmResource).__id
		id1 := resources[1].(*mqlHelmResource).__id
		assert.NotEqual(t, id0, id1, "duplicate resources should have different IDs due to docIndex")
	})
}

func TestParseK8sResourcesDocumentSeparatorInValue(t *testing.T) {
	t.Run("--- inside a quoted scalar must not split the document", func(t *testing.T) {
		// The previous strings.Split(content, "---") split this into an
		// unterminated-quote chunk that failed to unmarshal, dropping the whole
		// resource (0 results). Splitting only on real separators keeps it whole.
		yaml := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: inline-sep\ndata:\n  note: \"a --- b\"\n"

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/cm.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1, "a `---` inside a quoted value must not split (or drop) the document")
		assert.Equal(t, "inline-sep", resources[0].(*mqlHelmResource).Name.Data)
	})

	t.Run("--- inside an indented block scalar must not split the document", func(t *testing.T) {
		// strings.Split would cut the block scalar at the indented `---`,
		// truncating the resource. Real separators are column-0 only.
		yaml := "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: block-sep\ndata:\n  readme: |\n    intro\n    ---\n    outro\n"

		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/cm.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 1)
		assert.Equal(t, "block-sep", resources[0].(*mqlHelmResource).Name.Data)
	})

	t.Run("genuine separators still split", func(t *testing.T) {
		yaml := "kind: ConfigMap\nmetadata:\n  name: a\n---\nkind: ConfigMap\nmetadata:\n  name: b\n"
		runtime := newTestRuntime()
		resources, err := parseK8sResources(runtime, "mychart/templates/cm.yaml", yaml, false)
		require.NoError(t, err)
		require.Len(t, resources, 2)
	})
}

// TestParseK8sResourcesSkipsMalformed ensures a rendered document that fails to
// parse is skipped (and surfaced via a log) without dropping the valid
// resources around it.
func TestParseK8sResourcesSkipsMalformed(t *testing.T) {
	yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: good
---
- this is a yaml sequence, not a kubernetes object
---
apiVersion: v1
kind: Service
metadata:
  name: also-good`

	resources, err := parseK8sResources(newTestRuntime(), "mychart/templates/mixed.yaml", yaml, false)
	require.NoError(t, err)
	require.Len(t, resources, 2, "the malformed document is skipped; the two valid resources remain")

	names := map[string]bool{}
	for _, r := range resources {
		names[r.(*mqlHelmResource).Name.Data] = true
	}
	assert.True(t, names["good"] && names["also-good"])
}
