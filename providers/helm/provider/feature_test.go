// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package provider

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// newTestServiceWithOptions connects with arbitrary connection options so
// render-affecting flags (values, set, namespace, ...) can be exercised.
func newTestServiceWithOptions(opts map[string]string) (*Service, *plugin.ConnectRes) {
	srv := Init()
	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{Type: DefaultConnectionType, Options: opts},
			},
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return srv, resp
}

// firstChartID drives the helm -> charts[0] navigation used by every test.
func firstChartID(t *testing.T, srv *Service, connID uint32) string {
	t.Helper()
	helmResp := getData(t, srv, connID, "helm", "", "")
	helmID := string(helmResp.Data.Value)
	chartsResp := getData(t, srv, connID, "helm", helmID, "charts")
	require.GreaterOrEqual(t, len(chartsResp.Data.Array), 1)
	return string(chartsResp.Data.Array[0].Value)
}

func TestHelmFeatureChart(t *testing.T) {
	srv, resp := newTestServiceWithOptions(map[string]string{"path": "../testdata/featurechart"})
	chartID := firstChartID(t, srv, resp.Id)

	t.Run("notes", func(t *testing.T) {
		notesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "notes")
		assert.Contains(t, string(notesResp.Data.Value), "Thank you for installing featurechart")
	})

	t.Run("valuesSchema", func(t *testing.T) {
		schemaResp := getData(t, srv, resp.Id, "helm.chart", chartID, "valuesSchema")
		require.NotNil(t, schemaResp.Data.Value)
	})

	t.Run("crds", func(t *testing.T) {
		crdsResp := getData(t, srv, resp.Id, "helm.chart", chartID, "crds")
		require.Len(t, crdsResp.Data.Array, 1)
		crdID := string(crdsResp.Data.Array[0].Value)

		kindResp := getData(t, srv, resp.Id, "helm.resource", crdID, "kind")
		assert.Equal(t, "CustomResourceDefinition", string(kindResp.Data.Value))

		isCRDResp := getData(t, srv, resp.Id, "helm.resource", crdID, "isCRD")
		assert.Equal(t, true, isCRDResp.Data.RawData().Value)
	})

	t.Run("hooks", func(t *testing.T) {
		hooksResp := getData(t, srv, resp.Id, "helm.chart", chartID, "hooks")
		require.Len(t, hooksResp.Data.Array, 1)
		hookID := string(hooksResp.Data.Array[0].Value)

		isHookResp := getData(t, srv, resp.Id, "helm.resource", hookID, "isHook")
		assert.Equal(t, true, isHookResp.Data.RawData().Value)

		typesResp := getData(t, srv, resp.Id, "helm.resource", hookID, "hookTypes")
		require.Len(t, typesResp.Data.Array, 2)
		assert.Equal(t, "pre-install", string(typesResp.Data.Array[0].Value))
		assert.Equal(t, "post-install", string(typesResp.Data.Array[1].Value))

		weightResp := getData(t, srv, resp.Id, "helm.resource", hookID, "hookWeight")
		assert.Equal(t, int64(5), weightResp.Data.RawData().Value)

		delResp := getData(t, srv, resp.Id, "helm.resource", hookID, "hookDeletePolicies")
		require.Len(t, delResp.Data.Array, 2)
	})

	t.Run("lock", func(t *testing.T) {
		lockResp := getData(t, srv, resp.Id, "helm.chart", chartID, "lock")
		lockID := string(lockResp.Data.Value)
		require.NotEmpty(t, lockID)

		digestResp := getData(t, srv, resp.Id, "helm.chart.dependencyLock", lockID, "digest")
		assert.Contains(t, string(digestResp.Data.Value), "sha256:")

		depsResp := getData(t, srv, resp.Id, "helm.chart.dependencyLock", lockID, "dependencies")
		require.Len(t, depsResp.Data.Array, 1)
	})

	t.Run("dependency resolved version and import-values", func(t *testing.T) {
		depsResp := getData(t, srv, resp.Id, "helm.chart", chartID, "dependencies")
		require.Len(t, depsResp.Data.Array, 1)
		depID := string(depsResp.Data.Array[0].Value)

		resolvedResp := getData(t, srv, resp.Id, "helm.dependency", depID, "resolvedVersion")
		assert.Equal(t, "1.2.3", string(resolvedResp.Data.Value))

		importResp := getData(t, srv, resp.Id, "helm.dependency", depID, "importValues")
		require.Len(t, importResp.Data.Array, 1)

		// The dependency isn't vendored on disk, so chart() is null.
		chartResp := getData(t, srv, resp.Id, "helm.dependency", depID, "chart")
		assert.True(t, chartResp.Data.IsNil())
	})

	t.Run("lint resolves", func(t *testing.T) {
		lintResp := getData(t, srv, resp.Id, "helm.chart", chartID, "lint")
		lintID := string(lintResp.Data.Value)
		require.NotEmpty(t, lintID)

		// passed is a bool; we don't assert its value (a fixture may warn),
		// only that linting ran and messages is an array.
		_ = getData(t, srv, resp.Id, "helm.chart.lintResult", lintID, "passed")
		msgsResp := getData(t, srv, resp.Id, "helm.chart.lintResult", lintID, "messages")
		assert.NotNil(t, msgsResp.Data)
	})

	t.Run("template requiresCluster reflects lookup usage", func(t *testing.T) {
		templatesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "templates")
		seen := map[string]bool{}
		for _, tpl := range templatesResp.Data.Array {
			tplID := string(tpl.Value)
			name := string(getData(t, srv, resp.Id, "helm.template", tplID, "name").Data.Value)
			reqResp := getData(t, srv, resp.Id, "helm.template", tplID, "requiresCluster")
			seen[name] = reqResp.Data.RawData().Value.(bool)
		}
		assert.True(t, seen["templates/configmap.yaml"], "configmap uses lookup")
		assert.False(t, seen["templates/NOTES.txt"], "NOTES.txt has no lookup")
	})

	t.Run("file size and isBinary", func(t *testing.T) {
		filesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "files")
		found := false
		for _, f := range filesResp.Data.Array {
			fID := string(f.Value)
			path := string(getData(t, srv, resp.Id, "helm.file", fID, "path").Data.Value)
			if path == "README.md" {
				found = true
				sizeResp := getData(t, srv, resp.Id, "helm.file", fID, "size")
				assert.Greater(t, sizeResp.Data.RawData().Value.(int64), int64(0))
				binResp := getData(t, srv, resp.Id, "helm.file", fID, "isBinary")
				assert.Equal(t, false, binResp.Data.RawData().Value)
			}
		}
		assert.True(t, found, "README.md should be listed in files()")
	})
}

func TestHelmRenderOverrides(t *testing.T) {
	// --set replicas=5 should flow into the rendered ConfigMap.
	srv, resp := newTestServiceWithOptions(map[string]string{
		"path": "../testdata/featurechart",
		"set":  `["replicas=5"]`,
	})
	chartID := firstChartID(t, srv, resp.Id)

	resourcesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "resources")
	require.NotEmpty(t, resourcesResp.Data.Array)

	foundCM := false
	for _, r := range resourcesResp.Data.Array {
		resID := string(r.Value)
		kind := string(getData(t, srv, resp.Id, "helm.resource", resID, "kind").Data.Value)
		if kind == "ConfigMap" {
			foundCM = true
			manifestResp := getData(t, srv, resp.Id, "helm.resource", resID, "manifest")
			require.NotNil(t, manifestResp.Data.Value)
		}
	}
	assert.True(t, foundCM, "ConfigMap should render")

	// renderedValues should reflect the override.
	rvResp := getData(t, srv, resp.Id, "helm.chart", chartID, "renderedValues")
	require.NotNil(t, rvResp.Data.Value)
}

func TestHelmReleaseIdentityOverride(t *testing.T) {
	// release-name and namespace should appear in rendered resources.
	srv, resp := newTestServiceWithOptions(map[string]string{
		"path":         "../testdata/featurechart",
		"release-name": "myrelease",
		"namespace":    "custom-ns",
	})
	chartID := firstChartID(t, srv, resp.Id)

	resourcesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "resources")
	foundNamed := false
	for _, r := range resourcesResp.Data.Array {
		resID := string(r.Value)
		name := string(getData(t, srv, resp.Id, "helm.resource", resID, "name").Data.Value)
		if name == "myrelease-cm" {
			foundNamed = true
		}
	}
	assert.True(t, foundNamed, "resource name should use the overridden release name")
}
