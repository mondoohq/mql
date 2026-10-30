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

func newTestService(path string) (*Service, *plugin.ConnectRes) {
	srv := Init()

	resp, err := srv.Connect(&plugin.ConnectReq{
		Asset: &inventory.Asset{
			Connections: []*inventory.Config{
				{
					Type:    DefaultConnectionType,
					Options: map[string]string{"path": path},
				},
			},
		},
	}, nil)
	if err != nil {
		panic(err)
	}
	return srv, resp
}

// getData is a test helper that calls GetData and fails the test on error.
func getData(t *testing.T, srv *Service, connID uint32, resource, resourceID, field string) *plugin.DataRes {
	t.Helper()
	resp, err := srv.GetData(&plugin.DataReq{
		Connection: connID,
		Resource:   resource,
		ResourceId: resourceID,
		Field:      field,
	})
	require.NoError(t, err)
	require.Empty(t, resp.Error)
	return resp
}

func TestParseCLI(t *testing.T) {
	srv := Init()

	t.Run("path argument", func(t *testing.T) {
		res, err := srv.ParseCLI(&plugin.ParseCLIReq{
			Connector: "helm",
			Args:      []string{"./my-chart"},
		})
		require.NoError(t, err)
		require.NotNil(t, res.Asset)
		require.Len(t, res.Asset.Connections, 1)
		assert.Equal(t, "helm", res.Asset.Connections[0].Type)
		assert.Equal(t, "./my-chart", res.Asset.Connections[0].Options["path"])
	})

	t.Run("no args errors", func(t *testing.T) {
		_, err := srv.ParseCLI(&plugin.ParseCLIReq{
			Connector: "helm",
			Args:      []string{},
		})
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "requires a path argument")
	})
}

func TestConnect(t *testing.T) {
	t.Run("single chart", func(t *testing.T) {
		srv, resp := newTestService("../testdata/mychart")
		require.NotNil(t, srv)
		require.NotNil(t, resp)
		assert.NotZero(t, resp.Id)
		assert.Contains(t, resp.Asset.Name, "mychart")
		assert.Equal(t, "helm", resp.Asset.Platform.Name)
	})

	t.Run("multi-chart directory", func(t *testing.T) {
		srv, resp := newTestService("../testdata/multi-chart")
		require.NotNil(t, srv)
		require.NotNil(t, resp)
		assert.Contains(t, resp.Asset.Name, "multi-chart")
	})

	t.Run("nonexistent path", func(t *testing.T) {
		srv := Init()
		_, err := srv.Connect(&plugin.ConnectReq{
			Asset: &inventory.Asset{
				Connections: []*inventory.Config{
					{
						Type:    DefaultConnectionType,
						Options: map[string]string{"path": "../testdata/nonexistent"},
					},
				},
			},
		}, nil)
		assert.Error(t, err)
	})

	t.Run("nil request", func(t *testing.T) {
		srv := Init()
		_, err := srv.Connect(nil, nil)
		assert.Error(t, err)
	})
}

func TestDetect(t *testing.T) {
	_, resp := newTestService("../testdata/mychart")
	assert.Equal(t, "helm", resp.Asset.Platform.Name)
	assert.Equal(t, []string{"helm"}, resp.Asset.Platform.Family)
	assert.Equal(t, "Helm Chart", resp.Asset.Platform.Title)
	assert.NotEmpty(t, resp.Asset.PlatformIds)
	assert.Contains(t, resp.Asset.PlatformIds[0], "//platformid.api.mondoo.app/runtime/helm/hash/")
}

func TestParseNameFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"../testdata/mychart", "directory mychart"},
		{"/tmp/some-chart.tgz", "some-chart"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			result := parseNameFromPath(tt.path)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHelmCharts(t *testing.T) {
	srv, resp := newTestService("../testdata/mychart")

	// Get the helm resource
	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)

	// Fetch charts
	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	require.Len(t, chartsResp.Data.Array, 1)
	chartID := string(chartsResp.Data.Array[0].Value)

	t.Run("chart metadata", func(t *testing.T) {
		nameResp := getData(t, srv, resp.Id, "helm.chart", chartID, "name")
		assert.Equal(t, "mychart", string(nameResp.Data.Value))

		versionResp := getData(t, srv, resp.Id, "helm.chart", chartID, "version")
		assert.Equal(t, "1.2.3", string(versionResp.Data.Value))

		apiResp := getData(t, srv, resp.Id, "helm.chart", chartID, "apiVersion")
		assert.Equal(t, "v2", string(apiResp.Data.Value))

		typeResp := getData(t, srv, resp.Id, "helm.chart", chartID, "type")
		assert.Equal(t, "application", string(typeResp.Data.Value))

		appResp := getData(t, srv, resp.Id, "helm.chart", chartID, "appVersion")
		assert.Equal(t, "4.5.6", string(appResp.Data.Value))

		descResp := getData(t, srv, resp.Id, "helm.chart", chartID, "description")
		assert.Equal(t, "A test Helm chart", string(descResp.Data.Value))

		depResp := getData(t, srv, resp.Id, "helm.chart", chartID, "deprecated")
		assert.Equal(t, []byte{0x0}, depResp.Data.Value)
	})

	t.Run("chart keywords", func(t *testing.T) {
		kwResp := getData(t, srv, resp.Id, "helm.chart", chartID, "keywords")
		require.Len(t, kwResp.Data.Array, 2)
	})

	t.Run("chart dependencies", func(t *testing.T) {
		depsResp := getData(t, srv, resp.Id, "helm.chart", chartID, "dependencies")
		require.Len(t, depsResp.Data.Array, 1)

		depID := string(depsResp.Data.Array[0].Value)
		nameResp := getData(t, srv, resp.Id, "helm.dependency", depID, "name")
		assert.Equal(t, "redis", string(nameResp.Data.Value))

		condResp := getData(t, srv, resp.Id, "helm.dependency", depID, "condition")
		assert.Equal(t, "redis.enabled", string(condResp.Data.Value))
	})

	t.Run("chart maintainers", func(t *testing.T) {
		maintResp := getData(t, srv, resp.Id, "helm.chart", chartID, "maintainers")
		require.Len(t, maintResp.Data.Array, 1)

		maintID := string(maintResp.Data.Array[0].Value)
		nameResp := getData(t, srv, resp.Id, "helm.maintainer", maintID, "name")
		assert.Equal(t, "Test User", string(nameResp.Data.Value))

		emailResp := getData(t, srv, resp.Id, "helm.maintainer", maintID, "email")
		assert.Equal(t, "test@example.com", string(emailResp.Data.Value))
	})

	t.Run("chart values", func(t *testing.T) {
		valResp := getData(t, srv, resp.Id, "helm.chart", chartID, "values")
		require.NotNil(t, valResp.Data.Value)
	})
}

func TestHelmTemplates(t *testing.T) {
	srv, resp := newTestService("../testdata/mychart")

	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)
	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	chartID := string(chartsResp.Data.Array[0].Value)

	templatesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "templates")
	require.GreaterOrEqual(t, len(templatesResp.Data.Array), 3, "should have at least deployment, service, and multi-doc templates")

	// Find the deployment template
	for _, tpl := range templatesResp.Data.Array {
		tplID := string(tpl.Value)
		nameResp := getData(t, srv, resp.Id, "helm.template", tplID, "name")
		name := string(nameResp.Data.Value)

		if name == "templates/deployment.yaml" {
			t.Run("deployment template raw content", func(t *testing.T) {
				rawResp := getData(t, srv, resp.Id, "helm.template", tplID, "raw")
				raw := string(rawResp.Data.Value)
				assert.Contains(t, raw, "kind: Deployment")
				assert.Contains(t, raw, "{{ .Values.replicaCount }}")
			})

			t.Run("deployment template rendered content", func(t *testing.T) {
				rendResp := getData(t, srv, resp.Id, "helm.template", tplID, "rendered")
				rendered := string(rendResp.Data.Value)
				assert.Contains(t, rendered, "kind: Deployment")
				assert.Contains(t, rendered, "replicas: 3")
				assert.Contains(t, rendered, "namespace: production")
			})

			t.Run("deployment template directives", func(t *testing.T) {
				dirResp := getData(t, srv, resp.Id, "helm.template", tplID, "directives")
				// The deployment template has no if/range/with, only action expressions
				assert.NotNil(t, dirResp.Data)
			})
		}
	}
}

func TestHelmResources(t *testing.T) {
	srv, resp := newTestService("../testdata/mychart")

	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)
	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	chartID := string(chartsResp.Data.Array[0].Value)

	resourcesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "resources")
	// mychart has: 1 Deployment, 1 Service, 2 ConfigMaps (multi-doc) = 4 resources
	require.GreaterOrEqual(t, len(resourcesResp.Data.Array), 4, "should have at least 4 K8s resources")

	// Find the Deployment resource and verify fields
	for _, res := range resourcesResp.Data.Array {
		resID := string(res.Value)
		kindResp := getData(t, srv, resp.Id, "helm.resource", resID, "kind")
		kind := string(kindResp.Data.Value)

		if kind == "Deployment" {
			t.Run("deployment resource", func(t *testing.T) {
				nameResp := getData(t, srv, resp.Id, "helm.resource", resID, "name")
				assert.Contains(t, string(nameResp.Data.Value), "-app")

				nsResp := getData(t, srv, resp.Id, "helm.resource", resID, "namespace")
				assert.Equal(t, "production", string(nsResp.Data.Value))

				apiResp := getData(t, srv, resp.Id, "helm.resource", resID, "apiVersion")
				assert.Equal(t, "apps/v1", string(apiResp.Data.Value))

				manifestResp := getData(t, srv, resp.Id, "helm.resource", resID, "manifest")
				assert.NotNil(t, manifestResp.Data.Value)
			})
			break
		}
	}
}

func TestHelmFiles(t *testing.T) {
	srv, resp := newTestService("../testdata/mychart")

	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)
	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	chartID := string(chartsResp.Data.Array[0].Value)

	filesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "files")
	// Files excludes Chart.yaml, values.yaml, and templates/ — only "extra" files
	// mychart doesn't have extra files, so this may be empty
	assert.NotNil(t, filesResp.Data)
}

func TestHelmMultiChart(t *testing.T) {
	srv, resp := newTestService("../testdata/multi-chart")

	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)

	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	require.Len(t, chartsResp.Data.Array, 2)

	names := map[string]bool{}
	for _, c := range chartsResp.Data.Array {
		cID := string(c.Value)
		nameResp := getData(t, srv, resp.Id, "helm.chart", cID, "name")
		names[string(nameResp.Data.Value)] = true
	}
	assert.True(t, names["chart-a"])
	assert.True(t, names["chart-b"])
}

func TestHelmNoTemplates(t *testing.T) {
	srv, resp := newTestService("../testdata/no-templates")

	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)
	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	chartID := string(chartsResp.Data.Array[0].Value)

	templatesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "templates")
	assert.Empty(t, templatesResp.Data.Array)

	resourcesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "resources")
	assert.Empty(t, resourcesResp.Data.Array)
}

func TestHelmRequiredValuesGraceful(t *testing.T) {
	// Charts that use `required` fail rendering with default values.
	// resources() should return empty (not error), matching templates() behavior.
	srv, resp := newTestService("../testdata/required-values")

	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)
	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	chartID := string(chartsResp.Data.Array[0].Value)

	// resources should gracefully return empty, not error
	resourcesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "resources")
	assert.Empty(t, resourcesResp.Data.Array)

	// templates should still work (raw content available, rendered may be empty)
	templatesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "templates")
	require.GreaterOrEqual(t, len(templatesResp.Data.Array), 1)

	// chart metadata should still be fine
	nameResp := getData(t, srv, resp.Id, "helm.chart", chartID, "name")
	assert.Equal(t, "required-values", string(nameResp.Data.Value))
}

func TestHelmNoValues(t *testing.T) {
	srv, resp := newTestService("../testdata/no-values")

	helmResp := getData(t, srv, resp.Id, "helm", "", "")
	helmID := string(helmResp.Data.Value)
	chartsResp := getData(t, srv, resp.Id, "helm", helmID, "charts")
	chartID := string(chartsResp.Data.Array[0].Value)

	valResp := getData(t, srv, resp.Id, "helm.chart", chartID, "values")
	// Empty values should still be a valid (possibly nil/empty) dict
	assert.NotNil(t, valResp.Data)

	// Templates should still render (with no values substituted)
	templatesResp := getData(t, srv, resp.Id, "helm.chart", chartID, "templates")
	require.GreaterOrEqual(t, len(templatesResp.Data.Array), 1)
}
