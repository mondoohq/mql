// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func newTestConnection(path string) (*HelmConnection, error) {
	return NewHelmConnection(0, &inventory.Asset{
		Connections: []*inventory.Config{
			{
				Options: map[string]string{
					"path": path,
				},
			},
		},
	}, nil)
}

func TestLoadSingleChart(t *testing.T) {
	conn, err := newTestConnection("../testdata/mychart")
	require.NoError(t, err)

	charts := conn.Charts()
	require.Len(t, charts, 1)

	c := charts[0].Chart
	assert.Equal(t, "mychart", c.Name())
	assert.Equal(t, "1.2.3", c.Metadata.Version)
	assert.Equal(t, "4.5.6", c.Metadata.AppVersion)
	assert.Equal(t, "A test Helm chart", c.Metadata.Description)
	assert.Equal(t, "v2", c.Metadata.APIVersion)
	assert.Equal(t, "application", string(c.Metadata.Type))
	assert.False(t, c.Metadata.Deprecated)

	assert.Equal(t, []string{"test", "helm"}, c.Metadata.Keywords)
	assert.Equal(t, "https://example.com", c.Metadata.Home)
	assert.Equal(t, "https://example.com/icon.png", c.Metadata.Icon)

	require.Len(t, c.Metadata.Maintainers, 1)
	assert.Equal(t, "Test User", c.Metadata.Maintainers[0].Name)
	assert.Equal(t, "test@example.com", c.Metadata.Maintainers[0].Email)

	require.Len(t, c.Metadata.Dependencies, 1)
	assert.Equal(t, "redis", c.Metadata.Dependencies[0].Name)
	assert.Equal(t, "redis.enabled", c.Metadata.Dependencies[0].Condition)

	// Templates should be loaded
	assert.GreaterOrEqual(t, len(c.Templates), 3)

	// Values should be loaded
	assert.Equal(t, float64(3), c.Values["replicaCount"])
}

func TestLoadMultiChartDirectory(t *testing.T) {
	conn, err := newTestConnection("../testdata/multi-chart")
	require.NoError(t, err)

	charts := conn.Charts()
	require.Len(t, charts, 2)

	names := map[string]bool{}
	for _, lc := range charts {
		names[lc.Chart.Name()] = true
		assert.NotEmpty(t, lc.Path, "each LoadedChart should carry its filesystem path")
	}
	assert.True(t, names["chart-a"])
	assert.True(t, names["chart-b"])
}

func TestLoadNonexistentPath(t *testing.T) {
	_, err := newTestConnection("../testdata/nonexistent")
	assert.Error(t, err)
}

func TestLoadEmptyDirectory(t *testing.T) {
	_, err := newTestConnection("../testdata")
	// testdata itself has no Chart.yaml, and its subdirs (mychart, multi-chart)
	// are valid — multi-chart has Chart.yaml-less root so it scans subdirs
	// This should still load charts from mychart subdir
	assert.NoError(t, err)
}

func TestLoadDirectoryWithNoCharts(t *testing.T) {
	// empty-dir has no Chart.yaml and no subdirectories with Chart.yaml
	_, err := newTestConnection("../testdata/empty-dir")
	assert.Error(t, err, "should error when no Helm charts are found")
	assert.Contains(t, err.Error(), "no Helm charts found")
}

func TestLoadChartWithNoTemplates(t *testing.T) {
	conn, err := newTestConnection("../testdata/no-templates")
	require.NoError(t, err)

	charts := conn.Charts()
	require.Len(t, charts, 1)

	c := charts[0].Chart
	assert.Equal(t, "no-templates", c.Name())
	assert.Empty(t, c.Templates, "chart with no templates directory should have no templates")
}

func TestLoadChartWithNoValues(t *testing.T) {
	conn, err := newTestConnection("../testdata/no-values")
	require.NoError(t, err)

	charts := conn.Charts()
	require.Len(t, charts, 1)

	c := charts[0].Chart
	assert.Equal(t, "no-values", c.Name())
	// Values should be nil or empty when no values.yaml exists
	assert.Empty(t, c.Values, "chart with no values.yaml should have empty values")
	// Templates should still be loaded
	assert.GreaterOrEqual(t, len(c.Templates), 1)
}

func TestConnectionNameAndPath(t *testing.T) {
	conn, err := newTestConnection("../testdata/mychart")
	require.NoError(t, err)

	assert.Equal(t, "helm", conn.Name())
	assert.Equal(t, "../testdata/mychart", conn.Path())
	assert.NotNil(t, conn.Asset())
}

func TestLoadChartsFromFile(t *testing.T) {
	// loadCharts should handle a non-directory path (e.g., .tgz)
	// Test with a path that is not a directory and not a valid archive
	_, err := newTestConnection("../testdata/mychart/Chart.yaml")
	assert.Error(t, err, "loading a non-archive file should fail")
}
