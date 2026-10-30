// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"helm.sh/helm/v3/pkg/chart"
	"helm.sh/helm/v3/pkg/chart/loader"
)

func TestNewMqlHelmChart_KubeVersionAndAnnotations(t *testing.T) {
	t.Run("populated fields surface verbatim", func(t *testing.T) {
		c := &chart.Chart{Metadata: &chart.Metadata{
			Name:        "mychart",
			Version:     "1.2.3",
			KubeVersion: ">=1.27.0-0",
			Annotations: map[string]string{
				"artifacthub.io/license": "Apache-2.0",
				"artifacthub.io/changes": "Initial release",
			},
		}}

		mqlChart, err := newMqlHelmChart(newTestRuntime(), c, "", nil)
		require.NoError(t, err)
		assert.Equal(t, ">=1.27.0-0", mqlChart.KubeVersion.Data)
		assert.Equal(t, map[string]any{
			"artifacthub.io/license": "Apache-2.0",
			"artifacthub.io/changes": "Initial release",
		}, mqlChart.Annotations.Data)
	})

	t.Run("missing fields stay empty / nil", func(t *testing.T) {
		c := &chart.Chart{Metadata: &chart.Metadata{
			Name:    "mychart",
			Version: "1.2.3",
		}}

		mqlChart, err := newMqlHelmChart(newTestRuntime(), c, "", nil)
		require.NoError(t, err)
		assert.Equal(t, "", mqlChart.KubeVersion.Data)
		// A chart without `annotations:` parses to nil; the resource layer
		// passes NilData so audits can distinguish "no annotations" from
		// "explicitly empty annotations".
		assert.Nil(t, mqlChart.Annotations.Data)
	})
}

// loader.LoadFile can return a chart with a nil Metadata pointer when
// fed a malformed .tgz; newMqlHelmChart must refuse to dereference it.
func TestNewMqlHelmChart_NilMetadataReturnsError(t *testing.T) {
	t.Run("nil metadata", func(t *testing.T) {
		c := &chart.Chart{Metadata: nil}
		_, err := newMqlHelmChart(newTestRuntime(), c, "", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "metadata")
	})

	t.Run("nil chart", func(t *testing.T) {
		_, err := newMqlHelmChart(newTestRuntime(), nil, "", nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "metadata")
	})
}

// A chart that lists two maintainers with the same name (permitted by
// the Helm spec — e.g., the same person appearing in two roles) used
// to silently dedupe through the CreateResource cache because the
// __id was `helm.maintainer:<chart>:<name>`. Indexing fixes that.
func TestMaintainersDoNotDedupeOnDuplicateName(t *testing.T) {
	c := &chart.Chart{Metadata: &chart.Metadata{
		Name:    "mychart",
		Version: "1.0.0",
		Maintainers: []*chart.Maintainer{
			{Name: "Alex", Email: "alex-primary@example.com"},
			{Name: "Alex", Email: "alex-secondary@example.com"},
		},
	}}
	mqlChart, err := newMqlHelmChart(newTestRuntime(), c, "", nil)
	require.NoError(t, err)

	mqlChart.chartObj = c
	maints, err := mqlChart.maintainers()
	require.NoError(t, err)
	require.Len(t, maints, 2, "both Alex entries should materialize as distinct resources")

	// Different emails should be reachable through the typed resources.
	emails := map[string]bool{}
	for _, m := range maints {
		emails[m.(*mqlHelmMaintainer).Email.Data] = true
	}
	assert.True(t, emails["alex-primary@example.com"], "first Alex email kept")
	assert.True(t, emails["alex-secondary@example.com"], "second Alex email kept")
}

// A chart with a vendored subchart under charts/ should surface that
// subchart as a fully recursive helm.chart through subcharts(), with
// isSubchart set on the child, parent() linking back to the top chart,
// and nested fields (values/templates) resolving per-subchart.
func TestSubchartRecursion(t *testing.T) {
	c, err := loader.LoadDir("../testdata/with-subchart")
	require.NoError(t, err)

	mqlChart, err := newMqlHelmChart(newTestRuntime(), c, "../testdata/with-subchart", nil)
	require.NoError(t, err)

	// Top-level chart is not a subchart and has no parent.
	assert.False(t, mqlChart.IsSubchart.Data, "top-level chart is not a subchart")
	parent, err := mqlChart.parent()
	require.NoError(t, err)
	assert.Nil(t, parent, "top-level chart has no parent")
	assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull, mqlChart.Parent.State)

	subs, err := mqlChart.subcharts()
	require.NoError(t, err)
	require.Len(t, subs, 1, "the vendored subchart should be returned")

	sub := subs[0].(*mqlHelmChart)
	assert.Equal(t, "mysubchart", sub.Name.Data)
	assert.Equal(t, "0.2.0", sub.Version.Data)
	assert.True(t, sub.IsSubchart.Data, "the subchart must be flagged isSubchart")

	// parent() on the subchart links back to the top chart.
	subParent, err := sub.parent()
	require.NoError(t, err)
	require.NotNil(t, subParent)
	assert.Equal(t, "with-subchart", subParent.Name.Data)

	// Parent-qualified __id keeps the subchart distinct from the parent.
	assert.NotEqual(t, mqlChart.__id, sub.__id)
	assert.Contains(t, sub.__id, mqlChart.__id, "subchart id is parent-qualified")

	// Nested fields resolve per-subchart: the subchart's own values.yaml.
	vals, err := sub.values()
	require.NoError(t, err)
	valsMap, ok := vals.(map[string]any)
	require.True(t, ok)
	assert.Contains(t, valsMap, "subImage", "subchart values.yaml should resolve")

	// And the subchart's own template renders.
	tmpls, err := sub.templates()
	require.NoError(t, err)
	require.Len(t, tmpls, 1)
	assert.Equal(t, "templates/service.yaml", tmpls[0].(*mqlHelmTemplate).Name.Data)
}

// Two charts that share name + version (real for feature-branch forks
// in a multi-chart directory) used to collide on the CreateResource
// cache because the __id ignored their path. Including ChartFullPath
// makes them coexist.
func TestChartIDIncludesPathToDeduplicate(t *testing.T) {
	runtime := newTestRuntime()
	a := &chart.Chart{Metadata: &chart.Metadata{Name: "shared", Version: "1.0.0"}}
	b := &chart.Chart{Metadata: &chart.Metadata{Name: "shared", Version: "1.0.0"}}

	// Two charts with identical name+version at distinct paths is the
	// real-world case for feature-branch forks in a multi-chart
	// directory. The connection layer passes each chart's load path
	// into newMqlHelmChart so the __id stays unique.
	mqlA, err := newMqlHelmChart(runtime, a, "/repo/charts/a", nil)
	require.NoError(t, err)
	mqlB, err := newMqlHelmChart(runtime, b, "/repo/charts/b", nil)
	require.NoError(t, err)

	// CreateResource dedupes by __id; identical names would land both
	// pointers on the cached first instance. Distinct paths must keep
	// them separate.
	assert.NotSame(t, mqlA, mqlB, "charts at distinct paths must not dedupe")

	// And the path-less fallback still produces a stable id when no
	// path is available — the failure mode is then "two same-name
	// charts collide" but that matches prior behavior.
	mqlNoPath, err := newMqlHelmChart(runtime, &chart.Chart{
		Metadata: &chart.Metadata{Name: "lone", Version: "1.0.0"},
	}, "", nil)
	require.NoError(t, err)
	assert.NotEmpty(t, mqlNoPath.__id)
}
