// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"helm.sh/helm/v3/pkg/chart"
)

func newReverseLinkTestChart() *chart.Chart {
	return &chart.Chart{
		Metadata: &chart.Metadata{Name: "mychart", Version: "1.0.0", APIVersion: "v2"},
		Templates: []*chart.File{
			{
				Name: "templates/cm.yaml",
				Data: []byte("apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: {{ .Release.Name }}-cm\n"),
			},
		},
	}
}

// Regression for the helm.resource.template husk/cache-poisoning bug.
//
// Reached through the chart-wide resources path (helm.chart.resources), the
// reverse link used to rebuild the template from just its __id via NewResource.
// helm.template has no init, so that produced a husk with name/raw unset — and
// because the husk's __id was byte-identical to the real template's, it also
// poisoned the shared cache, making helm.chart.templates return husks too.
func TestResourceTemplateReverseLink(t *testing.T) {
	rt := newTestRuntime()
	c, err := newMqlHelmChart(rt, newReverseLinkTestChart(), "/charts/mychart", nil)
	require.NoError(t, err)

	// Reach resources through the chart — the path that used to husk.
	resources, err := c.resources()
	require.NoError(t, err)
	require.Len(t, resources, 1)
	res := resources[0].(*mqlHelmResource)

	// The reverse link must resolve to the real, populated template.
	tmpl, err := res.template()
	require.NoError(t, err)
	require.NotNil(t, tmpl)
	assert.NotZero(t, tmpl.Name.State&plugin.StateIsSet, "template.name must be set, not a husk")
	assert.Equal(t, "templates/cm.yaml", tmpl.Name.Data)
	assert.Contains(t, tmpl.Raw.Data, "ConfigMap")

	// Cache must not be poisoned: templates() materialized AFTER the reverse
	// link was used must still be fully populated (and the same instance).
	templates, err := c.templates()
	require.NoError(t, err)
	require.Len(t, templates, 1)
	got := templates[0].(*mqlHelmTemplate)
	assert.Equal(t, "templates/cm.yaml", got.Name.Data)
	assert.Contains(t, got.Raw.Data, "ConfigMap")
	assert.Same(t, tmpl, got, "reverse link and templates() must return the same cached template")
}

// A resource parsed straight from a template (helm.template.resources) links
// back to that exact template instance.
func TestResourceTemplateReverseLinkFromTemplate(t *testing.T) {
	rt := newTestRuntime()
	c, err := newMqlHelmChart(rt, newReverseLinkTestChart(), "/charts/mychart", nil)
	require.NoError(t, err)

	templates, err := c.templates()
	require.NoError(t, err)
	require.Len(t, templates, 1)
	tmpl := templates[0].(*mqlHelmTemplate)

	resources, err := tmpl.resources()
	require.NoError(t, err)
	require.Len(t, resources, 1)
	res := resources[0].(*mqlHelmResource)

	back, err := res.template()
	require.NoError(t, err)
	require.NotNil(t, back)
	assert.Same(t, tmpl, back)
}

// A resource with no backing template (e.g. one created without an owner, as
// happens for crds/) reports its template as null rather than a husk.
func TestResourceTemplateReverseLinkNoOwner(t *testing.T) {
	rt := newTestRuntime()
	resources, err := parseK8sResources(rt, "mychart/crds/foo.yaml",
		"apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: cm", true)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	res := resources[0].(*mqlHelmResource)

	tmpl, err := res.template()
	require.NoError(t, err)
	assert.Nil(t, tmpl)
	assert.NotZero(t, res.Template.State&plugin.StateIsNull, "template must be marked null, not a husk")
}

// Non-string scalar label/annotation values must be coerced to their string
// form rather than silently dropped, keeping helm.resource.labels consistent
// with the same keys under helm.resource.manifest.
func TestScalarLabelCoercion(t *testing.T) {
	yaml := `apiVersion: v1
kind: ConfigMap
metadata:
  name: cm
  labels:
    app: myapp
    replicas: 3
    enabled: true
  annotations:
    weight: 10`

	rt := newTestRuntime()
	resources, err := parseK8sResources(rt, "mychart/templates/cm.yaml", yaml, false)
	require.NoError(t, err)
	require.Len(t, resources, 1)
	res := resources[0].(*mqlHelmResource)

	assert.Equal(t, "myapp", res.Labels.Data["app"])
	assert.Equal(t, "3", res.Labels.Data["replicas"], "numeric label coerced, not dropped")
	assert.Equal(t, "true", res.Labels.Data["enabled"], "bool label coerced, not dropped")
	assert.Equal(t, "10", res.Annotations.Data["weight"], "numeric annotation coerced, not dropped")
}
