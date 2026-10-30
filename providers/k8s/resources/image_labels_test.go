// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
	corev1 "k8s.io/api/core/v1"
)

func TestImageLabelVerdicts(t *testing.T) {
	nsLabels := map[string]map[string]string{
		"team-alpha":     {"my.company.com/team": "alpha", "my.company.com/department": "d-1"},
		"team-beta":      {"my.company.com/team": "beta", "my.company.com/department": "d-1"},
		"platform-tools": {"my.company.com/department": "d-0"},
	}
	images := map[string][]string{
		"team-alpha":     {"nginx@sha256:shared", "web@sha256:alpha-only", "busybox@sha256:tools"},
		"team-beta":      {"nginx@sha256:shared"},
		"platform-tools": {"busybox@sha256:tools"},
	}
	got := imageLabelVerdicts(images, nsLabels, []string{"my.company.com/*"})

	assert.Equal(t, imageLabelVerdict{Labels: map[string]string{"my.company.com/team": "alpha", "my.company.com/department": "d-1"}}, got["web@sha256:alpha-only"])
	// team disagrees, department agrees: one value, marker names only the conflicting key
	assert.Equal(t, imageLabelVerdict{Labels: map[string]string{"my.company.com/department": "d-1"}, Conflicts: []string{"my.company.com/team"}}, got["nginx@sha256:shared"])
	// platform-tools lacks the team key and does not vote on it; it does vote on department
	assert.Equal(t, imageLabelVerdict{Labels: map[string]string{"my.company.com/team": "alpha"}, Conflicts: []string{"my.company.com/department"}}, got["busybox@sha256:tools"])
}

func TestImageLabelVerdictsNoVoters(t *testing.T) {
	got := imageLabelVerdicts(map[string][]string{"ns": {"img"}}, map[string]map[string]string{"ns": {"other": "x"}}, []string{"my.company.com/team"})
	assert.NotContains(t, got, "img")
}

func TestImageLabelVerdictsEncoding(t *testing.T) {
	v := map[string]imageLabelVerdict{"img": {Labels: map[string]string{"k": "v"}, Conflicts: []string{"c"}}}
	raw := encodeImageLabelVerdicts(v)
	got, skip, err := decodeImageLabelVerdicts(raw)
	require.NoError(t, err)
	assert.False(t, skip)
	assert.Equal(t, v, got)

	assert.Equal(t, "{}", encodeImageLabelVerdicts(nil))

	old := imageLabelVerdictsMaxBytes
	imageLabelVerdictsMaxBytes = 8
	defer func() { imageLabelVerdictsMaxBytes = old }()
	assert.Equal(t, imageLabelVerdictsSentinel, encodeImageLabelVerdicts(v))
	_, skip, err = decodeImageLabelVerdicts(imageLabelVerdictsSentinel)
	require.NoError(t, err)
	assert.True(t, skip)
}

func TestVerdictsForImages(t *testing.T) {
	all := map[string]imageLabelVerdict{"a": {Labels: map[string]string{"k": "1"}}, "b": {Labels: map[string]string{"k": "2"}}}
	assert.Equal(t, map[string]imageLabelVerdict{"a": all["a"]}, verdictsForImages(all, []string{"a", "missing"}))
}

func TestApplyImageLabelVerdicts(t *testing.T) {
	image := func(host string) *inventory.Asset {
		return &inventory.Asset{Connections: []*inventory.Config{{Type: registryImageConnectionType, Host: host}}}
	}
	labeled, conflicted, unknown := image("a"), image("b"), image("c")
	workload := &inventory.Asset{Name: "ns/pod", Labels: map[string]string{"app": "x"}, Connections: []*inventory.Config{{Type: "k8s"}}}
	applyImageLabelVerdicts([]*inventory.Asset{labeled, conflicted, unknown, workload}, map[string]imageLabelVerdict{
		"a": {Labels: map[string]string{"my.company.com/team": "alpha"}},
		"b": {Labels: map[string]string{"my.company.com/department": "d-1"}, Conflicts: []string{"my.company.com/dept", "my.company.com/team"}},
	})
	assert.Equal(t, map[string]string{"my.company.com/team": "alpha"}, labeled.Labels)
	assert.Equal(t, map[string]string{"my.company.com/department": "d-1", LabelNamespaceLabelConflict: "my.company.com/dept,my.company.com/team"}, conflicted.Labels)
	assert.Nil(t, unknown.Labels)
	assert.Equal(t, map[string]string{"app": "x"}, workload.Labels)
}

func TestClusterImagesByNamespaceHonoursScope(t *testing.T) {
	asset := &inventory.Asset{Connections: []*inventory.Config{{Type: "k8s", Options: map[string]string{}}}}
	conn := &namespaceDiscoveryConnection{
		Connection: plugin.NewConnection(1, asset),
		asset:      asset,
		pods: []corev1.Pod{
			newTestPod("team-alpha", "web", "u1", nil, "nginx@sha256:shared"),
			newTestPod("team-beta", "proxy", "u2", nil, "nginx@sha256:shared"),
			newTestPod("excluded-ns", "x", "u3", nil, "nginx@sha256:shared"),
			newTestPod("team-alpha", "skipme", "u4", map[string]string{"scan": "no"}, "other@sha256:1"),
		},
	}
	labelFilters, err := labelSelectorFilters(&inventory.Config{Options: map[string]string{shared.OPTION_OBJECT_LABEL_SELECTOR: "scan!=no"}})
	require.NoError(t, err)
	imgFilter, err := newFilterOpts(nil, nil)
	require.NoError(t, err)

	got, err := clusterImagesByNamespace(conn, []string{"team-alpha", "team-beta"}, labelFilters, imgFilter)
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"team-alpha": {"nginx@sha256:shared"}, "team-beta": {"nginx@sha256:shared"}}, got)
}

// A namespace-scoped service account cannot list pods cluster-wide (the API
// connection swallows the Forbidden and returns nothing), but can list them in
// the namespaces it was given. The index must use the latter.
func TestClusterImagesByNamespaceListsPerNamespace(t *testing.T) {
	asset := &inventory.Asset{Connections: []*inventory.Config{{Type: "k8s", Options: map[string]string{}}}}
	conn := &namespaceDiscoveryConnection{
		Connection:            plugin.NewConnection(1, asset),
		asset:                 asset,
		forbidClusterWidePods: true,
		pods: []corev1.Pod{
			newTestPod("team-alpha", "web", "u1", nil, "nginx@sha256:shared"),
			newTestPod("team-beta", "proxy", "u2", nil, "nginx@sha256:shared", "api@sha256:beta"),
		},
	}
	imgFilter, err := newFilterOpts(nil, nil)
	require.NoError(t, err)

	got, err := clusterImagesByNamespace(conn, []string{"team-alpha", "team-beta"}, &LabelSelectorFilters{}, imgFilter)
	require.NoError(t, err)
	assert.Equal(t, map[string][]string{"team-alpha": {"nginx@sha256:shared"}, "team-beta": {"api@sha256:beta", "nginx@sha256:shared"}}, got)
}
