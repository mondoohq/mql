// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"helm.sh/helm/v3/pkg/chart/loader"
)

func TestClassifyHelmSource(t *testing.T) {
	cases := []struct {
		repository string
		alias      string
		want       string
	}{
		{"oci://ghcr.io/acme/redis", "", "oci"},
		{"https://charts.bitnami.com/bitnami", "", "https"},
		{"http://charts.example.com", "", "http"},
		{"file://./charts/localchart", "", "file"},
		{"./charts/localchart", "", "file"},
		{"../sibling", "", "file"},
		{"/abs/path/chart", "", "file"},
		{"", "common", "alias"},
		{"", "", "unknown"},
		{"weird-value", "", "unknown"},
	}
	for _, c := range cases {
		assert.Equal(t, c.want, classifyHelmSource(c.repository, c.alias),
			"repository=%q alias=%q", c.repository, c.alias)
	}
}

func TestParseOciRef(t *testing.T) {
	t.Run("registry and repository from path", func(t *testing.T) {
		ref := parseOciRef("oci://ghcr.io/acme/charts/redis", "18.1.5")
		assert.Equal(t, "oci://ghcr.io/acme/charts/redis", ref.reference)
		assert.Equal(t, "ghcr.io", ref.registry)
		assert.Equal(t, "acme/charts/redis", ref.repository)
		// Concrete version maps onto the tag.
		assert.Equal(t, "18.1.5", ref.tag)
		assert.Equal(t, "", ref.digest)
	})

	t.Run("tag suffix on reference", func(t *testing.T) {
		ref := parseOciRef("oci://ghcr.io/acme/redis:1.2.3", "")
		assert.Equal(t, "ghcr.io", ref.registry)
		assert.Equal(t, "acme/redis", ref.repository)
		assert.Equal(t, "1.2.3", ref.tag)
	})

	t.Run("digest pin on reference", func(t *testing.T) {
		ref := parseOciRef("oci://ghcr.io/acme/redis@sha256:abc123", "")
		assert.Equal(t, "ghcr.io", ref.registry)
		assert.Equal(t, "acme/redis", ref.repository)
		assert.Equal(t, "sha256:abc123", ref.digest)
		assert.Equal(t, "", ref.tag, "digest pin should not also set a tag")
	})

	t.Run("digest from version constraint", func(t *testing.T) {
		ref := parseOciRef("oci://ghcr.io/acme/redis", "sha256:deadbeef")
		assert.Equal(t, "sha256:deadbeef", ref.digest)
		assert.Equal(t, "", ref.tag)
	})

	t.Run("range version is not a tag", func(t *testing.T) {
		ref := parseOciRef("oci://ghcr.io/acme/redis", ">=18.0.0")
		assert.Equal(t, "", ref.tag, "a SemVer range must not be treated as a concrete tag")
	})

	t.Run("host:port in registry", func(t *testing.T) {
		ref := parseOciRef("oci://registry.local:5000/team/app", "2.0.0")
		assert.Equal(t, "registry.local:5000", ref.registry)
		assert.Equal(t, "team/app", ref.repository)
		assert.Equal(t, "2.0.0", ref.tag)
	})

	t.Run("registry only, no path", func(t *testing.T) {
		ref := parseOciRef("oci://ghcr.io", "")
		assert.Equal(t, "ghcr.io", ref.registry)
		assert.Equal(t, "", ref.repository)
	})
}

// A chart with mixed dependency sources should classify each one and
// only expose a parsed registryRef for the OCI dependency.
func TestDependencySourceClassification(t *testing.T) {
	c, err := loader.LoadDir("../testdata/oci-deps")
	require.NoError(t, err)

	mqlChart, err := newMqlHelmChart(newTestRuntime(), c, "../testdata/oci-deps", nil)
	require.NoError(t, err)

	deps, err := mqlChart.dependencies()
	require.NoError(t, err)
	require.Len(t, deps, 3)

	byName := map[string]*mqlHelmDependency{}
	for _, d := range deps {
		dep := d.(*mqlHelmDependency)
		byName[dep.Name.Data] = dep
	}

	require.Contains(t, byName, "redis")
	require.Contains(t, byName, "nginx")
	require.Contains(t, byName, "localchart")

	assert.Equal(t, "oci", byName["redis"].SourceType.Data)
	assert.Equal(t, "https", byName["nginx"].SourceType.Data)
	assert.Equal(t, "file", byName["localchart"].SourceType.Data)

	// registryRef is non-null and parsed for the OCI dependency.
	ociRef, err := byName["redis"].registryRef()
	require.NoError(t, err)
	require.NotNil(t, ociRef)
	assert.Equal(t, "ghcr.io", ociRef.Registry.Data)
	assert.Equal(t, "acme/charts/redis", ociRef.Repository.Data)
	assert.Equal(t, "18.1.5", ociRef.Tag.Data)

	// registryRef is null for the non-OCI dependencies.
	for _, name := range []string{"nginx", "localchart"} {
		ref, err := byName[name].registryRef()
		require.NoError(t, err)
		assert.Nil(t, ref, "%s should have no registryRef", name)
		assert.Equal(t, plugin.StateIsSet|plugin.StateIsNull,
			byName[name].RegistryRef.State, "%s registryRef state", name)
	}
}
