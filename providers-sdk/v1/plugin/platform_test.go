// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	inventory "go.mondoo.com/mql/providers-sdk/v1/inventory"
)

func TestPlatformInfoApply(t *testing.T) {
	t.Run("single-valued kind/runtime are set", func(t *testing.T) {
		pi := &PlatformInfo{
			Name:    "aws-s3-bucket",
			Title:   "AWS S3 Bucket",
			Kind:    []string{"aws-object"},
			Runtime: []string{"aws"},
		}
		p := &inventory.Platform{}
		pi.Apply(p)
		assert.Equal(t, "aws-s3-bucket", p.Name)
		assert.Equal(t, "AWS S3 Bucket", p.Title)
		assert.Equal(t, "aws-object", p.Kind)
		assert.Equal(t, "aws", p.Runtime)
	})

	t.Run("multi-valued kind/runtime are left to the connection", func(t *testing.T) {
		pi := &PlatformInfo{
			Name:    "ubuntu",
			Family:  []string{"debian", "linux", "unix", "os"},
			Kind:    []string{"baremetal", "virtualmachine", "container", "container-image"},
			Runtime: []string{"docker-image", "docker"},
		}
		p := &inventory.Platform{Kind: "container", Runtime: "docker"}
		pi.Apply(p)
		assert.Equal(t, "ubuntu", p.Name)
		assert.Equal(t, []string{"debian", "linux", "unix", "os"}, p.Family)
		// connection-set values are preserved
		assert.Equal(t, "container", p.Kind)
		assert.Equal(t, "docker", p.Runtime)
	})

	t.Run("a runtime title wins over the catalog default", func(t *testing.T) {
		pi := &PlatformInfo{Name: "ubuntu", Title: "Ubuntu"}
		p := &inventory.Platform{Title: "Ubuntu 20.04 LTS"}
		pi.Apply(p)
		assert.Equal(t, "Ubuntu 20.04 LTS", p.Title)
	})

	t.Run("family is cloned, not aliased", func(t *testing.T) {
		fam := []string{"linux", "unix", "os"}
		pi := &PlatformInfo{Name: "x", Family: fam}
		p := &inventory.Platform{}
		pi.Apply(p)
		p.Family[0] = "mutated"
		assert.Equal(t, "linux", fam[0], "descriptor family must not be mutated via the applied platform")
	})

	t.Run("a nil descriptor falls back to an unknown platform", func(t *testing.T) {
		// PlatformByName returns nil for an unknown name; calling Apply on that
		// (e.g. a typo'd platform name at a call site) must not nil-deref. It
		// logs and falls back to an "unknown" platform instead.
		var pi *PlatformInfo
		p := &inventory.Platform{}
		assert.NotPanics(t, func() { pi.Apply(p) })
		assert.Equal(t, "unknown", p.Name)
		assert.Equal(t, "Unknown", p.Title)
		assert.Equal(t, "unknown", p.Kind)
		assert.Equal(t, "unknown", p.Runtime)
	})
}

func TestPlatformInfoConsistent(t *testing.T) {
	pi := &PlatformInfo{
		Name:    "ubuntu",
		Kind:    []string{"baremetal", "container"},
		Runtime: []string{"docker"},
	}
	assert.True(t, pi.Consistent(&inventory.Platform{Kind: "container", Runtime: "docker"}))
	assert.True(t, pi.Consistent(&inventory.Platform{}), "empty runtime platform is unconstrained")
	assert.False(t, pi.Consistent(&inventory.Platform{Kind: "virtualmachine"}), "kind not in set")
	assert.False(t, pi.Consistent(&inventory.Platform{Runtime: "podman"}), "runtime not in set")
}

func TestProviderPlatformsRoundTrip(t *testing.T) {
	src := Provider{
		Name:    "example",
		ID:      "go.mondoo.com/example",
		Version: "1.0.0",
		Platforms: []*PlatformInfo{
			{Name: "example", Title: "Example", Kind: []string{"api"}, Runtime: []string{"example"}},
			{Name: "ubuntu", Family: []string{"debian", "linux"}, Kind: []string{"baremetal", "container"}},
		},
	}
	data, err := json.Marshal(src)
	require.NoError(t, err)

	// mirrors providers.(*Provider).LoadJSON which json.Unmarshals into Provider
	var got Provider
	require.NoError(t, json.Unmarshal(data, &got))
	assert.Equal(t, src.Platforms, got.Platforms)
}
