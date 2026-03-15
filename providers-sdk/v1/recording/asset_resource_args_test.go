// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/v13/types"
)

func TestCreateAssetResourceArgs(t *testing.T) {
	t.Run("full asset with all fields", func(t *testing.T) {
		asset := &inventory.Asset{
			Name:        "test-asset",
			PlatformIds: []string{"platform-id-1", "platform-id-2"},
			Fqdn:        "test.example.com",
			Labels:      map[string]string{"env": "prod", "team": "platform"},
			Annotations: map[string]string{"note": "test annotation"},
			Platform: &inventory.Platform{
				Name:     "ubuntu",
				Kind:     "baremetal",
				Runtime:  "docker",
				Version:  "22.04",
				Arch:     "amd64",
				Title:    "Ubuntu 22.04 LTS",
				Family:   []string{"linux", "debian"},
				Build:    "build-123",
				Labels:   map[string]string{"platform-label": "value"},
				Metadata: map[string]string{"meta-key": "meta-value"},
			},
		}

		result := CreateAssetResourceArgs(asset)
		require.NotNil(t, result)

		// Check string fields
		assert.Equal(t, "ubuntu", result["platform"].Value)
		assert.Equal(t, "test-asset", result["name"].Value)
		assert.Equal(t, "baremetal", result["kind"].Value)
		assert.Equal(t, "docker", result["runtime"].Value)
		assert.Equal(t, "22.04", result["version"].Value)
		assert.Equal(t, "amd64", result["arch"].Value)
		assert.Equal(t, "Ubuntu 22.04 LTS", result["title"].Value)
		assert.Equal(t, "build-123", result["build"].Value)
		assert.Equal(t, "test.example.com", result["fqdn"].Value)

		// Check array fields
		ids := result["ids"].Value.([]any)
		assert.Len(t, ids, 2)
		assert.Equal(t, "platform-id-1", ids[0])
		assert.Equal(t, "platform-id-2", ids[1])

		family := result["family"].Value.([]any)
		assert.Len(t, family, 2)
		assert.Equal(t, "linux", family[0])
		assert.Equal(t, "debian", family[1])

		// Check map fields
		annotations := result["annotations"].Value.(map[string]any)
		assert.Equal(t, "test annotation", annotations["note"])

		metadata := result["platformMetadata"].Value.(map[string]any)
		assert.Equal(t, "meta-value", metadata["meta-key"])

		// Labels should merge platform.Labels and asset.Labels (with asset.Labels taking precedence)
		labels := result["labels"].Value.(map[string]any)
		assert.Equal(t, "prod", labels["env"])
		assert.Equal(t, "platform", labels["team"])
		assert.Equal(t, "value", labels["platform-label"])
	})

	t.Run("minimal asset with empty platform", func(t *testing.T) {
		asset := &inventory.Asset{
			Name:     "minimal-asset",
			Platform: &inventory.Platform{},
		}

		result := CreateAssetResourceArgs(asset)
		require.NotNil(t, result)

		// Check string fields are empty
		assert.Equal(t, "", result["platform"].Value)
		assert.Equal(t, "minimal-asset", result["name"].Value)
		assert.Equal(t, "", result["kind"].Value)
		assert.Equal(t, "", result["runtime"].Value)
		assert.Equal(t, "", result["version"].Value)
		assert.Equal(t, "", result["arch"].Value)
		assert.Equal(t, "", result["title"].Value)
		assert.Equal(t, "", result["build"].Value)
		assert.Equal(t, "", result["fqdn"].Value)

		// Check array types are correct
		assert.Equal(t, types.Array(types.String), result["ids"].Type)
		assert.Equal(t, types.Array(types.String), result["family"].Type)

		// Check map types are correct
		assert.Equal(t, types.Map(types.String, types.String), result["annotations"].Type)
		assert.Equal(t, types.Map(types.String, types.String), result["platformMetadata"].Type)
		assert.Equal(t, types.Map(types.String, types.String), result["labels"].Type)
	})

	t.Run("platform labels override asset labels for backwards compatibility", func(t *testing.T) {
		asset := &inventory.Asset{
			Name:   "override-test",
			Labels: map[string]string{"shared": "asset-value", "asset-only": "a"},
			Platform: &inventory.Platform{
				Labels: map[string]string{"shared": "platform-value", "platform-only": "p"},
			},
		}

		result := CreateAssetResourceArgs(asset)
		labels := result["labels"].Value.(map[string]any)

		// platform.Labels takes precedence over asset.Labels for shared keys
		// (this is v11 backwards compatibility behavior via mapx.Merge)
		assert.Equal(t, "platform-value", labels["shared"])
		// Both asset-only and platform-only keys should be present
		assert.Equal(t, "a", labels["asset-only"])
		assert.Equal(t, "p", labels["platform-only"])
	})
}
