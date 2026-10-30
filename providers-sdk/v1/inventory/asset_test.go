// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAddMondooLabels(t *testing.T) {
	asset := &Asset{
		Labels: map[string]string{
			"foo": "bar",
		},
	}

	rootAsset := &Asset{
		Labels: map[string]string{
			"k8s.mondoo.com/test": "val",
			"mondoo.com/sample":   "example",
			"random":              "random-val",
		},
	}

	asset.AddMondooLabels(rootAsset)
	assert.Equal(
		t,
		asset.Labels,
		map[string]string{
			"foo":                 "bar",
			"k8s.mondoo.com/test": "val",
			"mondoo.com/sample":   "example",
		})
}

func TestAddAnnotations(t *testing.T) {
	t.Run("AddAnnotations", func(t *testing.T) {
		asset := &Asset{
			Labels: map[string]string{
				"foo": "bar",
			},
		}
		asset.AddAnnotations(map[string]string{})
		assert.Equal(t, map[string]string(nil), asset.Annotations)
	})

	t.Run("test nil", func(t *testing.T) {
		asset := &Asset{
			Labels: map[string]string{
				"foo": "bar",
			},
		}
		asset.AddAnnotations(nil)
		assert.Equal(t, map[string]string(nil), asset.Annotations)
	})

	t.Run("test merge", func(t *testing.T) {
		asset := &Asset{
			Annotations: map[string]string{
				"foo": "bar",
			},
		}
		asset.AddAnnotations(map[string]string{
			"fruit": "banana",
		})
		assert.Equal(t, map[string]string{
			"foo":   "bar",
			"fruit": "banana",
		}, asset.Annotations)
	})

	t.Run("test overwrite", func(t *testing.T) {
		asset := &Asset{
			Annotations: map[string]string{
				"foo": "bar",
			},
		}
		asset.AddAnnotations(map[string]string{
			"foo": "not-bar",
		})
		assert.Equal(t, map[string]string{
			"foo": "not-bar",
		}, asset.Annotations)
	})
}

func TestAssetCategoryUnmarshalJSON(t *testing.T) {
	// swap the global logger so we can assert on the deprecation warning
	withCapturedLog := func(t *testing.T, f func()) string {
		t.Helper()
		var buf bytes.Buffer
		orig := log.Logger
		log.Logger = zerolog.New(&buf)
		defer func() { log.Logger = orig }()
		f()
		return buf.String()
	}

	t.Run("deprecated fleet still resolves and warns", func(t *testing.T) {
		var c AssetCategory
		out := withCapturedLog(t, func() {
			require.NoError(t, c.UnmarshalJSON([]byte(`"fleet"`)))
		})
		assert.Equal(t, AssetCategory_CATEGORY_INVENTORY, c)
		assert.Contains(t, out, "deprecated asset category")
		assert.Contains(t, out, `"category":"fleet"`)
		assert.Contains(t, out, `"use":"inventory"`)
	})

	t.Run("fleet warns even when padded", func(t *testing.T) {
		var c AssetCategory
		out := withCapturedLog(t, func() {
			require.NoError(t, c.UnmarshalJSON([]byte(`"  fleet  "`)))
		})
		assert.Equal(t, AssetCategory_CATEGORY_INVENTORY, c)
		assert.Contains(t, out, "deprecated asset category")
	})

	t.Run("supported names do not warn", func(t *testing.T) {
		for name, want := range map[string]AssetCategory{
			"inventory": AssetCategory_CATEGORY_INVENTORY,
			"cicd":      AssetCategory_CATEGORY_CICD,
		} {
			var c AssetCategory
			out := withCapturedLog(t, func() {
				require.NoError(t, c.UnmarshalJSON([]byte(`"`+name+`"`)))
			})
			assert.Equal(t, want, c, name)
			assert.Empty(t, out, name)
		}
	})

	t.Run("numeric form does not warn", func(t *testing.T) {
		var c AssetCategory
		out := withCapturedLog(t, func() {
			require.NoError(t, c.UnmarshalJSON([]byte(`1`)))
		})
		assert.Equal(t, AssetCategory(1), c)
		assert.Empty(t, out)
	})

	t.Run("unknown name errors", func(t *testing.T) {
		var c AssetCategory
		err := c.UnmarshalJSON([]byte(`"nope"`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unknown asset category value")
	})
}
