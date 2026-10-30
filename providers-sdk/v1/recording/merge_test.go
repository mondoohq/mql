// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package recording

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/utils/syncx"
)

func newMergeTestRecording(assets ...*Asset) *recording {
	for _, a := range assets {
		ensureAssetCaches(a)
	}
	r := &recording{
		Assets: assets,
		assets: syncx.Map[*Asset]{},
	}
	r.refreshCache()
	return r
}

func TestMerge_DisjointAssets(t *testing.T) {
	r1 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{Mrn: "mrn://a", Name: "a", Platform: &inventory.Platform{}},
	})
	r2 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{Mrn: "mrn://b", Name: "b", Platform: &inventory.Platform{}},
	})

	merged, err := Merge([]*recording{r1, r2}, MergeOpts{})
	require.NoError(t, err)
	assert.Len(t, merged.Assets, 2)
}

func TestMerge_MatchByMRN(t *testing.T) {
	r1 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{Mrn: "mrn://a", Name: "a", Platform: &inventory.Platform{}},
		Resources: []Resource{{
			Resource: "pkg",
			ID:       "1",
			Fields:   map[string]*llx.RawData{"name": llx.StringData("curl")},
		}},
	})
	r2 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{Mrn: "mrn://a", Name: "a-updated", Platform: &inventory.Platform{}},
		Resources: []Resource{{
			Resource: "pkg",
			ID:       "1",
			Fields:   map[string]*llx.RawData{"version": llx.StringData("7.88")},
		}, {
			Resource: "pkg",
			ID:       "2",
			Fields:   map[string]*llx.RawData{"name": llx.StringData("wget")},
		}},
	})

	merged, err := Merge([]*recording{r1, r2}, MergeOpts{})
	require.NoError(t, err)
	assert.Len(t, merged.Assets, 1)

	// pkg\x1e1 should have both fields merged.
	res, ok := merged.Assets[0].resources["pkg\x1e1"]
	require.True(t, ok)
	assert.Equal(t, "curl", res.Fields["name"].Value)
	assert.Equal(t, "7.88", res.Fields["version"].Value)

	// pkg\x1e2 should exist from r2.
	_, ok = merged.Assets[0].resources["pkg\x1e2"]
	assert.True(t, ok)
}

func TestMerge_MatchByPlatformID(t *testing.T) {
	r1 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{
			PlatformIds: []string{"pid-1", "pid-2"},
			Name:        "a",
			Platform:    &inventory.Platform{},
		},
		Resources: []Resource{{
			Resource: "os",
			ID:       "",
			Fields:   map[string]*llx.RawData{"name": llx.StringData("linux")},
		}},
	})
	r2 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{
			PlatformIds: []string{"pid-2", "pid-3"},
			Name:        "a",
			Platform:    &inventory.Platform{},
		},
		Resources: []Resource{{
			Resource: "os",
			ID:       "",
			Fields:   map[string]*llx.RawData{"arch": llx.StringData("amd64")},
		}},
	})

	merged, err := Merge([]*recording{r1, r2}, MergeOpts{})
	require.NoError(t, err)
	assert.Len(t, merged.Assets, 1)

	// Platform IDs should be the union.
	assert.ElementsMatch(t, []string{"pid-1", "pid-2", "pid-3"}, merged.Assets[0].Asset.PlatformIds)

	// Resources should be merged.
	res, ok := merged.Assets[0].resources["os\x1e"]
	require.True(t, ok)
	assert.Equal(t, "linux", res.Fields["name"].Value)
	assert.Equal(t, "amd64", res.Fields["arch"].Value)
}

func TestMerge_IdsLookup(t *testing.T) {
	r1 := newMergeTestRecording(&Asset{
		Asset:     &inventory.Asset{Mrn: "mrn://a", Platform: &inventory.Platform{}},
		IdsLookup: map[string]string{"res\x1e": "resolved-1"},
	})
	r2 := newMergeTestRecording(&Asset{
		Asset:     &inventory.Asset{Mrn: "mrn://a", Platform: &inventory.Platform{}},
		IdsLookup: map[string]string{"res2\x1e": "resolved-2"},
	})

	merged, err := Merge([]*recording{r1, r2}, MergeOpts{})
	require.NoError(t, err)
	assert.Equal(t, "resolved-1", merged.Assets[0].IdsLookup["res\x1e"])
	assert.Equal(t, "resolved-2", merged.Assets[0].IdsLookup["res2\x1e"])
}

func TestMerge_Connections(t *testing.T) {
	r1 := newMergeTestRecording(&Asset{
		Asset:       &inventory.Asset{Mrn: "mrn://a", Platform: &inventory.Platform{}},
		Connections: []connection{{Url: "ssh://host1", Id: 1}},
	})
	r2 := newMergeTestRecording(&Asset{
		Asset:       &inventory.Asset{Mrn: "mrn://a", Platform: &inventory.Platform{}},
		Connections: []connection{{Url: "ssh://host2", Id: 2}},
	})

	merged, err := Merge([]*recording{r1, r2}, MergeOpts{})
	require.NoError(t, err)
	assert.Len(t, merged.Assets[0].connections, 2)
}

func TestMerge_FieldConflictLastWins(t *testing.T) {
	r1 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{Mrn: "mrn://a", Platform: &inventory.Platform{}},
		Resources: []Resource{{
			Resource: "pkg",
			ID:       "1",
			Fields:   map[string]*llx.RawData{"version": llx.StringData("1.0")},
		}},
	})
	r2 := newMergeTestRecording(&Asset{
		Asset: &inventory.Asset{Mrn: "mrn://a", Platform: &inventory.Platform{}},
		Resources: []Resource{{
			Resource: "pkg",
			ID:       "1",
			Fields:   map[string]*llx.RawData{"version": llx.StringData("2.0")},
		}},
	})

	merged, err := Merge([]*recording{r1, r2}, MergeOpts{})
	require.NoError(t, err)
	res, ok := merged.Assets[0].resources["pkg\x1e1"]
	require.True(t, ok)
	assert.Equal(t, "2.0", res.Fields["version"].Value)
}

func TestMerge_Empty(t *testing.T) {
	merged, err := Merge(nil, MergeOpts{})
	require.NoError(t, err)
	assert.Empty(t, merged.Assets)
}
