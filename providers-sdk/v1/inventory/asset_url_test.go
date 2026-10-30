// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package inventory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/utils/sortx"
)

func genTestSchema(t *testing.T) *AssetUrlSchema {
	root, err := NewAssetUrlSchema("technology")
	require.NoError(t, err)

	err = root.Add(&AssetUrlBranch{
		PathSegments: []string{"technology=aws"},
		Key:          "account",
		Title:        "Account",
		Values: map[string]*AssetUrlBranch{
			"*": {
				Key: "service",
				Values: map[string]*AssetUrlBranch{
					"ec2": {
						References: []string{"technology=os"},
					},
				},
			},
		},
	})
	require.NoError(t, err)

	err = root.Add(&AssetUrlBranch{
		PathSegments: []string{"technology=os"},
		Key:          "family",
		Values: map[string]*AssetUrlBranch{
			"windows": {
				Key: "platform",
				Values: map[string]*AssetUrlBranch{
					"windows server": nil,
				},
			},
		},
	})
	require.NoError(t, err)

	err = root.Add(&AssetUrlBranch{
		PathSegments: []string{"technology=os", "family=windows", "platform=windows server"},
		Key:          "version",
		Values: map[string]*AssetUrlBranch{
			"2019": nil,
			"2022": nil,
		},
	})
	require.NoError(t, err)

	return root
}

func TestAddSubtree(t *testing.T) {
	root := genTestSchema(t)

	t.Run("refresh cache and access keys", func(t *testing.T) {
		err := root.RefreshCache()
		require.NoError(t, err)

		keys := sortx.Keys(root.keys)
		assert.Equal(t, []string{
			"account", "family", "platform", "service", "technology", "version",
		}, keys)
	})

	t.Run("build query with 1 params and 2 results", func(t *testing.T) {
		err := root.RefreshCache()
		require.NoError(t, err)

		queries := root.BuildQueries([]KV{
			{Key: "platform", Value: "windows server"},
		})
		assert.Equal(t, []AssetUrlChain{
			{
				KV{"technology", "aws"},
				KV{"account", "*"},
				KV{"service", "ec2"},
				KV{"family", "windows"},
				KV{"platform", "windows server"},
			},
			{
				KV{"technology", "os"},
				KV{"family", "windows"},
				KV{"platform", "windows server"},
			},
		}, queries)
	})

	t.Run("build query with 2 params and 1 result", func(t *testing.T) {
		err := root.RefreshCache()
		require.NoError(t, err)

		queries := root.BuildQueries([]KV{
			{Key: "account", Value: "123"},
			{Key: "platform", Value: "windows server"},
		})
		assert.Equal(t, []AssetUrlChain{
			{
				KV{"technology", "aws"},
				KV{"account", "123"},
				KV{"service", "ec2"},
				KV{"family", "windows"},
				KV{"platform", "windows server"},
			},
		}, queries)
	})

	t.Run("build query with 2 params (incl root) and 1 result", func(t *testing.T) {
		err := root.RefreshCache()
		require.NoError(t, err)

		queries := root.BuildQueries([]KV{
			{Key: "technology", Value: "os"},
			{Key: "platform", Value: "windows server"},
		})
		assert.Equal(t, []AssetUrlChain{
			{
				KV{"technology", "os"},
				KV{"family", "windows"},
				KV{"platform", "windows server"},
			},
		}, queries)
	})

	t.Run("test PathToAssetUrlChain", func(t *testing.T) {
		err := root.RefreshCache()
		require.NoError(t, err)

		chain, err := root.PathToAssetUrlChain([]string{"aws", "1234", "ec2", "windows", "windows server"})
		require.NoError(t, err)
		require.Equal(t, AssetUrlChain{
			KV{"technology", "aws"},
			KV{"account", "1234"},
			KV{"service", "ec2"},
			KV{"family", "windows"},
			KV{"platform", "windows server"},
		}, chain)
	})

	t.Run("test PathTitles", func(t *testing.T) {
		err := root.RefreshCache()
		require.NoError(t, err)

		chain, err := root.PathToAssetUrlChain([]string{"aws", "1234", "ec2", "windows", "windows server"})
		require.NoError(t, err)

		titles, err := root.PathTitles(chain)
		require.NoError(t, err)
		assert.Equal(t, []string{"technology", "Account", "service", "family", "platform"}, titles)
	})

	t.Run("find child key of a chain", func(t *testing.T) {
		err := root.RefreshCache()
		require.NoError(t, err)

		childBranch, err := root.FindChild(AssetUrlChain{
			KV{"technology", "aws"},
			KV{"account", "*"},
		})
		require.NoError(t, err)
		require.NotNil(t, childBranch)
		assert.Equal(t, "service", childBranch.Key)
	})
}
