// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/azuredevops/connection"
)

// assetUrlSchema builds the schema the way the CLI does: the technology=saas
// branch first, then the provider tree, then the cache refresh.
func assetUrlSchema(t *testing.T) *inventory.AssetUrlSchema {
	t.Helper()
	s, err := inventory.NewAssetUrlSchema("technology")
	require.NoError(t, err)
	require.NoError(t, s.Add(&inventory.AssetUrlBranch{
		PathSegments: []string{"technology=saas"},
		Key:          "provider",
		Title:        "Provider",
	}))
	require.Len(t, Config.AssetUrlTrees, 1)
	require.NoError(t, s.Add(Config.AssetUrlTrees[0]))
	// PathTitles walks parent links, which only the cache refresh sets, exactly
	// as LoadAssetUrlSchema does once every provider has added its tree.
	require.NoError(t, s.RefreshCache())
	return s
}

func TestAssetUrlTreeAcceptsTheSegmentsOfEveryPlatform(t *testing.T) {
	s := assetUrlSchema(t)

	platforms := map[string][]string{
		"organization": connection.NewOrgPlatform("mondoo-ado-scan-test").TechnologyUrlSegments,
		"repository":   connection.NewRepoPlatform("mondoo-ado-scan-test", "scan test").TechnologyUrlSegments,
		"odd project":  connection.NewRepoPlatform("mondoo-ado-scan-test", "Équipe (EU)").TechnologyUrlSegments,
	}
	for name, segments := range platforms {
		t.Run(name, func(t *testing.T) {
			chain, err := s.PathToAssetUrlChain(segments)
			require.NoError(t, err)
			// PathTitles walks the chain through the validator that rejects a
			// value outside the asset url alphabet.
			titles, err := s.PathTitles(chain)
			require.NoError(t, err)
			assert.Len(t, titles, len(segments))
		})
	}
}

func TestAssetUrlChainKeys(t *testing.T) {
	s := assetUrlSchema(t)

	chain, err := s.PathToAssetUrlChain(connection.NewRepoPlatform("mondoo-ado-scan-test", "scan test").TechnologyUrlSegments)
	require.NoError(t, err)
	assert.Equal(t, inventory.AssetUrlChain{
		{Key: "technology", Value: "saas"},
		{Key: "provider", Value: "azuredevops"},
		{Key: "scope", Value: "organization"},
		{Key: "organization", Value: "mondoo-ado-scan-test"},
		{Key: "asset", Value: "project"},
		{Key: "project", Value: "scan test"},
		{Key: "asset", Value: "repository"},
	}, chain)
}

func TestAssetUrlValidatorRejectsAPercentEscapedSegment(t *testing.T) {
	// This is why the technology url carries the name as it is and not the
	// escaped form the platform id uses.
	s := assetUrlSchema(t)
	chain, err := s.PathToAssetUrlChain([]string{"saas", "azuredevops", "organization", "mondoo-ado-scan-test", "project", "scan%20test", "repository"})
	require.NoError(t, err)
	_, err = s.PathTitles(chain)
	require.Error(t, err)
}

func TestConfigShape(t *testing.T) {
	assert.Equal(t, "azuredevops", Config.Root, "option root in the .lr must equal this")
	assert.Equal(t, "go.mondoo.com/mql/providers/azuredevops", Config.ID)
	assert.Regexp(t, `^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`, Config.Version, "semver, set by the release workflow")
	require.Len(t, Config.Requires, 1)
	assert.Equal(t, "go.mondoo.com/mql/providers/core", Config.Requires[0].ID)
	assert.Equal(t, 4, int(Config.DefaultParallelism))

	require.Len(t, Config.Connectors, 1)
	c := Config.Connectors[0]
	assert.Equal(t, 2, int(c.MinArgs))
	assert.Equal(t, 2, int(c.MaxArgs))
	assert.ElementsMatch(t,
		[]string{"organization", "repos", "terraform", "k8s-manifests"}, c.Discovery,
		"all and auto are handled by the provider and not listed")

	// Exactly these flags, all strings: a renamed, retyped or extra flag changes
	// the command line users have scripted against.
	flags := map[string]plugin.FlagType{}
	for _, f := range c.Flags {
		flags[f.Long] = f.Type
	}
	assert.Equal(t, map[string]plugin.FlagType{
		"token":         plugin.FlagType_String,
		"tenant-id":     plugin.FlagType_String,
		"client-id":     plugin.FlagType_String,
		"client-secret": plugin.FlagType_String,
		"repos":         plugin.FlagType_String,
		"repos-exclude": plugin.FlagType_String,
	}, flags)
	assert.Len(t, c.Flags, 6, "no flag is listed twice")
}

func TestAnAccentedProjectNameMapsToAnUnderscore(t *testing.T) {
	// The asset url alphabet has no accented letters, so each one becomes an
	// underscore, as do the parentheses. The space is kept.
	segments := connection.NewRepoPlatform("mondoo-ado-scan-test", "Équipe (EU)").TechnologyUrlSegments
	require.Len(t, segments, 7)
	assert.Equal(t, "_quipe _EU_", segments[5])
}
