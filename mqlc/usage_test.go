// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// Provider IDs resolved from the schema rather than hardcoded — the test
// schemas may be loaded from either the new `mql/providers/...` path or the
// legacy `cnquery/v9/providers/...` path depending on the testutils version.
var (
	coreProviderID = conf.Schema.Lookup("asset").GetProvider()
	osProviderID   = conf.Schema.Lookup("user").GetProvider()
)

func TestAnalyzeQuery_SingleResourceField(t *testing.T) {
	usage, bundle, err := mqlc.AnalyzeQuery("asset.platform", nil, conf)
	require.NoError(t, err)
	require.NotNil(t, usage)
	require.NotNil(t, bundle)

	assert.Equal(t, "asset.platform", usage.Source)
	assert.Equal(t, bundle.CodeV2.Id, usage.CodeID)
	assert.Empty(t, usage.Warnings)

	require.Contains(t, usage.Providers, coreProviderID)
	core := usage.Providers[coreProviderID]
	require.Contains(t, core.Resources, "asset")

	asset := core.Resources["asset"]
	assert.Equal(t, coreProviderID, asset.Provider)
	assert.Equal(t, "", asset.Maturity, "asset is stable")
	assert.GreaterOrEqual(t, asset.Count, 1)

	require.Contains(t, asset.Fields, "platform")
	platform := asset.Fields["platform"]
	assert.Equal(t, 1, platform.Count)
	assert.Equal(t, "", platform.Maturity)
	assert.Equal(t, "", platform.EffectiveMaturity)
}

func TestAnalyzeQuery_RepeatedReferences(t *testing.T) {
	usage, _, err := mqlc.AnalyzeQuery("asset.platform; asset.name", nil, conf)
	require.NoError(t, err)

	asset := usage.Providers[coreProviderID].Resources["asset"]
	assert.Equal(t, 2, asset.Count, "asset referenced twice in source")
	assert.Equal(t, 1, asset.Fields["platform"].Count)
	assert.Equal(t, 1, asset.Fields["name"].Count)
}

func TestAnalyzeQuery_OperatorsIgnored(t *testing.T) {
	usage, _, err := mqlc.AnalyzeQuery(`asset.platform == "linux"`, nil, conf)
	require.NoError(t, err)

	asset := usage.Providers[coreProviderID].Resources["asset"]
	require.NotNil(t, asset)
	// Only the `platform` field should be recorded — the `==` chunk binds to
	// the string result, not to the asset, so it's filtered out.
	assert.Len(t, asset.Fields, 1)
	assert.Contains(t, asset.Fields, "platform")
}

func TestAnalyzeQuery_BlockFieldAccess(t *testing.T) {
	usage, _, err := mqlc.AnalyzeQuery("users { name uid }", nil, conf)
	require.NoError(t, err)

	require.Contains(t, usage.Providers, osProviderID)
	os := usage.Providers[osProviderID]
	require.Contains(t, os.Resources, "users")
	require.Contains(t, os.Resources, "user")

	user := os.Resources["user"]
	assert.Contains(t, user.Fields, "name")
	assert.Contains(t, user.Fields, "uid")
	assert.Equal(t, 1, user.Fields["name"].Count)
	assert.Equal(t, 1, user.Fields["uid"].Count)
}

func TestAnalyzeQuery_MixedProviders(t *testing.T) {
	usage, _, err := mqlc.AnalyzeQuery("users { name }; asset.platform", nil, conf)
	require.NoError(t, err)

	assert.Contains(t, usage.Providers, coreProviderID)
	assert.Contains(t, usage.Providers, osProviderID)
	assert.Contains(t, usage.Providers[coreProviderID].Resources, "asset")
	assert.Contains(t, usage.Providers[osProviderID].Resources, "user")
}

func TestAnalyzeBundle_PreCompiled(t *testing.T) {
	bundle, err := mqlc.Compile("asset.platform", nil, conf)
	require.NoError(t, err)

	usage, err := mqlc.AnalyzeBundle(bundle, conf.Schema)
	require.NoError(t, err)

	assert.Equal(t, "", usage.Source, "Source is empty when bundle is passed directly")
	assert.Equal(t, bundle.CodeV2.Id, usage.CodeID)
	require.Contains(t, usage.Providers, coreProviderID)
	require.Contains(t, usage.Providers[coreProviderID].Resources, "asset")
}

func TestAnalyzeQuery_PreviewMaturity(t *testing.T) {
	// `unicode` in core.lr has @maturity("preview").
	usage, _, err := mqlc.AnalyzeQuery(`unicode("hello")`, nil, conf)
	require.NoError(t, err)

	core := usage.Providers[coreProviderID]
	require.NotNil(t, core)
	require.Contains(t, core.Resources, "unicode")
	unicode := core.Resources["unicode"]
	assert.Equal(t, resources.MaturityPreview, unicode.Maturity)
}

func TestAnalyzeQuery_DeprecatedFieldEffectiveMaturity(t *testing.T) {
	// privatekey.path has @maturity("deprecated") in os.lr; reach it via a user.
	// `users { sshkeys { path } }` walks user -> sshkeys ([]privatekey) -> path.
	usage, _, err := mqlc.AnalyzeQuery("users { sshkeys { path } }", nil, conf)
	require.NoError(t, err)

	os := usage.Providers[osProviderID]
	require.NotNil(t, os)
	pk, ok := os.Resources["privatekey"]
	require.True(t, ok, "privatekey resource should appear in usage stats")
	path, ok := pk.Fields["path"]
	require.True(t, ok, "privatekey.path field should be recorded")
	assert.Equal(t, resources.MaturityDeprecated, path.Maturity)
	assert.Equal(t, resources.MaturityDeprecated, path.EffectiveMaturity)
}

func TestAnalyzeQuery_MultiBlock(t *testing.T) {
	// `if` produces extra blocks; ensure both branches are walked.
	usage, _, err := mqlc.AnalyzeQuery(
		`if (asset.platform == "linux") { asset.name } else { asset.kind }`,
		nil, conf)
	require.NoError(t, err)

	asset := usage.Providers[coreProviderID].Resources["asset"]
	assert.Contains(t, asset.Fields, "platform")
	assert.Contains(t, asset.Fields, "name", "true-branch field should be recorded")
	assert.Contains(t, asset.Fields, "kind", "else-branch field should be recorded")
}

func TestAnalyzeBundle_NilSchema(t *testing.T) {
	bundle, err := mqlc.Compile("asset.platform", nil, conf)
	require.NoError(t, err)

	usage, err := mqlc.AnalyzeBundle(bundle, nil)
	require.Error(t, err, "nil schema should produce an error")
	require.NotNil(t, usage, "best-effort usage is still returned")

	// Resource counts present, bucketed under empty provider id, no maturity.
	require.Contains(t, usage.Providers, "")
	noProv := usage.Providers[""]
	require.Contains(t, noProv.Resources, "asset")
	assert.Equal(t, "", noProv.Resources["asset"].Provider)
	assert.Equal(t, "", noProv.Resources["asset"].Maturity)
	assert.Empty(t, noProv.Resources["asset"].Fields,
		"fields are skipped when schema is nil (cannot tell field vs builtin)")
}

func TestAnalyzeQuery_ProviderCountEqualsResourceSum(t *testing.T) {
	// Multiple resources + multiple field accesses on each, mixed across two
	// providers — exercises both the resource-count and field-count paths.
	usage, _, err := mqlc.AnalyzeQuery(
		"asset.platform; asset.name; users { name uid home }", nil, conf)
	require.NoError(t, err)

	for id, pu := range usage.Providers {
		var sum int
		for _, ru := range pu.Resources {
			sum += ru.Count
		}
		assert.Equal(t, sum, pu.Count,
			"provider %q: Count must equal sum of ResourceUsage.Count", id)
	}
}

func TestAnalyzeBundle_NilBundle(t *testing.T) {
	_, err := mqlc.AnalyzeBundle(nil, conf.Schema)
	assert.Error(t, err)
}
