// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMergeDeprecatedFlagsIntoConfig_ManifestURLHeader(t *testing.T) {
	// The --manifest-url-header flag must be read from its own key (not a
	// stray tab key, which previously panicked) and parsed into the config.
	cfg := map[string]any{}
	flags := map[string]any{
		"manifest-url-header": "X-Custom-Header:value,Other:thing",
	}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(cfg, flags)
		require.NoError(t, err)
	})

	headers, ok := cfg["staticPodURLHeader"].(map[string]any)
	require.True(t, ok, "staticPodURLHeader should be set as a dict")
	assert.Equal(t, "value", headers["X-Custom-Header"])
	assert.Equal(t, "thing", headers["Other"])
}

func TestMergeDeprecatedFlagsIntoConfig_ManifestURLHeaderColonValue(t *testing.T) {
	// A header value may itself contain colons (e.g. a bearer token). SplitN
	// with a limit of 2 must keep everything after the first colon as the value.
	cfg := map[string]any{}
	flags := map[string]any{
		"manifest-url-header": "Authorization:Bearer token:abc",
	}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(cfg, flags)
		require.NoError(t, err)
	})

	headers, ok := cfg["staticPodURLHeader"].(map[string]any)
	require.True(t, ok, "staticPodURLHeader should be set as a dict")
	assert.Equal(t, "Bearer token:abc", headers["Authorization"])
}

func TestMergeDeprecatedFlagsIntoConfig_ManifestURLHeaderMalformed(t *testing.T) {
	// A header token without a colon must be skipped, not panic.
	cfg := map[string]any{}
	flags := map[string]any{"manifest-url-header": "no-colon-here"}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(cfg, flags)
		require.NoError(t, err)
	})
}

func TestParseKeyValueListFlag(t *testing.T) {
	// Well-formed pairs parse; tokens without `=` (e.g. a trailing comma) are
	// skipped rather than panicking on an out-of-range index.
	res := parseKeyValueListFlag("a=1,malformed,b=2,")
	assert.Equal(t, map[string]string{"a": "1", "b": "2"}, res)
}

func TestMergeDeprecatedFlagsIntoConfig_FeatureGatesMalformed(t *testing.T) {
	cfg := map[string]any{}
	flags := map[string]any{"feature-gates": "Foo=true,malformed,Bar=false"}

	require.NotPanics(t, func() {
		err := mergeDeprecatedFlagsIntoConfig(cfg, flags)
		require.NoError(t, err)
	})

	fg, ok := cfg["featureGates"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "true", fg["Foo"])
	assert.Equal(t, "false", fg["Bar"])
	_, hasMalformed := fg["malformed"]
	assert.False(t, hasMalformed, "malformed token must be skipped")
}
