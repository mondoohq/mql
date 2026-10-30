// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
)

func TestUnmetRequirements(t *testing.T) {
	bundle := &llx.CodeBundle{
		MinProviderVersions: map[string]string{
			osProvider:   "13.16.9",
			coreProvider: "9.0.0",
		},
	}

	t.Run("reader is new enough", func(t *testing.T) {
		assert.Empty(t, mqlc.UnmetRequirements(bundle, map[string]string{
			osProvider:   "13.20.0",
			coreProvider: "11.0.0",
		}))
	})

	t.Run("reader is exactly at the floor", func(t *testing.T) {
		assert.Empty(t, mqlc.UnmetRequirements(bundle, map[string]string{
			osProvider:   "13.16.9",
			coreProvider: "9.0.0",
		}))
	})

	t.Run("reader is too old", func(t *testing.T) {
		got := mqlc.UnmetRequirements(bundle, map[string]string{
			osProvider:   "13.10.1",
			coreProvider: "9.0.0",
		})
		require.Len(t, got, 1)
		assert.Equal(t, "os", got[0].Provider, "requirements are keyed by the stable provider name")
		assert.Equal(t, "13.16.9", got[0].Required)
		assert.Equal(t, "13.10.1", got[0].Installed)
		assert.Equal(t, "requires the os provider >= 13.16.9 (13.10.1 is installed)", got[0].Error())
	})

	// An unstamped build reports its line with `rolling` as build metadata
	// (mql.GetVersion). Reading that as an older line would withhold content
	// from every developer running from source.
	t.Run("a source build satisfies its own floor", func(t *testing.T) {
		assert.Empty(t, mqlc.UnmetRequirements(bundle, map[string]string{
			osProvider:   "v13.16.9+rolling",
			coreProvider: "v9.0.0+rolling",
		}))
	})

	t.Run("a source build of an older line is still too old", func(t *testing.T) {
		got := mqlc.UnmetRequirements(bundle, map[string]string{
			osProvider:   "v13.10.1+rolling",
			coreProvider: "9.0.0",
		})
		require.Len(t, got, 1)
		assert.Equal(t, "v13.10.1+rolling", got[0].Installed)
	})

	t.Run("comparison is semver, not lexical", func(t *testing.T) {
		// "13.9.0" > "13.16.9" as strings, but is older as a version.
		got := mqlc.UnmetRequirements(bundle, map[string]string{
			osProvider:   "13.9.0",
			coreProvider: "9.0.0",
		})
		require.Len(t, got, 1)
		assert.Equal(t, "13.9.0", got[0].Installed)
	})

	t.Run("provider missing entirely", func(t *testing.T) {
		got := mqlc.UnmetRequirements(bundle, map[string]string{coreProvider: "9.0.0"})
		require.Len(t, got, 1)
		assert.Equal(t, "requires the os provider >= 13.16.9 (not installed)", got[0].Error())
	})

	// 45 of 81 providers ship a committed schema whose provider id predates the
	// current one, across three generations of the id format, because CI only
	// regenerates the providers a PR touches. So the two sides of this
	// comparison routinely spell the same provider differently.
	for _, legacyID := range []string{
		"go.mondoo.com/mql/v13/providers/aws",    // pre-v14: version segment
		"go.mondoo.com/cnquery/v9/providers/aws", // cnquery-era, versioned
		"go.mondoo.com/cnquery/providers/aws",    // pre-v10, unversioned
	} {
		t.Run("a legacy provider id matches a current one: "+legacyID, func(t *testing.T) {
			legacy := &llx.CodeBundle{MinProviderVersions: map[string]string{
				legacyID: "13.53.3",
			}}
			assert.Empty(t, mqlc.UnmetRequirements(legacy, map[string]string{
				"go.mondoo.com/mql/providers/aws": "13.60.0",
			}))

			got := mqlc.UnmetRequirements(legacy, map[string]string{
				"go.mondoo.com/mql/providers/aws": "13.50.0",
			})
			require.Len(t, got, 1)
			assert.Equal(t, "requires the aws provider >= 13.53.3 (13.50.0 is installed)", got[0].Error())
		})
	}

	t.Run("a bundle from before provenance is satisfiable", func(t *testing.T) {
		assert.Empty(t, mqlc.UnmetRequirements(&llx.CodeBundle{}, map[string]string{}))
	})

	t.Run("an unparseable version is not evidence of a mismatch", func(t *testing.T) {
		assert.Empty(t, mqlc.UnmetRequirements(bundle, map[string]string{
			osProvider:   "not-a-version",
			coreProvider: "9.0.0",
		}))
	})
}

// End to end: a query compiled against a current schema is correctly reported as
// unrunnable on a reader whose provider predates one of the fields it touches.
func TestUnmetRequirementsFromARealCompile(t *testing.T) {
	schema := provenanceSchema(t)
	conf := mqlc.NewConfig(schema, mql.Features{})

	bundle, err := mqlc.Compile(`sshd.config.effectiveCiphers`, nil, conf)
	require.NoError(t, err)

	tooOld := mqlc.UnmetRequirements(bundle, map[string]string{osProvider: "13.16.8"})
	require.Len(t, tooOld, 1)
	assert.Equal(t, "requires the os provider >= 13.16.9 (13.16.8 is installed)", tooOld[0].Error())

	assert.Empty(t, mqlc.UnmetRequirements(bundle, map[string]string{osProvider: "13.16.9"}))
}

// The opaque "cannot find field" message is the single most common symptom of
// version skew and used to say nothing about it.
func TestIdentifierErrorNamesTheProviderAndItsVersion(t *testing.T) {
	schema := provenanceSchema(t)
	conf := mqlc.NewConfig(schema, mql.Features{})

	// Every path a name-resolution failure can take has to carry the hint, not
	// just the one the root identifier takes.
	for _, query := range []string{
		`sshd.config.notAFieldAtAll`,
		`sshd.config { notAFieldAtAll }`,
		`sshd.config.params.length > 0 && sshd.config.notAFieldAtAll`,
	} {
		_, err := mqlc.Compile(query, nil, conf)
		require.Error(t, err, query)
		assert.Contains(t, err.Error(), "os provider 13.20.0 is installed", query)
		assert.Contains(t, err.Error(), "this field may require a newer one", query)
	}

	_, err := mqlc.Compile(`sshd.notAResourceAtAll`, nil, conf)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "os provider 13.20.0 is installed")
}

// When we cannot attribute the identifier to a provider we must not invent one.
func TestIdentifierErrorStaysBareWhenUnattributable(t *testing.T) {
	schema := provenanceSchema(t)
	conf := mqlc.NewConfig(schema, mql.Features{})

	_, err := mqlc.Compile(`totallyUnknownRoot`, nil, conf)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "is installed")
}
