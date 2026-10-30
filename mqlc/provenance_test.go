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
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

const (
	osProvider   = "go.mondoo.com/mql/providers/os"
	coreProvider = "go.mondoo.com/mql/providers/core"
)

func provenanceSchema(t *testing.T) *resources.Schema {
	t.Helper()
	osSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "os"})
	coreSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"})

	// The compiler resolves against the aggregate, so provenance has to survive
	// the merge to be worth anything.
	merged := &resources.Schema{
		Resources:    map[string]*resources.ResourceInfo{},
		Dependencies: map[string]*resources.ProviderInfo{},
		ProviderVersions: map[string]string{
			osProvider:   "13.20.0",
			coreProvider: "13.4.0",
		},
	}
	merged.Add(osSchema)
	merged.Add(coreSchema)
	return merged
}

func compileForProvenance(t *testing.T, schema *resources.Schema, query string) *llx.CodeBundle {
	t.Helper()
	conf := mqlc.NewConfig(schema, mql.Features{})
	res, err := mqlc.Compile(query, nil, conf)
	require.NoError(t, err, query)
	require.NotNil(t, res)
	return res
}

// A resource introduced in 9.0.0 with a field introduced in 13.16.9 requires
// 13.16.9 -- the highest requirement in the bundle wins, not the first one seen
// and not the resource's own.
func TestProvenanceTakesTheHighestFieldVersion(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `sshd.config.effectiveCiphers`)
	assert.Equal(t, "13.16.9", res.MinProviderVersions["os"])

	// Same resource, only the 9.0.0 field: the requirement drops accordingly.
	res = compileForProvenance(t, schema, `sshd.config.ciphers`)
	assert.Equal(t, "9.0.0", res.MinProviderVersions["os"])

	// Both in one query: the newer one sets the floor.
	res = compileForProvenance(t, schema, `sshd.config { ciphers effectiveCiphers }`)
	assert.Equal(t, "13.16.9", res.MinProviderVersions["os"])
}

// Version comparison must be semver, not lexical: 13.16.9 beats 13.9.0 even
// though it sorts lower as a string.
func TestProvenanceComparesSemverNotStrings(t *testing.T) {
	schema := provenanceSchema(t)
	res := compileForProvenance(t, schema, `sshd.config { hostkeyalgorithms effectiveCiphers }`)
	assert.Equal(t, "13.16.9", res.MinProviderVersions["os"],
		"13.16.9 > 13.10.1, but only under semver")
}

// Writer-schema identity is what the compiler saw, and it is per provider, so a
// query spanning two providers records both.
func TestProvenanceRecordsWriterSchemaPerProvider(t *testing.T) {
	schema := provenanceSchema(t)
	res := compileForProvenance(t, schema, `asset.name == "x" && sshd.config.ciphers != []`)

	assert.Equal(t, "13.20.0", res.ProviderSchemas["os"])
	assert.Equal(t, "13.4.0", res.ProviderSchemas["core"])
}

// Provenance is stamped from a walk of the finished bytecode, so it has to see
// resources reached through a block and through a list, not just at the root.
func TestProvenanceSeesNestedAndListedResources(t *testing.T) {
	schema := provenanceSchema(t)

	res := compileForProvenance(t, schema, `sshd.config.matchBlock { ciphers }`)
	assert.Equal(t, "11.4.10", res.MinProviderVersions["os"],
		"a field on a listed sub-resource must be attributed")
}

// A bundle that touches nothing versioned must claim nothing, rather than
// claiming a bogus floor that would have content withheld from clients that
// could run it.
func TestProvenanceClaimsNothingWhenItKnowsNothing(t *testing.T) {
	schema := provenanceSchema(t)
	res := compileForProvenance(t, schema, `1 + 1`)

	assert.Empty(t, res.MinProviderVersions)
	assert.Empty(t, res.ProviderSchemas)
	assert.Empty(t, res.MinMondooVersion)
}

// Strict mode (ADR 043) ships in v14.0.0, and an engine that predates the
// nullability marker reads it as "unspecified" and runs the bundle non-strict --
// it does not fail, it silently verifies less. So a strict bundle has to declare
// the engine floor rather than be allowed to degrade.
func TestMinMondooVersionTracksStrictMode(t *testing.T) {
	schema := provenanceSchema(t)

	strict := mqlc.NewConfig(schema, mql.Features{})
	strict.Strict = true
	res, err := mqlc.Compile(`sshd.config.ciphers`, nil, strict)
	require.NoError(t, err)
	assert.Equal(t, "14.0.0", res.MinMondooVersion)

	// The same source compiled non-strict claims no floor: it runs anywhere.
	res, err = mqlc.Compile(`sshd.config.ciphers`, nil, mqlc.NewConfig(schema, mql.Features{}))
	require.NoError(t, err)
	assert.Empty(t, res.MinMondooVersion)
}

// A strict compile of an expression with no dereference in it emits no marker,
// so it must not claim a floor it does not need.
func TestMinMondooVersionUnsetWhenStrictChangesNothing(t *testing.T) {
	conf := mqlc.NewConfig(provenanceSchema(t), mql.Features{})
	conf.Strict = true

	res, err := mqlc.Compile(`1 + 1`, nil, conf)
	require.NoError(t, err)
	assert.Empty(t, res.MinMondooVersion)
}
