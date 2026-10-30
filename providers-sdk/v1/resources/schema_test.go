// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func awsLikeSchema() *Schema {
	return &Schema{
		Resources: map[string]*ResourceInfo{
			"aws.vpc": {
				Id:                 "aws.vpc",
				Name:               "aws.vpc",
				Provider:           "go.mondoo.com/mql/providers/aws",
				MinProviderVersion: "11.15.2",
				Fields: map[string]*Field{
					"arn": {
						Name:     "arn",
						Type:     "\a",
						Provider: "go.mondoo.com/mql/providers/aws",
					},
					"blockPublicAccessOptions": {
						Name:               "blockPublicAccessOptions",
						Type:               "\n",
						Provider:           "go.mondoo.com/mql/providers/aws",
						MinProviderVersion: "13.52.0",
					},
				},
			},
		},
		Dependencies:     map[string]*ProviderInfo{},
		ProviderVersions: map[string]string{"go.mondoo.com/mql/providers/aws": "13.53.3"},
	}
}

// The aggregate schema is what the compiler resolves against, so version
// metadata that does not survive aggregation may as well not exist.
func TestAddPreservesVersionMetadata(t *testing.T) {
	agg := &Schema{
		Resources:    map[string]*ResourceInfo{},
		Dependencies: map[string]*ProviderInfo{},
	}
	agg.Add(awsLikeSchema())

	vpc := agg.Lookup("aws.vpc")
	require.NotNil(t, vpc)
	assert.Equal(t, "11.15.2", vpc.MinProviderVersion, "resource version must survive aggregation")
	assert.Equal(t, "13.52.0", vpc.Fields["blockPublicAccessOptions"].MinProviderVersion, "field version must survive aggregation")
	assert.Equal(t, "", vpc.Fields["arn"].MinProviderVersion, "a field at the resource version stays empty")

	v, ok := agg.ProviderVersion("go.mondoo.com/mql/providers/aws")
	assert.True(t, ok)
	assert.Equal(t, "13.53.3", v)

	_, ok = agg.ProviderVersion("go.mondoo.com/mql/providers/gcp")
	assert.False(t, ok, "an unknown provider is a miss, not an empty string")
}

// Add() appends to Others when two providers define the same field. It used to
// store the source pointer in the aggregate, so that append mutated the
// per-provider schema the coordinator caches, and every rebuild appended again.
func TestAddDoesNotMutateSourceSchema(t *testing.T) {
	awsSchema := awsLikeSchema()
	otherSchema := &Schema{
		Resources: map[string]*ResourceInfo{
			"aws.vpc": {
				Id:   "aws.vpc",
				Name: "aws.vpc",
				// An extension is what reaches the field-merge loop; two
				// competing bases short-circuit at the resource level.
				IsExtension: true,
				Provider:    "go.mondoo.com/mql/providers/other",
				Fields: map[string]*Field{
					"arn": {
						Name:     "arn",
						Type:     "\a",
						Provider: "go.mondoo.com/mql/providers/other",
					},
				},
			},
		},
		Dependencies:     map[string]*ProviderInfo{},
		ProviderVersions: map[string]string{"go.mondoo.com/mql/providers/other": "1.0.0"},
	}

	// Rebuild the aggregate repeatedly, the way unsafeRefresh does.
	for range 3 {
		agg := &Schema{
			Resources:    map[string]*ResourceInfo{},
			Dependencies: map[string]*ProviderInfo{},
		}
		agg.Add(awsSchema)
		agg.Add(otherSchema)
	}

	assert.Empty(t, awsSchema.Resources["aws.vpc"].Fields["arn"].Others,
		"aggregating must not write back into the per-provider schema")

	// And the aggregate still has to record the cross-provider duplicate once.
	agg := &Schema{
		Resources:    map[string]*ResourceInfo{},
		Dependencies: map[string]*ProviderInfo{},
	}
	agg.Add(awsSchema)
	agg.Add(otherSchema)
	assert.Len(t, agg.Lookup("aws.vpc").Fields["arn"].Others, 1)
}

func TestAddMergesProviderVersions(t *testing.T) {
	agg := &Schema{
		Resources:    map[string]*ResourceInfo{},
		Dependencies: map[string]*ProviderInfo{},
	}
	agg.Add(awsLikeSchema())
	agg.Add(&Schema{
		Resources:        map[string]*ResourceInfo{},
		Dependencies:     map[string]*ProviderInfo{},
		ProviderVersions: map[string]string{"go.mondoo.com/mql/providers/gcp": "12.1.0"},
	})
	// A schema with no provenance at all must not blank out what we have.
	agg.Add(&Schema{
		Resources:    map[string]*ResourceInfo{},
		Dependencies: map[string]*ProviderInfo{},
	})

	assert.Equal(t, map[string]string{
		"go.mondoo.com/mql/providers/aws": "13.53.3",
		"go.mondoo.com/mql/providers/gcp": "12.1.0",
	}, agg.AllProviderVersions())
}

// Aggregating schemas must not lose a resource's reachability-without-a-root
// flag or the roots providers declare: a rooted compile reads both off the
// merged schema, never off the per-provider one (ADR 031). Both were dropped -
// `asset`, which the os provider extends, came out of the merge looking
// non-global, so `asset.platform` stopped resolving under a rooted namespace.
func TestAggregationKeepsRootMetadata(t *testing.T) {
	core := &Schema{
		Resources: map[string]*ResourceInfo{
			"time":  {Id: "time", Name: "time", Global: true, Provider: "core"},
			"asset": {Id: "asset", Name: "asset", Global: true, Provider: "core"},
		},
		ProviderRoots: map[string]string{"core": ""},
	}
	os := &Schema{
		Resources: map[string]*ResourceInfo{
			// os extends asset, which is what forces the merge path
			"asset":    {Id: "asset", Name: "asset", IsExtension: true, Provider: "os"},
			"packages": {Id: "packages", Name: "packages", Provider: "os"},
		},
		ProviderRoots: map[string]string{"os": "os.any"},
	}

	aggregate := &Schema{Resources: map[string]*ResourceInfo{}}
	aggregate.Add(core)
	aggregate.Add(os)

	t.Run("global survives a fresh insert", func(t *testing.T) {
		assert.True(t, aggregate.Lookup("time").GetGlobal())
	})

	t.Run("global survives a merge with an extension", func(t *testing.T) {
		assert.True(t, aggregate.Lookup("asset").GetGlobal(),
			"one contributor claiming it is enough; extending a resource does not un-global it")
	})

	t.Run("a resource that claims nothing stays non-global", func(t *testing.T) {
		assert.False(t, aggregate.Lookup("packages").GetGlobal())
	})

	t.Run("declared roots survive", func(t *testing.T) {
		assert.Equal(t, "os.any", aggregate.AllProviderRoots()["os"])
	})
}
