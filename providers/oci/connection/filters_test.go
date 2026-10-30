// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"testing"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDiscoveryFiltersFromOpts(t *testing.T) {
	filters := DiscoveryFiltersFromOpts(map[string]string{
		"regions":                    "us-ashburn-1,us-phoenix-1",
		"exclude:regions":            "eu-frankfurt-1",
		"compartments":               "production,ocid1.compartment.oc1..aaa",
		"exclude:compartments":       "sandbox",
		"tag:env":                    "prod,staging",
		"tag:Operations.CostCenter":  "42",
		"exclude:tag:lifecycle":      "ephemeral",
		"unrelated-option":           "ignored",
		"":                           "empty key is skipped",
		"tag:blank-value-is-skipped": "",
	})

	assert.Equal(t, []string{"us-ashburn-1", "us-phoenix-1"}, filters.Regions)
	assert.Equal(t, []string{"eu-frankfurt-1"}, filters.ExcludeRegions)
	assert.Equal(t, []string{"production", "ocid1.compartment.oc1..aaa"}, filters.Compartments)
	assert.Equal(t, []string{"sandbox"}, filters.ExcludeCompartments)

	// An "exclude:tag:" key must not also land in Tags, or every exclusion
	// would silently double as an inclusion and widen the scan it was meant to
	// narrow.
	assert.Equal(t, map[string]string{"env": "prod,staging", "Operations.CostCenter": "42"}, filters.Tags)
	assert.Equal(t, map[string]string{"lifecycle": "ephemeral"}, filters.ExcludeTags)
}

func TestDiscoveryFiltersEmptyMeansNoRestriction(t *testing.T) {
	var filters DiscoveryFilters

	assert.False(t, filters.HasRegions())
	assert.False(t, filters.HasCompartments())
	assert.False(t, filters.HasTags())

	// The whole point: an unfiltered scan must admit everything. A filter that
	// defaulted to excluding would turn "no --filters given" into an empty
	// scan that still reported success.
	assert.True(t, filters.AdmitsRegion("IAD", "us-ashburn-1"))
	assert.True(t, filters.AdmitsCompartment("ocid1.compartment.oc1..aaa", "production"))
	assert.False(t, filters.IsFilteredOutByTags(map[string]string{"env": "prod"}, nil))
}

func TestAdmitsRegion(t *testing.T) {
	tests := []struct {
		name    string
		filters DiscoveryFilters
		key     string
		region  string
		want    bool
	}{
		{
			// The case that motivated matching both identifiers: the provider
			// carries the short key as the region's id, but a user writes the
			// region identifier they see in every endpoint and document.
			name:    "include matches the region name, not the key",
			filters: DiscoveryFilters{Regions: []string{"us-ashburn-1"}},
			key:     "IAD", region: "us-ashburn-1", want: true,
		},
		{
			name:    "include matches the short key",
			filters: DiscoveryFilters{Regions: []string{"IAD"}},
			key:     "IAD", region: "us-ashburn-1", want: true,
		},
		{
			name:    "include not matched",
			filters: DiscoveryFilters{Regions: []string{"us-phoenix-1"}},
			key:     "IAD", region: "us-ashburn-1", want: false,
		},
		{
			name:    "exclude beats include",
			filters: DiscoveryFilters{Regions: []string{"us-ashburn-1"}, ExcludeRegions: []string{"us-ashburn-1"}},
			key:     "IAD", region: "us-ashburn-1", want: false,
		},
		{
			name:    "exclude by short key",
			filters: DiscoveryFilters{ExcludeRegions: []string{"IAD"}},
			key:     "IAD", region: "us-ashburn-1", want: false,
		},
		{
			name:    "exclude alone admits everything else",
			filters: DiscoveryFilters{ExcludeRegions: []string{"eu-frankfurt-1"}},
			key:     "IAD", region: "us-ashburn-1", want: true,
		},
		{
			name:    "case insensitive",
			filters: DiscoveryFilters{Regions: []string{"US-ASHBURN-1"}},
			key:     "iad", region: "us-ashburn-1", want: true,
		},
		{
			name:    "surrounding whitespace tolerated",
			filters: DiscoveryFilters{Regions: []string{" us-ashburn-1 "}},
			key:     "IAD", region: "us-ashburn-1", want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, test.filters.AdmitsRegion(test.key, test.region))
		})
	}
}

func TestAdmitsCompartment(t *testing.T) {
	const ocid = "ocid1.compartment.oc1..aaaaproduction"

	tests := []struct {
		name    string
		filters DiscoveryFilters
		want    bool
	}{
		{
			name:    "matched by OCID",
			filters: DiscoveryFilters{Compartments: []string{ocid}},
			want:    true,
		},
		{
			name:    "matched by name",
			filters: DiscoveryFilters{Compartments: []string{"production"}},
			want:    true,
		},
		{
			name:    "not matched",
			filters: DiscoveryFilters{Compartments: []string{"staging"}},
			want:    false,
		},
		{
			name:    "excluded by name",
			filters: DiscoveryFilters{ExcludeCompartments: []string{"production"}},
			want:    false,
		},
		{
			name:    "exclude beats include",
			filters: DiscoveryFilters{Compartments: []string{ocid}, ExcludeCompartments: []string{"production"}},
			want:    false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, test.filters.AdmitsCompartment(ocid, "production"))
		})
	}
}

func TestSelectCompartments(t *testing.T) {
	compartments := []identity.Compartment{
		{Id: new("ocid1.compartment.oc1..prod"), Name: new("production")},
		{Id: new("ocid1.compartment.oc1..stage"), Name: new("staging")},
		// A compartment with no OCID cannot be asked about, so it is dropped
		// rather than producing an empty compartment id in a list request.
		{Id: nil, Name: new("broken")},
	}

	t.Run("no filter keeps every identifiable compartment", func(t *testing.T) {
		var filters DiscoveryFilters
		assert.Equal(t,
			[]string{"ocid1.compartment.oc1..prod", "ocid1.compartment.oc1..stage"},
			filters.SelectCompartments(compartments))
	})

	t.Run("filter narrows by name", func(t *testing.T) {
		filters := DiscoveryFilters{Compartments: []string{"production"}}
		assert.Equal(t, []string{"ocid1.compartment.oc1..prod"}, filters.SelectCompartments(compartments))
	})

	t.Run("a filter matching nothing selects nothing", func(t *testing.T) {
		filters := DiscoveryFilters{Compartments: []string{"absent"}}
		assert.Empty(t, filters.SelectCompartments(compartments))
	})
}

func TestOciTagLookup(t *testing.T) {
	lookup := ociTagLookup(
		map[string]string{"env": "prod"},
		map[string]map[string]any{
			"Operations": {"CostCenter": "42", "Owner": "platform"},
		},
	)

	assert.Equal(t, "prod", lookup["env"])
	assert.Equal(t, "42", lookup["Operations.CostCenter"])
	assert.Equal(t, "platform", lookup["Operations.Owner"])
}

func TestOciTagLookupFreeformWinsCollision(t *testing.T) {
	// A freeform key may itself contain a dot and collide with a defined tag's
	// flattened form. The freeform value wins because it is the literal key the
	// user typed.
	lookup := ociTagLookup(
		map[string]string{"Operations.CostCenter": "freeform"},
		map[string]map[string]any{"Operations": {"CostCenter": "defined"}},
	)
	assert.Equal(t, "freeform", lookup["Operations.CostCenter"])
}

func TestOciTagLookupRendersNonStringValues(t *testing.T) {
	// Defined tag values arrive as any because the API allows numbers. They
	// have to render to the string a user would type on the command line, or a
	// numeric cost centre could never be filtered on.
	lookup := ociTagLookup(nil, map[string]map[string]any{
		"Operations": {"CostCenter": 42, "Ratio": 1.5, "Missing": nil},
	})
	assert.Equal(t, "42", lookup["Operations.CostCenter"])
	assert.Equal(t, "1.5", lookup["Operations.Ratio"])
	assert.Equal(t, "", lookup["Operations.Missing"])
}

func TestIsFilteredOutByTags(t *testing.T) {
	freeform := map[string]string{"env": "prod", "team": "platform"}
	defined := map[string]map[string]any{"Operations": {"CostCenter": "42"}}

	tests := []struct {
		name    string
		filters DiscoveryFilters
		want    bool
	}{
		{
			name:    "no filters keeps everything",
			filters: DiscoveryFilters{},
			want:    false,
		},
		{
			name:    "include matched on a freeform tag",
			filters: DiscoveryFilters{Tags: map[string]string{"env": "prod"}},
			want:    false,
		},
		{
			name:    "include matched on a defined tag through its dotted key",
			filters: DiscoveryFilters{Tags: map[string]string{"Operations.CostCenter": "42"}},
			want:    false,
		},
		{
			name:    "include matched on one of several CSV values",
			filters: DiscoveryFilters{Tags: map[string]string{"env": "staging,prod"}},
			want:    false,
		},
		{
			name:    "include not matched filters the resource out",
			filters: DiscoveryFilters{Tags: map[string]string{"env": "staging"}},
			want:    true,
		},
		{
			name:    "include on a key the resource lacks filters it out",
			filters: DiscoveryFilters{Tags: map[string]string{"absent": "value"}},
			want:    true,
		},
		{
			// Several include filters are an OR: matching any one is enough.
			name:    "any matching include is enough",
			filters: DiscoveryFilters{Tags: map[string]string{"absent": "value", "env": "prod"}},
			want:    false,
		},
		{
			name:    "exclude matched filters the resource out",
			filters: DiscoveryFilters{ExcludeTags: map[string]string{"team": "platform"}},
			want:    true,
		},
		{
			name:    "exclude not matched keeps the resource",
			filters: DiscoveryFilters{ExcludeTags: map[string]string{"team": "other"}},
			want:    false,
		},
		{
			name: "exclude beats include",
			filters: DiscoveryFilters{
				Tags:        map[string]string{"env": "prod"},
				ExcludeTags: map[string]string{"team": "platform"},
			},
			want: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, test.filters.IsFilteredOutByTags(freeform, defined))
		})
	}
}

func TestIsFilteredOutByTagsOnUntaggedResource(t *testing.T) {
	filters := DiscoveryFilters{Tags: map[string]string{"env": "prod"}}

	// A resource with no tags cannot satisfy an include filter, so it is
	// filtered out. Reading absent tags as a match would make a tag filter a
	// no-op on exactly the resources least likely to be governed.
	assert.True(t, filters.IsFilteredOutByTags(nil, nil))
	assert.True(t, filters.IsFilteredOutByTags(map[string]string{}, map[string]map[string]any{}))
}

func TestParseMapOptPrefixIsolation(t *testing.T) {
	opts := map[string]string{
		"tag:env":           "prod",
		"exclude:tag:env":   "dev",
		"tagged":            "not a tag filter",
		"regions":           "us-ashburn-1",
		"tag:":              "empty remainder",
		"tag:blank":         "",
		"exclude:tag:blank": "",
	}

	tags := parseMapOpt(opts, "tag:")
	require.NotContains(t, tags, "env:dev", "an exclude key must not be read as an include")
	assert.Equal(t, "prod", tags["env"])
	assert.NotContains(t, tags, "blank", "a key with an empty value carries no filter")
	assert.NotContains(t, tags, "ged", "a key that merely starts with the letters is not a match")

	excluded := parseMapOpt(opts, "exclude:tag:")
	assert.Equal(t, map[string]string{"env": "dev"}, excluded)
}
