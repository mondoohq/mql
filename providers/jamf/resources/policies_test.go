// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/deploymenttheory/go-api-sdk-jamfpro/sdk/jamfpro"
	"github.com/stretchr/testify/assert"
)

func TestPolicyScriptParameters_CollectsOnlyNonEmpty(t *testing.T) {
	s := jamfpro.PolicySubsetScript{
		Parameter4:  "four",
		Parameter5:  "", // dropped
		Parameter6:  "six",
		Parameter7:  "",
		Parameter8:  "",
		Parameter9:  "nine",
		Parameter10: "",
		Parameter11: "eleven",
	}

	got := policyScriptParameters(s)

	assert.Equal(t, map[string]any{
		"parameter4":  "four",
		"parameter6":  "six",
		"parameter9":  "nine",
		"parameter11": "eleven",
	}, got, "only non-empty parameters must appear, keyed by their slot")
}

func TestPolicyScriptParameters_AllEmptyYieldsEmptyMap(t *testing.T) {
	got := policyScriptParameters(jamfpro.PolicySubsetScript{})
	assert.Empty(t, got, "no parameters set → empty map, never nil-keyed junk")
}

func TestScriptParameters_CollectsOnlyNonEmpty(t *testing.T) {
	s := jamfpro.ResourceScript{
		Parameter4:  "a",
		Parameter7:  "b",
		Parameter11: "c",
	}

	got := scriptParameters(s)

	assert.Equal(t, map[string]any{
		"parameter4":  "a",
		"parameter7":  "b",
		"parameter11": "c",
	}, got)
}

func TestScriptParameters_AllEmptyYieldsEmptyMap(t *testing.T) {
	got := scriptParameters(jamfpro.ResourceScript{})
	assert.Empty(t, got)
}

func TestJamfScopeEntities_RendersIdNameDicts(t *testing.T) {
	items := []jamfpro.PolicySubsetComputer{
		{ID: 1, Name: "mac-1"},
		{ID: 2, Name: "mac-2"},
	}
	idName := func(c jamfpro.PolicySubsetComputer) (any, string) { return int64(c.ID), c.Name }

	got := jamfScopeEntities(items, idName)

	assert.Equal(t, []any{
		map[string]any{"id": int64(1), "name": "mac-1"},
		map[string]any{"id": int64(2), "name": "mac-2"},
	}, got)
}

func TestJamfScopeEntities_EmptyInputYieldsEmptySlice(t *testing.T) {
	idName := func(c jamfpro.PolicySubsetComputer) (any, string) { return int64(c.ID), c.Name }
	got := jamfScopeEntities([]jamfpro.PolicySubsetComputer{}, idName)
	assert.NotNil(t, got)
	assert.Len(t, got, 0)
}

func TestJamfScopeEntitiesPtr_NilSliceYieldsEmptyNonNilSlice(t *testing.T) {
	// The Jamf policy scope uses pointer slices that are nil when empty. A nil
	// slice must render as an empty (non-nil) list, not panic and not null, so
	// `.scope.computers` is always an iterable list in MQL.
	idName := func(c jamfpro.PolicySubsetComputer) (any, string) { return int64(c.ID), c.Name }

	got := jamfScopeEntitiesPtr(nil, idName)

	assert.NotNil(t, got, "nil pointer slice must not render as MQL null")
	assert.Len(t, got, 0)
}

func TestJamfScopeEntitiesPtr_PopulatedSliceRenders(t *testing.T) {
	items := []jamfpro.PolicySubsetComputer{{ID: 7, Name: "mac-7"}}
	idName := func(c jamfpro.PolicySubsetComputer) (any, string) { return int64(c.ID), c.Name }

	got := jamfScopeEntitiesPtr(&items, idName)

	assert.Equal(t, []any{
		map[string]any{"id": int64(7), "name": "mac-7"},
	}, got)
}
