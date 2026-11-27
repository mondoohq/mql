// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/mqlc"
)

// failingItemFields returns, for the block that records a failing item of
// the assessment, the IDs of its entrypoint chunks, and the number of
// resources whose @defaults the compiler expanded.
func failingItemFields(t *testing.T, features mql.Features, src string) ([]string, int) {
	res, err := mqlc.Compile(src, nil, mqlc.NewConfig(conf.Schema, features))
	require.NoError(t, err)
	require.NoError(t, mqlc.Invariants.Check(res))

	// Block 0 is the query, block 1 the predicate, block 2 the failing item.
	require.GreaterOrEqual(t, len(res.CodeV2.Blocks), 3)
	block := res.CodeV2.Blocks[2]
	ids := make([]string, 0, len(block.Entrypoints))
	for _, ep := range block.Entrypoints {
		ids = append(ids, res.CodeV2.Chunk(ep).Id)
	}
	return ids, len(res.AutoExpand)
}

func TestAssessmentLeafFields(t *testing.T) {
	// group is a resource with @defaults("name gid") that the predicate only
	// passes through to compare its name.
	src := `users.list.all(group.name == "root")`

	t.Run("without the feature, the intermediate resource is expanded", func(t *testing.T) {
		ids, expanded := failingItemFields(t, features, src)
		// the group entrypoint is replaced by the {} block of its defaults
		assert.Contains(t, ids, "{}")
		assert.Equal(t, 2, expanded, "the user's and the group's default fields")
	})

	t.Run("with the feature, only the compared field is recorded", func(t *testing.T) {
		withFeature := append(mql.Features{byte(mql.AssessmentLeafFields)}, features...)
		ids, expanded := failingItemFields(t, withFeature, src)
		assert.NotContains(t, ids, "group")
		assert.NotContains(t, ids, "{}")
		assert.Equal(t, []string{"name", "uid", "gid", "name"}, ids, "the user's defaults, then group.name")
		assert.Equal(t, 1, expanded, "only the user's default fields")
	})

	t.Run("with the feature, a non-resource intermediate is still recorded", func(t *testing.T) {
		withFeature := append(mql.Features{byte(mql.AssessmentLeafFields)}, features...)
		ids, _ := failingItemFields(t, withFeature, `users.list.all(shell.downcase == "/bin/bash")`)
		assert.Contains(t, ids, "shell")
		assert.Contains(t, ids, "downcase")
	})
}

// The failing item's own default fields do not depend on the feature.
func TestAssessmentLeafFieldsKeepsItemDefaults(t *testing.T) {
	withFeature := append(mql.Features{byte(mql.AssessmentLeafFields)}, features...)
	for _, f := range []mql.Features{features, withFeature} {
		ids, _ := failingItemFields(t, f, `users.list.all(group.name == "root")`)
		for _, want := range []string{"name", "uid", "gid"} {
			assert.Contains(t, ids, want)
		}
	}
}
