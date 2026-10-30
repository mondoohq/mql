// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/types"
)

// Builtins carry maturity out through BuiltinDocs on the field, the same
// channel a schema field uses, so a docs or autocomplete consumer reads one
// vocabulary rather than two. `json` is the first non-stable builtin: its name
// shadows a dict key of the same name in dot form, and whether an
// already-decoded value should pass through instead of erroring is still open.
//
// Dropping `maturity:` from either entry in builtinFunctions fails this.
func TestJsonBuiltinIsDeclaredExperimental(t *testing.T) {
	docs := mqlc.BuiltinDocs()

	for _, typ := range []types.Type{types.String, types.Dict} {
		t.Run(typ.Label(), func(t *testing.T) {
			resource, ok := docs.Types[typ.Label()]
			require.True(t, ok, "no builtin docs for %s", typ.Label())

			field, ok := resource.Fields["json"]
			require.True(t, ok, "no `json` builtin on %s", typ.Label())

			assert.Equal(t, resources.MaturityExperimental, field.Maturity)
			assert.NoError(t, resources.ValidateMaturity(field.Maturity))
			assert.Contains(t, field.Desc, "Experimental.")
		})
	}
}

// The siblings `json` sits next to stay stable, so the new field defaults
// correctly and does not mark the whole table experimental by accident.
func TestStableBuiltinsCarryNoMaturity(t *testing.T) {
	docs := mqlc.BuiltinDocs()

	for _, name := range []string{"lines", "split", "trim", "upcase"} {
		field, ok := docs.Types[types.String.Label()].Fields[name]
		require.True(t, ok, "no `%s` builtin on string", name)
		assert.Empty(t, field.Maturity, "`%s` must stay stable", name)
	}
}
