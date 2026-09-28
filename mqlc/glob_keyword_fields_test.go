// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
)

// `{ * }` expands to one expression per field. A field named like a keyword
// (`return`, `empty`) cannot be a bare identifier in that expansion: `return`
// starts a return statement, which rejects the fields that follow it, and
// `empty` compiles to the empty value instead of the field. The glob reads
// those fields as `_.name`, which is what a user writes by hand.
func TestGlobReadsFieldsNamedLikeKeywords(t *testing.T) {
	mongoSchema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "mongo"})
	mongoConf := mqlc.NewConfig(core_schema.Add(mongoSchema), features)

	cases := []struct {
		name     string
		conf     mqlc.CompilerConfig
		glob     string
		explicit string
		field    string
		typ      types.Type
	}{
		{
			// failed to compile: return statement is followed by too many expressions
			name:     "nginx.conf.location.return",
			conf:     conf,
			glob:     `nginx.conf.servers { locations { * } }`,
			explicit: `nginx.conf.servers { locations { fastcgiPass modifier params path proxyPass _.return returnDirective root tryFiles } }`,
			field:    "return",
			typ:      types.String,
		},
		{
			// compiled, but reported the empty value in place of file.empty
			name:     "file.empty",
			conf:     conf,
			glob:     `file("/etc/hostname") { * }`,
			explicit: `file("/etc/hostname") { acl basename content dirname _.empty exists group path permissions size user }`,
			field:    "empty",
			typ:      types.Bool,
		},
		{
			name:     "mongo.database.empty",
			conf:     mongoConf,
			glob:     `mongo.instance.databases { * }`,
			explicit: `mongo.instance.databases { _.empty name sizeOnDisk }`,
			field:    "empty",
			typ:      types.Bool,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := mqlc.Compile(tc.glob, nil, tc.conf)
			require.NoError(t, err)
			require.NoError(t, mqlc.Invariants.Check(res))

			var read *llx.Chunk
			for _, block := range res.CodeV2.Blocks {
				for _, chunk := range block.Chunks {
					if chunk.Call == llx.Chunk_PRIMITIVE && chunk.Primitive != nil &&
						types.Type(chunk.Primitive.Type) == types.Empty {
						t.Fatalf("%s compiled the empty value instead of the %s field", tc.glob, tc.field)
					}
					if chunk.Id == tc.field {
						read = chunk
					}
				}
			}
			require.NotNil(t, read, "%s does not read the %s field", tc.glob, tc.field)
			require.NotNil(t, read.Function)
			assert.Equal(t, string(tc.typ), read.Function.Type)

			// The glob is the same query as the fields written out by hand.
			want, err := mqlc.Compile(tc.explicit, nil, tc.conf)
			require.NoError(t, err)
			assert.Equal(t, want.CodeV2.Id, res.CodeV2.Id)
		})
	}
}

// Fields whose names are not keywords still expand to bare identifiers, so
// a glob over them compiles to the same code it always did.
func TestGlobKeepsBareIdentifiersForOtherFields(t *testing.T) {
	glob, err := mqlc.Compile(`nginx.conf.servers { locations { * } }`, nil, conf)
	require.NoError(t, err)
	inner := glob.CodeV2.Blocks[len(glob.CodeV2.Blocks)-1]

	bare, err := mqlc.Compile(`nginx.conf.servers { locations { path } }`, nil, conf)
	require.NoError(t, err)
	bareInner := bare.CodeV2.Blocks[len(bare.CodeV2.Blocks)-1]

	pathSum := bare.CodeV2.Checksums[bareInner.Entrypoints[0]]
	found := false
	for _, ep := range inner.Entrypoints {
		if glob.CodeV2.Checksums[ep] == pathSum {
			found = true
		}
	}
	assert.True(t, found, "the glob's path read differs from a bare `path`")
}
