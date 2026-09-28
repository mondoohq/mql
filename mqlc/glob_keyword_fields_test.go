// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/testutils"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/sortx"
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

// Every field name declared in any provider schema, plus every word the parser
// or compiler treats as a value or keyword, must expand under `{ * }` to a
// read of that field. The allowlist in globFieldExpression is hand-kept, so
// this is what catches a provider adding a field whose name the compiler
// reads as something else.
//
// The test builds one resource that declares all of those names as string
// fields and globs it: a name that compiles to anything but a field read of
// that name fails here, with the name in the message.
func TestGlobReadsEveryDeclaredFieldName(t *testing.T) {
	lrFiles, err := filepath.Glob(filepath.Join(testutils.TestutilsDir, "../../../providers/*/resources/*.lr"))
	require.NoError(t, err)
	require.NotEmpty(t, lrFiles)

	names := map[string]struct{}{
		// parser values: parseValue turns these into literals
		"true": {}, "false": {}, "null": {}, "NaN": {}, "Infinity": {}, "Never": {},
		// compiler keywords and operators an expression can start with
		"return": {}, "empty": {}, "if": {}, "else": {}, "switch": {},
		"case": {}, "default": {}, "props": {}, "in": {},
	}
	for _, lrFile := range lrFiles {
		schema := testutils.MustLoadSchema(testutils.SchemaProvider{Path: lrFile})
		for _, info := range schema.Resources {
			for name := range info.Fields {
				names[name] = struct{}{}
			}
		}
	}

	// guards against the glob silently matching nothing: thousands of distinct
	// names are declared across the providers
	require.Greater(t, len(names), 1000)

	var lr strings.Builder
	lr.WriteString("option provider = \"go.mondoo.com/mql/providers/globtest\"\n\nglobtest {\n")
	for _, name := range sortx.Keys(names) {
		lr.WriteString("  " + name + " string\n")
	}
	lr.WriteString("}\n")
	lrPath := filepath.Join(t.TempDir(), "globtest.lr")
	require.NoError(t, os.WriteFile(lrPath, []byte(lr.String()), 0o600))

	schema := testutils.MustLoadSchema(testutils.SchemaProvider{Path: lrPath})
	res, err := mqlc.Compile(`globtest { * }`, nil, mqlc.NewConfig(schema, features))
	require.NoError(t, err)

	read := map[string]bool{}
	for _, chunk := range res.CodeV2.Blocks[len(res.CodeV2.Blocks)-1].Chunks {
		if chunk.Call == llx.Chunk_FUNCTION && chunk.Function != nil &&
			chunk.Function.Type == string(types.String) {
			read[chunk.Id] = true
		}
	}
	for name := range names {
		assert.True(t, read[name], "`{ * }` does not read the field %q; add it to globKeywordFields", name)
	}
}
