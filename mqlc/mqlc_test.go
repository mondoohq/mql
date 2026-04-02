// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package mqlc_test

import (
	"errors"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/v13"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/logger"
	"go.mondoo.com/mql/v13/mqlc"
	"go.mondoo.com/mql/v13/types"

	"go.mondoo.com/mql/v13/providers-sdk/v1/testutils"
)

var (
	features    = mql.Features{byte(mql.ResourceContext)}
	core_schema = testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "core"})
	os_schema   = testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "os"})
	conf        = mqlc.NewConfig(
		core_schema.Add(os_schema),
		features,
	)
)

func init() {
	logger.InitTestEnv()
}

func compileProps(t *testing.T, s string, props mqlc.PropsHandler, f func(res *llx.CodeBundle)) {
	res, err := mqlc.Compile(s, props, conf)
	require.Nil(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.CodeV2)
	assert.NoError(t, mqlc.Invariants.Check(res))

	assert.Nil(t, res.Suggestions)
	require.NotEmpty(t, res.CodeV2.Blocks)
	f(res)
}

func compileT(t *testing.T, s string, f func(res *llx.CodeBundle)) {
	compileProps(t, s, nil, f)
}

func compileCtx(t *testing.T, s string, f func(res *llx.CodeBundle)) {
	nuConf := conf
	nuConf.UseAssetContext = true
	res, err := mqlc.Compile(s, nil, nuConf)
	assert.Nil(t, err)
	assert.NotNil(t, res)
	assert.NoError(t, mqlc.Invariants.Check(res))
	if res != nil && res.CodeV2 != nil {
		assert.Nil(t, res.Suggestions)
		if assert.NotEmpty(t, res.CodeV2.Blocks) {
			f(res)
		}
	}
}

func compileEmpty(t *testing.T, s string, f func(res *llx.CodeBundle)) {
	res, err := mqlc.Compile(s, nil, conf)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Nil(t, res.Suggestions)

	f(res)
}

func compileErroneous(t *testing.T, s string, expectedError error, f func(res *llx.CodeBundle)) {
	res, err := mqlc.Compile(s, nil, conf)

	if err != nil && expectedError != nil {
		assert.Equal(t, expectedError.Error(), err.Error())
	} else {
		assert.Equal(t, expectedError, err)
	}

	if f != nil {
		f(res)
	}
}

func assertPrimitive(t *testing.T, p *llx.Primitive, chunk *llx.Chunk) {
	assert.Equal(t, llx.Chunk_PRIMITIVE, chunk.Call)
	assert.Nil(t, chunk.Function)
	assert.Equal(t, p, chunk.Primitive)
}

func assertFunction(t *testing.T, id string, f *llx.Function, chunk *llx.Chunk) {
	assert.Equal(t, llx.Chunk_FUNCTION, chunk.Call)
	assert.Equal(t, id, chunk.Id, "chunk.Id")
	assert.Nil(t, chunk.Primitive, "it is not a primitive")
	assert.Equal(t, f, chunk.Function, "chunk.Function")
}

func assertProperty(t *testing.T, name string, typ types.Type, chunk *llx.Chunk) {
	assert.Equal(t, llx.Chunk_PROPERTY, chunk.Call)
	assert.Equal(t, name, chunk.Id, "property name is set")
	assert.Equal(t, &llx.Primitive{Type: string(typ)}, chunk.Primitive, "property type is set")
}

//    ===========================
//   👋   VALUES + OPERATIONS   🍹
//    ===========================

func TestCompiler_Basics(t *testing.T) {
	data := []struct {
		code string
	}{
		{""},
		{"// some comment"},
		{"// some comment\n"},
	}
	for _, v := range data {
		t.Run(v.code, func(t *testing.T) {
			compileEmpty(t, v.code, func(res *llx.CodeBundle) {
				assert.Empty(t, res.CodeV2.Blocks[0].Chunks)
			})
		})
	}
}

func TestCompiler_Buggy(t *testing.T) {
	data := []struct {
		code string
		res  []*llx.Chunk
		err  error
	}{
		// https://github.com/mondoohq/mql/issues/2223#issuecomment-1780528051
		{`user(name: "z").authorizedkeys.all()`, []*llx.Chunk{
			{Id: "user", Call: llx.Chunk_FUNCTION, Function: &llx.Function{
				Type: string(types.Resource("user")),
				Args: []*llx.Primitive{
					{Type: string(types.String), Value: []byte("name")},
					{Type: string(types.String), Value: []byte("z")},
				},
			}},
			{Id: "authorizedkeys", Call: llx.Chunk_FUNCTION, Function: &llx.Function{
				Binding: (1<<32 | 1), Type: string(types.Resource("authorizedkeys")),
			}},
			{Id: "list", Call: llx.Chunk_FUNCTION, Function: &llx.Function{
				Binding: (1<<32 | 2), Type: string(types.Array(types.Resource("authorizedkeys.entry"))),
			}},
			{Id: "$all", Call: llx.Chunk_FUNCTION, Function: &llx.Function{
				Binding: (1<<32 | 3), Type: string(types.Bool),
			}},
			{Id: "{}", Call: llx.Chunk_FUNCTION, Function: &llx.Function{
				Binding: (1<<32 | 3), Type: string(types.Array(types.Block)),
				Args: []*llx.Primitive{
					llx.FunctionPrimitive(2 << 32),
				},
			}},
		}, nil},
		{`parse parse`, []*llx.Chunk{
			{Id: "parse", Call: llx.Chunk_FUNCTION},
			{Id: "parse", Call: llx.Chunk_FUNCTION},
		}, nil},
		{`parse # mondoo`, []*llx.Chunk{
			{Id: "parse", Call: llx.Chunk_FUNCTION},
		}, nil},
		{`parse }`, []*llx.Chunk{
			{Id: "parse", Call: llx.Chunk_FUNCTION},
		}, errors.New("mismatched symbol '}' at the end of expression")},
		{`parse ]`, []*llx.Chunk{
			{Id: "parse", Call: llx.Chunk_FUNCTION},
		}, errors.New("mismatched symbol ']' at the end of expression")},
		{`parse )`, []*llx.Chunk{
			{Id: "parse", Call: llx.Chunk_FUNCTION},
		}, errors.New("mismatched symbol ')' at the end of expression")},
		{`mondoo { version }`, []*llx.Chunk{
			{Id: "mondoo", Call: llx.Chunk_FUNCTION},
			{Id: "{}", Call: llx.Chunk_FUNCTION, Function: &llx.Function{
				Type:    string(types.Block),
				Binding: (1 << 32) | 1,
				Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
			}},
		}, nil},
		{"# ..\nmondoo { \n# ..\nversion\n# ..\n}\n# ..", []*llx.Chunk{
			{Call: llx.Chunk_FUNCTION, Id: "mondoo"},
			{Call: llx.Chunk_FUNCTION, Id: "{}", Function: &llx.Function{
				Type:    string(types.Block),
				Binding: (1 << 32) | 1,
				Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
			}},
		}, nil},
		{`users.list[]`, nil, errors.New("missing value inside of `[]` at <source>:1:12")},
		{`file(not-there)`, nil, errors.New("addResourceCall error: cannot find resource for identifier 'not'")},
		{`if(true) {`, []*llx.Chunk{
			{Call: llx.Chunk_FUNCTION, Id: "if", Function: &llx.Function{
				Type: string(types.Block),
				Args: []*llx.Primitive{
					llx.BoolPrimitive(true),
					llx.FunctionPrimitive(2 << 32),
					llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				},
			}},
		}, errors.New("incomplete query, missing closing '}' at <source>:1:11")},
		{`if(true) { return 1 } else { return 2 } return 3`, []*llx.Chunk{
			{Call: llx.Chunk_FUNCTION, Id: "if", Function: &llx.Function{
				Type: string(types.Int),
				Args: []*llx.Primitive{
					llx.BoolPrimitive(true),
					llx.FunctionPrimitive(2 << 32),
					llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
					llx.FunctionPrimitive(3 << 32),
					llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				},
			}},
		}, errors.New("single valued block followed by expressions")},
		{`parse.date`, []*llx.Chunk{
			{Id: "parse", Call: llx.Chunk_FUNCTION},
		}, errors.New("missing arguments to parse date")},
		{`parse.date()`, []*llx.Chunk{
			{Id: "parse", Call: llx.Chunk_FUNCTION},
		}, errors.New("missing arguments to parse date")},
		{`switch(mondoo) { case`, nil, errors.New("missing expression after `case` statement")},
	}

	for _, v := range data {
		t.Run(v.code, func(t *testing.T) {
			compileErroneous(t, v.code, v.err, func(res *llx.CodeBundle) {
				if res.CodeV2 != nil {
					assert.Equal(t, v.res, res.CodeV2.Blocks[0].Chunks)
				} else {
					assert.Nil(t, v.res)
				}
			})
		})
	}
}

func TestCompiler_FailIfNoEntrypoints(t *testing.T) {
	data := []string{
		"",
		"// some comment",
		"(asset.eol.date - time.now() > 90*time.day) && (asset.eol.date - time.now() < 180*time.day)",
	}
	for _, code := range data {
		t.Run(code, func(t *testing.T) {
			features := mql.Features{byte(mql.FailIfNoEntryPoints)}
			conf := mqlc.NewConfig(
				core_schema.Add(os_schema),
				features,
			)
			_, err := mqlc.Compile(code, nil, conf)
			assert.Error(t, err)
			assert.EqualError(t, err, "failed to compile: received an empty code structure. this is a bug with the query compilation")
		})
	}
}

func TestCompiler_StructuredErrors(t *testing.T) {
	data := []struct {
		code string
		errT any
	}{
		{
			code: `does_not_exist`,
			errT: mqlc.ErrIdentifierNotFound{},
		},
		{
			code: `mondoo.does_not_exist`,
			errT: mqlc.ErrIdentifierNotFound{},
		},
		{
			code: `props.does_not_exist`,
			errT: mqlc.ErrIdentifierNotFound{},
		},
	}

	for _, v := range data {
		t.Run(v.code, func(t *testing.T) {
			_, err := mqlc.Compile(v.code, nil, conf)
			assert.ErrorAs(t, err, &v.errT)
		})
	}
}

func TestCompiler_Semicolon(t *testing.T) {
	compileT(t, "mondoo.version;mondoo.build", func(res *llx.CodeBundle) {
		require.Len(t, res.CodeV2.Blocks, 1)
		require.Len(t, res.CodeV2.Blocks[0].Chunks, 4)
		assertFunction(t, "version",
			&llx.Function{Binding: (1 << 32) | 1, Type: string(types.String)},
			res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "build",
			&llx.Function{Binding: (1 << 32) | 3, Type: string(types.String)},
			res.CodeV2.Blocks[0].Chunks[3])
	})

	compileT(t, "mondoo{version;build}", func(res *llx.CodeBundle) {
		require.Len(t, res.CodeV2.Blocks, 2)
		require.Len(t, res.CodeV2.Blocks[1].Chunks, 3)
		assertFunction(t, "version",
			&llx.Function{Binding: (2 << 32) | 1, Type: string(types.String)},
			res.CodeV2.Blocks[1].Chunks[1])
		assertFunction(t, "build",
			&llx.Function{Binding: (2 << 32) | 1, Type: string(types.String)},
			res.CodeV2.Blocks[1].Chunks[2])
	})
}

func TestCompiler_DeterministicChecksum(t *testing.T) {
	// this is a query that in the past used to produce different checksum every now and then
	// this test ensures that the checksum is always deterministic now
	mql := `azure.subscription.sql.servers.all(databases.one (transparentDataEncryption["state"] == "Enabled") && encryptionProtector["serverKeyType"] == "AzureKeyVault" )`
	azure_schema := testutils.MustLoadSchema(testutils.SchemaProvider{Provider: "azure"})

	for range 10000 {
		azureConf := mqlc.NewConfig(azure_schema, features)
		res, err := mqlc.Compile(mql, mqlc.EmptyPropsHandler, azureConf)
		require.Nil(t, err)
		require.Equal(t, res.CodeV2.Id, "myGJk5hUrsM=")
	}
}

func TestCompiler_Simple(t *testing.T) {
	data := []struct {
		code string
		res  *llx.Primitive
	}{
		{"null", llx.NilPrimitive},
		{"false", llx.BoolPrimitive(false)},
		{"true", llx.BoolPrimitive(true)},
		{"123", llx.IntPrimitive(123)},
		{"010", llx.IntPrimitive(8)},
		{"12.3", llx.FloatPrimitive(12.3)},
		{"\"hi\"", llx.StringPrimitive("hi")},
		{"/hi/", llx.RegexPrimitive("hi")},
		{"[true, false]", &llx.Primitive{
			Type: string(types.Array(types.Bool)),
			Array: []*llx.Primitive{
				llx.BoolPrimitive(true),
				llx.BoolPrimitive(false),
			},
		}},
		{"[1, 2]", &llx.Primitive{
			Type: string(types.Array(types.Int)),
			Array: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.IntPrimitive(2),
			},
		}},
		{"[1.2,3.4]", &llx.Primitive{
			Type: string(types.Array(types.Float)),
			Array: []*llx.Primitive{
				llx.FloatPrimitive(1.2),
				llx.FloatPrimitive(3.4),
			},
		}},
		{"[\"a\",\"b\"]", &llx.Primitive{
			Type: string(types.Array(types.String)),
			Array: []*llx.Primitive{
				llx.StringPrimitive("a"),
				llx.StringPrimitive("b"),
			},
		}},
		{"[1.2,1]", &llx.Primitive{
			Type: string(types.Array(types.Any)),
			Array: []*llx.Primitive{
				llx.FloatPrimitive(1.2),
				llx.IntPrimitive(1),
			},
		}},
		{"[\n  1.2,\n  1\n]", &llx.Primitive{
			Type: string(types.Array(types.Any)),
			Array: []*llx.Primitive{
				llx.FloatPrimitive(1.2),
				llx.IntPrimitive(1),
			},
		}},
		{"{a: 123}", &llx.Primitive{
			Type: string(types.Map(types.String, types.Int)),
			Map: map[string]*llx.Primitive{
				"a": llx.IntPrimitive(123),
			},
		}},
	}
	for _, v := range data {
		t.Run(v.code, func(t *testing.T) {
			compileT(t, v.code, func(res *llx.CodeBundle) {
				o := res.CodeV2.Blocks[0].Chunks[0]
				assert.Equal(t, llx.Chunk_PRIMITIVE, o.Call)
				assert.Equal(t, v.res, o.Primitive)
			})
		})
	}
}

// FIXME: this is weirdly failing
// func TestCompiler_SimpleArrayResource(t *testing.T) {
// 	res := compileT(t, "[mochi, mochi]").Code.Code[2]
// 	assert.Equal(t, llx.Chunk_PRIMITIVE, res.Call)
// 	assert.Equal(t, []types.Type{types.Type_ARRAY, types.Type_ANY}, res.Primitive.Type)
// 	assert.Equal(t, []*llx.Primitive{
// 		llx.RefPrimitive(1),
// 		llx.RefPrimitive(2),
// 	}, res.Primitive.Array)
// 	assert.Nil(t, res.Primitive.Value)
// }

func TestCompiler_Comparisons(t *testing.T) {
	ops := []string{"==", "!=", ">", "<", ">=", "<="}
	vals := map[string]*llx.Primitive{
		"1":       llx.IntPrimitive(1),
		"1.2":     llx.FloatPrimitive(1.2),
		"true":    llx.BoolPrimitive(true),
		"\"str\"": llx.StringPrimitive("str"),
		"/str/":   llx.RegexPrimitive("str"),
	}
	for _, op := range ops {
		for val, valres := range vals {
			if types.Type(valres.Type) != types.Int && types.Type(valres.Type) != types.Float && types.Type(valres.Type) != types.String {
				continue
			}
			code := val + " " + op + " " + val
			t.Run(code, func(t *testing.T) {
				compileT(t, code, func(res *llx.CodeBundle) {
					o := res.CodeV2.Blocks[0].Chunks[0]
					assert.Equal(t, valres, o.Primitive)
					o = res.CodeV2.Blocks[0].Chunks[1]
					assert.Equal(t, llx.Chunk_FUNCTION, o.Call)
					assert.Equal(t, op+string(valres.Type), o.Id)
					assert.Equal(t, uint64((1<<32)|1), o.Function.Binding)
					assert.Equal(t, types.Bool, types.Type(o.Function.Type))
					assert.Equal(t, valres, o.Function.Args[0])
				})
			})
		}
	}
}

func TestCompiler_LogicalOps(t *testing.T) {
	ops := []string{"&&", "||"}
	vals := map[string]*llx.Primitive{
		"1":       llx.IntPrimitive(1),
		"1.2":     llx.FloatPrimitive(1.2),
		"true":    llx.BoolPrimitive(true),
		"\"str\"": llx.StringPrimitive("str"),
		"/str/":   llx.RegexPrimitive("str"),
		"[]":      llx.ArrayPrimitive([]*llx.Primitive{}, types.Unset),
		"{}":      llx.MapPrimitive(map[string]*llx.Primitive{}, types.Unset),
	}
	for _, op := range ops {
		for val1, valres1 := range vals {
			for val2, valres2 := range vals {
				code := val1 + " " + op + " " + val2
				t.Run(code, func(t *testing.T) {
					compileT(t, code, func(res *llx.CodeBundle) {
						l := res.CodeV2.Blocks[0].Chunks[0]
						assert.Equal(t, valres1, l.Primitive)

						r := res.CodeV2.Blocks[0].Chunks[1]
						assert.Equal(t, llx.Chunk_FUNCTION, r.Call)
						assert.Equal(t, uint64((1<<32)|1), r.Function.Binding)
						assert.Equal(t, types.Bool, types.Type(r.Function.Type))
						assert.Equal(t, valres2, r.Function.Args[0])

						f, err := llx.BuiltinFunctionV2(l.Type(), r.Id)
						assert.NoError(t, err, "was able to find builtin function for llx execution")
						assert.NotNil(t, f, "was able to get non-nil builtin function")
					})
				})
			}
		}
	}
}

func TestCompiler_Arithmetics(t *testing.T) {
	t.Run("concat arrays", func(t *testing.T) {
		compileT(t, "[1,2] + [3]", func(res *llx.CodeBundle) {
			require.NotEmpty(t, res.CodeV2)
			require.NotEmpty(t, res.CodeV2.Blocks)
			chunks := res.CodeV2.Blocks[0].Chunks
			require.NotEmpty(t, chunks)

			assert.Equal(t, llx.Chunk_PRIMITIVE, chunks[0].Call)
			assert.Equal(t, llx.Chunk_FUNCTION, chunks[1].Call)
			assert.Equal(t, "+", chunks[1].Id)
			assert.Equal(t, 1, len(chunks[1].Function.Args))
		})
	})
}

func TestCompiler_OperatorPrecedence(t *testing.T) {
	data := []struct {
		code   string
		idx    int
		first  string
		second string
	}{
		{"1 || 2 && 3", 2, string("&&" + types.Int), string("||" + types.Bool)},
		{"1 && 2 || 3", 1, string("&&" + types.Int), string("||" + types.Int)},
	}

	for _, d := range data {
		t.Run(d.code, func(t *testing.T) {
			compileT(t, d.code, func(res *llx.CodeBundle) {
				fmt.Printf("compiled: %#v\n", res)

				o := res.CodeV2.Blocks[0].Chunks[d.idx]
				assert.Equal(t, d.first, o.Id)

				o = res.CodeV2.Blocks[0].Chunks[d.idx+1]
				assert.Equal(t, d.second, o.Id)
			})
		})
	}
}

func TestCompiler_Assignment(t *testing.T) {
	compileT(t, "a = 123", func(res *llx.CodeBundle) {
		assertPrimitive(t, llx.IntPrimitive(123), res.CodeV2.Blocks[0].Chunks[0])
		assert.Empty(t, res.CodeV2.Entrypoints())
	})
	compileT(t, "a = 123\na", func(res *llx.CodeBundle) {
		assertPrimitive(t, llx.RefPrimitiveV2((1<<32)|1), res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
	})
}

func TestCompiler_Props(t *testing.T) {
	compileProps(t, "props.name", mqlc.SimpleProps{
		"name": {Type: string(types.String)},
	}, func(res *llx.CodeBundle) {
		assertProperty(t, "name", types.String, res.CodeV2.Blocks[0].Chunks[0])
		assert.Equal(t, []uint64{(1 << 32) | 1}, res.CodeV2.Entrypoints())
		assert.Equal(t, map[string]string{"name": string(types.String)}, res.Props)
	})

	// prop <op> value
	compileProps(t, "props.name == 'bob'", mqlc.SimpleProps{
		"name": {Type: string(types.String)},
	}, func(res *llx.CodeBundle) {
		assertProperty(t, "name", types.String, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "=="+string(types.String), &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.StringPrimitive("bob")},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
		assert.Equal(t, map[string]string{"name": string(types.String)}, res.Props)
	})

	// different compile stages yielding the same checksums
	compileProps(t, "props.name == 'bob'", mqlc.SimpleProps{
		"name": {Type: string(types.String)},
	}, func(res1 *llx.CodeBundle) {
		compileProps(t, "props.name == 'bob'", mqlc.SimpleProps{
			"name": {Type: string(types.String), Value: []byte("yoman")},
		}, func(res2 *llx.CodeBundle) {
			assert.Equal(t, res2.CodeV2.Id, res1.CodeV2.Id)
		})
	})

	compileProps(t, "props.name == props.name", mqlc.SimpleProps{
		"name": {Type: string(types.String)},
	}, func(res *llx.CodeBundle) {
		assertProperty(t, "name", types.String, res.CodeV2.Blocks[0].Chunks[0])
		assertProperty(t, "name", types.String, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "=="+string(types.String), &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.RefPrimitiveV2((1 << 32) | 2)},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())
		assert.Equal(t, map[string]string{"name": string(types.String)}, res.Props)
	})
}

func TestCompiler_Dict(t *testing.T) {
	compileProps(t, "props.d.A.B", mqlc.SimpleProps{
		"d": {Type: string(types.Dict)},
	}, func(res *llx.CodeBundle) {
		assertProperty(t, "d", types.Dict, res.CodeV2.Blocks[0].Chunks[0])
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())
		assertFunction(t, "[]", &llx.Function{
			Type:    string(types.Dict),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.StringPrimitive("A")},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "[]", &llx.Function{
			Type:    string(types.Dict),
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.StringPrimitive("B")},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, map[string]string{"d": string(types.Dict)}, res.Props)
	})

	compileProps(t, "props.d.A-1", mqlc.SimpleProps{
		"d": {Type: string(types.Dict)},
	}, func(res *llx.CodeBundle) {
		assertProperty(t, "d", types.Dict, res.CodeV2.Blocks[0].Chunks[0])
		assert.Equal(t, []uint64{(1 << 32) | 2, (1 << 32) | 3}, res.CodeV2.Entrypoints())
		assertFunction(t, "[]", &llx.Function{
			Type:    string(types.Dict),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.StringPrimitive("A")},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertPrimitive(t, llx.IntPrimitive(-1), res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, map[string]string{"d": string(types.Dict)}, res.Props)
	})
}

func TestCompiler_If(t *testing.T) {
	compileT(t, "if ( true ) { return 1 } else if ( false ) { return 2 } else { return 3 }", func(res *llx.CodeBundle) {
		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.BoolPrimitive(true),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.BoolPrimitive(false),
				llx.FunctionPrimitive(3 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.FunctionPrimitive(4 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])
		assert.Equal(t, []uint64{(1 << 32) | 1}, res.CodeV2.Entrypoints())
		assert.Equal(t, []uint64(nil), res.CodeV2.Datapoints())

		assertPrimitive(t, llx.IntPrimitive(1), res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "return", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((2 << 32) | 1),
			},
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(2), res.CodeV2.Blocks[2].Chunks[0])
		assertFunction(t, "return", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((3 << 32) | 1),
			},
		}, res.CodeV2.Blocks[2].Chunks[1])
		assert.Equal(t, []uint64{(3 << 32) | 2}, res.CodeV2.Blocks[2].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(3), res.CodeV2.Blocks[3].Chunks[0])
		assertFunction(t, "return", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((4 << 32) | 1),
			},
		}, res.CodeV2.Blocks[3].Chunks[1])
		assert.Equal(t, []uint64{(4 << 32) | 2}, res.CodeV2.Blocks[3].Entrypoints)
	})

	compileT(t, "if ( mondoo ) { return 123 } if ( true ) { return 456 } 789", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.FunctionPrimitive(3 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
		assert.Equal(t, []uint64(nil), res.CodeV2.Datapoints())

		assertPrimitive(t, llx.IntPrimitive(123), res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "return", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((2 << 32) | 1),
			},
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)

		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.BoolPrimitive(true),
				llx.FunctionPrimitive(4 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.FunctionPrimitive(5 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[2].Chunks[0])
		assert.Equal(t, []uint64{(3 << 32) | 1}, res.CodeV2.Blocks[2].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(456), res.CodeV2.Blocks[3].Chunks[0])
		assertFunction(t, "return", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((4 << 32) | 1),
			},
		}, res.CodeV2.Blocks[3].Chunks[1])
		assert.Equal(t, []uint64{(4 << 32) | 2}, res.CodeV2.Blocks[3].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(789), res.CodeV2.Blocks[4].Chunks[0])
		assert.Equal(t, []uint64{(5 << 32) | 1}, res.CodeV2.Blocks[4].Entrypoints)
	})

	compileT(t, "if ( mondoo ) { return 123 } 456", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.FunctionPrimitive(3 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
		assert.Equal(t, []uint64(nil), res.CodeV2.Datapoints())

		assertPrimitive(t, llx.IntPrimitive(123), res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "return", &llx.Function{
			Type:    string(types.Int),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((2 << 32) | 1),
			},
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(456), res.CodeV2.Blocks[2].Chunks[0])
		assert.Equal(t, []uint64{(3 << 32) | 1}, res.CodeV2.Blocks[2].Entrypoints)
	})

	// Test empty array with filled array and type-consolidation in the compiler
	compileT(t, "if ( mondoo ) { return [] } return [1,2,3]", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Array(types.Int)),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.FunctionPrimitive(3 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
		assert.Equal(t, []uint64(nil), res.CodeV2.Datapoints())

		assertPrimitive(t, llx.ArrayPrimitive([]*llx.Primitive{}, types.Unset),
			res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "return", &llx.Function{
			Type:    string(types.Array(types.Unset)),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((2 << 32) | 1),
			},
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)
	})

	compileT(t, "if ( mondoo.version != null ) { 123 }", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "version", &llx.Function{
			Type:    string(types.String),
			Binding: (1 << 32) | 1,
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "!=\x02", &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.NilPrimitive},
		}, res.CodeV2.Blocks[0].Chunks[2])

		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Block),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 3),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[3])
		assert.Equal(t, []uint64{(1 << 32) | 4}, res.CodeV2.Entrypoints())
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Datapoints())

		assertPrimitive(t, llx.IntPrimitive(123), res.CodeV2.Blocks[1].Chunks[0])
		assert.Equal(t, []uint64{(2 << 32) | 1}, res.CodeV2.Blocks[1].Entrypoints)
	})

	compileT(t, "if ( mondoo ) { 123 } else { 456 }", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Block),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.FunctionPrimitive(3 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
		assert.Equal(t, []uint64(nil), res.CodeV2.Datapoints())

		assertPrimitive(t, llx.IntPrimitive(123), res.CodeV2.Blocks[1].Chunks[0])
		assert.Equal(t, []uint64{(2 << 32) | 1}, res.CodeV2.Blocks[1].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(456), res.CodeV2.Blocks[2].Chunks[0])
		assert.Equal(t, []uint64{(3 << 32) | 1}, res.CodeV2.Blocks[2].Entrypoints)
	})

	compileT(t, "if ( mondoo ) { 123 } else if ( true ) { 456 } else { 789 }", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "if", &llx.Function{
			Type:    string(types.Block),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.BoolPrimitive(true),
				llx.FunctionPrimitive(3 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
				llx.FunctionPrimitive(4 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
		assert.Equal(t, []uint64(nil), res.CodeV2.Datapoints())

		assertPrimitive(t, llx.IntPrimitive(123), res.CodeV2.Blocks[1].Chunks[0])
		assert.Equal(t, []uint64{(2 << 32) | 1}, res.CodeV2.Blocks[1].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(456), res.CodeV2.Blocks[2].Chunks[0])
		assert.Equal(t, []uint64{(3 << 32) | 1}, res.CodeV2.Blocks[2].Entrypoints)

		assertPrimitive(t, llx.IntPrimitive(789), res.CodeV2.Blocks[3].Chunks[0])
		assert.Equal(t, []uint64{(4 << 32) | 1}, res.CodeV2.Blocks[3].Entrypoints)
	})
}

func TestCompiler_Switch(t *testing.T) {
	compileT(t, "switch ( 1 ) { case _ > 0: true; default: false }", func(res *llx.CodeBundle) {
		assertFunction(t, "switch", &llx.Function{
			Type:    string(types.Bool),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.RefPrimitiveV2((1 << 32) | 2),
				llx.FunctionPrimitive(2 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{
					// TODO(jaym): this shouldn't be needed. Its already
					// a dependency of the switch, and thus implicitly
					// will already be available for any blocks
					llx.RefPrimitiveV2((1 << 32) | 1),
				}, types.Ref),
				llx.BoolPrimitive(true),
				llx.FunctionPrimitive(3 << 32),
				llx.ArrayPrimitive([]*llx.Primitive{
					// TODO: this shouldn't be needed
					llx.RefPrimitiveV2((1 << 32) | 1),
				}, types.Ref),
			},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())
		assert.Empty(t, res.CodeV2.Datapoints())
	})

	compileT(t, "switch { case 3 > 2: 123; default: 321 }", func(res *llx.CodeBundle) {
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())
	})

	t.Run("test types fall back to any", func(t *testing.T) {
		compileT(t, "switch ( 1 ) { case _ > 0: true; case _ < 0: 'test'; default: false }", func(res *llx.CodeBundle) {
			assert.Equal(t, types.Any, res.CodeV2.Blocks[0].Chunks[3].Type())
		})
		compileT(t, "switch ( 1 ) { case _ > 0: true; default: 'test' }", func(res *llx.CodeBundle) {
			assert.Equal(t, types.Any, res.CodeV2.Blocks[0].Chunks[2].Type())
		})
	})
}

// //    =======================
// //   👋   ARRAYS and MAPS   🍹
// //    =======================

func TestCompiler_ArrayEmptyWhere(t *testing.T) {
	compileT(t, "[1,2,3].where()", func(res *llx.CodeBundle) {
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Array(types.Int)),
			Array: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.IntPrimitive(2),
				llx.IntPrimitive(3),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])
		assert.Equal(t, 1, len(res.CodeV2.Blocks[0].Chunks))
	})
}

func TestCompiler_ArrayWhereStatic(t *testing.T) {
	compileErroneous(t, "[1,2,3].where(sshd)", errors.New("called 'where' with wrong type; either provide a type int value or write it as an expression (e.g. \"_ == 123\")"), func(res *llx.CodeBundle) {
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Array(types.Int)),
			Array: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.IntPrimitive(2),
				llx.IntPrimitive(3),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])
	})

	compileT(t, "[1,2,3].where(2)", func(res *llx.CodeBundle) {
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Array(types.Int)),
			Array: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.IntPrimitive(2),
				llx.IntPrimitive(3),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "where", &llx.Function{
			Type:    string(types.Array(types.Int)),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])

		assert.Equal(t, 2, len(res.CodeV2.Blocks[0].Chunks))
	})
}

func TestCompiler_ArrayContains(t *testing.T) {
	compileT(t, "[1,2,3].contains(_ == 2)", func(res *llx.CodeBundle) {
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Array(types.Int)),
			Array: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.IntPrimitive(2),
				llx.IntPrimitive(3),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "where", &llx.Function{
			Type:    string(types.Array(types.Int)),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])

		assertFunction(t, "length", &llx.Function{
			Type:    string(types.Int),
			Binding: (1 << 32) | 2,
		}, res.CodeV2.Blocks[0].Chunks[2])
		assertFunction(t, string(">"+types.Int), &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 3,
			Args:    []*llx.Primitive{llx.IntPrimitive(0)},
		}, res.CodeV2.Blocks[0].Chunks[3])

		assert.Equal(t, 4, len(res.CodeV2.Blocks[0].Chunks))
	})
}

func TestCompiler_ArrayOne(t *testing.T) {
	compileT(t, "[1,2,3].one(_ == 2)", func(res *llx.CodeBundle) {
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Array(types.Int)),
			Array: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.IntPrimitive(2),
				llx.IntPrimitive(3),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "where", &llx.Function{
			Type:    string(types.Array(types.Int)),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])

		assertFunction(t, "$one", &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 2,
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, 3, len(res.CodeV2.Blocks[0].Chunks))
	})
}

func TestCompiler_ArrayAll(t *testing.T) {
	compileT(t, "[1,2,3].all(_ < 9)", func(res *llx.CodeBundle) {
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Array(types.Int)),
			Array: []*llx.Primitive{
				llx.IntPrimitive(1),
				llx.IntPrimitive(2),
				llx.IntPrimitive(3),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "$whereNot", &llx.Function{
			Type:    string(types.Array(types.Int)),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])

		assertFunction(t, "$all", &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 2,
		}, res.CodeV2.Blocks[0].Chunks[2])

		assert.Equal(t, 3, len(res.CodeV2.Blocks[0].Chunks))
	})

	compileT(t, "['a','b'].all(_ != empty)", func(res *llx.CodeBundle) {
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Array(types.String)),
			Array: []*llx.Primitive{
				llx.StringPrimitive("a"),
				llx.StringPrimitive("b"),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])

		assertFunction(t, "$whereNot", &llx.Function{
			Type:    string(types.Array(types.String)),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 1),
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[1])

		assertFunction(t, "$all", &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 2,
		}, res.CodeV2.Blocks[0].Chunks[2])

		assertFunction(t, "!=\r", &llx.Function{
			Type:    string(types.Type(types.Bool)),
			Binding: (2 << 32) | 1,
			Args: []*llx.Primitive{
				llx.EmptyPrimitive,
			},
		}, res.CodeV2.Blocks[1].Chunks[1])

		assert.Equal(t, 3, len(res.CodeV2.Blocks[0].Chunks))
		assert.Equal(t, 2, len(res.CodeV2.Blocks[1].Chunks))
	})

	compileT(t, "users.all(_ != empty)", func(res *llx.CodeBundle) {
		// 3 blocks:
		// 1. users
		// 2. function for != empty + ref
		// 3. users expand (properties)
		assert.Equal(t, 3, len(res.CodeV2.Blocks))
		assertFunction(t, "users", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "list", &llx.Function{
			Binding: (1 << 32) | 1,
			Args:    nil,
			Type:    string(types.Array(types.Resource("user"))),
		}, res.CodeV2.Blocks[0].Chunks[1])

		assertFunction(t, "!=\r", &llx.Function{
			Type:    string(types.Type(types.Bool)),
			Binding: (2 << 32) | 1,
			Args: []*llx.Primitive{
				llx.EmptyPrimitive,
			},
		}, res.CodeV2.Blocks[1].Chunks[1])
	})
}

func TestCompiler_Empty_All_ANY_Issue5248(t *testing.T) {
	unsetArray := []string{
		"[].any()",
		"[].all()",
		"[].none()",
		"[].any()",
	}
	for _, code := range unsetArray {
		t.Run(code, func(t *testing.T) {
			compileT(t, code, func(res *llx.CodeBundle) {
				require.Equal(t, 2, len(res.CodeV2.Blocks[0].Chunks))
				assert.Nil(t, res.CodeV2.Blocks[0].Chunks[0].Function)
				// all of these builtin functions should return an empty array
				// of unset values
				assertPrimitive(t, &llx.Primitive{
					// type is an array of unset values
					Type: string(types.Array(types.Unset)),
					// without content
					Array: []*llx.Primitive{},
				}, res.CodeV2.Blocks[0].Chunks[0])
			})
		})
	}

	unsetMap := []string{
		"{}.any()",
		"{}.all()",
		"{}.none()",
		"{}.any()",
	}
	for _, code := range unsetMap {
		t.Run(code, func(t *testing.T) {
			compileT(t, code, func(res *llx.CodeBundle) {
				require.Equal(t, 2, len(res.CodeV2.Blocks[0].Chunks))
				assert.Nil(t, res.CodeV2.Blocks[0].Chunks[0].Function)
				// all of these builtin functions should return an empty map
				// of unset values
				assertPrimitive(t, &llx.Primitive{
					// type is a map of unset values
					Type: string(types.Map(types.String, types.Unset)),
					// map without content
					Map: map[string]*llx.Primitive{},
				}, res.CodeV2.Blocks[0].Chunks[0])
			})
		})
	}

	otherCases := []struct {
		code string
		res  *llx.Primitive
	}{
		{
			code: "[1,2].any()",
			res: &llx.Primitive{
				// test that we compile successfully into int values
				Type: string(types.Array(types.Int)),
				Array: []*llx.Primitive{
					llx.IntPrimitive(1),
					llx.IntPrimitive(2),
				},
			},
		},
		{
			code: "[\"a\",\"b\"].all()",
			res: &llx.Primitive{
				// test that we compile successfully into string values
				Type: string(types.Array(types.String)),
				Array: []*llx.Primitive{
					llx.StringPrimitive("a"),
					llx.StringPrimitive("b"),
				},
			},
		},
		{
			code: "{a: 123}.all()",
			res: &llx.Primitive{
				// type is a map of unset values
				Type: string(types.Map(types.String, types.Int)),
				// map without content
				Map: map[string]*llx.Primitive{
					"a": llx.IntPrimitive(123),
				},
			},
		},
		{
			code: "[true,false].none()",
			res: &llx.Primitive{
				// test that we compile successfully into boolean values
				Type: string(types.Array(types.Bool)),
				Array: []*llx.Primitive{
					llx.BoolPrimitive(true),
					llx.BoolPrimitive(false),
				},
			},
		},
	}
	for _, v := range otherCases {
		t.Run(v.code, func(t *testing.T) {
			compileT(t, v.code, func(res *llx.CodeBundle) {
				require.Equal(t, 2, len(res.CodeV2.Blocks[0].Chunks))
				assert.Nil(t, res.CodeV2.Blocks[0].Chunks[0].Function)
				assertPrimitive(t, v.res, res.CodeV2.Blocks[0].Chunks[0])
			})
		})
	}
}

func TestCompiler_All_Issue919(t *testing.T) {
	// https://github.com/mondoohq/cnquery/issues/919
	compileT(t, `files.find(from: ".", type: "file").all( permissions.other_readable == false )`, func(res *llx.CodeBundle) {
		require.Equal(t, 3, len(res.CodeV2.Blocks))
		require.Equal(t, 6, len(res.CodeV2.Blocks[2].Chunks))
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("file")),
		}, res.CodeV2.Blocks[2].Chunks[0])
		assertFunction(t, "path", &llx.Function{
			Type:    string(types.String),
			Binding: (3 << 32) | 1,
		}, res.CodeV2.Blocks[2].Chunks[1])
		assertFunction(t, "size", &llx.Function{
			Type:    string(types.Int),
			Binding: (3 << 32) | 1,
		}, res.CodeV2.Blocks[2].Chunks[2])
		assertFunction(t, "permissions", &llx.Function{
			Type:    string(types.Resource("file.permissions")),
			Binding: (3 << 32) | 1,
		}, res.CodeV2.Blocks[2].Chunks[3])
		assertFunction(t, "string", &llx.Function{
			Type:    string(types.String),
			Binding: (3 << 32) | 4,
		}, res.CodeV2.Blocks[2].Chunks[4])
		assertFunction(t, "other_readable", &llx.Function{
			Type:    string(types.Bool),
			Binding: (3 << 32) | 4,
		}, res.CodeV2.Blocks[2].Chunks[5])
	})
}

func TestCompiler_All_Issue1316(t *testing.T) {
	// https://github.com/mondoohq/mql/issues/1316
	compileT(t, `files.find(from: ".", type: "file").all( permissions.other_readable == false )`, func(res *llx.CodeBundle) {
		require.Equal(t, 3, len(res.CodeV2.Blocks))
		require.Equal(t, 6, len(res.CodeV2.Blocks[2].Chunks))
		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("file")),
		}, res.CodeV2.Blocks[2].Chunks[0])
		assertFunction(t, "path", &llx.Function{
			Type:    string(types.String),
			Binding: (3 << 32) | 1,
		}, res.CodeV2.Blocks[2].Chunks[1])
		assertFunction(t, "size", &llx.Function{
			Type:    string(types.Int),
			Binding: (3 << 32) | 1,
		}, res.CodeV2.Blocks[2].Chunks[2])
		assertFunction(t, "permissions", &llx.Function{
			Type:    string(types.Resource("file.permissions")),
			Binding: (3 << 32) | 1,
		}, res.CodeV2.Blocks[2].Chunks[3])
		assertFunction(t, "string", &llx.Function{
			Type:    string(types.String),
			Binding: (3 << 32) | 4,
		}, res.CodeV2.Blocks[2].Chunks[4])
		assertFunction(t, "other_readable", &llx.Function{
			Type:    string(types.Bool),
			Binding: (3 << 32) | 4,
		}, res.CodeV2.Blocks[2].Chunks[5])
	})
}

//    =================
//   👋   RESOURCES   🍹
//    =================

func TestCompiler_Resource(t *testing.T) {
	compileT(t, "sshd", func(res *llx.CodeBundle) {
		assertFunction(t, "sshd", nil, res.CodeV2.Blocks[0].Chunks[0])
	})
}

func TestCompiler_ResourceWithCall(t *testing.T) {
	compileT(t, "sshd()", func(res *llx.CodeBundle) {
		assertFunction(t, "sshd", nil, res.CodeV2.Blocks[0].Chunks[0])
	})
}

func TestCompiler_LongResource(t *testing.T) {
	compileT(t, "sshd.config", func(res *llx.CodeBundle) {
		assertFunction(t, "sshd.config", nil, res.CodeV2.Blocks[0].Chunks[0])
	})
}

func TestCompiler_ResourceMap(t *testing.T) {
	compileT(t, "sshd.config.params", func(res *llx.CodeBundle) {
		assertFunction(t, "sshd.config", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "params", &llx.Function{
			Type:    string(types.Map(types.String, types.String)),
			Binding: (1 << 32) | 1,
		}, res.CodeV2.Blocks[0].Chunks[1])
	})
}

func TestCompiler_ResourceMapLength(t *testing.T) {
	compileT(t, "sshd.config.params.length", func(res *llx.CodeBundle) {
		assertFunction(t, "length", &llx.Function{
			Type:    string(types.Int),
			Binding: (1 << 32) | 2,
		}, res.CodeV2.Blocks[0].Chunks[2])
	})
}

func TestCompiler_ResourceExpansion(t *testing.T) {
	var cmd string

	cmd = "sshd.config.blocks"
	t.Run(cmd, func(t *testing.T) {
		compileT(t, cmd, func(res *llx.CodeBundle) {
			require.Len(t, res.CodeV2.Blocks, 3)

			require.Len(t, res.CodeV2.Blocks[0].Chunks, 3)
			require.Equal(t, "{}", res.CodeV2.Blocks[0].Chunks[2].Id)

			require.Len(t, res.CodeV2.Blocks[1].Chunks, 4)
			assertFunction(t, "context", &llx.Function{
				Type:    string(types.Resource("file.context")),
				Binding: (2 << 32) | 1,
				Args:    []*llx.Primitive{},
			}, res.CodeV2.Blocks[1].Chunks[2])
			assertFunction(t, "{}", &llx.Function{
				Type:    string(types.Block),
				Binding: (2 << 32) | 3,
				Args:    []*llx.Primitive{llx.FunctionPrimitive(3 << 32)},
			}, res.CodeV2.Blocks[1].Chunks[3])

			require.Len(t, res.CodeV2.Blocks[2].Chunks, 5)
			assertFunction(t, "file", &llx.Function{
				Type:    string(types.Resource("file")),
				Binding: (3 << 32) | 1,
			}, res.CodeV2.Blocks[2].Chunks[1])
			assertFunction(t, "path", &llx.Function{
				Type:    string(types.String),
				Binding: (3 << 32) | 2,
			}, res.CodeV2.Blocks[2].Chunks[2])
			assertFunction(t, "range", &llx.Function{
				Type:    string(types.Range),
				Binding: (3 << 32) | 1,
			}, res.CodeV2.Blocks[2].Chunks[3])
		})
	})

	cmd = "mondoo"
	t.Run(cmd, func(t *testing.T) {
		compileT(t, cmd, func(res *llx.CodeBundle) {
			assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])
			assertFunction(t, "{}", &llx.Function{
				Binding: (1 << 32) | 1,
				Type:    string(types.Block),
				Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
			}, res.CodeV2.Blocks[0].Chunks[1])

			assertFunction(t, "version", &llx.Function{
				Binding: (2 << 32) | 1,
				Type:    string(types.String),
			}, res.CodeV2.Blocks[1].Chunks[1])

			assert.Equal(t, map[string]uint64{res.CodeV2.Checksums[1<<32|2]: 2 << 32}, res.AutoExpand)
			assert.Equal(t, []uint64{1<<32 | 2}, res.CodeV2.Blocks[0].Entrypoints)
		})
	})

	cmd = "users"
	t.Run(cmd, func(t *testing.T) {
		compileT(t, cmd, func(res *llx.CodeBundle) {
			assertFunction(t, "users", nil, res.CodeV2.Blocks[0].Chunks[0])
			assertFunction(t, "list", &llx.Function{
				Binding: (1 << 32) | 1,
				Args:    nil,
				Type:    string(types.Array(types.Resource("user"))),
			}, res.CodeV2.Blocks[0].Chunks[1])
			assertFunction(t, "{}", &llx.Function{
				Binding: (1 << 32) | 2,
				Type:    string(types.Array(types.Block)),
				Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
			}, res.CodeV2.Blocks[0].Chunks[2])

			assertFunction(t, "name", &llx.Function{
				Binding: (2 << 32) | 1,
				Type:    string(types.String),
			}, res.CodeV2.Blocks[1].Chunks[1])
			assertFunction(t, "uid", &llx.Function{
				Binding: (2 << 32) | 1,
				Type:    string(types.Int),
			}, res.CodeV2.Blocks[1].Chunks[2])
			assertFunction(t, "gid", &llx.Function{
				Binding: (2 << 32) | 1,
				Type:    string(types.Int),
			}, res.CodeV2.Blocks[1].Chunks[3])

			assert.Equal(t, map[string]uint64{res.CodeV2.Checksums[1<<32|3]: 2 << 32}, res.AutoExpand)
			assert.Equal(t, []uint64{1<<32 | 3}, res.CodeV2.Blocks[0].Entrypoints)
			assert.Equal(t, []uint64{2<<32 | 2, 2<<32 | 3, 2<<32 | 4}, res.CodeV2.Blocks[1].Entrypoints)
		})
	})

	cmd = "users { group }"
	t.Run(cmd, func(t *testing.T) {
		compileT(t, cmd, func(res *llx.CodeBundle) {
			require.Len(t, res.CodeV2.Blocks, 3)

			assertFunction(t, "{}", &llx.Function{
				Binding: (1 << 32) | 2,
				Type:    string(types.Array(types.Block)),
				Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
			}, res.CodeV2.Blocks[0].Chunks[2])

			assertFunction(t, "group", &llx.Function{
				Binding: (2 << 32) | 1,
				Type:    string(types.Resource("group")),
			}, res.CodeV2.Blocks[1].Chunks[1])
			assertFunction(t, "{}", &llx.Function{
				Binding: (2 << 32) | 2,
				Type:    string(types.Block),
				Args:    []*llx.Primitive{llx.FunctionPrimitive(3 << 32)},
			}, res.CodeV2.Blocks[1].Chunks[2])

			assertFunction(t, "name", &llx.Function{
				Binding: (3 << 32) | 1,
				Type:    string(types.String),
			}, res.CodeV2.Blocks[2].Chunks[1])
			assertFunction(t, "gid", &llx.Function{
				Binding: (3 << 32) | 1,
				Type:    string(types.Int),
			}, res.CodeV2.Blocks[2].Chunks[2])

			assert.Equal(t, map[string]uint64{res.CodeV2.Checksums[2<<32|3]: 3 << 32}, res.AutoExpand)
			assert.Equal(t, []uint64{1<<32 | 3}, res.CodeV2.Blocks[0].Entrypoints)
			assert.Equal(t, []uint64{2<<32 | 3}, res.CodeV2.Blocks[1].Entrypoints)
			assert.Equal(t, []uint64{3<<32 | 2, 3<<32 | 3}, res.CodeV2.Blocks[2].Entrypoints)
		})
	})

	cmd = "pam.conf.entries['.']"
	t.Run(cmd, func(t *testing.T) {
		compileT(t, cmd, func(res *llx.CodeBundle) {
			assertFunction(t, "[]", &llx.Function{
				Binding: (1 << 32) | 2,
				Args: []*llx.Primitive{{
					Type:  string(types.String),
					Value: []byte("."),
				}},
				Type: string(types.Array(types.Resource("pam.conf.serviceEntry"))),
			}, res.CodeV2.Blocks[0].Chunks[2])
			assertFunction(t, "{}", &llx.Function{
				Binding: (1 << 32) | 3,
				Type:    string(types.Array(types.Block)),
				Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
			}, res.CodeV2.Blocks[0].Chunks[3])

			assertFunction(t, "service", &llx.Function{
				Binding: (2 << 32) | 1,
				Type:    string(types.String),
			}, res.CodeV2.Blocks[1].Chunks[1])
		})
	})
}

func TestCompiler_ArrayResource(t *testing.T) {
	var cmd string

	cmd = "packages[123]"
	t.Run(cmd, func(t *testing.T) {
		compileT(t, cmd, func(res *llx.CodeBundle) {
			assertFunction(t, "list", &llx.Function{
				Binding: (1 << 32) | 1,
				Args:    nil,
				Type:    string(types.Array(types.Resource("package"))),
			}, res.CodeV2.Blocks[0].Chunks[1])
			assertFunction(t, "[]", &llx.Function{
				Binding: (1 << 32) | 2,
				Args:    []*llx.Primitive{llx.IntPrimitive(123)},
				Type:    string(types.Resource("package")),
			}, res.CodeV2.Blocks[0].Chunks[2])
		})
	})

	cmd = "packages.length"
	t.Run(cmd, func(t *testing.T) {
		compileT(t, cmd, func(res *llx.CodeBundle) {
			assertFunction(t, "list", &llx.Function{
				Binding: (1 << 32) | 1,
				Args:    nil,
				Type:    string(types.Array(types.Resource("package"))),
			}, res.CodeV2.Blocks[0].Chunks[1])
			assertFunction(t, "length", &llx.Function{
				Binding: (1 << 32) | 1,
				Args:    []*llx.Primitive{llx.RefPrimitiveV2((1 << 32) | 2)},
				Type:    string(types.Int),
			}, res.CodeV2.Blocks[0].Chunks[2])
		})
	})

	compileT(t, "packages.list[123]", func(res *llx.CodeBundle) {
		assertFunction(t, "[]", &llx.Function{
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.IntPrimitive(123)},
			Type:    string(types.Resource("package")),
		}, res.CodeV2.Blocks[0].Chunks[2])
	})

	compileT(t, "packages.list.length", func(res *llx.CodeBundle) {
		assertFunction(t, "list", &llx.Function{
			Binding: (1 << 32) | 1,
			Type:    string(types.Array(types.Resource("package"))),
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "length", &llx.Function{
			Binding: (1 << 32) | 2,
			Type:    string(types.Int),
		}, res.CodeV2.Blocks[0].Chunks[2])
	})
}

func TestCompiler_ResourceFieldGlob(t *testing.T) {
	compileT(t, "mondoo{*}", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "arch", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
	})

	compileT(t, "pam.conf { * }", func(res *llx.CodeBundle) {
		assertFunction(t, "pam.conf", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Block),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("pam.conf")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "content", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assertFunction(t, "entries", &llx.Function{
			Type:    string(types.Map(types.String, types.Array(types.Resource("pam.conf.serviceEntry")))),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[2])
		assertFunction(t, "files", &llx.Function{
			Type:    string(types.Array(types.Resource("file"))),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[3])
		assertFunction(t, "services", &llx.Function{
			Type:    string(types.Map(types.String, types.Array(types.String))),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[4])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Array(types.Block)),
			Binding: (2 << 32) | 4,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(3 << 32)},
		}, res.CodeV2.Blocks[1].Chunks[5])
		assert.Equal(t, []uint64{(2 << 32) | 2, (2 << 32) | 3, (2 << 32) | 6, (2 << 32) | 5},
			res.CodeV2.Blocks[1].Entrypoints)
	})
}

func TestCompiler_ArrayResourceFieldGlob(t *testing.T) {
	compileT(t, "groups { * }", func(res *llx.CodeBundle) {
		assertFunction(t, "groups", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "list", &llx.Function{
			Binding: (1 << 32) | 1,
			Type:    string(types.Array(types.Resource("group"))),
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Array(types.Block)),
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("group")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "gid", &llx.Function{
			Type:    string(types.Int),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assertFunction(t, "members", &llx.Function{
			Type:    string(types.Array(types.Resource("user"))),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[2])
		assertFunction(t, "name", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[3])
		assertFunction(t, "sid", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[4])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Array(types.Block)),
			Binding: (2 << 32) | 3,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(3 << 32)},
		}, res.CodeV2.Blocks[1].Chunks[5])
		assert.Equal(t, []uint64{(2 << 32) | 2, (2 << 32) | 6, (2 << 32) | 4, (2 << 32) | 5},
			res.CodeV2.Blocks[1].Entrypoints)
	})
}

func TestCompiler_ResourceFieldArrayAccessor(t *testing.T) {
	compileT(t, "sshd.config.params[\"Protocol\"]", func(res *llx.CodeBundle) {
		assertFunction(t, "[]", &llx.Function{
			Type:    string(types.String),
			Binding: (1 << 32) | 2,
			Args: []*llx.Primitive{
				llx.StringPrimitive("Protocol"),
			},
		}, res.CodeV2.Blocks[0].Chunks[2])
	})
}

func TestCompiler_ResourceWithUnnamedArgs(t *testing.T) {
	compileT(t, "file(\"/path\")", func(res *llx.CodeBundle) {
		assertFunction(t, "file", &llx.Function{
			Type:    string(types.Resource("file")),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.StringPrimitive("path"),
				llx.StringPrimitive("/path"),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])
	})
}

func TestCompiler_ResourceWithNamedArgs(t *testing.T) {
	compileT(t, "file(path: \"/path\")", func(res *llx.CodeBundle) {
		assertFunction(t, "file", &llx.Function{
			Type:    string(types.Resource("file")),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.StringPrimitive("path"),
				llx.StringPrimitive("/path"),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])
	})
}

func TestCompiler_LongResourceWithUnnamedArgs(t *testing.T) {
	compileT(t, "sshd.config(\"/path\")", func(res *llx.CodeBundle) {
		assertFunction(t, "sshd.config", &llx.Function{
			Type:    string(types.Resource("sshd.config")),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.StringPrimitive("path"),
				llx.StringPrimitive("/path"),
			},
		}, res.CodeV2.Blocks[0].Chunks[0])
	})
}

func TestCompiler_EmbeddedResource(t *testing.T) {
	compileCtx(t, "docker.containers[0].os", func(res *llx.CodeBundle) {
		assertFunction(t, "os", &llx.Function{
			Type:    string(types.Resource("os.linux")),
			Binding: 1<<32 | 3,
		}, res.CodeV2.Blocks[0].Chunks[3])
	})
}

func TestCompiler_EmbeddedResource_Lookup(t *testing.T) {
	compileCtx(t, "docker.containers[0].hostname", func(res *llx.CodeBundle) {
		assertFunction(t, "os", &llx.Function{
			Type:    string(types.Resource("os.linux")),
			Binding: 1<<32 | 3,
		}, res.CodeV2.Blocks[0].Chunks[3])

		assertFunction(t, "unix", &llx.Function{
			Type:    string(types.Resource("os.unix")),
			Binding: 1<<32 | 4,
		}, res.CodeV2.Blocks[0].Chunks[4])

		assertFunction(t, "base", &llx.Function{
			Type:    string(types.Resource("os.base")),
			Binding: 1<<32 | 5,
		}, res.CodeV2.Blocks[0].Chunks[5])

		assertFunction(t, "hostname", &llx.Function{
			Type:    string(types.String),
			Binding: 1<<32 | 6,
		}, res.CodeV2.Blocks[0].Chunks[6])
	})
}

func TestCompiler_EmbeddedResource_ImplicitResource(t *testing.T) {
	compileCtx(t, "docker.containers[0].user(uid: 999).name", func(res *llx.CodeBundle) {
		assertFunction(t, "createResource", &llx.Function{
			Type: string(types.Resource("os.base.user")),
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2(1<<32 | 3),
				llx.StringPrimitive("uid"),
				llx.IntPrimitive(999),
			},
			Binding: 0,
		}, res.CodeV2.Blocks[0].Chunks[3])

		assert.Equal(t, "user", res.Labels.Labels[res.CodeV2.Checksums[1<<32|4]])

		assertFunction(t, "name", &llx.Function{
			Type:    string(types.String),
			Binding: 1<<32 | 4,
		}, res.CodeV2.Blocks[0].Chunks[4])
	})
}

func TestCompiler_EmbeddedResource_ImplicitResource_Block(t *testing.T) {
	compileCtx(t, "docker.containers[0].user(uid: 999) { name }", func(res *llx.CodeBundle) {
		assertFunction(t, "createResource", &llx.Function{
			Type:    string(types.Resource("os.base.user")),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2(1<<32 | 3),
				llx.StringPrimitive("uid"),
				llx.IntPrimitive(999),
			},
		}, res.CodeV2.Blocks[0].Chunks[3])

		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Block),
			Binding: 1<<32 | 4,
			Args: []*llx.Primitive{
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[4])
	})
}

func TestCompiler_EmbeddedResource_ImplicitResource_List(t *testing.T) {
	compileCtx(t, "docker.containers[0].packages", func(res *llx.CodeBundle) {
		assertFunction(t, "createResource", &llx.Function{
			Type:    string(types.Resource("os.base.packages")),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2(1<<32 | 3),
			},
		}, res.CodeV2.Blocks[0].Chunks[3])
	})
}

func TestCompiler_ExpectSimplest(t *testing.T) {
	compileT(t, "expect(true)", func(res *llx.CodeBundle) {
		f := res.CodeV2.Blocks[0].Chunks[0]
		assert.Equal(t, llx.Chunk_FUNCTION, f.Call)
		assert.Equal(t, "expect", f.Id)
		assert.Equal(t, []uint64{(1 << 32) | 1}, res.CodeV2.Entrypoints())
		assert.Equal(t, &llx.Function{
			Type:    string(types.Bool),
			Binding: 0,
			Args:    []*llx.Primitive{llx.BoolPrimitive(true)},
		}, f.Function)
	})
}

func TestCompiler_ExpectEq(t *testing.T) {
	compileT(t, "expect(1 == \"1\")", func(res *llx.CodeBundle) {
		cmp := res.CodeV2.Blocks[0].Chunks[1]
		assert.Equal(t, llx.Chunk_FUNCTION, cmp.Call)
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())
		assert.Equal(t, string("=="+types.String), cmp.Id)
		assert.Equal(t, &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.StringPrimitive("1"),
			},
		}, cmp.Function)

		f := res.CodeV2.Blocks[0].Chunks[2]
		assert.Equal(t, llx.Chunk_FUNCTION, f.Call)
		assert.Equal(t, "expect", f.Id)
		assert.Equal(t, &llx.Function{
			Type:    string(types.Bool),
			Binding: 0,
			Args:    []*llx.Primitive{llx.RefPrimitiveV2((1 << 32) | 2)},
		}, f.Function)
	})
}

func TestCompiler_EmptyBlock(t *testing.T) {
	compileT(t, "parse { }", func(res *llx.CodeBundle) {
		assertFunction(t, "parse", nil, res.CodeV2.Blocks[0].Chunks[0])
		assert.Equal(t, 1, len(res.CodeV2.Blocks[0].Chunks))
		assert.Len(t, res.CodeV2.Blocks, 1)
	})
}

func TestCompiler_Block(t *testing.T) {
	compileT(t, "mondoo { version build }", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Block),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("mondoo")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "version", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assertFunction(t, "build", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[2])
		assert.Equal(t, []uint64{(2 << 32) | 2, (2 << 32) | 3}, res.CodeV2.Blocks[1].Entrypoints)
	})
}

func TestCompiler_BlockWithSelf(t *testing.T) {
	compileT(t, "mondoo { _.version }", func(res *llx.CodeBundle) {
		assertFunction(t, "mondoo", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Block),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[1])
		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("mondoo")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "version", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)
	})

	compileT(t, "sshd.config.params { _['A'] != _['B'] }", func(res *llx.CodeBundle) {
		assertFunction(t, "sshd.config", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "params", &llx.Function{
			Type:    string(types.Map(types.String, types.String)),
			Binding: (1 << 32) | 1,
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Block),
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Map(types.String, types.String)),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "[]", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
			Args:    []*llx.Primitive{llx.StringPrimitive("A")},
		}, res.CodeV2.Blocks[1].Chunks[1])
		assertFunction(t, "[]", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
			Args:    []*llx.Primitive{llx.StringPrimitive("B")},
		}, res.CodeV2.Blocks[1].Chunks[2])
		assertFunction(t, string("!="+types.String), &llx.Function{
			Type:    string(types.Bool),
			Binding: (2 << 32) | 2,
			Args:    []*llx.Primitive{llx.RefPrimitiveV2((2 << 32) | 3)},
		}, res.CodeV2.Blocks[1].Chunks[3])
		assert.Equal(t, []uint64{(2 << 32) | 4}, res.CodeV2.Blocks[1].Entrypoints)
	})

	compileT(t, "\"alice\\nbob\".lines { _ != \"alice\" && _ != \"bob\" }", func(res *llx.CodeBundle) {
		assertPrimitive(t, llx.StringPrimitive("alice\nbob"), res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "lines", &llx.Function{
			Type:    string(types.Array(types.String)),
			Binding: (1 << 32) | 1,
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Array(types.Block)),
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, []uint64{(1 << 32) | 3}, res.CodeV2.Entrypoints())

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.String),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, string("!="+types.String), &llx.Function{
			Type:    string(types.Bool),
			Binding: (2 << 32) | 1,
			Args:    []*llx.Primitive{llx.StringPrimitive("alice")},
		}, res.CodeV2.Blocks[1].Chunks[1])
		assertFunction(t, string("!="+types.String), &llx.Function{
			Type:    string(types.Bool),
			Binding: (2 << 32) | 1,
			Args:    []*llx.Primitive{llx.StringPrimitive("bob")},
		}, res.CodeV2.Blocks[1].Chunks[2])
		assertFunction(t, string("&&"+types.Bool), &llx.Function{
			Type:    string(types.Bool),
			Binding: (2 << 32) | 2,
			Args:    []*llx.Primitive{llx.RefPrimitiveV2((2 << 32) | 3)},
		}, res.CodeV2.Blocks[1].Chunks[3])
		assert.Equal(t, []uint64{(2 << 32) | 4}, res.CodeV2.Blocks[1].Entrypoints)
	})
}

func TestCompiler_ContainsWithResource(t *testing.T) {
	compileT(t, "'hello'.contains(asset.family)", func(res *llx.CodeBundle) {
		assertPrimitive(t, llx.StringPrimitive("hello"), res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "asset", nil, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "family", &llx.Function{
			Type:    string(types.Array(types.String)),
			Binding: (1 << 32) | 2,
		}, res.CodeV2.Blocks[0].Chunks[2])
		assertFunction(t, "contains"+string(types.Array(types.String)), &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.RefPrimitiveV2((1 << 32) | 3)},
		}, res.CodeV2.Blocks[0].Chunks[3])

		assert.Equal(t, []uint64{(1 << 32) | 4}, res.CodeV2.Entrypoints())
	})
}

func TestCompiler_StringContainsWithInt(t *testing.T) {
	compileT(t, "'hello123'.contains(23)", func(res *llx.CodeBundle) {
		assertPrimitive(t, llx.StringPrimitive("hello123"), res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "contains"+string(types.Int), &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 1,
			Args:    []*llx.Primitive{llx.IntPrimitive(23)},
		}, res.CodeV2.Blocks[0].Chunks[1])

		assert.Equal(t, []uint64{(1 << 32) | 2}, res.CodeV2.Entrypoints())
	})
}

func TestCompiler_CallWithResource(t *testing.T) {
	compileT(t, "users { file(home) }", func(res *llx.CodeBundle) {
		assertFunction(t, "users", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "list", &llx.Function{
			Binding: (1 << 32) | 1,
			Type:    string(types.Array(types.Resource("user"))),
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Array(types.Block)),
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, 3, len(res.CodeV2.Blocks[0].Chunks))

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("user")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "home", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assertFunction(t, "file", &llx.Function{
			Type:    string(types.Resource("file")),
			Binding: 0,
			Args: []*llx.Primitive{
				llx.StringPrimitive("path"),
				llx.RefPrimitiveV2((2 << 32) | 2),
			},
		}, res.CodeV2.Blocks[1].Chunks[2])
		assert.EqualValues(t, 1, res.CodeV2.Blocks[1].Parameters)
	})
}

func TestCompiler_List(t *testing.T) {
	compileT(t, "packages { name }", func(res *llx.CodeBundle) {
		assertFunction(t, "packages", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "list", &llx.Function{
			Binding: (1 << 32) | 1,
			Type:    string(types.Array(types.Resource("package"))),
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "{}", &llx.Function{
			Type:    string(types.Array(types.Block)),
			Binding: (1 << 32) | 2,
			Args:    []*llx.Primitive{llx.FunctionPrimitive(2 << 32)},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assert.Equal(t, 3, len(res.CodeV2.Blocks[0].Chunks))

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("package")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "name", &llx.Function{
			Type:    string(types.String),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)
	})
}

func TestCompiler_ResourceEmptyWhere(t *testing.T) {
	compileT(t, "packages.where()", func(res *llx.CodeBundle) {
		assertFunction(t, "packages", nil, res.CodeV2.Blocks[0].Chunks[0])
		assert.Len(t, res.CodeV2.Blocks[0].Chunks, 3)
		assertFunction(t, "packages", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "list", &llx.Function{
			Binding: (1 << 32) | 1,
			Type:    string(types.Array(types.Resource("package"))),
		}, res.CodeV2.Blocks[0].Chunks[1])
	})
}

func TestCompiler_ResourceWhere(t *testing.T) {
	compileT(t, "packages.where(outdated)", func(res *llx.CodeBundle) {
		assertFunction(t, "packages", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "list", &llx.Function{
			Type:    string(types.Array(types.Resource("package"))),
			Binding: (1 << 32) | 1,
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "where", &llx.Function{
			Type:    string(types.Resource("packages")),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 2),
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[2])

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("package")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "outdated", &llx.Function{
			Type:    string(types.Bool),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)
	})
}

func TestCompiler_ResourceContains(t *testing.T) {
	compileT(t, "packages.contains(outdated)", func(res *llx.CodeBundle) {
		assertFunction(t, "packages", nil, res.CodeV2.Blocks[0].Chunks[0])
		assertFunction(t, "list", &llx.Function{
			Type:    string(types.Array(types.Resource("package"))),
			Binding: (1 << 32) | 1,
		}, res.CodeV2.Blocks[0].Chunks[1])
		assertFunction(t, "where", &llx.Function{
			Type:    string(types.Resource("packages")),
			Binding: (1 << 32) | 1,
			Args: []*llx.Primitive{
				llx.RefPrimitiveV2((1 << 32) | 2),
				llx.FunctionPrimitive(2 << 32),
			},
		}, res.CodeV2.Blocks[0].Chunks[2])
		assertFunction(t, "list", &llx.Function{
			Type:    string(types.Array(types.Resource("package"))),
			Binding: (1 << 32) | 3,
		}, res.CodeV2.Blocks[0].Chunks[3])
		assertFunction(t, "length", &llx.Function{
			Type:    string(types.Int),
			Binding: (1 << 32) | 4,
		}, res.CodeV2.Blocks[0].Chunks[4])
		assertFunction(t, string(">"+types.Int), &llx.Function{
			Type:    string(types.Bool),
			Binding: (1 << 32) | 5,
			Args:    []*llx.Primitive{llx.IntPrimitive(0)},
		}, res.CodeV2.Blocks[0].Chunks[5])

		assertPrimitive(t, &llx.Primitive{
			Type: string(types.Resource("package")),
		}, res.CodeV2.Blocks[1].Chunks[0])
		assertFunction(t, "outdated", &llx.Function{
			Type:    string(types.Bool),
			Binding: (2 << 32) | 1,
		}, res.CodeV2.Blocks[1].Chunks[1])
		assert.Equal(t, []uint64{(2 << 32) | 2}, res.CodeV2.Blocks[1].Entrypoints)
	})
}

//    ================
//   👋   INTERNAL   🍹
//    ================

func TestChecksums(t *testing.T) {
	t.Run("no duplicate code IDs", func(t *testing.T) {
		dupes := []struct {
			qa string
			qb string
		}{
			{
				"users.list { uid == 1 }",
				"users.list { uid == 2 }",
			},
			{
				"asset.platform\nasset.version",
				"asset.platform",
			},
			{
				"asset.platform\nasset.version",
				"asset.version",
			},
			{
				"if (true) { 2 }",
				"if (true) { 3 }",
			},
			{
				"mondoo { version == 'a'}",
				"mondoo { version == 'b' version == 'a'}",
			},
		}

		for i := range dupes {
			t.Run(dupes[i].qa+" != "+dupes[i].qb, func(t *testing.T) {
				a, err := mqlc.Compile(dupes[i].qa, nil, conf)
				assert.NoError(t, err)
				b, err := mqlc.Compile(dupes[i].qb, nil, conf)
				assert.NoError(t, err)
				assert.NotEqual(t, a.CodeV2.Id, b.CodeV2.Id)
			})
		}
	})
}

func TestChecksums_block(t *testing.T) {
	a, err := mqlc.Compile("mondoo { version == 'a'}", nil, conf)
	assert.NoError(t, err)
	b, err := mqlc.Compile("mondoo { version == 'b' version == 'a'}", nil, conf)
	assert.NoError(t, err)
	// make sure the checksum for the block calls are different
	assert.NotEqual(t, a.CodeV2.Checksums[4294967298], b.CodeV2.Checksums[4294967298])
}

func TestSuggestions(t *testing.T) {
	tests := []struct {
		code             string
		suggestions      []string
		err              error
		requiredFeatures mql.Features
	}{
		{
			"does_not_get_suggestions",
			[]string{},
			errors.New("cannot find resource for identifier 'does_not_get_suggestions'"),
			nil,
		},
		{
			// resource suggestions
			"ssh",
			[]string{"os.unix.sshd", "sshd", "sshd.config", "windows.security.health"},
			errors.New("cannot find resource for identifier 'ssh'"),
			nil,
		},
		{
			// resource with empty field call
			"sshd.",
			[]string{"config"},
			errors.New("incomplete query, missing identifier after '.' at <source>:1:6"),
			nil,
		},
		{
			// list resource with empty field call
			"users.",
			[]string{"all", "any", "contains", "first", "having", "last", "length", "list", "map", "none", "one", "sample", "where"},
			errors.New("incomplete query, missing identifier after '.' at <source>:1:7"),
			nil,
		},
		{
			// resource with partial field call
			"sshd.config.para",
			[]string{"params"},
			errors.New("cannot find field 'para' in sshd.config"),
			nil,
		},
		{
			// resource with partial field call in block
			"sshd.config { para }",
			[]string{"params"},
			errors.New("cannot find field or resource 'para' in block for type 'sshd.config'"),
			nil,
		},
		{
			// native type function call
			"sshd.config.ciphers.leng",
			[]string{"length"},
			errors.New("cannot find field 'leng' in []string"),
			nil,
		},
		{
			// builtin calls
			"parse.d",
			[]string{"date", "duration"},
			errors.New("cannot find field 'd' in parse"),
			nil,
		},
		{
			// embedded with asset context on
			"docker.containers[0].hostnam",
			[]string{"hostname"},
			errors.New("cannot find field 'hostnam' in docker.container"),
			mql.Features{byte(mql.MQLAssetContext)},
		},
		{
			// embedded with asset context off
			"docker.containers[0].hostnam",
			[]string{},
			errors.New("cannot find field 'hostnam' in docker.container"),
			nil,
		},
	}

	for i := range tests {
		cur := tests[i]
		t.Run(cur.code, func(t *testing.T) {
			nuConf := mqlc.NewConfig(conf.Schema,
				append(features, cur.requiredFeatures...))
			res, err := mqlc.Compile(cur.code, nil, nuConf)
			assert.Empty(t, res.CodeV2.Entrypoints())
			assert.Equal(t, cur.err.Error(), err.Error())

			suggestions := make([]string, len(res.Suggestions))
			for i := range res.Suggestions {
				suggestions[i] = res.Suggestions[i].Field
			}
			sort.Strings(suggestions)
			assert.Equal(t, cur.suggestions, suggestions)
		})
	}
}

func TestImplicitSuggestion(t *testing.T) {
	res, _ := mqlc.Compile("sshd.", nil, conf)
	require.NotEmpty(t, res.Suggestions)

	assert.Equal(t, "SSH server configuration", res.Suggestions[0].Title)
}

func TestCompiler_Error(t *testing.T) {
	t.Run("unknown term", func(t *testing.T) {
		_, err := mqlc.Compile("sshd.config.params == enabled", nil, conf)
		// assert.Nil(t, res)
		assert.EqualError(t, err, "failed to compile: cannot find resource for identifier 'enabled'")
	})
}

func TestCompiler_Multiline(t *testing.T) {
	compileT(t, "1 < 2\n2 != 3", func(res *llx.CodeBundle) {
		assert.Equal(t, 4, len(res.CodeV2.Blocks[0].Chunks))
	})
}

func TestCompiler_Entrypoints(t *testing.T) {
	tests := []struct {
		code        string
		datapoints  []uint64
		entrypoints []uint64
	}{
		{
			"1",
			[]uint64(nil),
			[]uint64{(1 << 32) | 1},
		},
		{
			"mondoo.version == 1",
			[]uint64{(1 << 32) | 2},
			[]uint64{(1 << 32) | 3},
		},
		{
			"mondoo.version == mondoo.build",
			[]uint64{(1 << 32) | 2, (1 << 32) | 4},
			[]uint64{(1 << 32) | 5},
		},
		{
			`
				a = "a"
				b = "b"
				a == "a"
				b == "b"
				c = "c"
				c == "c"
			`,
			[]uint64{(1 << 32) | 3, (1 << 32) | 5, (1 << 32) | 8},
			[]uint64{(1 << 32) | 4, (1 << 32) | 6, (1 << 32) | 9},
		},
		{
			`
				a = "a"
				b = "b"
				a == "a"
				b == "b"
				c = a == b
				c == false
			`,
			[]uint64{(1 << 32) | 3, (1 << 32) | 5, (1 << 32) | 10},
			[]uint64{(1 << 32) | 4, (1 << 32) | 6, (1 << 32) | 11},
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.code, func(t *testing.T) {
			compileT(t, test.code, func(res *llx.CodeBundle) {
				assert.ElementsMatch(t, test.entrypoints, res.CodeV2.Entrypoints())
				assert.Equal(t, test.datapoints, res.CodeV2.Datapoints())
			})
		})
	}
}

func TestCompiler_NestedEntrypoints(t *testing.T) {
	tests := []struct {
		code        string
		datapoints  []uint64
		entrypoints []uint64
	}{
		{
			`
				if(true) {
					a = "a"
					b = "b"
					a == b
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 1, (2 << 32) | 5},
		},
		{
			`
				if(true) {
					a = "a"
					b = "b"
					a == b
				} else {
					x = "x"
					y = "y"
					x == y
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 1, (2 << 32) | 5, (3 << 32) | 5},
		},
		{
			`
			  z = "z"
				if(z == "z") {
					a = "a"
					b = "b"
					a == b
				} else if (z == "a") {
					x = "x"
					y = "y"
					x == y
				} else {
					j = "j"
					k = "k"
					j == k
				}
			`,
			[]uint64{(1 << 32) | 2},
			[]uint64{(1 << 32) | 6, (2 << 32) | 5, (3 << 32) | 5, (4 << 32) | 5},
		},
		{
			`
				switch {
				case "a" == "a":
					a = "a"
					b = "b"
					a == b;
				case "b" == "b":
					x = "x"
					y = "y"
					x == y
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 5, (2 << 32) | 5, (3 << 32) | 5},
		},
		{
			`
				mondoo {
					a = "a"
					b = "b"
					a == b
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 2, (2 << 32) | 6},
		},
		{
			`
				{a: "a"} {
					x = "x"
					y = "y"
					x == y
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 2, (2 << 32) | 6},
		},
		{
			`
				[1,2,3] {
					x = "x"
					y = "y"
					x == y
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 2, (2 << 32) | 6},
		},
		{
			`
				mondoo {
					_
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 2, (2 << 32) | 1},
		},
		{
			`
				mondoo {
					a = true
					a
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 2, (2 << 32) | 3},
		},
		{
			`
				if(true) {
					a = true
					a
				}
			`,
			[]uint64{},
			[]uint64{(1 << 32) | 1, (2 << 32) | 2},
		},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.code, func(t *testing.T) {
			compileT(t, test.code, func(res *llx.CodeBundle) {
				entrypoints, datapoints := allCodepoints(res.CodeV2)
				assert.ElementsMatch(t, test.entrypoints, entrypoints)
				assert.ElementsMatch(t, test.datapoints, datapoints)
			})
		})
	}
}

func allCodepoints(code *llx.CodeV2) ([]uint64, []uint64) {
	entrypoints := []uint64{}
	datapoints := []uint64{}

	for _, b := range code.Blocks {
		entrypoints = append(entrypoints, b.Entrypoints...)
		datapoints = append(datapoints, b.Datapoints...)
	}
	return entrypoints, datapoints
}
