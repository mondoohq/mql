// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/logger"
)

func init() {
	logger.InitTestEnv()
}

func TestParser_Lex(t *testing.T) {
	tests := []struct {
		typ rune
		str string
	}{
		{Ident, "name"},
		{Float, "1.23"},
		{Int, "123"},
		{String, "'hi'"},
		{String, "\"hi\""},
		{Regex, "/regex/"},
		{Op, "+"},
	}
	for i := range tests {
		res, err := Lex(tests[i].str)
		assert.Nil(t, err)
		assert.Equal(t, tests[i].typ, res[0].Type)
	}
}

func sPtr(s string) *string {
	return &s
}

func vBool(b bool) *Value {
	return &Value{Bool: &b}
}

func vIdent(v string) *Value {
	return &Value{Ident: &v}
}

func vFloat(v float64) *Value {
	return &Value{Float: &v}
}

func vInt(v int64) *Value {
	return &Value{Int: &v}
}

func vString(v string) *Value {
	return &Value{String: &v}
}

func vRegex(v string) *Value {
	return &Value{Regex: &v}
}

func vMap(v map[string]*Expression) *Value {
	return &Value{Map: v}
}

func callIdent(ident string) *Call {
	return &Call{Ident: &ident}
}

func callConditionalIdent(ident string) *Call {
	return &Call{Ident: &ident, IsConditional: true}
}

type parserTest struct {
	code string
	res  *Expression
}

func runParserTests(t *testing.T, tests []parserTest) {
	for i := range tests {
		test := tests[i]

		t.Run(test.code, func(t *testing.T) {
			res, err := Parse(test.code)
			require.NoError(t, err, "parsing should not generate an error")
			require.NotNil(t, res, "parsing must generate a result value")
			require.NotEmpty(t, res.Expressions, "parsing must generate one expression")

			assert.Equal(t, test.res, res.Expressions[0])
		})
	}
}

type multiTest struct {
	code string
	res  []*Expression
}

func runMultiTest(t *testing.T, tests []multiTest) {
	for i := range tests {
		test := tests[i]

		t.Run(test.code, func(t *testing.T) {
			res, err := Parse(test.code)
			require.NoError(t, err, "parsing should not generate an error")
			require.NotNil(t, res, "parsing must generate a result value")
			assert.Equal(t, test.res, res.Expressions, "resulting expressions must match")
		})
	}
}

func TestParser_ParseValues(t *testing.T) {
	runParserTests(t, []parserTest{
		{"null", &Expression{Operand: &Operand{Value: &nilValue}}},
		{"NaN", &Expression{Operand: &Operand{Value: &nanValue}}},
		{"Infinity", &Expression{Operand: &Operand{Value: &infinityValue}}},
		{"Never", &Expression{Operand: &Operand{Value: &neverValue}}},
		{"true", &Expression{Operand: &Operand{Value: vBool(true)}}},
		{"false", &Expression{Operand: &Operand{Value: vBool(false)}}},
		{"name", &Expression{Operand: &Operand{Value: vIdent("name")}}},
		{"1.23", &Expression{Operand: &Operand{Value: vFloat(1.23)}}},
		{"123", &Expression{Operand: &Operand{Value: vInt(123)}}},
		{"'hi'", &Expression{Operand: &Operand{Value: vString("hi")}}},
		{"'h\\ni'", &Expression{Operand: &Operand{Value: vString("h\\ni")}}},
		{"'h\\i'", &Expression{Operand: &Operand{Value: vString("h\\i")}}},
		{"\"hi\"", &Expression{Operand: &Operand{Value: vString("hi")}}},
		{"\"h\\ni\"", &Expression{Operand: &Operand{Value: vString("h\ni")}}},
		{"\"h\\\\i\"", &Expression{Operand: &Operand{Value: vString("h\\i")}}},
		{"/hi/", &Expression{Operand: &Operand{Value: vRegex("hi")}}},
		{"[]", &Expression{Operand: &Operand{Value: &Value{Array: []*Expression{}}}}},
		{"[1]", &Expression{Operand: &Operand{Value: &Value{Array: []*Expression{
			{Operand: &Operand{Value: vInt(1)}},
		}}}}},
		{"[1,2.3]", &Expression{Operand: &Operand{Value: &Value{Array: []*Expression{
			{Operand: &Operand{Value: vInt(1)}},
			{Operand: &Operand{Value: vFloat(2.3)}},
		}}}}},
		{"[1,2,]", &Expression{Operand: &Operand{Value: &Value{Array: []*Expression{
			{Operand: &Operand{Value: vInt(1)}},
			{Operand: &Operand{Value: vInt(2)}},
		}}}}},
		{"{}", &Expression{Operand: &Operand{Value: vMap(map[string]*Expression{})}}},
		{"{'a': 'word'}", &Expression{Operand: &Operand{Value: vMap(map[string]*Expression{
			"a": {Operand: &Operand{Value: vString("word")}},
		})}}},
		{"{\"b\": \"there\"}", &Expression{Operand: &Operand{Value: vMap(map[string]*Expression{
			"b": {Operand: &Operand{Value: vString("there")}},
		})}}},
		{"{c: 123}", &Expression{Operand: &Operand{Value: vMap(map[string]*Expression{
			"c": {Operand: &Operand{Value: vInt(123)}},
		})}}},
		{"{a: 1, b: 2,}", &Expression{Operand: &Operand{Value: vMap(map[string]*Expression{
			"a": {Operand: &Operand{Value: vInt(1)}},
			"b": {Operand: &Operand{Value: vInt(2)}},
		})}}},
		{"name.last", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{callIdent("last")},
		}}},
		// the `?` guards `name`, the link to its left; see TestParser_OptionalChaining
		{"name?.last", &Expression{Operand: &Operand{
			Value:              vIdent("name"),
			ValueIsConditional: true,
			Calls:              []*Call{callIdent("last")},
		}}},
		{"name[1]", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Accessor: &Expression{Operand: &Operand{Value: vInt(1)}}}},
		}}},
		{"name()", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{}}},
		}}},
		{"name(1)", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{
				{Value: &Expression{Operand: &Operand{Value: vInt(1)}}},
			}}},
		}}},
		{"name(arg)", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{
				{Value: &Expression{Operand: &Operand{Value: vIdent("arg")}}},
			}}},
		}}},
		{"name(uid: 1)", &Expression{Operand: &Operand{
			Value: vIdent("name"),
			Calls: []*Call{{Function: []*Arg{
				{Name: "uid", Value: &Expression{Operand: &Operand{Value: vInt(1)}}},
			}}},
		}}},
		{"a(b(c,d))", &Expression{Operand: &Operand{
			Value: vIdent("a"),
			Calls: []*Call{{Function: []*Arg{
				{Value: &Expression{Operand: &Operand{
					Value: vIdent("b"),
					Calls: []*Call{{Function: []*Arg{
						{Value: &Expression{Operand: &Operand{Value: vIdent("c")}}},
						{Value: &Expression{Operand: &Operand{Value: vIdent("d")}}},
					}}},
				}}},
			}}},
		}}},
		{"a(\nb(\nc,\nd\n)\n)", &Expression{Operand: &Operand{
			Value: vIdent("a"),
			Calls: []*Call{{Function: []*Arg{
				{Value: &Expression{Operand: &Operand{
					Value: vIdent("b"),
					Calls: []*Call{{Function: []*Arg{
						{Value: &Expression{Operand: &Operand{Value: vIdent("c")}}},
						{Value: &Expression{Operand: &Operand{Value: vIdent("d")}}},
					}}},
				}}},
			}}},
		}}},
		{"user { name uid }", &Expression{Operand: &Operand{
			Value: vIdent("user"),
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("name")}},
				{Operand: &Operand{Value: vIdent("uid")}},
			},
		}}},
		{"user {\n  name\n  uid\n}", &Expression{Operand: &Operand{
			Value: vIdent("user"),
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("name")}},
				{Operand: &Operand{Value: vIdent("uid")}},
			},
		}}},
		{"users.list { uid }", &Expression{Operand: &Operand{
			Value: vIdent("users"),
			Calls: []*Call{callIdent("list")},
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("uid")}},
			},
		}}},
		{"users.where()", &Expression{Operand: &Operand{
			Value: vIdent("users"),
			Calls: []*Call{
				callIdent("where"),
				{Function: []*Arg{}},
			},
		}}},
		{"users.where(uid > 2).list { uid }", &Expression{Operand: &Operand{
			Value: vIdent("users"),
			Calls: []*Call{
				callIdent("where"),
				{Function: []*Arg{{Value: &Expression{
					Operand: &Operand{Value: vIdent("uid")},
					Operations: []*Operation{{
						Operator: OpGreater,
						Operand:  &Operand{Value: vInt(2)},
					}},
				}}}},
				callIdent("list"),
			},
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("uid")}},
			},
		}}},
		{"users.where(uid != empty)", &Expression{Operand: &Operand{
			Value: vIdent("users"),
			Calls: []*Call{
				callIdent("where"),
				{Function: []*Arg{{Value: &Expression{
					Operand: &Operand{Value: vIdent("uid")},
					Operations: []*Operation{{
						Operator: OpNotEqual,
						Operand:  &Operand{Value: vIdent("empty")},
					}},
				}}}},
			},
		}}},
		{"1 + 2 == 3", &Expression{
			Operand: &Operand{Value: vInt(1)},
			Operations: []*Operation{
				{Operator: OpAdd, Operand: &Operand{Value: vInt(2)}},
				{Operator: OpEqual, Operand: &Operand{Value: vInt(3)}},
			},
		}},
		{"1 && 2 || 3", &Expression{
			Operand: &Operand{Value: vInt(1)},
			Operations: []*Operation{
				{Operator: OpAnd, Operand: &Operand{Value: vInt(2)}},
				{Operator: OpOr, Operand: &Operand{Value: vInt(3)}},
			},
		}},
		{"true + 'some'.length()", &Expression{
			Operand: &Operand{Value: vBool(true)},
			Operations: []*Operation{
				{Operator: OpAdd, Operand: &Operand{
					Value: vString("some"),
					Calls: []*Call{callIdent("length"), {Function: []*Arg{}}},
				}},
			},
		}},
		{"// this // is a comment\n'hi'", &Expression{Operand: &Operand{
			Value:    vString("hi"),
			Comments: "this // is a comment\n",
		}}},
		{"# this # is a comment\n'hi'", &Expression{Operand: &Operand{
			Value:    vString("hi"),
			Comments: "this # is a comment\n",
		}}},
	})
}

func TestParser_Comments(t *testing.T) {
	runMultiTest(t, []multiTest{
		// empty comments
		{"#", []*Expression(nil)},
		{"//", []*Expression(nil)},
		// call chain with many newlines
		{"// 1\nsshd\n// 2\n\t.\n// 3\nconfig // 4", []*Expression{
			{Operand: &Operand{
				Comments: "1\n",
				Value:    vIdent("sshd"),
				Calls: []*Call{
					{
						Comments: "2\n3\n",
						Ident:    sPtr("config"),
					},
				},
			}},
			{Operand: &Operand{Comments: "4"}},
		}},
		// blocks and newlines
		{"file\n// 1\n{\n// 2\npath\n// 3\n==\n// 4\n'abc'\n// 5\n}\n// 6", []*Expression{
			{Operand: &Operand{
				Value: vIdent("file"),
				Block: []*Expression{
					{
						Operand: &Operand{
							Comments: "1\n2\n",
							Value:    vIdent("path"),
						},
						Operations: []*Operation{{
							Operator: 103,
							Operand: &Operand{
								Comments: "3\n4\n",
								Value:    vString("abc"),
							},
						}},
					},
					{
						Operand: &Operand{Comments: "5\n"},
					},
				},
			}},
			{Operand: &Operand{Comments: "6"}},
		}},
	})
}

func TestParser_Multiline(t *testing.T) {
	runMultiTest(t, []multiTest{
		{"true\n1\n2\n", []*Expression{
			{Operand: &Operand{Value: vBool(true)}},
			{Operand: &Operand{Value: vInt(1)}},
			{Operand: &Operand{Value: vInt(2)}},
		}},
	})
}

// TestParser_OptionalChaining pins every position a `?` can occupy. The mark
// always attaches to the link on its left - the last call, or the root value if
// there is no call yet - so `?.b`, `?["k"]`, `? { … }` and a trailing `b?` all
// go through one rule.
func TestParser_OptionalChaining(t *testing.T) {
	runParserTests(t, []parserTest{
		// The mark guards `a`, the link to its left, not `b`.
		{"a?.b", &Expression{Operand: &Operand{
			Value:              vIdent("a"),
			ValueIsConditional: true,
			Calls:              []*Call{callIdent("b")},
		}}},
		// `?` is not sticky: only the marked link is optional, so a null `b` in
		// `a?.b.c` still errors in strict mode (as it does in JavaScript).
		{"a?.b.c", &Expression{Operand: &Operand{
			Value:              vIdent("a"),
			ValueIsConditional: true,
			Calls:              []*Call{callIdent("b"), callIdent("c")},
		}}},
		{"a?.b?.c", &Expression{Operand: &Operand{
			Value:              vIdent("a"),
			ValueIsConditional: true,
			Calls:              []*Call{callConditionalIdent("b"), callIdent("c")},
		}}},
		{"a.b?.c", &Expression{Operand: &Operand{
			Value: vIdent("a"),
			Calls: []*Call{callConditionalIdent("b"), callIdent("c")},
		}}},

		// bracket accessors
		{"a?['k']", &Expression{Operand: &Operand{
			Value:              vIdent("a"),
			ValueIsConditional: true,
			Calls: []*Call{{
				Accessor: &Expression{Operand: &Operand{Value: vString("k")}},
			}},
		}}},
		{"a['k']?.c", &Expression{Operand: &Operand{
			Value: vIdent("a"),
			Calls: []*Call{
				{
					Accessor:      &Expression{Operand: &Operand{Value: vString("k")}},
					IsConditional: true,
				},
				callIdent("c"),
			},
		}}},

		// blocks
		{"a? { b }", &Expression{Operand: &Operand{
			Value:              vIdent("a"),
			ValueIsConditional: true,
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("b")}},
			},
		}}},
		{"a { b }", &Expression{Operand: &Operand{
			Value: vIdent("a"),
			Block: []*Expression{
				{Operand: &Operand{Value: vIdent("b")}},
			},
		}}},

		// trailing `?`, the only way to mark a terminal lookup optional
		{"a.b?", &Expression{Operand: &Operand{
			Value: vIdent("a"),
			Calls: []*Call{callConditionalIdent("b")},
		}}},
		{"a?", &Expression{Operand: &Operand{
			Value:              vIdent("a"),
			ValueIsConditional: true,
		}}},
	})
}

// TestParser_OptionalChaining_trailingWithOperator is separate because the
// expression carries an operation, which runParserTests' single-operand shape
// cannot express. A trailing `?` used to be swallowed silently here.
func TestParser_OptionalChaining_trailingWithOperator(t *testing.T) {
	res, err := Parse(`a.b? == "no"`)
	require.NoError(t, err)
	require.Len(t, res.Expressions, 1)

	op := res.Expressions[0].Operand
	require.NotNil(t, op)
	require.Len(t, op.Calls, 1)
	assert.True(t, op.Calls[0].IsConditional, "trailing `?` must survive an operator following it")
	require.Len(t, res.Expressions[0].Operations, 1)
	assert.Equal(t, OpEqual, res.Expressions[0].Operations[0].Operator)
}

// TestParser_StringEscapes pins the escape handling of string literals. Before
// the lexer learned about escape pairs, `"[^"]*"` ended the literal at the
// backslash in `\"`, so `"a\"b"` lexed as the string `a\` followed by the
// identifier `b` and an unterminated quote. The failure surfaced far from its
// cause ("cannot find resource for identifier 'b'", or a truncated string with
// no error at all), so every case below is asserted by value.
func TestParser_StringEscapes(t *testing.T) {
	tests := []struct {
		code string
		res  string
	}{
		// the bug: a double quote inside a double-quoted string
		{`"a\"b"`, `a"b`},
		{`"\""`, `"`},
		{`"he said \"hi\""`, `he said "hi"`},
		// both quote styles in one literal, previously unrepresentable
		{`"he said \"hi\" to 'me'"`, `he said "hi" to 'me'`},
		// inline JSON, the shape that found this
		{`"{\"a\": 1}"`, `{"a": 1}`},

		// escapes that already worked and must keep their values
		{`"a\nb"`, "a\nb"},
		{`"a\tb"`, "a\tb"},
		{`"a\\b"`, `a\b`},
		{`"\\"`, `\`},
		{`"tab\there"`, "tab\there"},
		{`"a\rb"`, "a\rb"},
		{`"a\vb"`, "a\vb"},
		{`"a\bb"`, "a\bb"},
		{`"a\fb"`, "a\fb"},
		{`"a\0b"`, "a\x00b"},
		// a quote of the other style may be escaped or not
		{`"a\'b"`, `a'b`},
		{`"a'b"`, `a'b`},
		// JSON escapes the forward slash, so we accept it
		{`"a\/b"`, `a/b`},
		{`""`, ``},

		// single-quoted strings are raw, backslash included, so a Windows or
		// registry path survives verbatim even when it ends in a separator
		{`'h\ni'`, `h\ni`},
		{`'h\i'`, `h\i`},
		{`'a\\b'`, `a\\b`},
		{`'HKEY\Providers\'`, `HKEY\Providers\`},
		{`'C:\path\'`, `C:\path\`},
		{`''`, ``},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.code, func(t *testing.T) {
			res, err := Parse(test.code)
			require.NoError(t, err)
			require.Len(t, res.Expressions, 1, "the literal must consume the whole source")

			op := res.Expressions[0].Operand
			require.NotNil(t, op)
			require.Empty(t, op.Calls, "a bare literal must not pick up trailing calls")
			require.NotNil(t, op.Value.String, "must parse as a string, not another value type")
			assert.Equal(t, test.res, *op.Value.String)
		})
	}
}

// TestParser_StringEscapes_invalid rejects a double-quoted literal carrying an
// escape sequence we do not define. It used to collapse to its second character,
// so `"C:\Users\dom"` silently became `C:Usersdom` and `"\d+"` became `d+`: a
// wrong value with no error anywhere. Single-quoted strings are raw and keep
// taking any backslash.
func TestParser_StringEscapes_invalid(t *testing.T) {
	for _, code := range []string{`"C:\Users"`, `"\d+"`, `"a\qb"`, `"\x41"`, `"\u00e9"`, `{"a\zb": 1}`} {
		t.Run(code, func(t *testing.T) {
			_, err := Parse(code)
			require.Error(t, err, "an invalid escape sequence must not parse")
			assert.Contains(t, err.Error(), "invalid escape sequence")
		})
	}
}

// TestParser_StringEscapes_unterminated rejects a double-quoted literal whose
// closing quote is consumed by a trailing backslash. `"a\"` used to lex as the
// string `a\`; now the backslash escapes the closing quote and the literal is
// unterminated, which is a deliberate tightening. Single-quoted literals are
// raw, so `'a\'` still closes and keeps its backslash.
func TestParser_StringEscapes_unterminated(t *testing.T) {
	for _, code := range []string{`"a\"`, `"\"`} {
		t.Run(code, func(t *testing.T) {
			_, err := Parse(code)
			assert.Error(t, err, "an unterminated string literal must not parse")
		})
	}
}

// TestParser_LexStringEscapes checks that an escaped quote stays inside one
// String token instead of splitting the source into three.
func TestParser_LexStringEscapes(t *testing.T) {
	for _, code := range []string{`"a\"b"`, `"a\\"`} {
		t.Run(code, func(t *testing.T) {
			res, err := Lex(code)
			require.NoError(t, err)
			require.Len(t, res, 1, "the whole literal must be a single token")
			assert.Equal(t, String, res[0].Type)
			assert.Equal(t, code, res[0].Value)
		})
	}
}
