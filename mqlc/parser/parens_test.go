// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package parser

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// callOp builds the operand a folded binary operator produces, e.g. `+(1,2)`
// for `1 + 2`. A group hands back exactly this shape, which is why a group that
// wraps one is indistinguishable from the expression written without it.
func callOp(op Operator, l *Operand, r *Operand) *Operand {
	name := op.String()
	return &Operand{
		Value: &Value{Ident: &name},
		Calls: []*Call{{Function: []*Arg{
			{Value: &Expression{Operand: l}},
			{Value: &Expression{Operand: r}},
		}}},
	}
}

func opnd(v *Value, calls ...*Call) *Operand {
	res := &Operand{Value: v}
	if len(calls) != 0 {
		res.Calls = calls
	}
	return res
}

// parse and fold, which is what the compiler sees.
func parseFolded(t *testing.T, code string) []*Expression {
	t.Helper()
	res, err := Parse(code)
	require.NoError(t, err)
	require.NotNil(t, res)
	for i := range res.Expressions {
		require.NoError(t, res.Expressions[i].ProcessOperators())
	}
	return res.Expressions
}

// chain appends further calls to an operand, for the cases where the chain
// continues off a group.
func chain(o *Operand, calls ...*Call) *Operand {
	res := *o
	res.Calls = append(append([]*Call{}, o.Calls...), calls...)
	return &res
}

// TestParser_Parens pins the tree a group reduces to. Every case names the
// unparenthesized query it has to be identical to, because that identity is the
// whole feature: redundant parens have to cost nothing downstream.
func TestParser_Parens(t *testing.T) {
	tests := []struct {
		code string
		res  *Operand
	}{
		// a group around a plain value is the value
		{"(1)", opnd(vInt(1))},
		{"(a)", opnd(vIdent("a"))},
		{"(((a)))", opnd(vIdent("a"))},
		{"('hi')", opnd(vString("hi"))},

		// a group around an access chain splices into it
		{"(a.b).c", opnd(vIdent("a"), callIdent("b"), callIdent("c"))},
		{"(a.b.c)", opnd(vIdent("a"), callIdent("b"), callIdent("c"))},

		// the group forces the multiplication to take the sum as one side
		{"1 * (2 + 3)", callOp(OpMultiply, opnd(vInt(1)), callOp(OpAdd, opnd(vInt(2)), opnd(vInt(3))))},
		// ... and every extra layer around it collapses
		{"1*(((2+3)))", callOp(OpMultiply, opnd(vInt(1)), callOp(OpAdd, opnd(vInt(2)), opnd(vInt(3))))},
		{"(1) * ((2 + 3))", callOp(OpMultiply, opnd(vInt(1)), callOp(OpAdd, opnd(vInt(2)), opnd(vInt(3))))},

		// a group that agrees with precedence leaves no trace
		{"1 + (2 * 3)", callOp(OpAdd, opnd(vInt(1)), callOp(OpMultiply, opnd(vInt(2)), opnd(vInt(3))))},
		// ... and one that overrides it does
		{"(1 + 2) * 3", callOp(OpMultiply, callOp(OpAdd, opnd(vInt(1)), opnd(vInt(2))), opnd(vInt(3)))},

		// left-associativity is what `(1-2)-3` already meant
		{"(1 - 2) - 3", callOp(OpSubtract, callOp(OpSubtract, opnd(vInt(1)), opnd(vInt(2))), opnd(vInt(3)))},
		// and this is the grouping it does not mean
		{"1 - (2 - 3)", callOp(OpSubtract, opnd(vInt(1)), callOp(OpSubtract, opnd(vInt(2)), opnd(vInt(3))))},

		// a group is an operand, so the chain continues off it
		{"(1 + 2).inRange", chain(callOp(OpAdd, opnd(vInt(1)), opnd(vInt(2))), callIdent("inRange"))},
	}

	for i := range tests {
		test := tests[i]
		t.Run(test.code, func(t *testing.T) {
			exps := parseFolded(t, test.code)
			require.Len(t, exps, 1)
			assert.Equal(t, &Expression{Operand: test.res}, exps[0])
		})
	}
}

// TestParser_ParensAreEquivalent states the same requirement structurally: any
// two spellings in a group must parse to the identical tree, which is what makes
// their checksums identical once compiled.
func TestParser_ParensAreEquivalent(t *testing.T) {
	groups := [][]string{
		{"1*(2+3)", "1 * (2 + 3)", "1*(((2+3)))", "(1)*((2+3))", "((1*(2+3)))"},
		{"1+2*3", "1 + (2 * 3)", "(1 + (2 * 3))", "1+((2)*(3))"},
		{"a.b.c", "(a.b).c", "((a).b).c", "(a.b.c)"},
		{"users.where(name == 'x')", "users.where((name) == ('x'))", "(users).where(name == 'x')"},
		{"1 - 2 - 3", "(1-2)-3", "((1)-(2))-(3)"},
	}

	for _, group := range groups {
		t.Run(group[0], func(t *testing.T) {
			want := parseFolded(t, group[0])
			for _, code := range group[1:] {
				assert.Equal(t, want, parseFolded(t, code), "%q must parse like %q", code, group[0])
			}
		})
	}
}

// TestParser_ParensChangeMeaning guards the other direction: a group that moves
// the grouping has to produce a different tree, or it is not doing anything.
func TestParser_ParensChangeMeaning(t *testing.T) {
	pairs := [][2]string{
		{"1 + 2 * 3", "(1 + 2) * 3"},
		{"1 - 2 - 3", "1 - (2 - 3)"},
		{"a || b && c", "(a || b) && c"},
		{"a == b < c", "(a == b) < c"},
	}

	for _, pair := range pairs {
		t.Run(pair[0]+" vs "+pair[1], func(t *testing.T) {
			assert.NotEqual(t, parseFolded(t, pair[0]), parseFolded(t, pair[1]))
		})
	}
}

// TestParser_ParensErrors covers what a group must refuse. An unterminated one
// is ErrIncomplete, not a plain error, because the shell uses that to decide
// whether to keep prompting for the rest of the query.
func TestParser_ParensErrors(t *testing.T) {
	t.Run("empty group", func(t *testing.T) {
		_, err := Parse("()")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "missing expression inside of `()`")
	})

	t.Run("comma inside a group", func(t *testing.T) {
		_, err := Parse("(1, 2)")
		require.Error(t, err)
		var incorrect *ErrIncorrect
		require.ErrorAs(t, err, &incorrect)
		assert.Contains(t, err.Error(), "expected closing ')', got ','")
	})

	t.Run("wrong closing symbol", func(t *testing.T) {
		_, err := Parse("(1 + 2]")
		require.Error(t, err)
		var incorrect *ErrIncorrect
		assert.ErrorAs(t, err, &incorrect)
	})

	t.Run("unterminated group", func(t *testing.T) {
		_, err := Parse("1 * (2 + 3")
		require.Error(t, err)
		var incomplete *ErrIncomplete
		require.ErrorAs(t, err, &incomplete)
		assert.Contains(t, err.Error(), "missing closing ')'")
	})
}

// TestParser_ParensNewline pins the rule that tells a call apart from a group.
// MQL has no statement terminator, so `x` and `(y)` on two lines would otherwise
// read as the call `x(y)` and silently run a query nobody wrote.
func TestParser_ParensNewline(t *testing.T) {
	t.Run("same line is a call", func(t *testing.T) {
		exps := parseFolded(t, "x(y)")
		require.Len(t, exps, 1)
		assert.Equal(t, &Expression{Operand: &Operand{
			Value: vIdent("x"),
			Calls: []*Call{{Function: []*Arg{{Value: &Expression{Operand: opnd(vIdent("y"))}}}}},
		}}, exps[0])
	})

	t.Run("new line is a group", func(t *testing.T) {
		exps := parseFolded(t, "x\n(y)")
		require.Len(t, exps, 2)
		assert.Equal(t, &Expression{Operand: opnd(vIdent("x"))}, exps[0])
		assert.Equal(t, &Expression{Operand: opnd(vIdent("y"))}, exps[1])
	})

	t.Run("new line after a field", func(t *testing.T) {
		exps := parseFolded(t, "a.b\n(c + d)")
		require.Len(t, exps, 2)
		assert.Equal(t, &Expression{Operand: opnd(vIdent("a"), callIdent("b"))}, exps[0])
		assert.Equal(t, &Expression{Operand: callOp(OpAdd, opnd(vIdent("c")), opnd(vIdent("d")))}, exps[1])
	})

	t.Run("an argument list may still span lines", func(t *testing.T) {
		exps := parseFolded(t, "users.where(\n  (a + b) > 1\n)")
		require.Len(t, exps, 1)
		require.NotNil(t, exps[0].Operand)
		assert.Len(t, exps[0].Operand.Calls, 2)
	})

	t.Run("a group may open a query", func(t *testing.T) {
		exps := parseFolded(t, "(a + b) > 1")
		require.Len(t, exps, 1)
		assert.Equal(t, &Expression{Operand: callOp(OpGreater,
			callOp(OpAdd, opnd(vIdent("a")), opnd(vIdent("b"))),
			opnd(vInt(1)),
		)}, exps[0])
	})
}

// TestParser_Signs covers the lexer change parens needed. The sign used to be
// glued onto the number, so `1+2` lexed as two numbers and compiled to `2`. It
// is an operator now, and the literals that want a sign get it back in the
// parser so their trees are unchanged.
func TestParser_Signs(t *testing.T) {
	t.Run("an adjacent sign is an operator", func(t *testing.T) {
		tests := [][2]string{
			{"1+2", "1 + 2"},
			{"1-2", "1 - 2"},
			{"a-1", "a - 1"},
			{"a.b-c.d", "a.b - c.d"},
			{"2+3", "2 + 3"},
		}
		for _, test := range tests {
			t.Run(test[0], func(t *testing.T) {
				assert.Equal(t, parseFolded(t, test[1]), parseFolded(t, test[0]))
			})
		}
	})

	t.Run("a negated literal stays a literal", func(t *testing.T) {
		runParserTests(t, []parserTest{
			{"-1", &Expression{Operand: opnd(vInt(-1))}},
			{"-1.5", &Expression{Operand: opnd(vFloat(-1.5))}},
			{"+1", &Expression{Operand: opnd(vInt(1))}},
			{"--1", &Expression{Operand: opnd(vInt(1))}},
			{"a[-1]", &Expression{Operand: opnd(vIdent("a"), &Call{
				Accessor: &Expression{Operand: opnd(vInt(-1))},
			})}},
		})
	})

	t.Run("a negated literal in an array", func(t *testing.T) {
		exps := parseFolded(t, "[1, -2, -3.5]")
		require.Len(t, exps, 1)
		require.NotNil(t, exps[0].Operand.Value)
		assert.Equal(t, []*Expression{
			{Operand: opnd(vInt(1))},
			{Operand: opnd(vInt(-2))},
			{Operand: opnd(vFloat(-3.5))},
		}, exps[0].Operand.Value.Array)
	})

	t.Run("anything else negates as 0 - x", func(t *testing.T) {
		runParserTests(t, []parserTest{
			{"-a", &Expression{Operand: callOp(OpSubtract, opnd(vInt(0)), opnd(vIdent("a")))}},
			{"-a.b", &Expression{Operand: callOp(OpSubtract, opnd(vInt(0)),
				opnd(vIdent("a"), callIdent("b")))}},
		})

		exps := parseFolded(t, "-(a + b)")
		require.Len(t, exps, 1)
		assert.Equal(t, &Expression{Operand: callOp(OpSubtract, opnd(vInt(0)),
			callOp(OpAdd, opnd(vIdent("a")), opnd(vIdent("b"))),
		)}, exps[0])
	})

	t.Run("a sign binds tighter than the operator it follows", func(t *testing.T) {
		// -2 * 3 is (-2) * 3, not -(2 * 3); the two differ in sign only for
		// division, so multiplication alone would not catch a mistake here.
		assert.Equal(t,
			parseFolded(t, "0 - 2 * 3"),
			parseFolded(t, "-(2 * 3)"),
		)
		assert.NotEqual(t,
			parseFolded(t, "-2 * 3"),
			parseFolded(t, "-(2 * 3)"),
		)
	})

	t.Run("a sign after an operator", func(t *testing.T) {
		assert.Equal(t,
			parseFolded(t, "1 - -2"),
			[]*Expression{{Operand: callOp(OpSubtract, opnd(vInt(1)), opnd(vInt(-2)))}},
		)
	})

	t.Run("a dangling sign errors", func(t *testing.T) {
		_, err := Parse("1 + ")
		assert.Error(t, err)
	})
}
