// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources_test

import (
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/testutils"
)

// TestParens_Arithmetic runs grouped expressions to their values. The compiler
// tests prove that two spellings agree with each other; these prove they agree
// with arithmetic, so a fold that groups consistently but wrongly still fails.
func TestParens_Arithmetic(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{Code: "1 * (2 + 3)", Expectation: int64(5)},
		{Code: "1*(((2+3)))", Expectation: int64(5)},
		{Code: "(1 + 2) * 3", Expectation: int64(9)},
		{Code: "1 + 2 * 3", Expectation: int64(7)},

		// subtraction and division are not associative, so these catch a fold
		// that drops a group instead of honoring it
		{Code: "(10 - 4) - 3", Expectation: int64(3)},
		{Code: "10 - (4 - 3)", Expectation: int64(9)},
		{Code: "12 / 2 * 3", Expectation: int64(18)},
		{Code: "12 / (2 * 3)", Expectation: int64(2)},

		{Code: "(1.0 + 2) * 2", Expectation: float64(6)},
		// each group is its own datapoint, so the comparison is the third result
		{Code: "(1 + 2) < (2 + 2)", Expectation: true, ResultIndex: 2},

		// `&&` binds tighter than `||`, so the group is what forces the or to
		// happen first. Index 0 is the inner operand either way.
		{Code: "true || false && false", Expectation: true, ResultIndex: 1},
		{Code: "(true || false) && false", Expectation: false, ResultIndex: 1},
	})
}

// TestParens_UnarySign covers the sign handling the group syntax needed. A
// literal keeps its sign; anything else negates as `0 - x`.
func TestParens_UnarySign(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{Code: "-1", Expectation: int64(-1)},
		{Code: "-1.5", Expectation: float64(-1.5)},
		{Code: "-2 * 3", Expectation: int64(-6)},
		{Code: "-(2 + 3)", Expectation: int64(-5)},
		{Code: "1 - -2", Expectation: int64(3)},
		{Code: "[1, -2, 3][1]", Expectation: int64(-2)},

		// a variable is not a literal, so these take the `0 - x` path
		{Code: "x = 2; -x", Expectation: int64(-2)},
		{Code: "x = 2; -(x * 3)", Expectation: int64(-6)},
	})
}

// TestParens_SignsNeedNoSpaces pins the lexer fix: the sign used to be part of
// the number token, so `1+2` was the two numbers 1 and +2 and the query returned
// 2 instead of 3.
func TestParens_SignsNeedNoSpaces(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{Code: "1+2", Expectation: int64(3)},
		{Code: "1-2", Expectation: int64(-1)},
		{Code: "2*3+1", Expectation: int64(7)},
		{Code: "1+2*3", Expectation: int64(7)},
		{Code: "1.5+1", Expectation: float64(2.5)},
		{Code: "3*-1", Expectation: int64(-3)},
	})
}

// TestParens_NewlineStartsAGroup: MQL has no statement terminator, so a line
// opening with `(` would otherwise be read as an argument list for the line
// above it and run a query nobody wrote.
func TestParens_NewlineStartsAGroup(t *testing.T) {
	x := testutils.InitTester(testutils.LinuxMock())
	x.TestSimple(t, []testutils.SimpleTest{
		{Code: "a = 1\nb = 2\n(a) + (b)", Expectation: int64(3)},
		{Code: "a = 1\n(a + 4)", Expectation: int64(5)},
	})
}
