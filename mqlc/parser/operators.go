// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package parser

import "errors"

// Operator list
type Operator int

// Operator precedence in MQL
//
// MQL follows JavaScript-style operator precedence. Each operator has a rank;
// higher rank binds tighter. From lowest to highest:
//
//	Tier            Operators              Example grouping
//	----            ---------              ----------------
//	assignment      =                      a = b + c       →  a = (b + c)
//	logical or      ||                     a || b && c     →  a || (b && c)
//	logical and     &&                     a && b == c     →  a && (b == c)
//	equality        == =~ != !~            a == b < c      →  a == (b < c)
//	comparison      <  <=  >  >=           a < b + c       →  a < (b + c)
//	additive        +  -                   a + b * c       →  a + (b * c)
//	multiplicative  *  /  %                a * b           →  (a * b)
//
// Operators within the same tier have equal precedence and associate
// left-to-right. So `10 - 4 - 3` evaluates as `(10 - 4) - 3 = 3`, and
// `a == b =~ c` evaluates as `(a == b) =~ c`. The two equality-style
// matchers (`=~` for regex match, `!~` for no-match) share the
// equality tier with `==` and `!=`.
//
// Parentheses override precedence: `(a + b) * c` forces the addition
// first. A group that agrees with precedence costs nothing - it is
// folded away in parseGroup before the compiler ever sees it, so
// `1*(((2+3)))`, `1 * (2 + 3)` and `(1*(2+3))` are one query with one
// checksum.
//
// A `-` or `+` in front of an operand is a sign, and binds tighter than
// any operator: `-2 * 3` is `(-2) * 3`. On a literal it stays part of
// the literal; on anything else it compiles as `0 - x`.
//
// Examples:
//
//	1 + 2 * 3            →  1 + (2 * 3)          = 7
//	a || b && c          →  a || (b && c)
//	users.length > 0 && active
//	                     →  (users.length > 0) && active
//	age >= 18 && age < 65
//	                     →  (age >= 18) && (age < 65)
//	name =~ /admin/ || role == "root"
//	                     →  (name =~ /admin/) || (role == "root")
//
// Implementation note: at parse time every operator is rewritten into a
// function call (e.g. `1 + 2` becomes `+(1, 2)`), so by the time the
// compiler sees the tree there are no operators left — only calls. The
// fold itself happens in processOperators, which buckets operators by
// their tens digit and collapses one precedence tier per pass.
const (
	OpAssignment Operator = iota + 30
	OpOr         Operator = iota + 60
	OpAnd        Operator = iota + 70
	OpEqual      Operator = iota + 100
	OpCmp
	OpNotEqual
	OpNotCmp
	OpSmaller Operator = iota + 110
	OpSmallerEqual
	OpGreater
	OpGreaterEqual
	OpAdd Operator = iota + 130
	OpSubtract
	OpMultiply Operator = iota + 140
	OpDivide
	OpRemainder
)

var Operators = map[string]Operator{
	"=":  OpAssignment,
	"&&": OpAnd,
	"||": OpOr,
	"==": OpEqual,
	"=~": OpCmp,
	"!=": OpNotEqual,
	"!~": OpNotCmp,
	"<":  OpSmaller,
	"<=": OpSmallerEqual,
	">":  OpGreater,
	">=": OpGreaterEqual,
	"+":  OpAdd,
	"-":  OpSubtract,
	"*":  OpMultiply,
	"/":  OpDivide,
	"%":  OpRemainder,
}

var operatorCharacter map[rune]struct{}

var operatorsStrings map[Operator]string

func init() {
	operatorsStrings = make(map[Operator]string)
	operatorCharacter = make(map[rune]struct{})
	for k, v := range Operators {
		operatorsStrings[v] = k
		operatorCharacter[[]rune(k)[0]] = struct{}{}
	}
}

func IsOperator(s string) bool {
	if s == "" {
		return false
	}
	_, ok := operatorCharacter[[]rune(s)[0]]
	return ok
}

// Capture an operator in participle
func (o *Operator) Capture(s []string) error {
	// capture both tokens
	sop := s[0]
	if len(s) == 2 {
		sop += s[1]
	}

	*o = Operators[sop]
	return nil
}

func (o *Operator) String() string {
	r, ok := operatorsStrings[*o]
	if !ok {
		return "unknown operator"
	}
	return r
}

// processOperators handles simple ops like ==, >=, *, ...
// and turns them into functions; only on the level of this expression and its
// Operations children, not deeper function calls
func (e *Expression) processOperators() error {
	if len(e.Operations) == 0 {
		return nil
	}

	if e.Operand == nil {
		return errors.New("expression doesn't have any operand, i.e. it has been parsed without a body")
	}

	// group operators into precedence (matchOp as the cut-off line)
	// check if every value has an operator (since they are all linked)
	// and cycle through all calls and process their parameters too
	maxOp := 0
	for idx := range e.Operations {
		v := e.Operations[idx]
		if maxOp < int(v.Operator) {
			maxOp = int(v.Operator)
		}
	}
	matchOp := maxOp - (maxOp % 10)

	first := []*Operation{{Operand: e.Operand}}
	allOps := append(first, e.Operations...)
	nuOps := first
	for idx := 1; idx < len(allOps); idx++ {
		v := allOps[idx]
		if int(v.Operator) < matchOp {
			nuOps = append(nuOps, allOps[idx])
			continue
		}

		prevIdx := len(nuOps) - 1
		prev := nuOps[prevIdx]
		op := v.Operator.String()
		cur := &Operation{
			Operator: prev.Operator,
			Operand: &Operand{
				Value: &Value{Ident: &op},
				Calls: []*Call{{Function: []*Arg{
					{Value: &Expression{Operand: prev.Operand}},
					{Value: &Expression{Operand: v.Operand}},
				}}},
			},
		}
		nuOps[prevIdx] = cur
	}

	e.Operand = nuOps[0].Operand
	// nil rather than an empty slice, so a fully folded expression is
	// structurally identical however it got there. A group folds its contents
	// on the way out (parseGroup), so `(1+2)` and a top-level `1+2` reach this
	// point by different routes and have to land on the same tree.
	if len(nuOps) == 1 {
		e.Operations = nil
	} else {
		e.Operations = nuOps[1:]
	}
	return e.processOperators()
}

// processChildOperators of all block, accessor, and function child calls
func (e *Expression) processChildOperators() error {
	ops := append([]*Operation{{Operand: e.Operand}}, e.Operations...)

	// tackle all command calls recursively
	for i := range ops {
		v := ops[i].Operand
		if v == nil {
			return errors.New("missing operand in child block")
		}

		if v.Value != nil {
			for j := range v.Value.Array {
				if err := v.Value.Array[j].ProcessOperators(); err != nil {
					return err
				}
			}

			for _, vv := range v.Value.Map {
				if err := vv.ProcessOperators(); err != nil {
					return err
				}
			}
		}

		for fi := range v.Block {
			if err := v.Block[fi].ProcessOperators(); err != nil {
				return err
			}
		}

		for fi := range v.Calls {
			if err := v.Calls[fi].Accessor.ProcessOperators(); err != nil {
				return err
			}

			args := v.Calls[fi].Function
			for ffi := range args {
				if err := args[ffi].Value.ProcessOperators(); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ProcessOperators of this expression and all its children recursively
// and make everything be a flat expression with function calls only
func (e *Expression) ProcessOperators() error {
	if e == nil {
		return nil
	}
	if err := e.processChildOperators(); err != nil {
		return err
	}
	return e.processOperators()
}
