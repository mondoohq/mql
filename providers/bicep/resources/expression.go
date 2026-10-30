// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "strings"

// exprKind classifies a parsed Bicep expression node.
const (
	exprKindLiteral        = "literal"
	exprKindFunctionCall   = "functionCall"
	exprKindPropertyAccess = "propertyAccess"
	exprKindSymbolicRef    = "symbolicRef"
	exprKindInterpolation  = "interpolation"
	exprKindTernary        = "ternary"
	exprKindArray          = "array"
	exprKindUnknown        = "unknown"
)

// exprNode is the structured, queryable view of a single Bicep expression.
// It is produced by parseExpression and never carries evaluated values —
// it describes the *shape* of an expression (a function call, a symbolic
// reference, an interpolated string, …), not its computed result.
type exprNode struct {
	kind string
	// raw is the original source text of this node, always populated.
	raw string

	// functionName is set for functionCall nodes (e.g. "resourceId").
	functionName string
	// args holds the parsed arguments of a functionCall.
	args []*exprNode

	// target is the root identifier of a propertyAccess or symbolicRef
	// (e.g. "vnet" in vnet.properties.subnets[0].id).
	target string
	// path is the accessor chain of a propertyAccess
	// (e.g. ["properties","subnets","0","id"]).
	path []string

	// segments holds the alternating literal / embedded-expression parts
	// of an interpolated string ('...${expr}...').
	segments []*exprNode
}

// parseExpression turns a raw Bicep expression string into a structured
// exprNode tree. It never panics and never returns an error — any input it
// can't classify becomes an exprNode of kind "unknown" with raw preserved,
// so audits always get a usable node. The grammar covered is intentionally
// bounded (literals, identifiers, member/index chains, function calls,
// ternaries, arrays, and interpolated-string segments); this is structure
// only, never evaluation.
// maxExprDepth bounds recursion in the expression parser. Bicep expressions
// are shallow in practice; the cap exists so a deeply nested, possibly
// adversarial input (e.g. tens of thousands of nested parens / arrays /
// interpolations in a single value) degrades to an `unknown` node instead of
// driving super-linear work that wedges the query. See parsePrimary.
const maxExprDepth = 200

func parseExpression(raw string) *exprNode {
	return parseExpressionDepth(raw, 0)
}

// parseExpressionDepth is parseExpression carrying the current recursion depth
// across the new-parser boundary (sub-expressions and string interpolation
// each start a fresh exprParser).
func parseExpressionDepth(raw string, depth int) *exprNode {
	trimmed := strings.TrimSpace(raw)
	if depth > maxExprDepth {
		return &exprNode{kind: exprKindUnknown, raw: trimmed}
	}
	p := &exprParser{src: trimmed, depth: depth}
	node := p.parseTernary()
	// If the parser couldn't consume the whole input, the expression is
	// outside the supported grammar — fall back to "unknown" but keep the
	// original text intact.
	if node == nil || !p.atEnd() {
		return &exprNode{kind: exprKindUnknown, raw: trimmed}
	}
	// Always report the original (untrimmed-internal) text as raw.
	node.raw = trimmed
	return node
}

// exprParser is a tiny recursive-descent parser over the bounded Bicep
// expression grammar. It walks the source by byte index and reuses the
// package's string-aware scanState for skipping quoted literals when it
// needs to find delimiters.
type exprParser struct {
	src   string
	pos   int
	depth int
}

func (p *exprParser) atEnd() bool {
	p.skipSpace()
	return p.pos >= len(p.src)
}

func (p *exprParser) skipSpace() {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' {
			p.pos++
			continue
		}
		break
	}
}

func (p *exprParser) peek() byte {
	if p.pos >= len(p.src) {
		return 0
	}
	return p.src[p.pos]
}

// parseTernary parses `cond ? a : b`, falling through to the primary/postfix
// grammar when no `?` is present at the current top level.
func (p *exprParser) parseTernary() *exprNode {
	start := p.pos
	// A ternary is recognized by a `?` at the current top level. Scan for
	// it first (string- and bracket-aware) so a condition that uses binary
	// operators we don't model (`a == b`, `a && b`) still yields a ternary
	// node — the condition simply parses as `unknown` with raw preserved,
	// rather than collapsing the whole expression to unknown.
	// The operand span runs from `start` up to the next top-level element
	// terminator (`,`, `)`, `]`) or end of source — this keeps ternary
	// detection scoped to a single array element or call argument.
	operandEnd := p.findOperandEnd(start)
	qPos := p.findTopLevelWithin('?', start, operandEnd)
	if qPos < 0 {
		return p.parsePostfix()
	}
	cPos := p.findTopLevelWithin(':', qPos+1, operandEnd)
	if cPos < 0 {
		return p.parsePostfix()
	}

	cond := parseSubExpression(p.src[start:qPos], p.depth+1)
	thenNode := parseSubExpression(p.src[qPos+1:cPos], p.depth+1)
	elseNode := parseSubExpression(p.src[cPos+1:operandEnd], p.depth+1)
	p.pos = operandEnd

	return &exprNode{
		kind: exprKindTernary,
		raw:  strings.TrimSpace(p.src[start:operandEnd]),
		args: []*exprNode{cond, thenNode, elseNode},
	}
}

// findOperandEnd returns the byte index where the current operand ends — the
// first top-level `,`, `)`, or `]`, or len(src) if none. This bounds ternary
// detection to one element inside arrays and argument lists.
func (p *exprParser) findOperandEnd(from int) int {
	st := scanState{}
	for i := from; i < len(p.src); {
		if st.inStr == 0 && !st.inMulti && st.totalDepth() == 0 {
			switch p.src[i] {
			case ',', ')', ']':
				return i
			}
		}
		i = st.stepAt(p.src, i)
	}
	return len(p.src)
}

// findTopLevelWithin returns the index of the first `target` at depth zero,
// outside any string, in [from, end). Returns -1 if not found. Reuses
// scanState so quotes and nested brackets are respected.
func (p *exprParser) findTopLevelWithin(target byte, from, end int) int {
	st := scanState{}
	for i := from; i < end; {
		if st.inStr == 0 && !st.inMulti && st.totalDepth() == 0 && p.src[i] == target {
			return i
		}
		i = st.stepAt(p.src, i)
	}
	return -1
}

// parseSubExpression parses a standalone sub-expression (a ternary branch or
// condition). It never returns nil — anything outside the supported grammar
// becomes an `unknown` node with raw preserved.
func parseSubExpression(raw string, depth int) *exprNode {
	return parseExpressionDepth(raw, depth)
}

// parsePostfix parses a primary expression followed by any chain of member
// (`.foo`), index (`[...]`), or call (`(...)`) accessors.
func (p *exprParser) parsePostfix() *exprNode {
	node := p.parsePrimary()
	if node == nil {
		return nil
	}

	for {
		p.skipSpace()
		c := p.peek()
		switch {
		case c == '.':
			p.pos++
			name := p.readIdentifier()
			if name == "" {
				return nil
			}
			node = appendAccess(node, name)
		case c == '[':
			idx, ok := p.readIndex()
			if !ok {
				return nil
			}
			node = appendAccess(node, idx)
		case c == '(':
			// A call applies only to a bare identifier (function name).
			if node.kind != exprKindSymbolicRef {
				return nil
			}
			args, ok := p.readArgs()
			if !ok {
				return nil
			}
			node = &exprNode{
				kind:         exprKindFunctionCall,
				functionName: node.target,
				args:         args,
			}
		default:
			return node
		}
	}
}

// appendAccess turns the base node into (or extends) a propertyAccess node
// with the given accessor appended to its path. A bare symbolicRef or a
// functionCall both become the `target`-less / `target`-bearing root of the
// access chain as appropriate.
func appendAccess(base *exprNode, accessor string) *exprNode {
	if base.kind == exprKindSymbolicRef {
		return &exprNode{
			kind:   exprKindPropertyAccess,
			target: base.target,
			path:   []string{accessor},
		}
	}
	if base.kind == exprKindPropertyAccess {
		base.path = append(base.path, accessor)
		return base
	}
	// Accessing into a functionCall, array, etc. — model it as a
	// propertyAccess whose target is empty and that carries the base as
	// its first arg so the chain stays queryable.
	return &exprNode{
		kind:   exprKindPropertyAccess,
		target: "",
		path:   []string{accessor},
		args:   []*exprNode{base},
	}
}

// parsePrimary parses a leaf: a string literal (possibly interpolated), a
// number / bool / null literal, an array, a parenthesized sub-expression, or
// a bare identifier (symbolic reference / function-name root).
func (p *exprParser) parsePrimary() *exprNode {
	p.skipSpace()
	if p.pos >= len(p.src) {
		return nil
	}
	// parsePrimary is the choke point every nested operand descends through
	// (parens, arrays). Bound the recursion so deeply nested input degrades to
	// an unknown node rather than driving super-linear rescans.
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxExprDepth {
		return nil
	}
	c := p.peek()

	switch {
	case c == '\'':
		return p.parseString()
	case c == '"':
		return p.parseDoubleString()
	case c == '[':
		return p.parseArray()
	case c == '(':
		return p.parseParen()
	case c >= '0' && c <= '9', c == '-':
		return p.parseNumber()
	case isIdentStart(c):
		ident := p.readIdentifier()
		switch ident {
		case "true", "false", "null":
			return &exprNode{kind: exprKindLiteral, raw: ident}
		case "":
			return nil
		}
		return &exprNode{kind: exprKindSymbolicRef, raw: ident, target: ident}
	}
	return nil
}

// parseString parses a single-quoted Bicep string. If it contains `${...}`
// interpolation it returns an interpolation node whose segments alternate
// literal text and embedded expressions; otherwise a plain literal node.
func (p *exprParser) parseString() *exprNode {
	start := p.pos
	// Triple-quoted multi-line string: treat as an opaque literal.
	if strings.HasPrefix(p.src[p.pos:], "'''") {
		end := strings.Index(p.src[p.pos+3:], "'''")
		if end < 0 {
			return nil
		}
		p.pos = p.pos + 3 + end + 3
		return &exprNode{kind: exprKindLiteral, raw: p.src[start:p.pos]}
	}

	p.pos++ // consume opening quote
	var segments []*exprNode
	var lit strings.Builder
	hasInterp := false

	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\\' && p.pos+1 < len(p.src) {
			// Preserve the escape pair verbatim in the literal text.
			lit.WriteByte(ch)
			lit.WriteByte(p.src[p.pos+1])
			p.pos += 2
			continue
		}
		if ch == '$' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '{' {
			hasInterp = true
			// Flush the literal collected so far as a segment.
			segments = append(segments, &exprNode{kind: exprKindLiteral, raw: lit.String()})
			lit.Reset()
			inner, ok := p.readInterpolation()
			if !ok {
				return nil
			}
			segments = append(segments, parseExpressionDepth(inner, p.depth+1))
			continue
		}
		if ch == '\'' {
			p.pos++ // consume closing quote
			raw := p.src[start:p.pos]
			if !hasInterp {
				return &exprNode{kind: exprKindLiteral, raw: raw}
			}
			// Flush trailing literal segment.
			segments = append(segments, &exprNode{kind: exprKindLiteral, raw: lit.String()})
			return &exprNode{kind: exprKindInterpolation, raw: raw, segments: segments}
		}
		lit.WriteByte(ch)
		p.pos++
	}
	// Unterminated string.
	return nil
}

// parseDoubleString parses a double-quoted string as an opaque literal.
// (Bicep proper uses single quotes; double quotes show up in compiled/ARM
// fragments and are treated as plain literals here.)
func (p *exprParser) parseDoubleString() *exprNode {
	start := p.pos
	p.pos++ // consume opening quote
	for p.pos < len(p.src) {
		ch := p.src[p.pos]
		if ch == '\\' && p.pos+1 < len(p.src) {
			p.pos += 2
			continue
		}
		if ch == '"' {
			p.pos++
			return &exprNode{kind: exprKindLiteral, raw: p.src[start:p.pos]}
		}
		p.pos++
	}
	return nil
}

// readInterpolation consumes a `${ ... }` block (cursor sitting on `$`) and
// returns the inner expression text. Brace and string nesting inside the
// block is respected via scanState so a `}` inside a nested string doesn't
// close it early.
func (p *exprParser) readInterpolation() (string, bool) {
	// Cursor is on '$', next is '{'.
	p.pos += 2 // skip "${"
	start := p.pos
	st := scanState{brace: 1}
	for p.pos < len(p.src) {
		next := st.stepAt(p.src, p.pos)
		if st.brace == 0 {
			inner := p.src[start:p.pos]
			p.pos = next
			return inner, true
		}
		p.pos = next
	}
	return "", false
}

// parseNumber parses an integer literal (optionally negative).
func (p *exprParser) parseNumber() *exprNode {
	start := p.pos
	if p.peek() == '-' {
		p.pos++
	}
	digits := false
	for p.pos < len(p.src) && p.src[p.pos] >= '0' && p.src[p.pos] <= '9' {
		p.pos++
		digits = true
	}
	if !digits {
		// Rewind: a bare '-' (e.g. in an unsupported binary expression like
		// `a - b`) is not a number, so leave the cursor where we found it.
		p.pos = start
		return nil
	}
	return &exprNode{kind: exprKindLiteral, raw: p.src[start:p.pos]}
}

// parseArray parses `[ a, b, ... ]` into an array node whose args are the
// parsed elements.
func (p *exprParser) parseArray() *exprNode {
	start := p.pos
	p.pos++ // consume '['
	var elems []*exprNode
	for {
		p.skipSpace()
		if p.peek() == ']' {
			p.pos++
			return &exprNode{kind: exprKindArray, raw: p.src[start:p.pos], args: elems}
		}
		if p.pos >= len(p.src) {
			return nil
		}
		elem := p.parseTernary()
		if elem == nil {
			return nil
		}
		elems = append(elems, elem)
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case ']':
			p.pos++
			return &exprNode{kind: exprKindArray, raw: p.src[start:p.pos], args: elems}
		default:
			return nil
		}
	}
}

// parseParen parses a parenthesized sub-expression and returns the inner
// node directly (the parentheses are purely for grouping).
func (p *exprParser) parseParen() *exprNode {
	p.pos++ // consume '('
	inner := p.parseTernary()
	if inner == nil {
		return nil
	}
	p.skipSpace()
	if p.peek() != ')' {
		return nil
	}
	p.pos++
	return inner
}

// readArgs parses a `( arg1, arg2, ... )` argument list (cursor on `(`).
func (p *exprParser) readArgs() ([]*exprNode, bool) {
	p.pos++ // consume '('
	var args []*exprNode
	for {
		p.skipSpace()
		if p.peek() == ')' {
			p.pos++
			return args, true
		}
		if p.pos >= len(p.src) {
			return nil, false
		}
		arg := p.parseTernary()
		if arg == nil {
			return nil, false
		}
		args = append(args, arg)
		p.skipSpace()
		switch p.peek() {
		case ',':
			p.pos++
		case ')':
			p.pos++
			return args, true
		default:
			return nil, false
		}
	}
}

// readIndex parses a `[...]` index accessor (cursor on `[`) and returns the
// accessor as a path segment: a quoted key becomes its unquoted contents, a
// numeric index becomes its digits, everything else is the raw inner text.
func (p *exprParser) readIndex() (string, bool) {
	p.pos++ // consume '['
	start := p.pos
	st := scanState{bracket: 1}
	for p.pos < len(p.src) {
		next := st.stepAt(p.src, p.pos)
		if st.bracket == 0 {
			inner := strings.TrimSpace(p.src[start:p.pos])
			p.pos = next
			return normalizeIndex(inner), true
		}
		p.pos = next
	}
	return "", false
}

// normalizeIndex strips surrounding quotes from a string key so
// foo['bar'] and foo.bar produce the same path segment "bar". Numeric and
// expression indices are returned as-is — including a concatenation that
// merely starts and ends with a quote (e.g. `'a' + suffix + 'b'`), which is
// NOT a single literal and must not be unquoted.
func normalizeIndex(s string) string {
	if isSingleQuotedLiteral(s) {
		return s[1 : len(s)-1]
	}
	return s
}

// isSingleQuotedLiteral reports whether s is exactly one quoted string literal
// (e.g. "'key'"), as opposed to an expression that only happens to start and
// end with a quote (e.g. "'a' + x + 'b'"). It walks s string-aware so a
// concatenation whose first literal closes before the end is rejected.
func isSingleQuotedLiteral(s string) bool {
	if len(s) < 2 || (s[0] != '\'' && s[0] != '"') || s[len(s)-1] != s[0] {
		return false
	}
	st := scanState{}
	i := st.stepAt(s, 0) // consume the opening quote -> inStr set
	for i < len(s) {
		// The string closing before the final byte means s is not a lone literal.
		if st.inStr == 0 && !st.inMulti && i < len(s)-1 {
			return false
		}
		i = st.stepAt(s, i)
	}
	return st.inStr == 0 && !st.inMulti
}

func (p *exprParser) readIdentifier() string {
	p.skipSpace()
	start := p.pos
	if p.pos < len(p.src) && isIdentStart(p.src[p.pos]) {
		p.pos++
		for p.pos < len(p.src) && isIdentPart(p.src[p.pos]) {
			p.pos++
		}
	}
	return p.src[start:p.pos]
}

func isIdentStart(c byte) bool {
	return c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentPart(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9')
}
