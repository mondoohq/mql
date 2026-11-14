// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package format pretty-prints MQL.
//
// The formatter only changes whitespace. It keeps every token exactly as
// written and keeps the author's line breaks, recomputes indentation from
// bracket nesting, normalizes the spacing between tokens, and breaks lines that
// are longer than the width at their outermost structure. Before it returns, it
// re-lexes and re-parses its output and checks that both match the input; if
// they don't, it returns the input unchanged together with an error.
//
// Policy formatting is the intended caller: format each query's MQL before the
// bundle is written back out.
package format

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/alecthomas/participle/lexer"
	"go.mondoo.com/mql/mqlc/parser"
)

// Indent is one level of indentation.
const Indent = "  "

var mqlLexer = lexer.Must(lexer.Regexp(parser.LexerRegex))

type kind int

const (
	kOperand kind = iota // identifiers and literals
	kOp                  // single or merged operator: && == - . ? etc.
	kOpen                // ( [ {
	kClose               // ) ] }
	kComment
)

type token struct {
	kind  kind
	value string
	// newlines is how many line breaks the source had before this token.
	newlines int
	// call marks a `(` or `[` that attaches to the operand before it.
	call bool
	// unary marks a `-` or `+` that is a sign rather than an operator.
	unary bool
}

// merged are operators the lexer emits as two single-character tokens and the
// parser reads as one, whatever whitespace sits between them.
var merged = map[string]bool{
	"&&": true, "||": true, "==": true, "!=": true,
	"=~": true, "!~": true, "<=": true, ">=": true,
}

// DefaultWidth is the line length Format breaks long lines at.
const DefaultWidth = 100

// Format returns src pretty-printed with lines broken at DefaultWidth. On any
// error it returns src unchanged.
func Format(src string) (string, error) {
	return FormatWidth(src, DefaultWidth)
}

// FormatWidth is Format with a custom line width, counted from the start of the
// query; 0 never breaks lines.
func FormatWidth(src string, width int) (string, error) {
	if _, err := parser.Parse(src); err != nil {
		return src, fmt.Errorf("parse: %w", err)
	}

	toks, err := tokenize(src)
	if err != nil {
		return src, err
	}

	out := render(toks, width)
	if err := verify(src, out); err != nil {
		return src, err
	}
	return out, nil
}

func tokenize(src string) ([]token, error) {
	lex, err := mqlLexer.Lex(strings.NewReader(src))
	if err != nil {
		return nil, err
	}

	var res []token
	prevEnd := 0
	pendingNL := 0
	for {
		t, err := lex.Next()
		if err != nil {
			return nil, err
		}
		if t.EOF() {
			break
		}

		nl := pendingNL + strings.Count(src[prevEnd:t.Pos.Offset], "\n")
		pendingNL = 0
		prevEnd = t.Pos.Offset + len(t.Value)

		tok := token{value: t.Value, newlines: nl}
		switch t.Type {
		case parser.Comment:
			tok.kind = kComment
			if strings.HasSuffix(tok.value, "\n") {
				// the comment token swallows its line break; hand it to the next token
				pendingNL = 1
			}
			tok.value = strings.TrimRight(tok.value, " \t\r\n")
		case parser.Op:
			tok.kind = kOp
		case parser.CallType:
			if strings.ContainsAny(t.Value, "([{") {
				tok.kind = kOpen
			} else {
				tok.kind = kClose
			}
		default:
			tok.kind = kOperand
		}

		// merge two-character operators
		if tok.kind == kOp && len(res) > 0 {
			last := &res[len(res)-1]
			if last.kind == kOp && len(last.value) == 1 && merged[last.value+tok.value] {
				last.value += tok.value
				continue
			}
		}
		res = append(res, tok)
	}

	// classify calls and unary signs, which depend on the previous code token
	var prev *token
	for i := range res {
		t := &res[i]
		if t.kind == kComment {
			continue
		}
		after := prev != nil && endsOperand(prev)
		switch {
		case t.kind == kOpen && t.value == "(":
			// the parser only reads `x (` as a call when both sit on one line; a
			// comment in between always ends its line, so newlines covers it
			t.call = after && t.newlines == 0
		case t.kind == kOpen && t.value == "[":
			t.call = after
		case t.kind == kOp && (t.value == "-" || t.value == "+"):
			t.unary = !after
		}
		prev = t
	}
	return res, nil
}

// endsOperand reports whether t can end an operand, which makes a following
// `-` binary, a `(` a call and a `[` an accessor.
func endsOperand(t *token) bool {
	switch t.kind {
	case kOperand:
		// `return` ends its expression: what follows is a new one, so
		// `return [1]` is an array, never an index into `return`
		return t.value != "return"
	case kClose:
		return true
	case kOp:
		return t.value == "?"
	}
	return false
}

func isBinary(t *token) bool {
	if t.kind != kOp || t.unary {
		return false
	}
	switch t.value {
	case ".", ",", ";", ":", "?":
		return false
	}
	return true
}

// space reports whether a space separates a and b on one line.
func space(a, b *token) bool {
	switch {
	case b.kind == kComment:
		return true
	case a.kind == kOp && a.value == ".", b.kind == kOp && b.value == ".":
		return false
	case b.kind == kOp && (b.value == "," || b.value == ";" || b.value == ":"):
		return false
	case b.kind == kOp && b.value == "?":
		return false
	case a.kind == kOp && a.value == "?":
		return !(b.kind == kOpen && b.value == "[")
	case a.unary:
		return false
	case a.kind == kOperand && a.value == "if" && b.value == "(":
		return true // `if (x)` reads as the keyword it is
	case b.call:
		return false
	case a.kind == kOpen && a.value != "{", b.kind == kClose && b.value != "}":
		return false
	case a.kind == kOpen && a.value == "{" && b.kind == kClose:
		return false // {}
	}
	return true
}

type line struct {
	toks []*token // nil for a blank line
	text string   // rendered, with indentation
}

// layout splits toks into lines and renders each with its indentation.
func layout(toks []token) []line {
	var groups [][]*token
	for i := range toks {
		t := &toks[i]
		if len(groups) == 0 || t.newlines > 0 {
			if len(groups) > 0 && t.newlines > 1 {
				groups = append(groups, nil) // keep one blank line
			}
			groups = append(groups, nil)
		}
		groups[len(groups)-1] = append(groups[len(groups)-1], t)
	}

	res := make([]line, 0, len(groups))
	var stack []int      // indent of the line each open bracket sits on
	trailingDot := false // the previous line ended in `.`, as in `a.where(x).`
	for _, g := range groups {
		if len(g) == 0 {
			res = append(res, line{})
			continue
		}

		first := g[0]
		indent := 0
		if first.kind == kClose && len(stack) > 0 {
			indent = stack[len(stack)-1]
		} else {
			if len(stack) > 0 {
				indent = stack[len(stack)-1] + 1
			}
			// a chain continued on its own line sits one level under its resource
			if trailingDot || first.kind == kOp && (first.value == "." || first.value == "?") {
				indent++
			}
		}
		trailingDot = false
		for i := len(g) - 1; i >= 0; i-- {
			if g[i].kind != kComment {
				trailingDot = g[i].kind == kOp && g[i].value == "."
				break
			}
		}

		var sb strings.Builder
		sb.WriteString(strings.Repeat(Indent, indent))
		for i, t := range g {
			if i > 0 && space(g[i-1], t) {
				sb.WriteByte(' ')
			}
			sb.WriteString(t.value)
			switch t.kind {
			case kOpen:
				stack = append(stack, indent)
			case kClose:
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
			}
		}
		res = append(res, line{toks: g, text: sb.String()})
	}
	return res
}

// render lays out toks, breaking lines longer than width until they fit or
// cannot be broken further. A width of 0 keeps the author's line breaks only.
func render(toks []token, width int) string {
	var lines []line
	// every successful break adds a line break before some token, so this
	// terminates within len(toks) rounds
	for range len(toks) + 1 {
		lines = layout(toks)
		if width <= 0 {
			break
		}
		broke := false
		for _, l := range lines {
			if utf8.RuneCountInString(l.text) > width && breakLine(l.toks) {
				broke = true
				break
			}
		}
		if !broke {
			break
		}
	}

	parts := make([]string, len(lines))
	for i, l := range lines {
		parts[i] = l.text
	}
	return strings.TrimSpace(strings.Join(parts, "\n"))
}

// breakLine adds line breaks to one over-long line, at the outermost level
// first. It only breaks where the parser ignores line breaks: after `,`, `&&`,
// `||` and an opening bracket, before `.` and a closing bracket, and between
// two expressions. It never puts a `(` at the start of a line, which would turn
// a call into a group. It reports whether it changed anything.
func breakLine(toks []*token) bool {
	code := toks
	if n := len(code); n > 0 && code[n-1].kind == kComment {
		code = code[:n-1]
	}
	if len(code) < 2 {
		return false
	}

	// depth of each token relative to the line; the outermost level is the
	// lowest depth reached, which is below zero when the line starts by
	// closing brackets opened on earlier lines
	depth := make([]int, len(code))
	d, top := 0, 0
	for i, t := range code {
		if t.kind == kClose {
			d--
		}
		depth[i] = d
		top = min(top, d)
		if t.kind == kOpen {
			d++
		}
	}
	atTop := func(i int) bool { return depth[i] == top }

	breakBefore := func(idx []int) bool {
		for _, i := range idx {
			code[i].newlines = 1
		}
		return len(idx) > 0
	}

	// 1. after top-level commas
	var idx []int
	for i := 0; i+1 < len(code); i++ {
		if atTop(i) && code[i].kind == kOp && code[i].value == "," {
			idx = append(idx, i+1)
		}
	}
	if breakBefore(idx) {
		return true
	}

	// 2. after top-level && and ||, keeping the operator at the end of the line
	for i := 0; i+1 < len(code); i++ {
		if atTop(i) && code[i].kind == kOp && (code[i].value == "&&" || code[i].value == "||") {
			idx = append(idx, i+1)
		}
	}
	if breakBefore(idx) {
		return true
	}

	// 3. between top-level expressions, e.g. the fields of a block
	for i := 1; i < len(code); i++ {
		prev := code[i-1]
		if atTop(i) && code[i].kind == kOperand && endsOperand(prev) &&
			prev.value != "return" && prev.value != "case" && prev.value != "default" {
			idx = append(idx, i)
		}
	}
	if breakBefore(idx) {
		return true
	}

	// 4. before each link of a call chain: `.name(` or `.name {`
	hasBinary := false
	for i, t := range code {
		if atTop(i) && isBinary(t) && t.value != "=" {
			hasBinary = true
			break
		}
	}
	if !hasBinary && code[0].kind != kClose {
		for i := 1; i+2 < len(code); i++ {
			next := code[i+2]
			if atTop(i) && code[i].kind == kOp && code[i].value == "." &&
				code[i-1].value != "?" && code[i+1].kind == kOperand &&
				((next.call && next.value == "(") || next.value == "{") {
				idx = append(idx, i)
			}
		}
		// keep a short head with its first call: `terraform.resources("x")`
		if len(idx) > 0 && code[0].kind == kOperand && idx[0] == 1 {
			idx = idx[1:]
		}
		if len(idx) >= 2 && breakBefore(idx) {
			return true
		}
		idx = idx[:0]
	}

	// 5. open the widest top-level bracket: content on its own lines
	best, bestClose, bestLen := -1, -1, 0
	for i, t := range code {
		if !atTop(i) || t.kind != kOpen || (t.value == "[" && t.call) {
			continue
		}
		closeAt, size := -1, 0
		for j := i + 1; j < len(code); j++ {
			if depth[j] == depth[i] {
				closeAt = j
				break
			}
			size += len(code[j].value) + 1
		}
		if size > bestLen {
			best, bestClose, bestLen = i, closeAt, size
		}
	}
	if best < 0 || best+1 >= len(code) || code[best+1].kind == kClose {
		return false
	}
	code[best+1].newlines = 1
	if bestClose > 0 {
		code[bestClose].newlines = 1
	}
	return true
}

// verify checks that out is the same program as src: the same tokens, the
// same calls versus groups, and the same syntax tree.
func verify(src, out string) error {
	a, err := tokenize(src)
	if err != nil {
		return err
	}
	b, err := tokenize(out)
	if err != nil {
		return fmt.Errorf("re-lex output: %w", err)
	}
	if len(a) != len(b) {
		return fmt.Errorf("token count changed: %d -> %d", len(a), len(b))
	}
	for i := range a {
		if a[i].kind != b[i].kind || a[i].value != b[i].value || a[i].call != b[i].call || a[i].unary != b[i].unary {
			return fmt.Errorf("token %d changed: %q -> %q", i, a[i].value, b[i].value)
		}
	}

	astA, errA := parser.Parse(src)
	astB, errB := parser.Parse(out)
	if (errA == nil) != (errB == nil) {
		return errors.New("parse result changed")
	}
	ja, _ := json.Marshal(astA)
	jb, _ := json.Marshal(astB)
	if string(ja) != string(jb) {
		return errors.New("syntax tree changed")
	}
	return nil
}
