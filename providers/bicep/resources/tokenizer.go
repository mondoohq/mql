// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import "strings"

// bicepStatement is a single top-level construct in a .bicep file —
// a `param`, `var`, `resource`, `module`, `output`, `targetScope`, or an
// unrecognized line — together with any leading `@decorator(...)` lines
// that attach to it. The tokenizer yields these so the parser can dispatch
// on a complete, brace/bracket/string-aware statement body rather than
// re-walking raw source lines.
type bicepStatement struct {
	decorators []string // leading @decorators attached to this statement
	keyword    string   // "targetScope" | "param" | "var" | "resource" | "module" | "output" | "type" | "func" | "import" | "metadata" | "" (unknown)
	text       string   // the full statement source, multi-line, from keyword to the end of its body
	startLine  int      // 1-based, for diagnostics/future use
}

// knownKeywords maps a leading token to the canonical statement keyword.
// Anything not in this set produces a statement with an empty keyword so
// the parser never silently drops a line and future PRs can extend the
// classification (user-defined types, functions, imports, metadata, …).
var knownKeywords = map[string]string{
	"targetScope": "targetScope",
	"param":       "param",
	"var":         "var",
	"resource":    "resource",
	"module":      "module",
	"output":      "output",
	"type":        "type",
	"func":        "func",
	"import":      "import",
	"metadata":    "metadata",
}

// tokenizeBicep walks the source once and returns its top-level statements.
//
// A statement begins at the first non-blank, non-comment line after any
// leading decorators. It ends when, after consuming its first line, the
// running bracket/brace/paren depth (tracked string-aware via scanState)
// has returned to zero — so a single-line `param x string` ends at end of
// line, while a `resource ... = { ... }`, a `var x = [ ... ]`, or a
// multi-line object default keep consuming lines until their delimiters
// balance.
//
// Leading `@decorator(...)` lines — themselves possibly multi-line and
// depth-aware (e.g. `@allowed([\n ... \n])`) — attach to the next
// statement. Blank lines and `// ...` comment-only lines between
// statements are skipped.
func tokenizeBicep(content string) []bicepStatement {
	lines := strings.Split(content, "\n")

	// Every top-level construct starts at column 0 and its continuation lines
	// are indented, so the unindented lines are a tight upper bound on the
	// statement count. Sizing the slice from that one cheap pass beats growing
	// it by doubling, which reallocates and copies the whole run of statements
	// a dozen times on a large template.
	starts := 0
	for _, line := range lines {
		if line != "" && line[0] != ' ' && line[0] != '\t' {
			starts++
		}
	}
	statements := make([]bicepStatement, 0, starts)

	// One scratch slice for every statement's body: reset per statement rather
	// than reallocated. strings.Join copies what it needs (and returns the
	// single line unchanged when a statement is one line), so no statement
	// keeps a reference to this backing array.
	var bodyLines []string

	i := 0
	for i < len(lines) {
		trimmed := strings.TrimSpace(lines[i])

		// Skip blank lines, comment-only lines, and `#` directives that sit
		// between statements (decorators are handled below, so we only land
		// here for separators).
		if isSeparatorLine(trimmed) {
			i++
			continue
		}

		// Collect leading decorators. Each decorator may span multiple
		// lines; the string-aware scanner reassembles it so that delimiters
		// inside string literals (e.g. `@description('contains ] bracket')`)
		// don't keep it open past its real end.
		var decorators []string
		for strings.HasPrefix(trimmed, "@") {
			var decLine strings.Builder
			decLine.WriteString(trimmed)
			st := scanState{}
			st.feed(trimmed)
			i++
			for st.open() && i < len(lines) {
				t := strings.TrimSpace(lines[i])
				decLine.WriteString("\n" + t)
				st.feed(t)
				i++
			}
			decorators = append(decorators, decLine.String())

			// Advance past any blank, comment, or directive lines between a
			// decorator and the statement (or the next decorator) it attaches
			// to. `#disable-next-line` idiomatically sits right here, below
			// the decorators and above the declaration.
			for i < len(lines) {
				if !isSeparatorLine(strings.TrimSpace(lines[i])) {
					break
				}
				i++
			}
			if i >= len(lines) {
				break
			}
			trimmed = strings.TrimSpace(lines[i])
		}

		// If decorators ran to EOF without a following statement, still emit
		// them as an empty-keyword statement so nothing is dropped.
		if i >= len(lines) {
			if len(decorators) > 0 {
				statements = append(statements, bicepStatement{
					decorators: decorators,
					keyword:    "",
					text:       "",
					startLine:  len(lines),
				})
			}
			break
		}

		// Reassemble the statement body: consume its first line, then keep
		// pulling continuation lines until the running depth returns to zero.
		startLine := i + 1 // 1-based
		st := scanState{}
		bodyLines = bodyLines[:0]

		bodyLines = append(bodyLines, lines[i])
		st.feed(lines[i])
		i++
		for st.open() && i < len(lines) {
			bodyLines = append(bodyLines, lines[i])
			st.feed(lines[i])
			i++
		}

		text := strings.Join(bodyLines, "\n")
		keyword := classifyKeyword(strings.TrimSpace(bodyLines[0]))

		statements = append(statements, bicepStatement{
			decorators: decorators,
			keyword:    keyword,
			text:       text,
			startLine:  startLine,
		})
	}

	return statements
}

// isSeparatorLine reports whether a trimmed line carries no statement content
// and may be skipped between (or inside) statements.
//
// Besides blank and `// …` comment lines, this covers Bicep's `#` directives —
// `#disable-next-line <rule>` is a first-class construct that idiomatically
// sits between a declaration's decorators and the declaration itself. Treating
// it as content there detached every decorator onto a phantom empty statement,
// so an `@secure()` parameter read back as not secure.
func isSeparatorLine(trimmed string) bool {
	return trimmed == "" ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "#")
}

// classifyKeyword returns the canonical statement keyword for the leading
// token of a (trimmed) statement line, or "" when the leading token is not
// a recognized Bicep top-level keyword.
func classifyKeyword(line string) string {
	// The leading token ends at the first whitespace or `=` (covers
	// `targetScope = '...'` with no space before `=`).
	end := len(line)
	for idx := 0; idx < len(line); idx++ {
		c := line[idx]
		if c == ' ' || c == '\t' || c == '=' {
			end = idx
			break
		}
	}
	return knownKeywords[line[:end]]
}
