// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package bind9

import (
	"fmt"
	"strings"
)

type tokenKind int

const (
	tokenWord tokenKind = iota
	tokenOpenBrace
	tokenCloseBrace
	tokenSemicolon
)

type token struct {
	kind tokenKind
	text string
	line int
	// quoted records that the word arrived in double quotes, so an empty
	// quoted string stays an argument rather than disappearing.
	quoted bool
}

// tokenize splits configuration text into words, braces and semicolons,
// dropping comments and whitespace.
//
// named accepts three comment spellings: `//` and `#` to end of line, and
// `/* */` spanning lines. A `#` or `//` inside a quoted string is data, not a
// comment, which is why quoting is handled here rather than by a pre-pass that
// strips comments line by line.
func tokenize(input, file string) []token {
	var tokens []token
	line := 1
	i := 0
	n := len(input)

	flush := func(buf *strings.Builder, startLine int, quoted bool) {
		if buf.Len() == 0 && !quoted {
			return
		}
		tokens = append(tokens, token{kind: tokenWord, text: buf.String(), line: startLine, quoted: quoted})
		buf.Reset()
	}

	var buf strings.Builder
	wordLine := line

	for i < n {
		c := input[i]

		switch {
		// line comment
		case c == '#' || (c == '/' && i+1 < n && input[i+1] == '/'):
			flush(&buf, wordLine, false)
			for i < n && input[i] != '\n' {
				i++
			}

		// block comment
		case c == '/' && i+1 < n && input[i+1] == '*':
			flush(&buf, wordLine, false)
			i += 2
			for i < n {
				if input[i] == '*' && i+1 < n && input[i+1] == '/' {
					i += 2
					break
				}
				if input[i] == '\n' {
					line++
				}
				i++
			}

		// quoted string
		case c == '"':
			flush(&buf, wordLine, false)
			i++
			start := line
			var q strings.Builder
			for i < n && input[i] != '"' {
				// named has no escape sequences inside quoted strings other
				// than a backslash before the closing quote; keep the bytes as
				// they are so a path or a base64 secret survives intact.
				if input[i] == '\\' && i+1 < n && input[i+1] == '"' {
					q.WriteByte('"')
					i += 2
					continue
				}
				if input[i] == '\n' {
					line++
				}
				q.WriteByte(input[i])
				i++
			}
			i++ // closing quote, or end of input on an unterminated string
			tokens = append(tokens, token{kind: tokenWord, text: q.String(), line: start, quoted: true})

		case c == '{':
			flush(&buf, wordLine, false)
			tokens = append(tokens, token{kind: tokenOpenBrace, text: "{", line: line})
			i++

		case c == '}':
			flush(&buf, wordLine, false)
			tokens = append(tokens, token{kind: tokenCloseBrace, text: "}", line: line})
			i++

		case c == ';':
			flush(&buf, wordLine, false)
			tokens = append(tokens, token{kind: tokenSemicolon, text: ";", line: line})
			i++

		case c == ' ' || c == '\t' || c == '\r' || c == '\n':
			flush(&buf, wordLine, false)
			if c == '\n' {
				line++
			}
			i++

		default:
			if buf.Len() == 0 {
				wordLine = line
			}
			buf.WriteByte(c)
			i++
		}
	}
	flush(&buf, wordLine, false)
	return tokens
}

// parseStatements turns a token stream into statements. Errors are collected
// and parsing continues: an unbalanced brace late in a file should not cost the
// reader every answer the file gives before it.
func parseStatements(tokens []token, file string) ([]Statement, []error) {
	stmts, errs, pos := parseBlock(tokens, 0, file, false)
	if pos < len(tokens) {
		errs = append(errs, fmt.Errorf("%s:%d: unexpected %q", file, tokens[pos].line, tokens[pos].text))
	}
	return stmts, errs
}

func parseBlock(tokens []token, pos int, file string, inBlock bool) ([]Statement, []error, int) {
	var stmts []Statement
	var errs []error

	for pos < len(tokens) {
		t := tokens[pos]

		switch t.kind {
		case tokenCloseBrace:
			if inBlock {
				return stmts, errs, pos + 1
			}
			errs = append(errs, fmt.Errorf("%s:%d: unmatched closing brace", file, t.line))
			pos++
			continue

		case tokenSemicolon:
			// a stray semicolon between statements is harmless
			pos++
			continue

		case tokenOpenBrace:
			errs = append(errs, fmt.Errorf("%s:%d: block without a statement name", file, t.line))
			_, blockErrs, next := parseBlock(tokens, pos+1, file, true)
			errs = append(errs, blockErrs...)
			pos = next
			continue
		}

		stmt := Statement{Name: t.text, File: file, Line: t.line}
		pos++

		// arguments up to the block, the semicolon, or the end
		for pos < len(tokens) && tokens[pos].kind == tokenWord {
			stmt.Args = append(stmt.Args, tokens[pos].text)
			pos++
		}

		if pos < len(tokens) && tokens[pos].kind == tokenOpenBrace {
			block, blockErrs, next := parseBlock(tokens, pos+1, file, true)
			errs = append(errs, blockErrs...)
			// an empty block is still a block, so never leave this nil
			if block == nil {
				block = []Statement{}
			}
			stmt.Block = block
			pos = next
		}

		// the terminating semicolon; a missing one at end of file is worth
		// reporting because it usually means the file was truncated
		if pos < len(tokens) && tokens[pos].kind == tokenSemicolon {
			pos++
		} else if pos >= len(tokens) && !inBlock {
			errs = append(errs, fmt.Errorf("%s:%d: %q is not terminated with a semicolon", file, stmt.Line, stmt.Name))
		}

		stmts = append(stmts, stmt)
	}

	if inBlock {
		errs = append(errs, fmt.Errorf("%s: block opened but never closed", file))
	}
	return stmts, errs, pos
}
