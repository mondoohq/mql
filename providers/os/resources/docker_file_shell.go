// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"regexp"
	"strings"
)

// shellToken is a single lexed token from a shell script. Operator tokens
// (&&, ||, ;, |, &, newline) separate commands; everything else is a word.
type shellToken struct {
	text string
	op   bool
}

// lexShell tokenizes a shell command line into words and operators. It honors
// single quotes (literal), double quotes (with backslash escapes for " \ $ `),
// backslash escapes, line continuations, and `#` comments. It is intentionally
// lightweight: it does not interpret subshells, command substitutions, or
// redirections, treating their characters as ordinary word content.
func lexShell(s string) []shellToken {
	var toks []shellToken
	var buf strings.Builder
	wordInProgress := false

	flush := func() {
		if wordInProgress {
			toks = append(toks, shellToken{text: buf.String()})
			buf.Reset()
			wordInProgress = false
		}
	}

	runes := []rune(s)
	n := len(runes)
	for i := 0; i < n; {
		c := runes[i]
		switch c {
		case ' ', '\t', '\r':
			flush()
			i++
		case '\n', ';':
			flush()
			toks = append(toks, shellToken{text: string(c), op: true})
			i++
		case '&':
			flush()
			if i+1 < n && runes[i+1] == '&' {
				toks = append(toks, shellToken{text: "&&", op: true})
				i += 2
			} else {
				toks = append(toks, shellToken{text: "&", op: true})
				i++
			}
		case '|':
			flush()
			if i+1 < n && runes[i+1] == '|' {
				toks = append(toks, shellToken{text: "||", op: true})
				i += 2
			} else {
				toks = append(toks, shellToken{text: "|", op: true})
				i++
			}
		case '#':
			if wordInProgress {
				buf.WriteRune(c)
				i++
				continue
			}
			// a comment runs to the end of the line; the newline itself is
			// left for the next iteration to emit as a command separator
			for i < n && runes[i] != '\n' {
				i++
			}
		case '\'':
			wordInProgress = true
			i++
			for i < n && runes[i] != '\'' {
				buf.WriteRune(runes[i])
				i++
			}
			if i < n {
				i++ // closing quote
			}
		case '"':
			wordInProgress = true
			i++
			for i < n && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < n {
					nxt := runes[i+1]
					if nxt == '"' || nxt == '\\' || nxt == '$' || nxt == '`' {
						buf.WriteRune(nxt)
						i += 2
						continue
					}
				}
				buf.WriteRune(runes[i])
				i++
			}
			if i < n {
				i++ // closing quote
			}
		case '\\':
			if i+1 < n {
				if runes[i+1] == '\n' {
					i += 2 // line continuation
					continue
				}
				wordInProgress = true
				buf.WriteRune(runes[i+1])
				i += 2
			} else {
				i++
			}
		default:
			wordInProgress = true
			buf.WriteRune(c)
			i++
		}
	}
	flush()
	return toks
}

var shellEnvAssignment = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)

// stripEnvAssignments removes leading VAR=value tokens (e.g. the
// `DEBIAN_FRONTEND=noninteractive` prefix on `apt-get install`) so the first
// remaining token is the executable. It stops at the first non-assignment.
func stripEnvAssignments(argv []string) []string {
	i := 0
	for i < len(argv) && shellEnvAssignment.MatchString(argv[i]) {
		i++
	}
	return argv[i:]
}

// parseShellCommands splits a shell script into individual commands on the
// top-level operators &&, ||, ;, |, & and newlines, then returns the argv of
// each command with any leading environment assignments removed. Empty
// commands are dropped.
func parseShellCommands(script string) [][]string {
	toks := lexShell(script)

	var cmds [][]string
	var cur []string
	push := func() {
		argv := stripEnvAssignments(cur)
		if len(argv) > 0 {
			cmds = append(cmds, argv)
		}
		cur = nil
	}

	for _, t := range toks {
		if t.op {
			push()
			continue
		}
		cur = append(cur, t.text)
	}
	push()

	return cmds
}
