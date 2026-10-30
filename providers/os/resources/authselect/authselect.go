// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package authselect reads authselect's configuration and generates a
// profile's files from its templates the way authselect does.
// see https://github.com/authselect/authselect/blob/main/src/lib/util/template.c
package authselect

import (
	"bytes"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode"
)

const CustomPrefix = "custom/"

// Config is the content of /etc/authselect/authselect.conf: the selected
// profile on the first line, one enabled feature on each line after it.
type Config struct {
	ProfileID string
	Features  []string
}

// ParseConfig reads authselect.conf. Lines are trimmed, and empty lines and
// comments are skipped. ok is false when no profile is named, which
// authselect treats as no configuration.
func ParseConfig(content string) (cfg Config, ok bool) {
	lines := significantLines(content)
	if len(lines) == 0 {
		return Config{}, false
	}
	cfg.ProfileID = lines[0]
	cfg.Features = []string{}
	for _, f := range lines[1:] {
		if !slices.Contains(cfg.Features, f) {
			cfg.Features = append(cfg.Features, f)
		}
	}
	return cfg, true
}

// IsCustom reports whether a profile ID names a custom profile.
func IsCustom(profileID string) bool {
	return strings.HasPrefix(profileID, CustomPrefix)
}

// Line is one line of a generated file and the zero-based line of the
// template it came from.
type Line struct {
	Source int
	Text   string
}

// Text joins generated lines into file content.
func Text(lines []Line) string {
	texts := make([]string, len(lines))
	for i := range lines {
		texts[i] = lines[i].Text
	}
	return strings.Join(texts, "\n")
}

// operatorRe matches one template operator. Operators never span lines.
//
//	{include if EXPR} {exclude if EXPR} {continue if EXPR} {stop if EXPR}
//	{if EXPR:TRUE} {if EXPR:TRUE|FALSE}
//	{imply "FEATURE" if EXPR}
var operatorRe = regexp.MustCompile(`\{(?:` +
	`(continue if|stop if|include if|exclude if) ([^{}|:\n]+)` +
	`|if ([^{}|:\n]+):([^{}|\n]*)(?:\|([^{}|\n]*))?` +
	`|imply "([^{}"|\n]+)" if ([^{}|:\n]+)` +
	`)\}`)

// Generate applies features to a template. Lines an operator removes are
// left out; every kept line is trimmed on the right. Features a template
// implies apply to the lines after the `{imply ...}` line.
func Generate(template string, features []string) ([]Line, error) {
	enabled := make(map[string]bool, len(features))
	for _, f := range features {
		enabled[f] = true
	}

	out := []Line{}
	for i, line := range strings.Split(template, "\n") {
		text, keep, stop, err := generateLine(line, enabled)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
		if keep {
			out = append(out, Line{Source: i, Text: strings.TrimRightFunc(text, unicode.IsSpace)})
		}
		if stop {
			break
		}
	}
	return out, nil
}

// generateLine resolves the operators of one line. keep is false when the
// line is removed; stop is true when nothing after this point is generated,
// in which case the text before the operator is still kept.
func generateLine(line string, enabled map[string]bool) (text string, keep, stop bool, err error) {
	var b strings.Builder
	rest := line
	for {
		m := operatorRe.FindStringSubmatchIndex(rest)
		if m == nil {
			b.WriteString(rest)
			return b.String(), true, false, nil
		}
		b.WriteString(rest[:m[0]])
		group := func(n int) string {
			if m[2*n] < 0 {
				return ""
			}
			return rest[m[2*n]:m[2*n+1]]
		}

		switch {
		case m[2] >= 0: // line operators
			on, err := Evaluate(group(2), enabled)
			if err != nil {
				return "", false, false, err
			}
			switch group(1) {
			case "include if":
				if !on {
					return "", false, false, nil
				}
			case "exclude if":
				if on {
					return "", false, false, nil
				}
			case "continue if":
				if on {
					return "", false, false, nil
				}
				return b.String(), true, true, nil
			case "stop if":
				if !on {
					return "", false, false, nil
				}
				return b.String(), true, true, nil
			}
		case m[6] >= 0: // {if EXPR:TRUE|FALSE}
			on, err := Evaluate(group(3), enabled)
			if err != nil {
				return "", false, false, err
			}
			if on {
				b.WriteString(group(4))
			} else {
				b.WriteString(group(5))
			}
		default: // {imply "FEATURE" if EXPR}
			on, err := Evaluate(group(7), enabled)
			if err != nil {
				return "", false, false, err
			}
			if on {
				enabled[group(6)] = true
			}
			return "", false, false, nil
		}
		rest = rest[m[1]:]
	}
}

var errExpression = errors.New("invalid expression")

// Evaluate evaluates a template condition such as `"with-faillock"` or
// `not "a" and ("b" or "c")` against the enabled features. As in authselect,
// `and` and `or` have the same precedence and apply from left to right, and
// the keywords are case-insensitive. A character that starts no token ends
// the expression.
func Evaluate(expression string, enabled map[string]bool) (bool, error) {
	e := &evaluator{s: expression, enabled: enabled}
	res, err := e.expr(0)
	if err != nil {
		return false, fmt.Errorf("%w %q", err, expression)
	}
	return res, nil
}

type evaluator struct {
	s       string
	pos     int
	enabled map[string]bool
}

type token int

const (
	tokEnd token = iota
	tokFeature
	tokOpen
	tokClose
	tokAnd
	tokOr
	tokNot
)

// next returns the next token and, for a feature, its name.
func (e *evaluator) next() (token, string, error) {
	for e.pos < len(e.s) && (e.s[e.pos] == ' ' || e.s[e.pos] == '\t') {
		e.pos++
	}
	if e.pos >= len(e.s) {
		return tokEnd, "", nil
	}
	switch e.s[e.pos] {
	case '(':
		e.pos++
		return tokOpen, "", nil
	case ')':
		e.pos++
		return tokClose, "", nil
	case '"':
		end := strings.IndexByte(e.s[e.pos+1:], '"')
		if end < 0 {
			return tokEnd, "", errExpression
		}
		name := e.s[e.pos+1 : e.pos+1+end]
		e.pos += end + 2
		return tokFeature, name, nil
	default:
		start := e.pos
		for e.pos < len(e.s) && isASCIILetter(e.s[e.pos]) {
			e.pos++
		}
		switch strings.ToLower(e.s[start:e.pos]) {
		case "":
			return tokEnd, "", nil
		case "and":
			return tokAnd, "", nil
		case "or":
			return tokOr, "", nil
		case "not":
			return tokNot, "", nil
		}
		return tokEnd, "", errExpression
	}
}

func isASCIILetter(c byte) bool {
	return ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z')
}

// expr reads operands joined by `and`/`or` until the end of the expression,
// or until the `)` that closes this depth.
func (e *evaluator) expr(depth int) (bool, error) {
	var result bool
	op := tokEnd // no operator before the first operand
	negate := false
	wantOperand := true

	for {
		tok, name, err := e.next()
		if err != nil {
			return false, err
		}

		if wantOperand {
			var v bool
			switch tok {
			case tokNot:
				negate = !negate
				continue
			case tokFeature:
				v = e.enabled[name]
			case tokOpen:
				if v, err = e.expr(depth + 1); err != nil {
					return false, err
				}
			default:
				return false, errExpression
			}
			if negate {
				v = !v
			}
			switch op {
			case tokAnd:
				result = result && v
			case tokOr:
				result = result || v
			default:
				result = v
			}
			negate = false
			wantOperand = false
			continue
		}

		switch tok {
		case tokAnd, tokOr:
			op = tok
			wantOperand = true
		case tokClose:
			if depth == 0 {
				return false, errExpression
			}
			return result, nil
		case tokEnd:
			if depth != 0 {
				return false, errExpression
			}
			return result, nil
		default:
			return false, errExpression
		}
	}
}

const UserNsswitchPath = "/etc/authselect/user-nsswitch.conf"

// userNsswitchMarker is part of the comment authselect writes at the top of
// a nsswitch.conf it merged with user-nsswitch.conf. Only a build with that
// merge (RHEL before 10, Fedora before 36) carries it.
var userNsswitchMarker = []byte("user-nsswitch.conf and run 'authselect apply-changes'")

// MergesUserNsswitch reports whether the authselect library merges
// user-nsswitch.conf into the nsswitch.conf it generates.
func MergesUserNsswitch(library []byte) bool {
	return bytes.Contains(library, userNsswitchMarker)
}

var nsswitchMapRe = regexp.MustCompile(`^\s*([^\s:]+):`)

// MergeUserNsswitch appends to a generated nsswitch.conf the lines of
// user-nsswitch.conf whose map the profile does not set. As in authselect, a
// user map is dropped when a profile map starts with its name, so `auto:`
// gives way to the profile's `automount:`.
func MergeUserNsswitch(generated, user string) string {
	var profileMaps []string
	for line := range strings.SplitSeq(generated, "\n") {
		if m := nsswitchMapRe.FindStringSubmatch(line); m != nil {
			profileMaps = append(profileMaps, m[1])
		}
	}

	var kept strings.Builder
	for _, line := range strings.SplitAfter(user, "\n") {
		if m := nsswitchMapRe.FindStringSubmatch(line); m != nil &&
			slices.ContainsFunc(profileMaps, func(p string) bool { return strings.HasPrefix(p, m[1]) }) {
			continue
		}
		kept.WriteString(line)
	}
	if kept.Len() == 0 {
		return generated
	}
	return generated + "\n# Included from " + UserNsswitchPath + "\n\n" + kept.String()
}

// SameContent reports whether a written file holds the expected content,
// ignoring comments, empty lines and the spaces around each line, as
// authselect does when it validates the files it generated.
func SameContent(written, expected string) bool {
	return slices.Equal(significantLines(written), significantLines(expected))
}

// significantLines splits content into trimmed lines, skipping empty lines
// and comments.
func significantLines(content string) []string {
	var lines []string
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines
}
