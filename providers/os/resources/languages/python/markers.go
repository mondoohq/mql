// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package python

import (
	"regexp"
	"strconv"
	"strings"
)

// MarkerEnvironment holds the PEP 508 environment marker variables known for
// one installation, such as python_version or sys_platform. A variable missing
// from the map is unknown, and a marker that depends on it may hold.
type MarkerEnvironment map[string]string

// pythonVersionSegment finds the interpreter version in a site-packages path:
// /usr/lib/python3.11/site-packages, /opt/venv/lib/python3.9/site-packages.
// Debian's /usr/lib/python3/dist-packages names only the major version. That
// still decides a comparison like python_version < "3" and leaves one like
// python_version < "3.8" unknown, see compareMarkerVersions.
var pythonVersionSegment = regexp.MustCompile(`(?:^|/)(?:python|pypy)(\d+(?:\.\d+)?)(?:/|$)`)

// SiteMarkerEnvironment returns the marker variables known for packages
// installed under path on an OS of the given family ("linux", "darwin",
// "windows" or "" when unknown).
//
// extra is always "": the metadata does not record which extras were asked
// for when a package was installed, and a requirement that only an extra
// brings in is optional.
func SiteMarkerEnvironment(path string, osFamily string) MarkerEnvironment {
	env := MarkerEnvironment{"extra": ""}
	if m := pythonVersionSegment.FindStringSubmatch(strings.ReplaceAll(path, "\\", "/")); m != nil {
		env["python_version"] = m[1]
	}
	switch osFamily {
	case "linux":
		env["sys_platform"] = "linux"
		env["platform_system"] = "Linux"
		env["os_name"] = "posix"
	case "darwin":
		env["sys_platform"] = "darwin"
		env["platform_system"] = "Darwin"
		env["os_name"] = "posix"
	case "windows":
		env["sys_platform"] = "win32"
		env["platform_system"] = "Windows"
		env["os_name"] = "nt"
	}
	return env
}

// requirementName matches the project name at the start of a PEP 508
// requirement. The name can be followed directly by extras, a version
// specifier, a marker or nothing: "requests>=2", "idna (<4,>=2.5)",
// "zope.interface[test]", "pywin32; sys_platform == 'win32'".
var requirementName = regexp.MustCompile(`^\s*([A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)`)

// ParseRequirement splits a PEP 508 requirement into its project name and its
// environment marker, the text after ";". Both are "" when absent; the name is
// "" when the requirement does not start with one.
func ParseRequirement(req string) (name string, marker string) {
	spec, marker, _ := strings.Cut(req, ";")
	if m := requirementName.FindStringSubmatch(spec); m != nil {
		name = m[1]
	}
	return name, strings.TrimSpace(marker)
}

// MarkerMayHold evaluates a PEP 508 environment marker and reports false only
// when it is false in env. A marker that depends on an unknown variable, or
// that cannot be parsed, may hold.
func MarkerMayHold(marker string, env MarkerEnvironment) bool {
	if strings.TrimSpace(marker) == "" {
		return true
	}
	p := &markerParser{tokens: tokenizeMarker(marker), env: env}
	res, ok := p.parseOr()
	if !ok || p.pos != len(p.tokens) {
		return true
	}
	return res != triFalse
}

type tri int8

const (
	triFalse tri = iota
	triTrue
	triUnknown
)

func triOf(b bool) tri {
	if b {
		return triTrue
	}
	return triFalse
}

type markerToken struct {
	text   string
	quoted bool
}

// markerTokenRegex splits a marker into quoted strings, operators,
// parentheses and words (variables and the keywords and, or, in, not).
var markerTokenRegex = regexp.MustCompile(`"[^"]*"|'[^']*'|===|==|!=|<=|>=|~=|<|>|\(|\)|[A-Za-z0-9_.]+`)

func tokenizeMarker(marker string) []markerToken {
	raw := markerTokenRegex.FindAllString(marker, -1)
	res := make([]markerToken, 0, len(raw))
	for _, t := range raw {
		if len(t) >= 2 && (t[0] == '"' || t[0] == '\'') {
			res = append(res, markerToken{text: t[1 : len(t)-1], quoted: true})
			continue
		}
		res = append(res, markerToken{text: t})
	}
	return res
}

type markerParser struct {
	tokens []markerToken
	pos    int
	env    MarkerEnvironment
}

func (p *markerParser) peek(word string) bool {
	return p.pos < len(p.tokens) && !p.tokens[p.pos].quoted && p.tokens[p.pos].text == word
}

func (p *markerParser) parseOr() (tri, bool) {
	res, ok := p.parseAnd()
	if !ok {
		return triUnknown, false
	}
	for p.peek("or") {
		p.pos++
		rhs, ok := p.parseAnd()
		if !ok {
			return triUnknown, false
		}
		switch {
		case res == triTrue || rhs == triTrue:
			res = triTrue
		case res == triUnknown || rhs == triUnknown:
			res = triUnknown
		default:
			res = triFalse
		}
	}
	return res, true
}

func (p *markerParser) parseAnd() (tri, bool) {
	res, ok := p.parseExpr()
	if !ok {
		return triUnknown, false
	}
	for p.peek("and") {
		p.pos++
		rhs, ok := p.parseExpr()
		if !ok {
			return triUnknown, false
		}
		switch {
		case res == triFalse || rhs == triFalse:
			res = triFalse
		case res == triUnknown || rhs == triUnknown:
			res = triUnknown
		default:
			res = triTrue
		}
	}
	return res, true
}

func (p *markerParser) parseExpr() (tri, bool) {
	if p.peek("(") {
		p.pos++
		res, ok := p.parseOr()
		if !ok || !p.peek(")") {
			return triUnknown, false
		}
		p.pos++
		return res, true
	}
	// lhs, operator, rhs; "not in" is two tokens
	if p.pos+3 > len(p.tokens) {
		return triUnknown, false
	}
	lhs := p.tokens[p.pos]
	op := p.tokens[p.pos+1].text
	p.pos += 2
	if op == "not" {
		if !p.peek("in") || p.pos+2 > len(p.tokens) {
			return triUnknown, false
		}
		p.pos++
		op = "not in"
	}
	rhs := p.tokens[p.pos]
	p.pos++

	left, leftOK := p.value(lhs)
	right, rightOK := p.value(rhs)
	if !leftOK || !rightOK {
		return triUnknown, true
	}
	switch {
	case !lhs.quoted && markerVersionVariables[lhs.text]:
		return compareMarker(true, left, op, right, true), true
	case !rhs.quoted && markerVersionVariables[rhs.text]:
		return compareMarker(true, left, op, right, false), true
	}
	return compareMarker(false, left, op, right, false), true
}

// value resolves a token to its string: a quoted string as written, a
// variable from the environment.
func (p *markerParser) value(t markerToken) (string, bool) {
	if t.quoted {
		return t.text, true
	}
	v, ok := p.env[t.text]
	return v, ok
}

// markerVersionVariables are compared as versions rather than strings.
var markerVersionVariables = map[string]bool{
	"python_version":         true,
	"python_full_version":    true,
	"implementation_version": true,
}

// compareMarker applies op. A version variable's value can be known only in
// part (python_version "3"), so its side is passed along: varLeft is true when
// the variable is on the left.
func compareMarker(isVersion bool, left, op, right string, varLeft bool) tri {
	// "in" compares strings: a partly known python_version ("3") is a
	// substring of "3.4 3.5" whatever the minor version is, so it decides
	// nothing
	if isVersion && (op == "in" || op == "not in") {
		known := left
		if !varLeft {
			known = right
		}
		if !strings.Contains(known, ".") {
			return triUnknown
		}
	}
	switch op {
	case "in":
		return triOf(strings.Contains(right, left))
	case "not in":
		return triOf(!strings.Contains(right, left))
	case "===":
		return triOf(left == right)
	}
	if isVersion {
		if res, ok := compareMarkerVersions(left, op, right, varLeft); ok {
			return res
		}
	}
	switch op {
	case "==":
		return triOf(left == right)
	case "!=":
		return triOf(left != right)
	}
	return triUnknown
}

// compareMarkerVersions compares release versions such as "3.11" and "3.8",
// with "3.*" as a prefix match for == and !=. Anything with a pre-release or
// other suffix is not compared. When the variable's value has fewer parts than
// the other side and agrees with it as far as it goes ("3" against "3.8"), the
// answer is unknown.
func compareMarkerVersions(left, op, right string, varLeft bool) (tri, bool) {
	if prefix, ok := strings.CutSuffix(right, ".*"); ok && (op == "==" || op == "!=") {
		l, leftOK := parseMarkerVersion(left)
		r, rightOK := parseMarkerVersion(prefix)
		if !leftOK || !rightOK {
			return triUnknown, false
		}
		// a partly known version ("3") that agrees with the prefix as far as
		// it goes ("3.8") may or may not match it
		if len(l) < len(r) && compareVersionParts(l, r[:len(l)]) == 0 {
			return triUnknown, true
		}
		match := len(l) >= len(r)
		for i := 0; match && i < len(r); i++ {
			match = l[i] == r[i]
		}
		return triOf(match == (op == "==")), true
	}
	l, leftOK := parseMarkerVersion(left)
	r, rightOK := parseMarkerVersion(right)
	if !leftOK || !rightOK {
		return triUnknown, false
	}
	known, other := l, r
	if !varLeft {
		known, other = r, l
	}
	if len(known) < len(other) && compareVersionParts(known, other[:len(known)]) == 0 {
		return triUnknown, true
	}
	c := compareVersionParts(l, r)
	switch op {
	case "==":
		return triOf(c == 0), true
	case "!=":
		return triOf(c != 0), true
	case "<":
		return triOf(c < 0), true
	case "<=":
		return triOf(c <= 0), true
	case ">":
		return triOf(c > 0), true
	case ">=":
		return triOf(c >= 0), true
	case "~=":
		// compatible release: >= right, and the same release up to right's
		// second-to-last part
		if len(r) < 2 {
			return triUnknown, false
		}
		if c < 0 {
			return triFalse, true
		}
		prefix := r[:len(r)-1]
		for i := range prefix {
			if i >= len(l) || l[i] != prefix[i] {
				return triFalse, true
			}
		}
		return triTrue, true
	}
	return triUnknown, false
}

func parseMarkerVersion(v string) ([]int, bool) {
	parts := strings.Split(strings.TrimSpace(v), ".")
	res := make([]int, len(parts))
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return nil, false
		}
		res[i] = n
	}
	return res, true
}

func compareVersionParts(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		var x, y int
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}
