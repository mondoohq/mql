// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package versionx

import (
	"errors"
	"strconv"
	"strings"
)

// Constraint is one version bound, e.g. ">= 1.2.3" or "^1.4". Build them with
// [ParseConstraint] and test with [Constraint.Check]; [Satisfies] does both for a list.
//
// Because the bounds compare through [Version.Compare], a constraint works on every
// version shape this package accepts — a four-component version and an epoch'd deb
// version are range-checkable, where a semver-only implementation had to error out.
type Constraint struct {
	src string
	op  string
	ver Version
	// hi is the exclusive upper bound of a shorthand range (^, ~, 1.2.x); zero for
	// the plain operators.
	hi     Version
	ranged bool
}

// operators are matched longest-first so that ">=" is never read as ">" followed by a
// junk "=" in the version.
var operators = []string{">=", "<=", "!=", "==", "~>", ">", "<", "=", "^", "~"}

// ParseConstraint reads a single bound. Supported forms:
//
//	>= 1.2.3   > 1.2.3   <= 1.2.3   < 1.2.3   = 1.2.3   == 1.2.3   != 1.2.3
//	^1.2.3     (>= 1.2.3, < 2.0.0 — and < 0.3.0 for ^0.2.3, npm's 0.x rule)
//	~1.2.3     (>= 1.2.3, < 1.3.0)    ~>1.2.3 is a synonym
//	1.2.x      (>= 1.2.0, < 1.3.0)    "1.2.*" and a bare "x" for "anything"
//	1.2.3      (exact, compared semantically: "1.2" equals "1.2.0")
//
// Prereleases are not treated specially: "< 2.0.0" admits "2.0.0-rc1" because that
// version really is below 2.0.0. Callers wanting npm's exclude-prereleases behavior
// should say so in the range.
func ParseConstraint(s string) (Constraint, error) {
	c := Constraint{src: s}

	rest := strings.TrimSpace(s)
	if rest == "" {
		return c, errors.New("empty version constraint")
	}

	for _, op := range operators {
		if strings.HasPrefix(rest, op) {
			c.op = op
			rest = strings.TrimSpace(rest[len(op):])
			break
		}
	}
	if rest == "" {
		return c, errors.New("version constraint '" + s + "' has no version")
	}
	// A second operator means the caller stacked one bound on another (">= ^1.2.3",
	// which a caller that defaults bare bounds to ">=" produces from "^1.2.3"). Left
	// alone it parses as a comparison against the nonsense version "^1.2.3" and
	// answers cheerfully, so it is rejected here instead.
	if strings.ContainsAny(rest[:1], "<>=!^~") {
		return c, errors.New("version constraint '" + s + "' stacks two operators")
	}

	switch c.op {
	case "^", "~", "~>":
		lo, hi, err := shorthandBounds(c.op, rest)
		if err != nil {
			return c, err
		}
		c.ver, c.hi, c.ranged = lo, hi, true
		return c, nil
	case "":
		// A wildcard is only meaningful without an operator ("< 1.2.x" is not a bound
		// anyone can act on), so it is resolved here and nowhere else.
		if lo, hi, ok := wildcardBounds(rest); ok {
			c.ver, c.hi, c.ranged = lo, hi, true
			return c, nil
		}
		c.op = "="
	}

	c.ver = Parse(rest)
	if c.ver.IsZero() {
		return c, errors.New("version constraint '" + s + "' has no version")
	}
	return c, nil
}

// Check reports whether v satisfies the constraint.
func (c Constraint) Check(v Version) bool {
	if c.ranged {
		if c.hi.IsZero() { // a bare "x": everything matches
			return v.Compare(c.ver) >= 0
		}
		return v.Compare(c.ver) >= 0 && v.Compare(c.hi) < 0
	}

	cmp := v.Compare(c.ver)
	switch c.op {
	case ">":
		return cmp > 0
	case ">=":
		return cmp >= 0
	case "<":
		return cmp < 0
	case "<=":
		return cmp <= 0
	case "!=":
		return cmp != 0
	default: // "=", "=="
		return cmp == 0
	}
}

// String returns the constraint as it was written.
func (c Constraint) String() string { return c.src }

// Satisfies reports whether v meets every constraint (they AND together). An
// unparseable constraint is an error, not a silent false — a typo'd bound that quietly
// matched nothing would read as "no version qualifies".
func Satisfies(v Version, constraints ...string) (bool, error) {
	for _, s := range constraints {
		c, err := ParseConstraint(s)
		if err != nil {
			return false, err
		}
		if !c.Check(v) {
			return false, nil
		}
	}
	return true, nil
}

// NeedsOperator reports whether s is a BARE version — it names no comparison operator
// and is not a range shorthand or wildcard, so it carries no bound of its own. Callers
// that default a bare bound to ">=" or "<=" (MQL's inRange does) must ask this first:
// prefixing an operator onto "^1.2.3" or "1.2.x" produces a constraint that compares
// against a nonsense version rather than the range the author wrote.
func NeedsOperator(s string) bool {
	rest := strings.TrimSpace(s)
	if rest == "" {
		return false
	}
	for _, op := range operators {
		if strings.HasPrefix(rest, op) {
			return false
		}
	}
	if _, _, ok := wildcardBounds(rest); ok {
		return false
	}
	return true
}

// shorthandBounds expands ^ / ~ / ~> into the half-open range they stand for.
func shorthandBounds(op, s string) (lo, hi Version, err error) {
	lo = Parse(s)
	if lo.IsZero() {
		return lo, hi, errors.New("version constraint '" + op + s + "' has no version")
	}

	parts, ok := numericRelease(lo.release)
	if !ok {
		return lo, hi, errors.New("version constraint '" + op + s + "' needs a numeric version")
	}

	var bound []int
	switch {
	case op == "^" && parts[0] == 0 && len(parts) > 2 && parts[1] == 0:
		// ^0.0.z pins the patch: npm treats every 0.0.z as its own incompatible line.
		bound = []int{0, 0, parts[2] + 1}
	case op == "^" && parts[0] == 0 && len(parts) > 1:
		bound = []int{0, parts[1] + 1, 0}
	case op == "^":
		bound = []int{parts[0] + 1, 0, 0}
	case len(parts) > 1: // ~1.2 / ~1.2.3 — the minor is the line
		bound = []int{parts[0], parts[1] + 1, 0}
	default: // ~1 — only the major is pinned
		bound = []int{parts[0] + 1, 0, 0}
	}

	return lo, Parse(joinVersion(lo.epoch, bound)), nil
}

// wildcardBounds expands "1.2.x" / "1.*" / "x" into a half-open range. ok is false when
// the string carries no wildcard, which is the common case.
func wildcardBounds(s string) (lo, hi Version, ok bool) {
	parts := strings.Split(s, ".")
	idx := -1
	for i, p := range parts {
		if p == "x" || p == "X" || p == "*" {
			idx = i
			break
		}
	}
	if idx < 0 {
		return lo, hi, false
	}

	fixed := make([]int, 0, idx)
	for _, p := range parts[:idx] {
		n, err := strconv.Atoi(p)
		if err != nil {
			return lo, hi, false
		}
		fixed = append(fixed, n)
	}
	if len(fixed) == 0 { // a bare "x" — every version qualifies
		return Parse("0"), Version{}, true
	}

	lower := append(append([]int(nil), fixed...), 0, 0)[:3]
	upper := append([]int(nil), fixed...)
	upper[len(upper)-1]++
	for len(upper) < 3 {
		upper = append(upper, 0)
	}
	return Parse(joinVersion(0, lower)), Parse(joinVersion(0, upper)), true
}

// numericRelease reads a release as plain integers. It refuses anything that is not
// purely numeric ("1.1.1k"), because "the next major after 1.1.1k" has no answer.
func numericRelease(release string) ([]int, bool) {
	parts := strings.Split(release, ".")
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, false
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil, false
	}
	return out, true
}

// joinVersion renders numeric components back into a version string, carrying the
// epoch so a bound stays comparable with the version it was derived from.
func joinVersion(epoch int, parts []int) string {
	var b strings.Builder
	if epoch > 0 {
		b.WriteString(strconv.Itoa(epoch))
		b.WriteByte(':')
	}
	for i, p := range parts {
		if i > 0 {
			b.WriteByte('.')
		}
		b.WriteString(strconv.Itoa(p))
	}
	return b.String()
}
