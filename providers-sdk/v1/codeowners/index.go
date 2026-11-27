// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package codeowners

import (
	"slices"
	"strings"
	"unicode/utf8"
)

// Index answers Match and MatchRules for many paths against one file. It
// gives the same answers as the package functions and only skips rules that
// cannot match: a rule with a literal segment (`/services/api/`) is tried
// only for paths containing that segment, a rule whose last glob ends in a
// literal (`*.proto`) only for paths with a segment ending in it, and every
// other rule always.
//
// An Index is safe for concurrent use.
type Index struct {
	d        Dialect
	rules    []Rule
	matchers []*matcher
	bySeg    map[string][]int
	bySuffix map[string][]int
	always   []int
	// sections is the order in which sections first appear (GitLab).
	sections []string
}

// NewIndex builds an index over rules, which must be in file order.
func NewIndex(rules []Rule, d Dialect) *Index {
	x := &Index{
		d:        d,
		rules:    rules,
		matchers: make([]*matcher, len(rules)),
		bySeg:    map[string][]int{},
		bySuffix: map[string][]int{},
	}
	seen := map[string]bool{}
	for i := range rules {
		m := rules[i].matcher(d)
		x.matchers[i] = m
		if key := strings.ToLower(rules[i].Section); !seen[key] {
			seen[key] = true
			x.sections = append(x.sections, key)
		}
		if lit, ok := literalSegment(m); ok {
			x.bySeg[lit] = append(x.bySeg[lit], i)
		} else if suf, ok := literalSuffix(m); ok {
			x.bySuffix[suf] = append(x.bySuffix[suf], i)
		} else {
			x.always = append(x.always, i)
		}
	}
	return x
}

// literalSegment returns the last literal segment of the pattern, which the
// path must contain as a whole segment.
func literalSegment(m *matcher) (string, bool) {
	for i := len(m.segs) - 1; i >= 0; i-- {
		if m.segs[i].literal {
			return m.segs[i].text, true
		}
	}
	return "", false
}

// literalSuffix returns the literal text after the last wildcard of the last
// glob segment, which some path segment must end with.
func literalSuffix(m *matcher) (string, bool) {
	for i := len(m.segs) - 1; i >= 0; i-- {
		s := m.segs[i]
		if s.doubleStar {
			continue
		}
		j := len(s.toks)
		for j > 0 && s.toks[j-1].kind == tokChar {
			j--
		}
		if j == len(s.toks) {
			return "", false
		}
		var b strings.Builder
		for _, t := range s.toks[j:] {
			// A byte that is not UTF-8 compiles to U+FFFD, whose encoding
			// never appears in the path's raw bytes: keep such a rule in
			// always, where the matcher decides.
			if t.r == utf8.RuneError {
				return "", false
			}
			b.WriteRune(t.r)
		}
		return b.String(), true
	}
	return "", false
}

// candidates returns the indexes of the rules that can match segs, in file
// order.
func (x *Index) candidates(segs []string) []int {
	c := slices.Clone(x.always)
	for _, s := range segs {
		c = append(c, x.bySeg[s]...)
		if len(x.bySuffix) > 0 {
			for k := range len(s) {
				// Keys are whole runes, so only a rune start can begin one.
				if utf8.RuneStart(s[k]) {
					c = append(c, x.bySuffix[s[k:]]...)
				}
			}
		}
	}
	slices.Sort(c)
	return slices.Compact(c)
}

// MatchRules is MatchRules for the indexed rules.
func (x *Index) MatchRules(path string) []Rule {
	segs := splitPath(path)
	if len(segs) == 0 {
		return nil
	}
	c := x.candidates(segs)
	switch x.d {
	case GitHub:
		for i := len(c) - 1; i >= 0; i-- {
			if x.matchers[c[i]].matchPath(segs) {
				return []Rule{x.rules[c[i]]}
			}
		}
	case GitLab:
		best := map[string]int{}
		excluded := map[string]bool{}
		for _, i := range c {
			key := strings.ToLower(x.rules[i].Section)
			if excluded[key] || !x.matchers[i].matchPath(segs) {
				continue
			}
			if x.rules[i].Exclusion {
				excluded[key] = true
				continue
			}
			if b, ok := best[key]; !ok || x.rules[i].Line >= x.rules[b].Line {
				best[key] = i
			}
		}
		var out []Rule
		for _, key := range x.sections {
			if b, ok := best[key]; ok && !excluded[key] {
				out = append(out, x.rules[b])
			}
		}
		return out
	}
	return nil
}

// Match is Match for the indexed rules.
func (x *Index) Match(path string) []Owner {
	var owners []Owner
	for _, r := range x.MatchRules(path) {
		for _, name := range r.Owners {
			owners = append(owners, Owner{Name: name, Rule: r})
		}
	}
	return owners
}
