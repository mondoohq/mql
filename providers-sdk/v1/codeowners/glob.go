// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package codeowners

import (
	"strings"
	"unicode/utf8"
)

// matcher is a compiled CODEOWNERS pattern. It matches a repository-relative
// path split into its segments.
type matcher struct {
	segs []segment
	// dirOnly is set for a GitHub pattern with a trailing `/`: it matches the
	// files below a directory, never a file of that name.
	dirOnly bool
	// descend lets the pattern match everything below a directory it matches
	// (gitignore semantics, GitHub dialect).
	descend bool
	// trailingAll makes a final `**` segment match one or more segments
	// (gitignore semantics, GitHub dialect).
	trailingAll bool
}

// segment is one `/`-separated part of a pattern.
type segment struct {
	// doubleStar is a `**` segment that matches zero or more path segments.
	doubleStar bool
	// literal is set when the segment has no metacharacters; it is compared
	// with ==.
	literal bool
	text    string
	toks    []token
}

type tokenKind int

const (
	tokChar  tokenKind = iota
	tokAny             // ?
	tokStar            // *
	tokClass           // [...]
)

type token struct {
	kind   tokenKind
	r      rune
	negate bool
	ranges []runeRange
}

type runeRange struct{ lo, hi rune }

// compileGitHub compiles a pattern with gitignore semantics, the base GitHub
// documents for CODEOWNERS:
//
//   - a trailing `/` matches a directory, so the files below it;
//   - a pattern with a `/` at the start or in the middle is relative to the
//     repository root; any other pattern matches at any depth;
//   - a pattern that matches a directory matches everything below it, except
//     that a final `*` segment matches only the entries directly inside
//     (GitHub documents that `docs/*` does not match `docs/build-app/x.md`);
//   - `**` as a whole segment matches zero or more directories; a final `**`
//     matches everything below;
//   - `*` and `?` do not cross `/`; there is no escaping and no character class
//     (Parse rejects those patterns).
func compileGitHub(pattern string) *matcher {
	m := &matcher{trailingAll: true}
	p := pattern
	if strings.HasSuffix(p, "/") {
		m.dirOnly = true
		p = strings.TrimRight(p, "/")
	}
	anchored := strings.Contains(p, "/")
	p = strings.TrimLeft(p, "/")

	parts := splitSegments(p)
	if !anchored {
		parts = append([]string{"**"}, parts...)
	}
	for _, part := range parts {
		m.segs = append(m.segs, compileSegment(part, false))
	}
	m.descend = len(parts) == 0 || parts[len(parts)-1] != "*"
	return m
}

// compileGitLab compiles a pattern the way GitLab does: the pattern is
// normalized (`*` becomes `/**/*`, a leading `\#` becomes `#`, an escaped
// whitespace becomes a space, a pattern without a leading `/` gets `/**/`
// prepended, a trailing `/` gets `**/*` appended) and matched with Ruby's
// File.fnmatch under FNM_PATHNAME and FNM_DOTMATCH: `**/` matches zero or more
// directories, any other `**` behaves like `*`, `*` and `?` do not cross `/`,
// `[...]` is a character class and `\` escapes the next character.
func compileGitLab(pattern string) *matcher {
	m := &matcher{}
	norm := normalizeGitLab(pattern)
	parts := strings.Split(strings.TrimPrefix(norm, "/"), "/")
	for i, part := range parts {
		if part == "**" && i == len(parts)-1 {
			// fnmatch: `**` not followed by `/` is a plain `*`.
			m.segs = append(m.segs, compileSegment("*", true))
			continue
		}
		m.segs = append(m.segs, compileSegment(part, true))
	}
	return m
}

// normalizeGitLab mirrors the pattern normalization of GitLab's CODEOWNERS
// parser.
func normalizeGitLab(pattern string) string {
	if pattern == "*" {
		return "/**/*"
	}
	if strings.HasPrefix(pattern, `\#`) {
		pattern = pattern[1:]
	}
	pattern = unescapeWhitespace(pattern)
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/**/" + pattern
	}
	if strings.HasSuffix(pattern, "/") {
		pattern += "**/*"
	}
	return pattern
}

// unescapeWhitespace replaces every backslash followed by a run of whitespace
// with one space.
func unescapeWhitespace(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && isSpace(s[i+1]) {
			b.WriteByte(' ')
			i++
			for i+1 < len(s) && isSpace(s[i+1]) {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isSpace(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\v', '\f', '\r':
		return true
	}
	return false
}

func splitSegments(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// compileSegment compiles one segment. gitlab enables character classes and
// backslash escapes.
func compileSegment(s string, gitlab bool) segment {
	if s == "**" {
		return segment{doubleStar: true, text: s}
	}
	meta := "*?"
	if gitlab {
		meta = `*?[\`
	}
	if !strings.ContainsAny(s, meta) {
		return segment{literal: true, text: s}
	}
	seg := segment{text: s}
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == '*':
			// Consecutive stars are one star within a segment.
			if n := len(seg.toks); n == 0 || seg.toks[n-1].kind != tokStar {
				seg.toks = append(seg.toks, token{kind: tokStar})
			}
			i += size
		case r == '?':
			seg.toks = append(seg.toks, token{kind: tokAny})
			i += size
		case gitlab && r == '\\' && i+size < len(s):
			e, esize := utf8.DecodeRuneInString(s[i+size:])
			seg.toks = append(seg.toks, token{kind: tokChar, r: e})
			i += size + esize
		case gitlab && r == '[':
			if tok, n, ok := parseClass(s[i:]); ok {
				seg.toks = append(seg.toks, tok)
				i += n
				continue
			}
			// An unclosed bracket is a literal.
			seg.toks = append(seg.toks, token{kind: tokChar, r: r})
			i += size
		default:
			seg.toks = append(seg.toks, token{kind: tokChar, r: r})
			i += size
		}
	}
	return seg
}

// parseClass parses a bracket expression at the start of s, such as `[a-z]`,
// `[!0-9]` or `[^.]`, and returns the token and the bytes consumed.
func parseClass(s string) (token, int, bool) {
	tok := token{kind: tokClass}
	i := 1
	if i < len(s) && (s[i] == '!' || s[i] == '^') {
		tok.negate = true
		i++
	}
	first := true
	for i < len(s) {
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == ']' && !first {
			return tok, i + size, true
		}
		first = false
		if r == '\\' && i+size < len(s) {
			i += size
			r, size = utf8.DecodeRuneInString(s[i:])
		}
		i += size
		lo, hi := r, r
		if i+1 < len(s) && s[i] == '-' && s[i+1] != ']' {
			h, hsize := utf8.DecodeRuneInString(s[i+1:])
			if h == '\\' && i+1+hsize < len(s) {
				h, hsize = utf8.DecodeRuneInString(s[i+1+hsize:])
				hsize++
			}
			hi = h
			i += 1 + hsize
		}
		tok.ranges = append(tok.ranges, runeRange{lo, hi})
	}
	return token{}, 0, false
}

func (t token) matchRune(r rune) bool {
	switch t.kind {
	case tokChar:
		return t.r == r
	case tokAny:
		return true
	case tokClass:
		in := false
		for _, rg := range t.ranges {
			if r >= rg.lo && r <= rg.hi {
				in = true
				break
			}
		}
		return in != t.negate
	}
	return false
}

// match reports whether the segment matches one path segment.
func (s *segment) match(name string) bool {
	if s.literal {
		return s.text == name
	}
	return matchTokens(s.toks, name)
}

// matchTokens matches tokens against name with single-star backtracking,
// which is linear in practice because stars never cross a segment.
func matchTokens(toks []token, name string) bool {
	ti, ni := 0, 0
	starTi, starNi := -1, 0
	for ni < len(name) {
		if ti < len(toks) {
			t := toks[ti]
			if t.kind == tokStar {
				starTi, starNi = ti, ni
				ti++
				continue
			}
			r, size := utf8.DecodeRuneInString(name[ni:])
			if t.matchRune(r) {
				ti++
				ni += size
				continue
			}
		}
		if starTi < 0 {
			return false
		}
		_, size := utf8.DecodeRuneInString(name[starNi:])
		starNi += size
		ni = starNi
		ti = starTi + 1
	}
	for ti < len(toks) && toks[ti].kind == tokStar {
		ti++
	}
	return ti == len(toks)
}

// matchPath reports whether the pattern matches the path split into segs.
//
// Each `**` tries every split point, so without memory a pattern with many
// `**` segments takes exponential time on a deep path that does not match
// (`/**/a/**/a/.../b` against `a/a/.../c`), and a CODEOWNERS file is input
// from the scanned repository. failed remembers the (pattern segment, path
// segment) states that cannot match, which bounds the work by
// len(m.segs)*len(segs) and the recursion depth by len(m.segs)+len(segs).
func (m *matcher) matchPath(segs []string) bool {
	// One `**` only scans the path once; the blowup needs two or more.
	stars := 0
	for i := range m.segs {
		if m.segs[i].doubleStar {
			stars++
		}
	}
	if stars < 2 {
		return m.matchFrom(0, 0, segs, nil)
	}
	var buf [256]bool
	return m.matchFrom(0, 0, segs, newFailedSet(len(m.segs)+1, len(segs)+1, buf[:]))
}

// maxDenseStates caps the flat table at 1 MiB of bools. Above it, which
// takes a pattern and a path that are both long, failed states go in a map,
// which only grows with the states actually visited.
const maxDenseStates = 1 << 20

// failedSet records the (pattern segment, path segment) states that cannot
// match. A nil *failedSet records nothing.
type failedSet struct {
	cols   int
	dense  []bool
	sparse map[[2]int]struct{}
}

func newFailedSet(rows, cols int, buf []bool) *failedSet {
	// rows*cols compared by division, so a huge pattern or path cannot
	// overflow the product.
	if rows > maxDenseStates/cols {
		return &failedSet{sparse: map[[2]int]struct{}{}}
	}
	n := rows * cols
	if n <= len(buf) {
		return &failedSet{cols: cols, dense: buf[:n]}
	}
	return &failedSet{cols: cols, dense: make([]bool, n)}
}

func (f *failedSet) has(pi, si int) bool {
	if f.sparse != nil {
		_, ok := f.sparse[[2]int{pi, si}]
		return ok
	}
	return f.dense[pi*f.cols+si]
}

func (f *failedSet) add(pi, si int) {
	if f.sparse != nil {
		f.sparse[[2]int{pi, si}] = struct{}{}
		return
	}
	f.dense[pi*f.cols+si] = true
}

func (m *matcher) matchFrom(pi, si int, segs []string, failed *failedSet) bool {
	if failed == nil {
		return m.matchStep(pi, si, segs, failed)
	}
	if failed.has(pi, si) {
		return false
	}
	if m.matchStep(pi, si, segs, failed) {
		return true
	}
	failed.add(pi, si)
	return false
}

func (m *matcher) matchStep(pi, si int, segs []string, failed *failedSet) bool {
	if pi == len(m.segs) {
		rest := len(segs) - si
		if rest == 0 {
			return !m.dirOnly
		}
		return m.descend || m.dirOnly
	}
	seg := &m.segs[pi]
	if seg.doubleStar {
		if pi == len(m.segs)-1 {
			if m.trailingAll {
				return si < len(segs)
			}
		}
		for k := si; k <= len(segs); k++ {
			if m.matchFrom(pi+1, k, segs, failed) {
				return true
			}
		}
		return false
	}
	if si == len(segs) || !seg.match(segs[si]) {
		return false
	}
	return m.matchFrom(pi+1, si+1, segs, failed)
}

// splitPath turns a repository-relative path into segments. A leading `/` or
// `./` is ignored, as are empty segments.
func splitPath(path string) []string {
	path = strings.TrimPrefix(path, "./")
	return splitSegments(path)
}
