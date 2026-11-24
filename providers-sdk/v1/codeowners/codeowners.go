// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package codeowners parses CODEOWNERS files and answers who owns a path.
//
// GitHub and GitLab share the file name and little else. On GitHub the file
// is one list where the last matching pattern wins and patterns follow
// gitignore. On GitLab the file is split into sections, each section
// contributes its own last match, patterns follow fnmatch, and an entry can
// exclude paths. A file is therefore always parsed for one Dialect, and the
// same text can give different owners under the other.
package codeowners

import (
	"regexp"
	"strconv"
	"strings"
)

// Dialect selects whose rules a CODEOWNERS file is read by.
type Dialect int

const (
	GitHub Dialect = iota
	GitLab
)

// Rule is one entry of a CODEOWNERS file.
type Rule struct {
	// Pattern is the path pattern as written, without a GitLab `!` prefix.
	Pattern string
	// Owners are the entry's owners as written: `@user`, `@org/team`,
	// `@@role` or an email address. On GitLab an entry that names no owner
	// takes its section's default owners. Empty means the entry leaves the
	// paths it matches without an owner.
	Owners []string
	// Line is the 1-based line of the entry in the file.
	Line int
	// Section is the GitLab section the entry belongs to, "" for entries
	// outside any section and for every GitHub entry.
	Section string
	// Optional is true when the entry's GitLab section is optional (`^[Name]`).
	Optional bool
	// Approvals is the number of approvals the entry's GitLab section
	// requires, 0 when the section does not say.
	Approvals int
	// Exclude is true for a GitLab `!pattern` entry: paths it matches need no
	// owner from its section.
	Exclude bool

	match *regexp.Regexp
}

// File is a parsed CODEOWNERS file.
type File struct {
	Dialect Dialect
	// Rules are the valid entries in file order. Lines the dialect ignores
	// (comments, blank lines, entries it cannot use) are not in it.
	Rules []Rule
	// sections is the order GitLab sections first appear in, lower-cased.
	sections []string
}

// Parse reads the content of a CODEOWNERS file. It never fails: both forges
// skip a line they cannot use and keep the rest, and so does Parse.
func Parse(dialect Dialect, content string) *File {
	if dialect == GitLab {
		return parseGitLab(content)
	}
	return parseGitHub(content)
}

// Match returns the entries that decide the owners of path, which is relative
// to the repository root and uses forward slashes; a leading slash is ignored.
//
// On GitHub that is the last entry whose pattern matches, or nothing. The
// entry may have no owners: a later, more specific pattern without owners
// leaves its paths unowned.
//
// On GitLab it is the last matching entry of each section, in the order the
// sections first appear, leaving out every section in which an exclusion
// matches the path.
func (f *File) Match(path string) []Rule {
	if f == nil {
		return nil
	}
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return nil
	}
	if f.Dialect == GitHub {
		for i := len(f.Rules) - 1; i >= 0; i-- {
			if f.Rules[i].match.MatchString(path) {
				return []Rule{f.Rules[i]}
			}
		}
		return nil
	}

	last := map[string]int{}
	excluded := map[string]bool{}
	for i := range f.Rules {
		r := &f.Rules[i]
		if !r.match.MatchString(path) {
			continue
		}
		key := strings.ToLower(r.Section)
		if r.Exclude {
			excluded[key] = true
			continue
		}
		last[key] = i
	}
	var out []Rule
	for _, key := range f.sections {
		if i, ok := last[key]; ok && !excluded[key] {
			out = append(out, f.Rules[i])
		}
	}
	return out
}

// Owners returns the owners of path: the owners of every entry Match returns,
// in order, each once. Nil means the file names no owner for the path.
func (f *File) Owners(path string) []string {
	var out []string
	seen := map[string]bool{}
	for _, r := range f.Match(path) {
		for _, o := range r.Owners {
			if !seen[o] {
				seen[o] = true
				out = append(out, o)
			}
		}
	}
	return out
}

// isOwner reports whether a token can name an owner: `@name`, `@org/team`,
// `@@role`, or an email address.
func isOwner(tok string) bool {
	if strings.HasPrefix(tok, "@") {
		return len(strings.TrimLeft(tok, "@")) > 0
	}
	at := strings.Index(tok, "@")
	return at > 0 && at < len(tok)-1
}

// ---- GitHub ----

func parseGitHub(content string) *File {
	f := &File{Dialect: GitHub}
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimRight(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		pattern := fields[0]
		// Three gitignore features do not work in CODEOWNERS: `!` negation,
		// `[ ]` ranges, and `\#` to start a pattern with a hash. A line that
		// uses one is invalid, and GitHub skips an invalid line.
		if strings.HasPrefix(pattern, "!") || strings.HasPrefix(pattern, `\#`) || strings.ContainsAny(pattern, "[]") {
			continue
		}
		owners := []string{}
		valid := true
		for _, tok := range fields[1:] {
			if strings.HasPrefix(tok, "#") { // inline comment: the rest is not owners
				break
			}
			if !isOwner(tok) {
				valid = false
				break
			}
			owners = append(owners, tok)
		}
		if !valid {
			continue
		}
		re, err := regexp.Compile(gitHubPatternRegex(pattern))
		if err != nil {
			continue
		}
		f.Rules = append(f.Rules, Rule{Pattern: pattern, Owners: owners, Line: i + 1, match: re})
	}
	return f
}

// gitHubPatternRegex translates a GitHub CODEOWNERS pattern, which follows
// gitignore:
//
//   - a pattern with a slash anywhere but at its end is relative to the
//     repository root; one without matches at any depth;
//   - a trailing slash names a directory and matches everything under it;
//   - `*` and `?` do not cross a slash, `**` does;
//   - a pattern that names a file or directory also matches what is inside it,
//     except when its last segment is `*`: `docs/*` matches the files directly
//     in docs and nothing nested deeper.
func gitHubPatternRegex(pattern string) string {
	dirOnly := strings.HasSuffix(pattern, "/")
	p := strings.TrimSuffix(pattern, "/")
	anchored := strings.Contains(p, "/")
	p = strings.TrimPrefix(p, "/")

	var b strings.Builder
	b.WriteString("^")
	if !anchored {
		b.WriteString("(?:.*/)?")
	}
	segs := strings.Split(p, "/")
	for i, seg := range segs {
		lastSeg := i == len(segs)-1
		if seg == "**" {
			if lastSeg {
				b.WriteString(".*")
			} else {
				b.WriteString("(?:.*/)?")
			}
			continue
		}
		b.WriteString(globSegment(seg))
		if !lastSeg {
			b.WriteString("/")
		}
	}
	switch last := segs[len(segs)-1]; {
	case dirOnly:
		b.WriteString("/.*")
	case last == "**":
	case last == "*":
		// direct children only
	default:
		b.WriteString("(?:/.*)?")
	}
	b.WriteString("$")
	return b.String()
}

// globSegment translates one path segment: `*` and `?` stay inside the
// segment, everything else is literal.
func globSegment(seg string) string {
	var b strings.Builder
	for _, r := range seg {
		switch r {
		case '*':
			b.WriteString("[^/]*")
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return b.String()
}

// ---- GitLab ----

// gitLabSection matches a section heading: an optional `^`, a name in square
// brackets, an optional approval count in a second pair, then default owners.
var gitLabSection = regexp.MustCompile(`^(\^)?\[([^\]]+)\](?:\[(\d*)\])?(?:\s+(.*))?$`)

type gitLabSectionState struct {
	name      string // as first written
	optional  bool
	approvals int
	defaults  []string
}

func parseGitLab(content string) *File {
	f := &File{Dialect: GitLab, sections: []string{""}}
	// Sections with the same name, compared without case, are one section
	// that keeps the first spelling. It is optional only if every heading
	// for it is.
	sections := map[string]*gitLabSectionState{"": {}}
	cur := sections[""]

	for i, raw := range strings.Split(content, "\n") {
		line := strings.TrimSpace(strings.TrimRight(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") || strings.HasPrefix(line, "^[") {
			m := gitLabSection.FindStringSubmatch(line)
			if m == nil {
				// A heading that cannot be parsed is ignored and the entries
				// after it stay in the section before it.
				continue
			}
			key := strings.ToLower(strings.TrimSpace(m[2]))
			st, ok := sections[key]
			if !ok {
				st = &gitLabSectionState{name: strings.TrimSpace(m[2]), optional: true}
				sections[key] = st
				f.sections = append(f.sections, key)
			}
			st.optional = st.optional && m[1] == "^"
			if n, err := strconv.Atoi(m[3]); err == nil && n > st.approvals {
				st.approvals = n
			}
			st.defaults = ownerTokens(strings.Fields(m[4]))
			cur = st
			continue
		}

		pattern, rest := splitGitLabEntry(line)
		exclude := strings.HasPrefix(pattern, "!")
		pattern = strings.TrimPrefix(pattern, "!")
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(gitLabPatternRegex(pattern))
		if err != nil {
			continue
		}
		// Owners are the tokens that can name one; anything else on the line
		// is ignored, and text after a `#` is still read for owners, as
		// GitLab does not support inline comments.
		owners := ownerTokens(strings.Fields(rest))
		if len(owners) == 0 && !exclude {
			owners = append([]string{}, cur.defaults...)
		}
		f.Rules = append(f.Rules, Rule{
			Pattern: pattern, Owners: owners, Line: i + 1, Section: cur.name, Exclude: exclude, match: re,
		})
	}
	for i := range f.Rules {
		st := sections[strings.ToLower(f.Rules[i].Section)]
		f.Rules[i].Optional = st.name != "" && st.optional
		f.Rules[i].Approvals = st.approvals
	}
	return f
}

func ownerTokens(toks []string) []string {
	out := []string{}
	for _, t := range toks {
		if isOwner(t) {
			out = append(out, t)
		}
	}
	return out
}

// splitGitLabEntry splits an entry into its path and the rest of the line. The
// path ends at the first whitespace that is not escaped with a backslash; the
// escapes `\ ` and `\#` are removed from it.
func splitGitLabEntry(line string) (path, rest string) {
	var b strings.Builder
	for i := 0; i < len(line); i++ {
		c := line[i]
		if c == '\\' && i+1 < len(line) && (line[i+1] == ' ' || line[i+1] == '#') {
			b.WriteByte(line[i+1])
			i++
			continue
		}
		if c == ' ' || c == '\t' {
			return b.String(), line[i+1:]
		}
		b.WriteByte(c)
	}
	return b.String(), ""
}

// gitLabPatternRegex translates a GitLab CODEOWNERS pattern. GitLab matches
// with fnmatch, where `*` and `?` do not cross a slash and match dotfiles, and
// `**/` matches any number of directories:
//
//   - a path with a leading slash matches from the repository root;
//   - a path without one matches at any depth, as if it began with `/**/`;
//   - a trailing slash matches every file in the directory and below.
//
// Unlike GitHub, a path that names a directory without a trailing slash does
// not match the files inside it.
func gitLabPatternRegex(pattern string) string {
	if !strings.HasPrefix(pattern, "/") {
		pattern = "/**/" + pattern
	}
	if strings.HasSuffix(pattern, "/") {
		pattern += "**/*"
	}
	segs := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	var b strings.Builder
	b.WriteString("^")
	for i, seg := range segs {
		lastSeg := i == len(segs)-1
		if seg == "**" && !lastSeg {
			b.WriteString("(?:.*/)?")
			continue
		}
		if seg == "**" {
			b.WriteString(".*")
			continue
		}
		b.WriteString(globSegment(seg))
		if !lastSeg {
			b.WriteString("/")
		}
	}
	b.WriteString("$")
	return b.String()
}
