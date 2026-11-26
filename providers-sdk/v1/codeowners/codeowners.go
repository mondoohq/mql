// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

// Package codeowners parses CODEOWNERS files and answers "who owns this
// path", with the semantics of the forge that reads the file. Every consumer
// that needs owners (the github and gitlab providers, code scanners) uses this
// package, so one path has one answer.
//
// Two dialects are supported:
//
//   - GitHub: gitignore-style patterns, the last matching rule wins. Lines
//     with syntax GitHub does not support (`!` negation, `[ ]` character
//     ranges, `\#` escapes, malformed owners) are skipped, as GitHub skips
//     invalid lines, and reported in Parse's error.
//   - GitLab: patterns normalized and matched as GitLab does (fnmatch with
//     FNM_PATHNAME and FNM_DOTMATCH, a pattern without a leading `/` matches
//     at any depth), `[Section]` headers with optional (`^[Section]`), approval
//     counts (`[Section][2]`) and default owners, duplicate sections combined
//     case-insensitively, `!` exclusions per section, and the last matching
//     rule per section, all sections combined.
//
// A path no rule matches has no owners. The package never infers an owner.
//
// Match and MatchRules scan the rules once per path. For many paths against
// one file, NewIndex gives the same answers and tries only the rules that can
// match each path.
package codeowners

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Dialect selects the forge whose CODEOWNERS semantics apply.
type Dialect int

const (
	// GitHub is GitHub's CODEOWNERS syntax.
	GitHub Dialect = iota + 1
	// GitLab is GitLab's CODEOWNERS syntax, with sections.
	GitLab
)

// String returns the dialect's name.
func (d Dialect) String() string {
	switch d {
	case GitHub:
		return "github"
	case GitLab:
		return "gitlab"
	}
	return "Dialect(" + strconv.Itoa(int(d)) + ")"
}

// ErrDialect is returned for a dialect this package does not implement.
var ErrDialect = errors.New("codeowners: unknown dialect")

// Rule is one rule of a CODEOWNERS file.
type Rule struct {
	// Pattern is the path pattern as written in the file (for a GitLab
	// exclusion, without its leading `!`).
	Pattern string
	// Owners are the rule's owners in file order: `@user`, `@org/team`,
	// `@group/subgroup`, `@@role` (GitLab) or an email address. For a GitLab
	// rule without owners of its own, the section's default owners. Empty for
	// a rule that assigns no owner, which still matches and so removes the
	// owners an earlier rule gave.
	Owners []string
	// Line is the 1-based line number of the rule in the file.
	Line int
	// Section is the GitLab section name, in the case of its first header; ""
	// for rules outside any section and for GitHub.
	Section string
	// Optional is set when the GitLab section is optional: every header of
	// that name was written `^[Section]`.
	Optional bool
	// ApprovalsRequired is the count from the GitLab section header
	// (`[Section][2]`), 0 when not given. GitLab treats a value below 1 as 1.
	ApprovalsRequired int
	// Exclusion is set for a GitLab `!pattern`: a path it matches has no
	// owners from its section.
	Exclusion bool

	m *matcher
}

// Owner is one owner of a path, with the rule that assigned it.
type Owner struct {
	Name string
	Rule Rule
}

// LineError describes one line Parse skipped or found malformed.
type LineError struct {
	Line   int
	Reason string
}

func (e *LineError) Error() string {
	return fmt.Sprintf("codeowners: line %d: %s", e.Line, e.Reason)
}

// Parse parses a CODEOWNERS file.
//
// The rules are returned in file order and are what the forge applies. The
// error, when not nil, joins one *LineError per line that was skipped or is
// malformed; the forge reports the same lines as errors and applies the other
// rules, so the returned rules stay usable. A caller that wants no owners from
// a file with errors checks the error. An empty file gives no rules and no
// error.
func Parse(content string, d Dialect) ([]Rule, error) {
	switch d {
	case GitHub:
		return parseGitHub(content)
	case GitLab:
		return parseGitLab(content)
	}
	return nil, ErrDialect
}

// MatchRules returns the rules that decide the owners of path, a
// repository-relative path with `/` separators. For GitHub that is the last
// matching rule, at most one. For GitLab it is the last matching rule of each
// section, in the order the sections first appear, and nothing from a section
// in which an exclusion matches the path.
//
// rules must be in file order, as Parse returns them.
func MatchRules(rules []Rule, path string, d Dialect) []Rule {
	segs := splitPath(path)
	if len(segs) == 0 {
		return nil
	}
	switch d {
	case GitHub:
		for i := len(rules) - 1; i >= 0; i-- {
			if rules[i].matcher(d).matchPath(segs) {
				return []Rule{rules[i]}
			}
		}
	case GitLab:
		return matchGitLab(rules, segs)
	}
	return nil
}

// Match returns the owners of path, each with the rule that assigned it, in
// the order of MatchRules and then of the rule's owners. A path no rule
// matches, or that only rules without owners match, has no owners.
func Match(rules []Rule, path string, d Dialect) []Owner {
	var owners []Owner
	for _, r := range MatchRules(rules, path, d) {
		for _, name := range r.Owners {
			owners = append(owners, Owner{Name: name, Rule: r})
		}
	}
	return owners
}

// Names returns the distinct owner names, in order of first appearance.
func Names(owners []Owner) []string {
	seen := make(map[string]struct{}, len(owners))
	var names []string
	for _, o := range owners {
		if _, ok := seen[o.Name]; ok {
			continue
		}
		seen[o.Name] = struct{}{}
		names = append(names, o.Name)
	}
	return names
}

// matcher returns the rule's compiled pattern. Rules from Parse carry it; a
// rule built by hand is compiled on every call.
func (r *Rule) matcher(d Dialect) *matcher {
	if r.m != nil {
		return r.m
	}
	if d == GitLab {
		return compileGitLab(r.Pattern)
	}
	return compileGitHub(r.Pattern)
}

func matchGitLab(rules []Rule, segs []string) []Rule {
	type state struct {
		best     int
		excluded bool
	}
	var order []string
	states := map[string]*state{}
	for i := range rules {
		key := strings.ToLower(rules[i].Section)
		st, ok := states[key]
		if !ok {
			st = &state{best: -1}
			states[key] = st
			order = append(order, key)
		}
		if st.excluded || !rules[i].matcher(GitLab).matchPath(segs) {
			continue
		}
		if rules[i].Exclusion {
			st.excluded = true
			continue
		}
		if st.best < 0 || rules[i].Line >= rules[st.best].Line {
			st.best = i
		}
	}
	var out []Rule
	for _, key := range order {
		if st := states[key]; !st.excluded && st.best >= 0 {
			out = append(out, rules[st.best])
		}
	}
	return out
}

// ---------- GitHub ----------

// githubOwner matches the owner forms GitHub documents: `@username`,
// `@org/team-name` and an email address.
var githubOwner = regexp.MustCompile(`^(@[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9_])?(?:/[A-Za-z0-9_.-]+)?|[^@\s]+@[^@\s]+\.[^@\s]+)$`)

func parseGitHub(content string) ([]Rule, error) {
	var rules []Rule
	var errs []error
	for i, line := range strings.Split(content, "\n") {
		n := i + 1
		fields := strings.Fields(strings.TrimRight(line, "\r"))
		if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		pattern := fields[0]
		var owners []string
		for _, f := range fields[1:] {
			if strings.HasPrefix(f, "#") {
				break // inline comment
			}
			owners = append(owners, f)
		}
		if reason := githubUnsupported(pattern); reason != "" {
			errs = append(errs, &LineError{Line: n, Reason: reason})
			continue
		}
		if bad := firstInvalid(owners); bad != "" {
			errs = append(errs, &LineError{Line: n, Reason: fmt.Sprintf("invalid owner %q", bad)})
			continue
		}
		rules = append(rules, Rule{Pattern: pattern, Owners: owners, Line: n, m: compileGitHub(pattern)})
	}
	return rules, errors.Join(errs...)
}

// githubUnsupported returns why GitHub does not apply a pattern, or "".
// GitHub documents that `\#` escaping, `!` negation and `[ ]` character
// ranges do not work in CODEOWNERS.
func githubUnsupported(pattern string) string {
	switch {
	case strings.HasPrefix(pattern, `\#`):
		return "escaping a leading # is not supported"
	case strings.HasPrefix(pattern, "!"):
		return "negation (!) is not supported"
	case strings.ContainsAny(pattern, "[]"):
		return "character ranges ([ ]) are not supported"
	}
	return ""
}

func firstInvalid(owners []string) string {
	for _, o := range owners {
		if !githubOwner.MatchString(o) {
			return o
		}
	}
	return ""
}

// ---------- GitLab ----------

// gitlabHeader is GitLab's section header: an optional `^`, the name in
// brackets, an optional approval count in brackets, then default owners.
// Like GitLab's own expression it is anchored only at the start.
var gitlabHeader = regexp.MustCompile(`^(\^)?\[(.*?)\](?:\[([\s\d]*)\])?(\s*[@\w.\-/\s]*)?`)

// gitlabUnparsableHeader is a line GitLab treats as a broken section header:
// it is ignored and its rules stay in the previous section.
var gitlabUnparsableHeader = regexp.MustCompile(`^(\^)?\[`)

var gitlabApprovals = regexp.MustCompile(`^\s*\d+\s*$`)

type gitlabSection struct {
	name          string
	optional      bool
	approvals     int
	defaultOwners []string
}

func parseGitLab(content string) ([]Rule, error) {
	var errs []error
	addErr := func(line int, format string, args ...any) {
		errs = append(errs, &LineError{Line: line, Reason: fmt.Sprintf(format, args...)})
	}

	type key struct{ section, pattern string }
	var rules []Rule
	index := map[key]int{}       // position in rules of a (section, normalized pattern)
	names := map[string]string{} // lower-cased section name -> first spelling
	allOptional := map[string]bool{}

	current := gitlabSection{}
	for i, raw := range strings.Split(content, "\n") {
		n := i + 1
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if idx := gitlabHeader.FindStringSubmatchIndex(line); idx != nil {
			m := submatches(line, idx)
			name := m[2]
			if name == "" {
				addErr(n, "section header without a name")
			}
			if first, ok := names[strings.ToLower(name)]; ok {
				name = first
			} else {
				names[strings.ToLower(name)] = name
			}
			sec := gitlabSection{name: name, optional: m[1] == "^"}
			if idx[6] >= 0 { // an approval count in brackets was given
				if !gitlabApprovals.MatchString(m[3]) {
					addErr(n, "invalid approval count %q", m[3])
				}
				sec.approvals, _ = strconv.Atoi(strings.TrimSpace(m[3]))
				if sec.optional && sec.approvals > 0 {
					addErr(n, "an optional section cannot require approvals")
				}
			}
			sec.defaultOwners = gitlabOwners(m[4])
			if rest := strings.Fields(m[4]); len(rest) != len(sec.defaultOwners) {
				addErr(n, "malformed section default owner")
			}
			current = sec
			continue
		}
		if gitlabUnparsableHeader.MatchString(line) {
			addErr(n, "unparsable section header, ignored")
			continue
		}

		pattern, ownerText := splitGitLabEntry(line)
		exclusion := strings.HasPrefix(pattern, "!")
		if exclusion {
			pattern = pattern[1:]
		}
		var owners []string
		if !exclusion {
			owners = gitlabOwners(ownerText)
			if len(owners) != len(strings.Fields(ownerText)) {
				addErr(n, "malformed owner")
			}
			if strings.TrimSpace(ownerText) == "" {
				owners = current.defaultOwners
			}
			if len(owners) == 0 {
				addErr(n, "rule without owners")
			}
		}

		k := key{strings.ToLower(current.name), normalizeGitLab(pattern)}
		r := Rule{
			Pattern:           pattern,
			Owners:            owners,
			Line:              n,
			Section:           current.name,
			Optional:          current.optional,
			ApprovalsRequired: current.approvals,
			Exclusion:         exclusion,
			m:                 compileGitLab(pattern),
		}
		// GitLab keys rules by section and normalized pattern: a later rule
		// replaces an earlier one with the same pattern, exclusion or not.
		if pos, ok := index[k]; ok {
			rules = append(rules[:pos], rules[pos+1:]...)
			for kk, p := range index {
				if p > pos {
					index[kk] = p - 1
				}
			}
		}
		index[k] = len(rules)
		rules = append(rules, r)

		sk := strings.ToLower(current.name)
		if opt, ok := allOptional[sk]; ok {
			allOptional[sk] = opt && current.optional
		} else {
			allOptional[sk] = current.optional
		}
	}

	// A section is optional only when all its rules are: one required header
	// of a name makes the combined section required.
	for i := range rules {
		rules[i].Optional = allOptional[strings.ToLower(rules[i].Section)]
	}
	return rules, errors.Join(errs...)
}

// submatches returns the groups of a FindStringSubmatchIndex result, "" for a
// group that did not participate.
func submatches(s string, idx []int) []string {
	out := make([]string, len(idx)/2)
	for i := range out {
		if idx[2*i] >= 0 {
			out[i] = s[idx[2*i]:idx[2*i+1]]
		}
	}
	return out
}

// splitGitLabEntry splits a rule at the first whitespace not preceded by a
// backslash, as GitLab does, so `path\ with\ spaces/ @owner` keeps its spaces.
func splitGitLabEntry(line string) (pattern, owners string) {
	for i := 0; i < len(line); i++ {
		if isSpace(line[i]) && (i == 0 || line[i-1] != '\\') {
			return line[:i], strings.TrimSpace(line[i:])
		}
	}
	return line, ""
}

// gitlabReference matches the owner references GitLab extracts: `@name`,
// `@group/subgroup`, `@@role` and email addresses. Other tokens, such as the
// words of an inline comment, are ignored, as GitLab ignores them.
var gitlabReference = regexp.MustCompile(`^(@@?[\w.\-]+(?:/[\w.\-]+)*|[^@\s]+@[^@\s]+\.[^@\s]+)$`)

func gitlabOwners(s string) []string {
	var out []string
	for _, f := range strings.Fields(s) {
		if gitlabReference.MatchString(f) {
			out = append(out, f)
		}
	}
	return out
}
