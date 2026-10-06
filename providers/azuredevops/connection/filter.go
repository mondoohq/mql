// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
)

// The option names of the two filter lists, as they appear in
// inventory.Config.Options and as CLI flags of the same name.
const (
	OPTION_REPOS         = "repos"
	OPTION_REPOS_EXCLUDE = "repos-exclude"
)

// RepoFilter narrows an organization to some of its repositories.
//
// Patterns are globs matched against "<project>/<repo>". The separator is the
// slash, so "*" never crosses it: "scan-test/*" is every repository of one
// project and "*/ado-*" is the repositories with that prefix in any project.
// "**" does cross it. Matching is case-insensitive.
//
// An include list keeps only what matches it, and the exclude list then removes
// what it matches. Without an include list everything starts out kept.
type RepoFilter struct {
	include []*glob.Pattern
	exclude []*glob.Pattern
}

// NewRepoFilter reads comma-separated include and exclude lists. A pattern that
// is not a valid glob is an error, so a typo is not read as "match nothing".
func NewRepoFilter(include, exclude string) (*RepoFilter, error) {
	in, err := compilePatterns(include)
	if err != nil {
		return nil, fmt.Errorf("azure devops: bad %s pattern: %w", OPTION_REPOS, err)
	}
	ex, err := compilePatterns(exclude)
	if err != nil {
		return nil, fmt.Errorf("azure devops: bad %s pattern: %w", OPTION_REPOS_EXCLUDE, err)
	}
	return &RepoFilter{include: in, exclude: ex}, nil
}

func compilePatterns(list string) ([]*glob.Pattern, error) {
	var out []*glob.Pattern
	for _, p := range strings.Split(list, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		p = strings.ToLower(p)
		g, err := glob.Compile(p, '/')
		if err != nil {
			return nil, fmt.Errorf("%q: %w", p, err)
		}
		out = append(out, g)
	}
	return out, nil
}

// Empty reports a filter that keeps everything.
func (f *RepoFilter) Empty() bool {
	return f == nil || (len(f.include) == 0 && len(f.exclude) == 0)
}

// HasInclude reports whether the filter has an include list. A filter with only
// an exclude list keeps every repository it does not exclude, while one with an
// include list keeps nothing that its patterns do not name.
func (f *RepoFilter) HasInclude() bool {
	return f != nil && len(f.include) > 0
}

// Keep reports whether the repository passes the filter.
func (f *RepoFilter) Keep(project, repo string) bool {
	if f.Empty() {
		return true
	}
	name := strings.ToLower(project) + "/" + strings.ToLower(repo)
	if len(f.include) > 0 && !matchesAny(f.include, name) {
		return false
	}
	return !matchesAny(f.exclude, name)
}

func matchesAny(globs []*glob.Pattern, name string) bool {
	for _, g := range globs {
		if g.Match(name) {
			return true
		}
	}
	return false
}
