// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"fmt"
	"strings"

	"github.com/gobwas/glob"
)

// globMetaChars are the characters gobwas/glob treats as pattern syntax outside
// a character class. A namespace name is an RFC 1123 label, so none of them can
// appear in a real one: a value containing any is a pattern, and a value
// containing none names exactly one namespace. That lets the connection ask the
// API server for that namespace directly instead of listing every namespace and
// filtering afterwards.
//
// `-`, `,` and `!` are deliberately absent. They are only special inside `[]` or
// `{}`, and `-` is legal in a namespace name, so treating it as a metacharacter
// would send every ordinary name like "kube-system" down the slow path.
const globMetaChars = `*?[]{}\`

// NamespaceFilter decides which namespaces a scan may read objects from. It
// mirrors the include/exclude precedence discovery uses to pick namespace
// assets, so the objects a query returns match the namespaces that were
// discovered.
//
// Include wins: when any include pattern is set, only namespaces matching one
// of them are kept and exclude is not consulted. With no includes, exclude
// removes matching namespaces. Patterns are globs, so "kube-*" works.
type NamespaceFilter struct {
	include    []glob.Glob
	exclude    []glob.Glob
	includeRaw []string
	excludeRaw []string
}

// NewNamespaceFilter builds a filter from the comma-separated option values of
// --namespaces and --namespaces-exclude.
func NewNamespaceFilter(include, exclude string) (NamespaceFilter, error) {
	f := NamespaceFilter{
		includeRaw: SplitFilterValues(include),
		excludeRaw: SplitFilterValues(exclude),
	}

	var err error
	if f.include, err = compileGlobs(f.includeRaw); err != nil {
		return NamespaceFilter{}, err
	}
	if f.exclude, err = compileGlobs(f.excludeRaw); err != nil {
		return NamespaceFilter{}, err
	}
	return f, nil
}

func compileGlobs(patterns []string) ([]glob.Glob, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	out := make([]glob.Glob, 0, len(patterns))
	for _, p := range patterns {
		g, err := glob.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid namespace pattern %q: %w", p, err)
		}
		out = append(out, g)
	}
	return out, nil
}

// IsEmpty reports whether the filter accepts every namespace.
func (f NamespaceFilter) IsEmpty() bool {
	return len(f.include) == 0 && len(f.exclude) == 0
}

// Matches reports whether objects in the namespace are in scope.
func (f NamespaceFilter) Matches(namespace string) bool {
	if len(f.include) > 0 {
		return matchesAnyGlob(f.include, namespace)
	}
	return !matchesAnyGlob(f.exclude, namespace)
}

func matchesAnyGlob(globs []glob.Glob, value string) bool {
	for _, g := range globs {
		if g.Match(value) {
			return true
		}
	}
	return false
}

// SingleNamespace returns the one namespace this filter selects, when it
// selects exactly one by name. That is the case the API server can answer
// directly, so the caller can scope the list request instead of listing every
// namespace and filtering the result.
func (f NamespaceFilter) SingleNamespace() (string, bool) {
	if len(f.includeRaw) != 1 || len(f.excludeRaw) != 0 {
		return "", false
	}
	ns := f.includeRaw[0]
	if !IsLiteralNamespace(ns) {
		return "", false
	}
	return ns, true
}

// IsLiteralNamespace reports whether the value names exactly one namespace
// rather than being a glob pattern.
func IsLiteralNamespace(value string) bool {
	return !strings.ContainsAny(value, globMetaChars)
}

// SplitFilterValues splits a comma-separated option value, dropping empties.
func SplitFilterValues(value string) []string {
	values := strings.Split(value, ",")
	res := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			res = append(res, v)
		}
	}
	return res
}
