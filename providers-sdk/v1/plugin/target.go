// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"path"
	"strings"
)

// TargetOptIn is a provider's declaration that some shape of file tree is its
// own (ADR 045). A meta-target such as `iac` walks a tree, offers each
// candidate to the providers whose opt-ins matched, and keeps what they
// accepted.
//
// It is deliberately not Requires: declaring an opt-in installs nothing. The
// providers a run needs follow from the meta-target's --discover value, and
// are resolved through ProviderLookup{Target, Discovery} on demand.
type TargetOptIn struct {
	// Target is the meta-target this opt-in joins. "iac" today.
	Target string
	// Discovery is the name users pass to --discover. It is not the provider
	// name: one provider can join a target several times.
	Discovery string
	// ConnType is the connection type to give the child asset. The coordinator
	// resolves it to a provider and installs it.
	ConnType string
	// Match is what makes a path a candidate for this discovery.
	Match []Matcher
	// PerFile hands the provider the matching file itself. Off, it is handed
	// the folder the match was found in. A provider that reads one document
	// per asset (cloudformation, docker-file) sets it; one that reads a
	// directory (terraform, helm, kustomize, k8s, bicep, ansible) leaves it
	// off.
	PerFile bool `json:",omitempty"`
	// Options are set on the child connection as-is. This is how one provider
	// tells two of its opt-ins apart at connect time (terraform's dialect).
	Options map[string]string `json:",omitempty"`
	// Auto puts this discovery in the set an unset --discover expands to. A
	// provider opts itself in, which is the same trust the Match patterns
	// already carry. Leave it off for a discovery that is noisy enough to be
	// worth asking for by name.
	Auto bool `json:",omitempty"`
}

// Matcher is what makes a path a candidate. A glob and nothing else: anything
// richer is Connect's job, because a glob cannot settle whether something
// truly belongs to a provider and the provider it is offered to already knows
// how to read a directory. A false positive costs one probe; a false negative
// silently drops an asset from the scan, so matching is tuned to be generous.
type Matcher struct {
	// Glob matches the file's base name, or, when it contains a slash, the
	// tail of the path relative to the folder being considered.
	Glob string
}

// Match reports whether a tree-relative path matches, and the directory the
// match sites at: the file's own directory for a glob with no slash, and the
// directory the glob's segments hang below for one that has one. The site is
// what gets offered to the provider, so `roles/*/tasks/main.yml` offers the
// project directory rather than the task file. The root of the tree is "".
//
// path.Match, not filepath.Match: every path here comes from an fs.FS walk or
// a forge's tree API, both of which are always slash-separated, and
// filepath.Match on Windows takes the separator to be `\` -- so a glob like
// `roles/*/tasks/main.yml` would never match there.
func (m Matcher) Match(relPath string) (site string, ok bool) {
	if m.Glob == "" || relPath == "" {
		return "", false
	}

	if !strings.Contains(m.Glob, "/") {
		// path.Match only errors on a malformed pattern, which is an authoring
		// mistake in a config, not a property of the path. Treat it as "does
		// not match" rather than propagating an error into the walk.
		if matched, err := path.Match(m.Glob, path.Base(relPath)); err != nil || !matched {
			return "", false
		}
		return dirOf(relPath), true
	}

	depth := strings.Count(m.Glob, "/") + 1
	segs := strings.Split(relPath, "/")
	if len(segs) < depth {
		return "", false
	}
	tail := strings.Join(segs[len(segs)-depth:], "/")
	if matched, err := path.Match(m.Glob, tail); err != nil || !matched {
		return "", false
	}
	return strings.Join(segs[:len(segs)-depth], "/"), true
}

// dirOf is path.Dir with the root reported as "" rather than ".", so the root
// of the tree is the empty path everywhere and joins onto a tree root cleanly.
func dirOf(relPath string) string {
	dir := path.Dir(relPath)
	if dir == "." || dir == "/" {
		return ""
	}
	return dir
}

// Matches reports whether any of the opt-in's matchers fire on relPath, and
// the site of the first that does. Matchers are tried in order, so an opt-in
// that mixes base-name and slashed globs gets the site of whichever matched.
//
// Named Matches rather than Match because the field it reads is called Match,
// and a type cannot carry both.
func (t TargetOptIn) Matches(relPath string) (site string, ok bool) {
	for _, m := range t.Match {
		if site, ok := m.Match(relPath); ok {
			return site, true
		}
	}
	return "", false
}

// TargetOptIns returns the opt-ins this provider declares for target.
func (p *Provider) TargetOptIns(target string) []TargetOptIn {
	if p == nil || target == "" {
		return nil
	}
	var res []TargetOptIn
	for _, t := range p.Targets {
		if t.Target == target {
			res = append(res, t)
		}
	}
	return res
}

// DeclaresTarget reports whether any of this provider's opt-ins name target.
//
// This is how the CLI recognizes a meta-target connector without a hardcoded
// list: the opt-ins name their target, and the target is the connector name.
func (p *Provider) DeclaresTarget(target string) bool {
	if p == nil || target == "" {
		return false
	}
	for _, t := range p.Targets {
		if t.Target == target {
			return true
		}
	}
	return false
}
