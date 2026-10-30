// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/mqlr/lrcore"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

// Every provider you can connect to has to declare an asset root.
//
// A root is the type that bounds a query on a connected asset (ADR 031): it is
// what `_` resolves to, what carries `asset`, and what lets a bundle derive
// which assets it applies to instead of being told by hand. A provider that
// declares connectors hands out assets, so it owes a root. A provider that
// declares none - core, which is always builtin and only supplies globals - has
// nothing to be the root of, so it is exempt by construction rather than by
// being named here.
//
// rootBacklog is the providers that predate the rule. It is a ratchet in both
// directions: a connectable provider that is neither rooted nor listed fails,
// and a *listed* provider that has since been rooted also fails. The second
// half is the point - an allowlist nobody has to maintain stops describing
// reality, and then it is worse than no test at all.
var rootBacklog = map[string]struct{}{}

func init() {
	// What is left needs a decision, not a sweep:
	//   aws, azure, gcp - "the root of an account" is the flat-os question again
	for _, p := range []string{
		"aws", "azure", "gcp",
	} {
		rootBacklog[p] = struct{}{}
	}
}

var (
	reConfigRoot   = regexp.MustCompile(`\bRoot:\s*"([^"]*)"`)
	reHasConnector = regexp.MustCompile(`Connectors:\s*\[\]plugin\.Connector\{\s*\{`)
)

// providerRootState is what a provider says about its roots, read the way the
// build reads it: the schema through the real parser, the plugin declaration
// out of its config.
type providerRootState struct {
	connectable bool
	roots       []string
	declared    string // `option root` in the schema
	configRoot  string // `Root:` in config.go
}

func readProviderRootState(t *testing.T, dir string) (providerRootState, bool) {
	t.Helper()
	var st providerRootState

	cfg, err := os.ReadFile(filepath.Join(dir, "config", "config.go"))
	if err != nil {
		return st, false // not a provider
	}
	st.connectable = reHasConnector.Match(cfg)
	if m := reConfigRoot.FindSubmatch(cfg); m != nil {
		st.configRoot = string(m[1])
	}

	lrs, _ := filepath.Glob(filepath.Join(dir, "resources", "*.lr"))
	for _, lr := range lrs {
		raw, err := os.ReadFile(lr)
		require.NoError(t, err)
		// Parse, not Resolve: this only needs what the file itself declares,
		// and Parse does not have to chase imports across the repo to say it.
		ast, err := lrcore.Parse(string(raw))
		require.NoErrorf(t, err, "parsing %s", lr)
		if root, ok := ast.Options["root"]; ok && root != "" {
			st.declared = root
		}
		for _, r := range ast.Resources {
			if r.IsRoot {
				st.roots = append(st.roots, r.ID)
			}
		}
	}
	sort.Strings(st.roots)
	return st, true
}

func TestEveryConnectableProviderDeclaresARoot(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("..", "providers", "*"))
	require.NoError(t, err)

	var missing, rootedButBacklogged []string
	seen := 0

	for _, dir := range dirs {
		name := filepath.Base(dir)
		st, ok := readProviderRootState(t, dir)
		if !ok {
			continue
		}
		seen++

		// A provider with no connectors is not something you connect to, so
		// there is no asset for it to root.
		if !st.connectable {
			assert.Emptyf(t, st.roots, "%s declares no connectors but declares roots %v", name, st.roots)
			continue
		}

		_, backlogged := rootBacklog[name]
		switch {
		case len(st.roots) == 0 && !backlogged:
			missing = append(missing, name)
		case len(st.roots) > 0 && backlogged:
			rootedButBacklogged = append(rootedButBacklogged, name)
		}
	}

	require.Greater(t, seen, 50, "the provider scan found almost nothing, so it is measuring the wrong directory")

	assert.Emptyf(t, missing, "these providers accept connections but declare no asset root (ADR 031). "+
		"Mark the resource a connection binds to with `@root`, declare `option root`, and set `Root:` in config.go: %v", missing)

	assert.Emptyf(t, rootedButBacklogged, "these providers are rooted now and must come off rootBacklog in this file: %v",
		rootedButBacklogged)
}

// The two places a provider names its root have to agree, and the name has to
// be one of the roots it actually declares. They are written in different files
// - the schema and the plugin config - so nothing but a check keeps them from
// drifting into naming different resources, which surfaces as `_` binding to
// something the connection never exposed.
func TestDeclaredRootsAgree(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("..", "providers", "*"))
	require.NoError(t, err)

	for _, dir := range dirs {
		name := filepath.Base(dir)
		st, ok := readProviderRootState(t, dir)
		if !ok || len(st.roots) == 0 {
			continue
		}

		t.Run(name, func(t *testing.T) {
			require.NotEmpty(t, st.declared, "declares roots %v but no `option root`", st.roots)
			assert.Equalf(t, st.declared, st.configRoot,
				"`option root` in the schema and `Root:` in config.go disagree")
			assert.Containsf(t, st.roots, st.declared,
				"`option root` names %q, which is not one of the roots this provider declares", st.declared)
		})
	}
}

// Every resource a rooted provider owns has to be reachable from one of its
// roots, or it stops resolving in v15 when the root becomes the namespace
// (ADR 031).
//
// This is the check that was missing. `@replaced_by` targets are verified at
// generate time, so an orphan is caught only if something happens to point at
// it: ms365's orphaned Exchange/SharePoint/Teams tree failed loudly because a
// deprecation pointed into it, while vsphere's `vulnmgmt` and its whole ESXi
// host tree passed in silence. Nothing was checking a provider's own surface.
//
// Exempt, and why:
//   - `@global` says outright that it needs no root (core's `time`, network's
//     `url` - a parser, not an aspect of any asset)
//   - private resources are reached through a parent by construction
//   - a namespaced name (`foo.bar`) is reached through `foo`
//   - deprecated resources are on their way out; flat `os` and vsphere's `esxi`
//     are *expected* to be unreachable, that being the point of retiring them
func TestRootedProvidersHaveNoOrphans(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("..", "providers", "*"))
	require.NoError(t, err)

	repoFile := func(p string) ([]byte, error) { return os.ReadFile(filepath.Join("..", p)) }

	checked := 0
	for _, dir := range dirs {
		name := filepath.Base(dir)
		lrs, _ := filepath.Glob(filepath.Join(dir, "resources", "*.lr"))
		if len(lrs) != 1 {
			continue
		}
		raw, err := os.ReadFile(lrs[0])
		require.NoError(t, err)
		if !strings.Contains(string(raw), "@root") {
			continue
		}

		t.Run(name, func(t *testing.T) {
			// Resolve, not Parse: aliases are what attach a provider's surface
			// to its root, and they only exist after imports are resolved.
			ast, err := lrcore.Resolve(
				filepath.ToSlash(filepath.Join("providers", name, "resources", filepath.Base(lrs[0]))),
				repoFile)
			require.NoError(t, err)
			schema, err := lrcore.Schema(ast)
			require.NoError(t, err)

			var orphans []string
			for res, info := range schema.Resources {
				switch {
				case info == nil, info.Id != res, strings.Contains(res, "."),
					info.Private, info.GetGlobal(), info.IsExtension,
					info.Maturity == "deprecated",
					!strings.HasSuffix(info.Provider, "/"+name):
					continue
				}
				if !resources.RootReachable(schema, res) {
					orphans = append(orphans, res)
				}
			}
			sort.Strings(orphans)
			assert.Emptyf(t, orphans, "unreachable from any root, so they stop resolving in v15: %v. "+
				"Attach each to a root (`alias <root>.<name> = <name>`), mark it `@global` if it "+
				"genuinely needs no asset, or deprecate it", orphans)
		})
		checked++
	}

	require.Greater(t, checked, 50, "the provider scan found almost nothing, so it is measuring the wrong directory")
}
