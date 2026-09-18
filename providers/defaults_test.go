// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDefaultProvidersIncludesAllLocalProviders guards against the recurring
// mistake of adding a provider to ./providers without regenerating
// defaults.go (see PR #8187, which had to retroactively register bicep, helm,
// and kustomize). Every provider directory in this repository must have a
// matching entry in DefaultProviders. Extra entries (external providers that
// don't live in this repo) are fine — we only require the local ones to be
// present.
//
// Fix a failure by running: make providers/defaults
func TestDefaultProvidersIncludesAllLocalProviders(t *testing.T) {
	// The test runs with the package directory as its working directory, so
	// ./ is the providers/ directory that holds every provider subdirectory.
	entries, err := os.ReadDir(".")
	assert.NoError(t, err)

	foundProvider := false
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		// A provider directory is identified by its config/config.go. This
		// skips non-provider directories (e.g. test fixtures) without needing
		// a hardcoded allowlist.
		if _, err := os.Stat(filepath.Join(name, "config", "config.go")); err != nil {
			continue
		}
		foundProvider = true

		assert.Containsf(t, DefaultProviders, name,
			"provider %q is missing from DefaultProviders; run `make providers/defaults` to regenerate providers/defaults.go", name)
	}

	// Sanity check: make sure the directory scan actually discovered
	// providers, so a future refactor that breaks the scan doesn't silently
	// turn this into a no-op test.
	assert.True(t, foundProvider, "no provider directories were discovered; the directory scan is likely broken")
}

// TestDefaultProvidersIncludesExternalProviders pins the providers that are
// published to the registry but do not live in this repository. The generator
// behind defaults.go builds its map by scanning ./providers on disk, so it
// cannot see these — and regenerating the file silently deletes them.
// TestDefaultProvidersIncludesAllLocalProviders can't catch that either,
// because it only walks local provider directories.
//
// A missing entry is not a cosmetic problem: DefaultProviders is the only
// bridge between a policy that requires provider X and the on-demand install
// in EnsureProvider. Without it, Lookup returns nil, Install is never reached,
// and the scan dies with "cannot find provider for provider=X".
//
// Add to this list whenever a new externally published provider is registered
// in defaults.go by hand.
func TestDefaultProvidersIncludesExternalProviders(t *testing.T) {
	external := []string{
		"ai",
		"bigip",
		"checkpoint",
		"db2",
		"fortios",
		"junos",
		"networkdevices",
		"networkdiscovery",
		"oracledb",
		"panos",
		"unifi",
		"yara",
	}

	for _, name := range external {
		assert.Containsf(t, DefaultProviders, name,
			"externally published provider %q is missing from DefaultProviders; it must be added by hand (the generator only sees local provider directories)", name)
	}
}

// TestProviderIDsAreConsistent guards the invariant that a provider's ID is
// declared identically in all three places that carry it:
//
//  1. providers/<name>/config/config.go   — the ID the binary reports
//  2. providers/<name>/resources/<name>.lr — `option provider`, which becomes
//     the "provider" key on every resource in the generated schema
//  3. providers/defaults.go               — the air-gapped fallback entry
//
// Nothing else enforces this, and a mismatch is a *silent runtime* failure
// rather than a build error: resource routing compares the schema's provider
// string against the running provider's ID (see Runtime.lookupResourceProvider),
// so a config.go edit without the matching .lr edit makes every resource in
// that provider fail to resolve with "incorrect provider for asset". A stale
// defaults.go entry instead breaks on-demand install, which Lookup's
// name-based fallback then masks until the name no longer matches either.
//
// Fix a failure by aligning the three declarations, then running:
//
//	make providers/defaults
func TestProviderIDsAreConsistent(t *testing.T) {
	entries, err := os.ReadDir(".")
	assert.NoError(t, err)

	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		configPath := filepath.Join(name, "config", "config.go")
		raw, err := os.ReadFile(configPath)
		if err != nil {
			continue // not a provider directory
		}

		m := providerConfigIDRe.FindSubmatch(raw)
		if m == nil {
			continue // no ID declared (e.g. a provider still being scaffolded)
		}
		configID := string(m[1])
		checked++

		t.Run(name, func(t *testing.T) {
			// Providers are addressed by a version-less ID in the mql
			// namespace. This is what apps/provider-scaffold emits; pinning it
			// keeps a versioned or cnquery-namespaced ID from creeping back in.
			assert.Equalf(t, "go.mondoo.com/mql/providers/"+name, configID,
				"%s declares an unexpected provider ID", configPath)

			if p, ok := DefaultProviders[name]; ok {
				assert.Equalf(t, configID, p.ID,
					"defaults.go entry for %q disagrees with %s; run `make providers/defaults`", name, configPath)
			}

			lrs, err := filepath.Glob(filepath.Join(name, "resources", "*.lr"))
			assert.NoError(t, err)
			for _, lr := range lrs {
				lrRaw, err := os.ReadFile(lr)
				assert.NoError(t, err)
				for _, om := range lrOptionProviderRe.FindAllSubmatch(lrRaw, -1) {
					assert.Equalf(t, configID, string(om[1]),
						"`option provider` in %s disagrees with %s; resources would fail to route at runtime", lr, configPath)
				}
			}
		})
	}

	assert.NotZero(t, checked, "no provider configs were discovered; the directory scan is likely broken")
}

// TestDefaultProvidersCarryConnectorAliases guards the aliases a connector
// declares against being dropped from defaults.go.
//
// DefaultProviders is what resolves a connector name *before* the provider
// binary exists on the machine: AttachCLIs reads the name off the command line
// and hands it to EnsureProvider, which falls back to DefaultProviders.Lookup
// to decide what to install. Lookup matches a connector's Name and its Aliases,
// so an entry without them makes the alias unresolvable — `mql shell tofu ...`
// on a machine with no terraform provider dies with "cannot find provider"
// instead of installing it, while `mql shell opentofu ...` works.
//
// The generator used to drop every alias, so all six of these were broken. The
// scan is over config.go source rather than an import because defaults_test
// cannot import ~90 provider config packages.
//
// Fix a failure by running: make providers/defaults
func TestDefaultProvidersCarryConnectorAliases(t *testing.T) {
	entries, err := os.ReadDir(".")
	assert.NoError(t, err)

	checked := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()

		raw, err := os.ReadFile(filepath.Join(name, "config", "config.go"))
		if err != nil {
			continue // not a provider directory
		}

		for _, m := range connectorAliasesRe.FindAllSubmatch(raw, -1) {
			for _, am := range quotedStringRe.FindAllSubmatch(m[1], -1) {
				alias := string(am[1])
				checked++

				t.Run(name+"/"+alias, func(t *testing.T) {
					found := DefaultProviders.Lookup(ProviderLookup{ConnName: alias})
					if assert.NotNilf(t, found,
						"connector alias %q declared in %s/config/config.go does not resolve through DefaultProviders; on-demand install fails for it. Run `make providers/defaults`",
						alias, name) {
						assert.Equalf(t, name, found.Name,
							"alias %q resolves to provider %q, not %q", alias, found.Name, name)
					}
				})
			}
		}
	}

	// The scan finding nothing would turn this into a no-op that passes while
	// every alias is broken.
	assert.NotZero(t, checked, "no connector aliases were discovered; the source scan is likely broken")
}

var (
	providerConfigIDRe = regexp.MustCompile(`(?m)^\s*ID:\s*"([^"]+)"`)
	connectorAliasesRe = regexp.MustCompile(`(?m)^\s*Aliases:\s*\[\]string\{([^}]*)\}`)
	quotedStringRe     = regexp.MustCompile(`"([^"]+)"`)
	lrOptionProviderRe = regexp.MustCompile(`(?m)^\s*option\s+provider\s*=\s*"([^"]+)"`)
)

// TestDefaultProvidersCarryTargetOptIns is the guard against a forgotten
// `make providers/defaults`.
//
// DefaultProviders is what resolves a --discover value before the provider
// binary exists, so a target opt-in that is declared in a config but missing
// here means `mql shell iac ./repo --discover k8s` on a clean machine cannot
// find a provider to install (ADR 045). Nothing else would notice.
func TestDefaultProvidersCarryTargetOptIns(t *testing.T) {
	dirs, err := filepath.Glob(filepath.Join("..", "providers", "*"))
	require.NoError(t, err)

	reDiscovery := regexp.MustCompile(`Target:\s*"([^"]+)",\s*Discovery:\s*"([^"]+)"`)

	checked := 0
	for _, dir := range dirs {
		raw, err := os.ReadFile(filepath.Join(dir, "config", "config.go"))
		if err != nil {
			continue // not a provider
		}
		name := filepath.Base(dir)

		for _, match := range reDiscovery.FindAllStringSubmatch(string(raw), -1) {
			target, discovery := match[1], match[2]
			found := DefaultProviders.Lookup(ProviderLookup{Target: target, Discovery: discovery})
			require.NotNilf(t, found,
				"provider %q declares target %q discovery %q, but DefaultProviders cannot resolve it. Run `make providers/defaults`.",
				name, target, discovery)
			assert.Equalf(t, name, found.Name,
				"target %q discovery %q resolves to provider %q, expected %q",
				target, discovery, found.Name, name)
			checked++
		}
	}

	// A guard on the guard: if the regex stops matching, the loop above passes
	// while checking nothing.
	assert.Greater(t, checked, 5, "expected several target opt-ins across the providers")
}
