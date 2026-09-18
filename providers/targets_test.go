// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func testProvider(name string, targets ...plugin.TargetOptIn) *Provider {
	return &Provider{Provider: &plugin.Provider{
		Name:    name,
		ID:      "go.mondoo.com/mql/providers/" + name,
		Targets: targets,
	}}
}

func iacOptIn(discovery string, auto bool) plugin.TargetOptIn {
	return plugin.TargetOptIn{Target: "iac", Discovery: discovery, ConnType: discovery, Auto: auto}
}

func testUniverse() map[string][]TargetDiscovery {
	installed := Providers{
		"tf":  testProvider("terraform", iacOptIn("terraform", false), iacOptIn("opentofu", false)),
		"k8s": testProvider("k8s", iacOptIn("k8s", true)),
	}
	defaults := Providers{
		"helm": testProvider("helm", iacOptIn("helm", true)),
	}
	return TargetUniverse("iac", installed, defaults)
}

func TestTargetUniverse(t *testing.T) {
	u := testUniverse()

	assert.Equal(t, []string{"helm", "k8s", "opentofu", "terraform"}, TargetDiscoveryNames(u))
	require.Len(t, u["terraform"], 1)
	assert.Equal(t, "terraform", u["terraform"][0].Provider.Name)

	// A target nobody declares is empty, not a panic, and that is how the CLI
	// tells an ordinary connector from a meta-target one.
	assert.Empty(t, TargetUniverse("nope", Providers{"k8s": testProvider("k8s", iacOptIn("k8s", true))}, nil))
	assert.Empty(t, TargetUniverse("", nil, nil))
}

func TestTargetUniverseInstalledShadowsDefaults(t *testing.T) {
	// The same provider ID on both sides: the installed copy is authoritative,
	// because its <name>.json on disk is newer than release-time defaults. A
	// merge would report the retired opt-in as still available.
	installed := Providers{"k8s": testProvider("k8s", iacOptIn("k8s", true))}
	defaults := Providers{"k8s": testProvider("k8s", iacOptIn("k8s", true), iacOptIn("k8s-legacy", true))}

	u := TargetUniverse("iac", installed, defaults)
	assert.Equal(t, []string{"k8s"}, TargetDiscoveryNames(u))
	assert.Len(t, u["k8s"], 1)
}

func TestTargetUniverseSharedDiscoveryName(t *testing.T) {
	// Two opt-ins under one discovery name both land, so `--discover x` selects
	// the pair.
	p := testProvider("ansible",
		plugin.TargetOptIn{Target: "iac", Discovery: "ansible", ConnType: "ansible", Auto: true},
		plugin.TargetOptIn{Target: "iac", Discovery: "ansible", ConnType: "ansible", Auto: true, PerFile: true},
	)
	u := TargetUniverse("iac", Providers{"ansible": p}, nil)
	assert.Len(t, u["ansible"], 2)
}

// discoveryNames returns nil rather than an empty slice for an empty
// selection, so a table case can state "nothing selected" as nil and read the
// same way as the unknown column beside it.
func discoveryNames(selected []TargetDiscovery) []string {
	var names []string
	for _, d := range selected {
		names = append(names, d.OptIn.Discovery)
	}
	return names
}

func TestResolveTargetDiscoveries(t *testing.T) {
	u := testUniverse()

	tests := []struct {
		name         string
		requested    []string
		requestedSet bool
		want         []string
		wantUnknown  []string
	}{
		// Unset means the declared Auto subset, so terraform and opentofu --
		// which the user has to name by dialect -- are deliberately absent.
		{"unset selects the auto subset", nil, false, []string{"helm", "k8s"}, nil},
		{"auto named explicitly", []string{"auto"}, true, []string{"helm", "k8s"}, nil},
		{"all selects every opt-in", []string{"all"}, true, []string{"helm", "k8s", "opentofu", "terraform"}, nil},
		{"explicit names", []string{"terraform", "k8s"}, true, []string{"terraform", "k8s"}, nil},
		{"a non-auto name on its own", []string{"opentofu"}, true, []string{"opentofu"}, nil},
		{"both dialects", []string{"terraform", "opentofu"}, true, []string{"terraform", "opentofu"}, nil},
		{"a repeated name is selected once", []string{"k8s", "k8s"}, true, []string{"k8s"}, nil},
		{"auto plus a named one", []string{"auto", "terraform"}, true, []string{"helm", "k8s", "terraform"}, nil},

		// An empty flag is not an unset flag: it selects nothing, and must not
		// silently become the default set.
		{"empty flag selects nothing", []string{""}, true, nil, nil},

		{"a typo is reported", []string{"terrafrom"}, true, nil, []string{"terrafrom"}},
		// A typo alongside a good name still reports the typo; the caller
		// decides whether to fail.
		{"a typo beside a good name", []string{"k8s", "terrafrom"}, true, []string{"k8s"}, []string{"terrafrom"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			selected, unknown := ResolveTargetDiscoveries(u, test.requested, test.requestedSet)
			assert.Equal(t, test.want, discoveryNames(selected))
			assert.Equal(t, test.wantUnknown, unknown)
		})
	}
}

func TestResolveTargetDiscoveriesEmptyUniverse(t *testing.T) {
	// An ordinary connector: nothing is selected and nothing is unknown, so the
	// CLI can tell "not a meta-target" from "you asked for something that does
	// not exist".
	selected, unknown := ResolveTargetDiscoveries(nil, []string{"anything"}, true)
	assert.Nil(t, selected)
	assert.Nil(t, unknown)
}

func TestProvidersLookupTarget(t *testing.T) {
	tf := testProvider("terraform", iacOptIn("terraform", false))
	k8s := testProvider("k8s", iacOptIn("k8s", true))
	k8s.ConnectionTypes = []string{"k8s"}
	all := Providers{tf.ID: tf, k8s.ID: k8s}

	assert.Same(t, tf, all.Lookup(ProviderLookup{Target: "iac", Discovery: "terraform"}))
	assert.Same(t, k8s, all.Lookup(ProviderLookup{Target: "iac", Discovery: "k8s"}))

	assert.Nil(t, all.Lookup(ProviderLookup{Target: "iac", Discovery: "helm"}))
	assert.Nil(t, all.Lookup(ProviderLookup{Target: "other", Discovery: "terraform"}))

	// Either field alone resolves nothing: a Target-only lookup would match
	// whichever provider happens to declare any opt-in for it.
	assert.Nil(t, all.Lookup(ProviderLookup{Target: "iac"}))
	assert.Nil(t, all.Lookup(ProviderLookup{Discovery: "terraform"}))

	// The target clause is last, so a more specific key still wins.
	assert.Same(t, k8s, all.Lookup(ProviderLookup{ConnType: "k8s", Target: "iac", Discovery: "terraform"}))
}

func TestProviderLookupStringIncludesTarget(t *testing.T) {
	assert.Equal(t, "target=iac discovery=k8s",
		ProviderLookup{Target: "iac", Discovery: "k8s"}.String())
	// The error a missing provider produces has to name what was looked for.
	assert.Equal(t, "cannot find provider for target=iac discovery=k8s",
		(&ProviderNotFoundError{lookup: ProviderLookup{Target: "iac", Discovery: "k8s"}}).Error())
}
