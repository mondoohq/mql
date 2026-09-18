// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

func iacProviders() providers.Providers {
	return providers.Providers{
		"go.mondoo.com/mql/providers/k8s": {Provider: &plugin.Provider{
			Name: "k8s", ID: "go.mondoo.com/mql/providers/k8s",
			Targets: []plugin.TargetOptIn{{Target: "iac", Discovery: "k8s", ConnType: "k8s", Auto: true}},
		}},
		"go.mondoo.com/mql/providers/terraform": {Provider: &plugin.Provider{
			Name: "terraform", ID: "go.mondoo.com/mql/providers/terraform",
			Targets: []plugin.TargetOptIn{{Target: "iac", Discovery: "terraform", ConnType: "terraform-hcl"}},
		}},
	}
}

// withDefaultProviders swaps the package-level DefaultProviders for the length
// of a test. Every test here has to do it: that global now carries the real iac
// opt-ins, and TargetUniverse unions it with what is installed, so a test that
// did not swap it would be asserting against whatever the repo happens to
// declare today.
func withDefaultProviders(t *testing.T, nu providers.Providers) {
	t.Helper()
	old := providers.DefaultProviders
	providers.DefaultProviders = nu
	t.Cleanup(func() { providers.DefaultProviders = old })
}

// helmOnlyInDefaults is a provider this release knows about but that is not
// installed on this machine.
func helmOnlyInDefaults() providers.Providers {
	return providers.Providers{
		"helm": {Provider: &plugin.Provider{
			Name: "helm", ID: "go.mondoo.com/mql/providers/helm",
			Targets: []plugin.TargetOptIn{{Target: "iac", Discovery: "helm", ConnType: "helm", Auto: true}},
		}},
	}
}

func TestDetectConnectorNameDiscover(t *testing.T) {
	rootCmd := &cobra.Command{Use: "mql"}
	commands := []*Command{{Command: &cobra.Command{Use: "shell"}}}

	tests := []struct {
		name          string
		args          []string
		wantConnector string
		wantDiscover  []string
		wantSet       bool
	}{
		{
			name:          "no flag",
			args:          []string{"mql", "shell", "iac", "./repo"},
			wantConnector: "iac",
			wantDiscover:  []string{},
			wantSet:       false,
		},
		{
			name:          "a list",
			args:          []string{"mql", "shell", "iac", "./repo", "--discover", "terraform,k8s"},
			wantConnector: "iac",
			wantDiscover:  []string{"terraform", "k8s"},
			wantSet:       true,
		},
		{
			// An empty flag is not an unset flag. Without Changed() these two
			// are indistinguishable, and "nothing" would silently become "the
			// default set".
			name:          "an empty flag",
			args:          []string{"mql", "shell", "iac", "./repo", "--discover", ""},
			wantConnector: "iac",
			wantDiscover:  []string{},
			wantSet:       true,
		},
		{
			name:          "no connector named",
			args:          []string{"mql", "shell"},
			wantConnector: "local",
			wantDiscover:  []string{},
			wantSet:       false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			pre := detectConnectorName(test.args, rootCmd, commands, nil)
			assert.Equal(t, test.wantConnector, pre.ConnectorName)
			assert.Equal(t, test.wantDiscover, pre.Discover)
			assert.Equal(t, test.wantSet, pre.DiscoverSet)
		})
	}
}

func TestDiscoveriesForHelp(t *testing.T) {
	withDefaultProviders(t, nil)
	existing := iacProviders()

	// A meta-target connector lists the enumerated opt-ins, which is what makes
	// `mql shell iac --help` name what this machine can reach.
	iac := &plugin.Connector{Name: "iac"}
	assert.Equal(t, []string{"k8s", "terraform"}, discoveriesForHelp(iac, existing))

	desc := discoverFlagDesc(t, genBuiltinFlags(discoveriesForHelp(iac, existing)...))
	for _, want := range []string{"all", "auto", "k8s", "terraform"} {
		assert.Contains(t, desc, want)
	}

	// An ordinary connector keeps its own static slice, byte for byte.
	ssh := &plugin.Connector{Name: "ssh", Discovery: []string{"containers"}}
	assert.Equal(t, []string{"containers"}, discoveriesForHelp(ssh, existing))
	assert.Equal(t,
		discoverFlagDesc(t, genBuiltinFlags(ssh.Discovery...)),
		discoverFlagDesc(t, genBuiltinFlags(discoveriesForHelp(ssh, existing)...)))
}

func discoverFlagDesc(t *testing.T, flags []plugin.Flag) string {
	t.Helper()
	for _, flag := range flags {
		if flag.Long == "discover" {
			return flag.Desc
		}
	}
	t.Fatal("no --discover flag was generated")
	return ""
}

func TestEnsureTargetDiscoveriesUnknownValue(t *testing.T) {
	withDefaultProviders(t, nil)
	err := ensureTargetDiscoveries(cliPreflight{
		ConnectorName: "iac",
		Discover:      []string{"terrafrom"},
		DiscoverSet:   true,
	}, iacProviders())

	require.Error(t, err)
	// The message has to name the typo and list what would have worked; a bare
	// "unknown value" leaves the user guessing.
	assert.Contains(t, err.Error(), "terrafrom")
	assert.Contains(t, err.Error(), "k8s")
	assert.Contains(t, err.Error(), "terraform")
}

func TestEnsureTargetDiscoveriesIgnoresOrdinaryConnectors(t *testing.T) {
	withDefaultProviders(t, nil)
	// `ssh` declares no target, so nothing is resolved and no provider is
	// touched -- including for a --discover value that means something else
	// entirely to that connector.
	err := ensureTargetDiscoveries(cliPreflight{
		ConnectorName: "ssh",
		Discover:      []string{"containers"},
		DiscoverSet:   true,
	}, iacProviders())
	assert.NoError(t, err)
}

func TestEnsureTargetDiscoveriesInstalledNeedsNoFetch(t *testing.T) {
	withDefaultProviders(t, nil)
	// Both providers are in `existing`, so EnsureProvider resolves them from
	// there and nothing is fetched. AutoUpdate false proves it: a lookup that
	// fell through to an install would fail with it off.
	err := ensureTargetDiscoveries(cliPreflight{
		ConnectorName: "iac",
		Discover:      []string{"terraform", "k8s"},
		DiscoverSet:   true,
		AutoUpdate:    false,
	}, iacProviders())
	assert.NoError(t, err)
}

func TestEnsureTargetDiscoveriesNamedAndMissingIsAnError(t *testing.T) {
	withDefaultProviders(t, helmOnlyInDefaults())

	// helm is enumerated, so this is not a typo -- it is a discovery the user
	// asked for by name whose provider is absent, with installation off. That
	// has to fail: quietly skipping it produces a clean report missing exactly
	// the thing the user asked about (ADR 045).
	err := ensureTargetDiscoveries(cliPreflight{
		ConnectorName: "iac",
		Discover:      []string{"helm"},
		DiscoverSet:   true,
		AutoUpdate:    false,
	}, iacProviders())

	require.Error(t, err)
	assert.Contains(t, err.Error(), "helm")
	// The provider name is what the user has to install, so it is named too.
	assert.Contains(t, err.Error(), "(helm)")
}

func TestEnsureTargetDiscoveriesUnsetAndMissingDegrades(t *testing.T) {
	withDefaultProviders(t, helmOnlyInDefaults())

	// The same missing provider, reached through an unset --discover. That is
	// a preference rather than a statement, so the run continues on what is
	// installed instead of failing.
	err := ensureTargetDiscoveries(cliPreflight{
		ConnectorName: "iac",
		DiscoverSet:   false,
		AutoUpdate:    false,
	}, iacProviders())

	assert.NoError(t, err)
}

func TestTargetUniverseForEmptyConnector(t *testing.T) {
	withDefaultProviders(t, nil)
	assert.Empty(t, targetUniverseFor("", iacProviders()))
	assert.Empty(t, targetUniverseFor("ssh", iacProviders()))
	assert.Len(t, targetUniverseFor("iac", iacProviders()), 2)
}

func TestGenBuiltinFlagsSortsDiscoveries(t *testing.T) {
	desc := discoverFlagDesc(t, genBuiltinFlags("terraform", "k8s"))
	assert.True(t, strings.Contains(desc, "all, auto, k8s, terraform"), desc)
}
