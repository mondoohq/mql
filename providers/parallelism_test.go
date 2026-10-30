// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// testProviders builds a provider index for the resolver tests. Each entry maps
// a provider name to the connection types it serves and the parallelism it
// declares.
func testProviders() Providers {
	mk := func(name string, parallelism int, connTypes ...string) *Provider {
		return &Provider{
			Provider: &plugin.Provider{
				Name:               name,
				ID:                 "go.mondoo.com/mql/providers/" + name,
				ConnectionTypes:    connTypes,
				DefaultParallelism: parallelism,
			},
		}
	}

	all := []*Provider{
		mk("aws", 8, "aws", "ebs"),
		mk("azure", 6, "azure", "azure-snapshot"),
		mk("github", 4, "github"),
		mk("network", 10, "host"),
		// os has not opted in
		mk("os", 0, "ssh", "local"),
	}

	res := make(Providers, len(all))
	for _, p := range all {
		res[p.ID] = p
	}
	return res
}

func asset(connTypes ...string) *inventory.Asset {
	a := &inventory.Asset{}
	for _, t := range connTypes {
		a.Connections = append(a.Connections, &inventory.Config{Type: t})
	}
	return a
}

func TestResolveParallelismExplicitRequestWins(t *testing.T) {
	// An operator who names a number gets it, even above what the machine or
	// the provider would have chosen on its own.
	assert.Equal(t, 20, ResolveParallelism(20, []*inventory.Asset{asset("github")}))
	assert.Equal(t, 1, ResolveParallelism(1, []*inventory.Asset{asset("aws")}))
}

func TestResolveParallelismUsesProviderDefault(t *testing.T) {
	provs := testProviders()

	tests := []struct {
		name     string
		roots    []*inventory.Asset
		cpuLimit int
		expected int
	}{
		{
			name:     "single provider under the cap",
			roots:    []*inventory.Asset{asset("aws")},
			cpuLimit: 16,
			expected: 8,
		},
		{
			name:     "alternate connection type of the same provider",
			roots:    []*inventory.Asset{asset("azure-snapshot")},
			cpuLimit: 16,
			expected: 6,
		},
		{
			name:     "capped by available cpu",
			roots:    []*inventory.Asset{asset("host")},
			cpuLimit: 6,
			expected: 6,
		},
		{
			name:     "several assets of one provider",
			roots:    []*inventory.Asset{asset("aws"), asset("aws"), asset("ebs")},
			cpuLimit: 16,
			expected: 8,
		},
		{
			name:     "mixed roots take the smallest declared value",
			roots:    []*inventory.Asset{asset("host"), asset("github"), asset("aws")},
			cpuLimit: 16,
			expected: 4,
		},
		{
			name:     "one asset carrying several connections",
			roots:    []*inventory.Asset{asset("aws", "github")},
			cpuLimit: 16,
			expected: 4,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, resolveParallelism(tc.roots, provs, tc.cpuLimit))
		})
	}
}

func TestResolveParallelismFallsBackToSequential(t *testing.T) {
	provs := testProviders()

	tests := []struct {
		name  string
		roots []*inventory.Asset
	}{
		{
			name:  "no roots",
			roots: nil,
		},
		{
			name:  "provider has not opted in",
			roots: []*inventory.Asset{asset("ssh")},
		},
		{
			// The one that matters: a single un-vetted root has to hold the
			// whole scan back, because one worker pool serves every asset.
			name:  "one opted-in root next to one that is not",
			roots: []*inventory.Asset{asset("aws"), asset("ssh")},
		},
		{
			name:  "unknown connection type",
			roots: []*inventory.Asset{asset("not-a-real-provider")},
		},
		{
			name:  "asset without connections",
			roots: []*inventory.Asset{{}},
		},
		{
			name:  "connection without a type",
			roots: []*inventory.Asset{{Connections: []*inventory.Config{{}}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, SequentialParallelism, resolveParallelism(tc.roots, provs, 16))
		})
	}
}

func TestResolveParallelismToleratesNilEntries(t *testing.T) {
	provs := testProviders()
	roots := []*inventory.Asset{nil, asset("aws"), {Connections: []*inventory.Config{nil}}}
	assert.Equal(t, 8, resolveParallelism(roots, provs, 16))
}

// TestDefaultParallelismSurvivesTheDescriptor covers the path the value really
// travels: a provider declares it in config.go, gen marshals it into
// dist/<name>.json, and Provider.LoadJSON reads it back on the client.
func TestDefaultParallelismSurvivesTheDescriptor(t *testing.T) {
	data, err := json.Marshal(&plugin.Provider{
		Name:               "gitlab",
		ID:                 "go.mondoo.com/mql/providers/gitlab",
		ConnectionTypes:    []string{"gitlab"},
		DefaultParallelism: 4,
	})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"DefaultParallelism":4`)

	var decoded plugin.Provider
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, 4, decoded.DefaultParallelism)
}

// TestDefaultParallelismAbsentFromOlderDescriptor pins the version-skew
// behavior: a provider built before this field existed decodes to zero, which
// resolves to sequential scanning rather than to a surprise default.
func TestDefaultParallelismAbsentFromOlderDescriptor(t *testing.T) {
	var decoded plugin.Provider
	// The versioned ID is intentional: this descriptor stands in for a
	// provider built before the field existed, which is also before provider
	// IDs became version-less. Do not "fix" it to the current form.
	require.NoError(t, json.Unmarshal([]byte(`{
		"Name": "gitlab",
		"ID": "go.mondoo.com/cnquery/v9/providers/gitlab",
		"ConnectionTypes": ["gitlab"]
	}`), &decoded))
	assert.Equal(t, 0, decoded.DefaultParallelism)

	provs := Providers{decoded.ID: {Provider: &decoded}}
	assert.Equal(t, SequentialParallelism, resolveParallelism([]*inventory.Asset{asset("gitlab")}, provs, 16))
}

func TestCpuCapFor(t *testing.T) {
	tests := []struct {
		cpus     int
		expected int
	}{
		{cpus: 0, expected: 1},
		{cpus: 1, expected: 1},
		{cpus: 2, expected: 1},
		{cpus: 3, expected: 2},
		{cpus: 4, expected: 2},
		{cpus: 8, expected: 4},
		{cpus: 12, expected: 6},
		{cpus: 16, expected: 8},
		{cpus: 64, expected: 32},
	}

	for _, tc := range tests {
		assert.Equal(t, tc.expected, cpuCapFor(tc.cpus), "cpus=%d", tc.cpus)
	}
}

// TestCpuCapForLeavesHeadroom pins the property the cap exists for: we never
// hand the scanner every core on the machine.
func TestCpuCapForLeavesHeadroom(t *testing.T) {
	for cpus := 1; cpus <= 128; cpus++ {
		cap := cpuCapFor(cpus)
		assert.GreaterOrEqual(t, cap, 1, "cpus=%d", cpus)
		if cpus > 2 {
			assert.Less(t, cap, cpus, "cpus=%d must keep cores free", cpus)
		}
	}
}
