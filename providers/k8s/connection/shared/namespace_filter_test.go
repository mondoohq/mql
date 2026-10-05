// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNamespaceFilterMatches mirrors the include/exclude precedence discovery
// applies when picking namespace assets. The connection has to agree with it,
// or a query returns objects from namespaces that were never discovered (or
// drops objects from ones that were).
func TestNamespaceFilterMatches(t *testing.T) {
	tests := []struct {
		name      string
		include   string
		exclude   string
		namespace string
		want      bool
	}{
		{name: "no filters accept everything", namespace: "prod", want: true},
		{name: "include exact match", include: "prod", namespace: "prod", want: true},
		{name: "include non-match", include: "prod", namespace: "dev", want: false},
		{name: "include glob match", include: "kube-*", namespace: "kube-system", want: true},
		{name: "include glob non-match", include: "kube-*", namespace: "prod", want: false},
		{name: "include list first", include: "prod,staging", namespace: "prod", want: true},
		{name: "include list second", include: "prod,staging", namespace: "staging", want: true},
		{name: "include list non-match", include: "prod,staging", namespace: "dev", want: false},
		{name: "exclude exact match", exclude: "kube-system", namespace: "kube-system", want: false},
		{name: "exclude non-match", exclude: "kube-system", namespace: "prod", want: true},
		{name: "exclude glob match", exclude: "kube-*", namespace: "kube-public", want: false},
		{name: "exclude list", exclude: "kube-system,kube-public", namespace: "kube-public", want: false},
		// include wins over exclude, matching FilterOpts.skip in discovery
		{name: "include wins over exclude", include: "prod", exclude: "prod", namespace: "prod", want: true},
		{name: "include set skips non-included", include: "prod", exclude: "dev", namespace: "staging", want: false},
		{name: "whitespace around values is trimmed", include: " prod , staging ", namespace: "staging", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewNamespaceFilter(tt.include, tt.exclude)
			require.NoError(t, err)
			assert.Equal(t, tt.want, f.Matches(tt.namespace))
		})
	}
}

// TestNamespaceFilterSingleNamespace pins which filters can be pushed down to
// the API server as a scoped list request. Anything else must list across
// namespaces, because the API server takes a namespace name and not a pattern:
// asking it for "a,b" or "kube-*" yields nothing.
func TestNamespaceFilterSingleNamespace(t *testing.T) {
	tests := []struct {
		name    string
		include string
		exclude string
		wantNs  string
		wantOk  bool
	}{
		{name: "single literal is pushed down", include: "prod", wantNs: "prod", wantOk: true},
		{name: "no filter is not a single namespace", wantOk: false},
		{name: "comma-separated list cannot be pushed down", include: "prod,staging", wantOk: false},
		{name: "glob cannot be pushed down", include: "kube-*", wantOk: false},
		{name: "character class cannot be pushed down", include: "ns[12]", wantOk: false},
		{name: "an exclude needs client-side filtering", include: "prod", exclude: "other", wantOk: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := NewNamespaceFilter(tt.include, tt.exclude)
			require.NoError(t, err)
			ns, ok := f.SingleNamespace()
			assert.Equal(t, tt.wantOk, ok)
			if tt.wantOk {
				assert.Equal(t, tt.wantNs, ns)
			}
		})
	}
}

func TestNamespaceFilterIsEmpty(t *testing.T) {
	f, err := NewNamespaceFilter("", "")
	require.NoError(t, err)
	assert.True(t, f.IsEmpty())
	assert.True(t, f.Matches("anything"))

	f, err = NewNamespaceFilter("", "kube-system")
	require.NoError(t, err)
	assert.False(t, f.IsEmpty())
}

func TestNamespaceFilterInvalidPattern(t *testing.T) {
	_, err := NewNamespaceFilter("prod,[", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid namespace pattern")
}

func TestIsLiteralNamespace(t *testing.T) {
	// Ordinary namespace names are RFC 1123 labels. `-` is legal in one, so it
	// must not be mistaken for character-class syntax.
	assert.True(t, IsLiteralNamespace("kube-system"))
	assert.True(t, IsLiteralNamespace("prod"))
	assert.True(t, IsLiteralNamespace("my-app-123"))

	assert.False(t, IsLiteralNamespace("kube-*"))
	assert.False(t, IsLiteralNamespace("ns?"))
	assert.False(t, IsLiteralNamespace("ns[12]"))
	assert.False(t, IsLiteralNamespace("{a,b}"))
}
