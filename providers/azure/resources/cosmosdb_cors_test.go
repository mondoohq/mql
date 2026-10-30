// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	cosmosdb "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/cosmos/armcosmos/v4"
	"github.com/stretchr/testify/assert"
)

func corsPolicy(allowedOrigins string) *cosmosdb.CorsPolicy {
	return &cosmosdb.CorsPolicy{AllowedOrigins: &allowedOrigins}
}

func TestCosmosCorsOrigins(t *testing.T) {
	for _, tc := range []struct {
		name     string
		policies []*cosmosdb.CorsPolicy
		want     []any
	}{
		{
			// The shape the bug turned on: ARM packs the whole list into one
			// string, so this used to be a single element.
			name:     "a comma-separated list becomes one entry per origin",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("https://app.example.com,https://admin.example.com")},
			want:     []any{"https://app.example.com", "https://admin.example.com"},
		},
		{
			name:     "the portal writes the list with spaces after the commas",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("https://a.example.com, https://b.example.com")},
			want:     []any{"https://a.example.com", "https://b.example.com"},
		},
		{
			name:     "a single origin still yields one entry",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("https://app.example.com")},
			want:     []any{"https://app.example.com"},
		},
		{
			name:     "a wildcard is its own entry",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("*")},
			want:     []any{"*"},
		},
		{
			name:     "several policies are gathered together",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("https://a.example.com"), corsPolicy("https://b.example.com,*")},
			want:     []any{"https://a.example.com", "https://b.example.com", "*"},
		},
		{
			// Repeating an origin across policies is what the account is
			// configured with, so it is reported rather than collapsed.
			name:     "duplicates across policies are kept",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("https://a.example.com"), corsPolicy("https://a.example.com")},
			want:     []any{"https://a.example.com", "https://a.example.com"},
		},
		{
			name:     "empty segments are dropped",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("https://a.example.com,,  ,https://b.example.com")},
			want:     []any{"https://a.example.com", "https://b.example.com"},
		},
		{
			name:     "an empty origin string yields nothing",
			policies: []*cosmosdb.CorsPolicy{corsPolicy("")},
			want:     []any{},
		},
		{
			name:     "a nil policy element is skipped, not dereferenced",
			policies: []*cosmosdb.CorsPolicy{nil, corsPolicy("*")},
			want:     []any{"*"},
		},
		{
			name:     "a policy with no origins is skipped",
			policies: []*cosmosdb.CorsPolicy{{}},
			want:     []any{},
		},
		{
			// Non-nil so a query can assert on length without a null guard.
			name:     "no policies at all",
			policies: nil,
			want:     []any{},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cosmosCorsOrigins(tc.policies)
			assert.NotNil(t, got)
			assert.Equal(t, tc.want, got)
		})
	}
}

// The audit this field exists for: an account that allows every origin must be
// findable. While the whole list was one element, neither of these comparisons
// could match, so a wildcard beside a real origin read as safe.
func TestCosmosCorsWildcardIsFindable(t *testing.T) {
	origins := cosmosCorsOrigins([]*cosmosdb.CorsPolicy{
		corsPolicy("https://app.example.com,*"),
	})

	assert.Contains(t, origins, "*", "a wildcard packed beside another origin must still be found")
	assert.Contains(t, origins, "https://app.example.com")
	assert.NotContains(t, origins, "https://app.example.com,*",
		"the unsplit string must not survive as an entry")
}

// cosmosNetworkConsistency is the caller, so pin that it passes the policies
// through rather than reintroducing the whole-string append.
func TestCosmosNetworkConsistencyCorsIsSplit(t *testing.T) {
	props := &cosmosdb.DatabaseAccountGetProperties{
		Cors: []*cosmosdb.CorsPolicy{corsPolicy("https://a.example.com,*")},
	}
	_, _, origins, _ := cosmosNetworkConsistency(props)
	assert.Equal(t, []any{"https://a.example.com", "*"}, origins)

	_, _, empty, locations := cosmosNetworkConsistency(nil)
	assert.Equal(t, []any{}, empty)
	assert.Equal(t, []any{}, locations)
}
