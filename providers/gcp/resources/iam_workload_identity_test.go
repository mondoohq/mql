// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWifProviderPathSuffix(t *testing.T) {
	// Synthetic: the format live provider listings return, with the project
	// spelled as a project number; no real project is named.
	assert.Equal(t, "workloadIdentityPools/github/providers/actions",
		wifProviderPathSuffix("projects/123456789012/locations/global/workloadIdentityPools/github/providers/actions"))
	// Synthetic: a full resource name with the service prefix.
	assert.Equal(t, "workloadIdentityPools/github/providers/actions",
		wifProviderPathSuffix("//iam.googleapis.com/projects/my-project/locations/global/workloadIdentityPools/github/providers/actions"))
	// Synthetic: a pool name without a provider segment, and garbage.
	assert.Equal(t, "", wifProviderPathSuffix("projects/1/locations/global/workloadIdentityPools/github"))
	assert.Equal(t, "", wifProviderPathSuffix("actions"))
	assert.Equal(t, "", wifProviderPathSuffix(""))
}

func TestResolveWifActorProviders(t *testing.T) {
	const (
		actions = "projects/123456789012/locations/global/workloadIdentityPools/github/providers/actions"
		broker  = "projects/123456789012/locations/global/workloadIdentityPools/github/providers/broker"
	)
	pool := map[string]string{actions: "actions", broker: "broker"}

	t.Run("no actor providers configured", func(t *testing.T) {
		// Synthetic: every provider seen live had no actorProviders.
		resolved, unresolved := resolveWifActorProviders(nil, pool)
		assert.Empty(t, resolved)
		assert.NotNil(t, resolved, "an unconfigured list is empty, not null")
		assert.Empty(t, unresolved)
	})

	t.Run("exact names resolve in order", func(t *testing.T) {
		// Synthetic: no target had actor providers configured.
		resolved, unresolved := resolveWifActorProviders([]string{broker, actions}, pool)
		assert.Equal(t, []string{"broker", "actions"}, resolved)
		assert.Empty(t, unresolved)
	})

	t.Run("a project ID spelling resolves by pool-relative suffix", func(t *testing.T) {
		// Synthetic: the listing names providers by project number, so a
		// reference spelled with the project ID must still match.
		resolved, unresolved := resolveWifActorProviders(
			[]string{"projects/my-project/locations/global/workloadIdentityPools/github/providers/broker"}, pool)
		assert.Equal(t, []string{"broker"}, resolved)
		assert.Empty(t, unresolved)
	})

	t.Run("a provider of another pool does not match", func(t *testing.T) {
		// Synthetic: same provider ID, different pool.
		other := "projects/123456789012/locations/global/workloadIdentityPools/gitlab/providers/broker"
		resolved, unresolved := resolveWifActorProviders([]string{other}, pool)
		assert.Empty(t, resolved)
		assert.Equal(t, []string{other}, unresolved)
	})

	t.Run("a purged provider is reported unresolved and left out", func(t *testing.T) {
		// Synthetic: a reference to a provider no longer in the pool listing.
		purged := "projects/123456789012/locations/global/workloadIdentityPools/github/providers/gone"
		resolved, unresolved := resolveWifActorProviders([]string{purged, actions, ""}, pool)
		assert.Equal(t, []string{"actions"}, resolved)
		assert.Equal(t, []string{purged}, unresolved)
	})
}
