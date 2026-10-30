// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"sync"
	"testing"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

var (
	snapshotProviderA = plugin.Provider{Name: "snapshot-a", ID: "go.mondoo.com/mql/providers/snapshot-a", Version: "1.0.0"}
	snapshotProviderB = plugin.Provider{Name: "snapshot-b", ID: "go.mondoo.com/mql/providers/snapshot-b", Version: "1.0.0"}
)

// TestCoordinatorProvidersSnapshot pins the contract that lets LoadSchema read
// c.providers under providersMu alone, without coordinator.mutex: nobody else
// holds an alias of the published map.
//
// Callers really do mutate the map they are handed — EnsureProvider adds the
// builtin connection providers (mock/sbom/recording) to the map it is given,
// and installDependencies adds freshly installed dependencies to the map
// ListActive returned — so an alias would be an unsynchronized write racing
// LoadSchema's read. That is a fatal runtime error ("concurrent map read and
// map write"), which kills the scanner rather than returning an error.
//
// This check is deliberately deterministic instead of relying on -race: the
// repo's race job only covers internal/workerpool, so a -race-only guard
// would not run here.
func TestCoordinatorProvidersSnapshot(t *testing.T) {
	t.Run("SetProviders stores a snapshot", func(t *testing.T) {
		c := newCoordinator()
		published := Providers{snapshotProviderA.ID: {Provider: &snapshotProviderA}}
		c.SetProviders(published)

		published.Add(&Provider{Provider: &snapshotProviderB})

		if _, ok := c.Providers()[snapshotProviderB.ID]; ok {
			t.Fatal("a write to the map passed to SetProviders reached the published map")
		}
	})

	t.Run("Providers returns a snapshot", func(t *testing.T) {
		c := newCoordinator()
		c.SetProviders(Providers{snapshotProviderA.ID: {Provider: &snapshotProviderA}})

		c.Providers().Add(&Provider{Provider: &snapshotProviderB})

		if _, ok := c.Providers()[snapshotProviderB.ID]; ok {
			t.Fatal("a write to the map returned by Providers reached the published map")
		}
	})

	// The snapshots above must not cost us the install-on-demand handoff:
	// EnsureProvider installs a missing provider and adds it to the map it
	// was handed (its own copy), then the runtime immediately asks the
	// coordinator to start it by id. The coordinator has to find it.
	t.Run("a provider installed on demand is startable", func(t *testing.T) {
		cached := CachedProviders
		t.Cleanup(func() { CachedProviders = cached })

		installed := &Provider{Provider: &snapshotProviderA}
		CachedProviders = []*Provider{installed}

		c := newCoordinator()
		listed, err := ListActive()
		if err != nil {
			t.Fatal(err)
		}
		c.SetProviders(listed)

		// What EnsureProvider does: install, then add to the caller's map.
		// Install resets the cache, so the next listing re-scans and sees it.
		newlyInstalled := &Provider{Provider: &snapshotProviderB}
		listed.Add(newlyInstalled)
		CachedProviders = []*Provider{installed, newlyInstalled}

		resolved, err := c.unsafeResolveProvider(snapshotProviderB.ID)
		if err != nil {
			t.Fatalf("provider installed on demand is not startable: %v", err)
		}
		if resolved.ID != snapshotProviderB.ID {
			t.Fatalf("resolved the wrong provider: %s", resolved.ID)
		}
	})

	t.Run("an unknown provider is still an error", func(t *testing.T) {
		cached := CachedProviders
		t.Cleanup(func() { CachedProviders = cached })
		CachedProviders = []*Provider{{Provider: &snapshotProviderA}}

		c := newCoordinator()
		if _, err := c.unsafeResolveProvider("go.mondoo.com/mql/providers/nope"); err == nil {
			t.Fatal("expected an error for an unknown provider")
		}
	})

	// Belt and braces: under -race this also catches an alias the two checks
	// above would miss. It is a no-op otherwise.
	t.Run("concurrent readers and writers", func(t *testing.T) {
		c := newCoordinator()
		c.SetProviders(Providers{snapshotProviderA.ID: {Provider: &snapshotProviderA}})

		var wg sync.WaitGroup
		wg.Add(3)
		// The installDependencies shape: mutates under coordinator.mutex.
		go func() {
			defer wg.Done()
			for range 500 {
				c.mutex.Lock()
				c.Providers().Add(&Provider{Provider: &snapshotProviderB})
				c.mutex.Unlock()
			}
		}()
		// The EnsureProvider shape: mutates with no lock at all.
		go func() {
			defer wg.Done()
			for range 500 {
				c.Providers().Add(&Provider{Provider: &snapshotProviderB})
			}
		}()
		// LoadSchema's read, which holds only providersMu.
		go func() {
			defer wg.Done()
			for range 500 {
				_, _ = c.LoadSchema(snapshotProviderA.ID)
			}
		}()
		wg.Wait()
	})
}
