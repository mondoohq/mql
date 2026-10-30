// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The availability-domain cache exists so a lister running inside the
// compartment fan-out does not pay one Identity call per compartment for an
// answer that is the same in all of them. What makes that work is that every
// caller for a region shares one fetch guard, so these tests are about the map
// wiring rather than about ociRetryLazy, whose own semantics are covered in
// ocilazy_test.go.

func TestOciAvailabilityDomainEntryIsSharedPerKey(t *testing.T) {
	t.Cleanup(resetOciAvailabilityDomainCache)
	resetOciAvailabilityDomainCache()

	first := ociAvailabilityDomainEntry("1/us-sanjose-1")
	second := ociAvailabilityDomainEntry("1/us-sanjose-1")

	// Same pointer, so the second caller waits on the first caller's fetch
	// instead of making its own.
	assert.Same(t, first, second)
}

func TestOciAvailabilityDomainEntryIsPerRegionAndConnection(t *testing.T) {
	t.Cleanup(resetOciAvailabilityDomainCache)
	resetOciAvailabilityDomainCache()

	sanjose := ociAvailabilityDomainEntry("1/us-sanjose-1")
	ashburn := ociAvailabilityDomainEntry("1/us-ashburn-1")
	otherConn := ociAvailabilityDomainEntry("2/us-sanjose-1")

	// A tenancy's domains differ between regions, so regions must not share an
	// entry - and two connections may be different tenancies entirely.
	assert.NotSame(t, sanjose, ashburn)
	assert.NotSame(t, sanjose, otherConn)
}

func TestOciAvailabilityDomainsFetchesOncePerKey(t *testing.T) {
	t.Cleanup(resetOciAvailabilityDomainCache)
	resetOciAvailabilityDomainCache()

	var calls atomic.Int32
	fetch := func() ([]string, error) {
		calls.Add(1)
		return []string{"cIew:US-SANJOSE-1-AD-1"}, nil
	}

	// Concurrent callers for one region, as the compartment fan-out produces.
	// Exactly one may reach the API; the rest must observe its result.
	const concurrency = 24
	var wg sync.WaitGroup
	results := make([][]string, concurrency)
	for i := range concurrency {
		wg.Go(func() {
			got, err := ociAvailabilityDomainEntry("1/us-sanjose-1").get(fetch)
			assert.NoError(t, err)
			results[i] = got
		})
	}
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load(),
		"the fan-out must cost one Identity call per region, not one per compartment")
	for i := range results {
		require.Equal(t, []string{"cIew:US-SANJOSE-1-AD-1"}, results[i])
	}
}

func TestOciAvailabilityDomainsDoesNotCacheFailure(t *testing.T) {
	t.Cleanup(resetOciAvailabilityDomainCache)
	resetOciAvailabilityDomainCache()

	entry := ociAvailabilityDomainEntry("1/us-sanjose-1")

	_, err := entry.get(func() ([]string, error) {
		return nil, assert.AnError
	})
	require.Error(t, err)

	// A throttled or transient Identity failure must not empty the region for
	// the rest of the scan - the next caller retries.
	got, err := entry.get(func() ([]string, error) {
		return []string{"cIew:US-SANJOSE-1-AD-1"}, nil
	})
	require.NoError(t, err)
	assert.Equal(t, []string{"cIew:US-SANJOSE-1-AD-1"}, got)
}

func resetOciAvailabilityDomainCache() {
	ociAvailabilityDomainCacheMu.Lock()
	defer ociAvailabilityDomainCacheMu.Unlock()
	ociAvailabilityDomainCache = map[string]*ociRetryLazy[[]string]{}
}
