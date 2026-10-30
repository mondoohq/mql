// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package manifest

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/k8s/connection/shared"
)

// countingLoad returns a load function that counts its calls.
func countingLoad(calls *atomic.Int32) func() (*loaded, error) {
	return func() (*loaded, error) {
		calls.Add(1)
		return &loaded{}, nil
	}
}

func TestCacheLoadsOncePerKeyUnderConcurrency(t *testing.T) {
	c := NewCache()
	key := cacheKey{path: "/manifests"}
	var calls atomic.Int32
	start := make(chan struct{})

	const n = 32
	got := make([]*loaded, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() {
			<-start
			l, _, err := c.acquire(key, countingLoad(&calls))
			assert.NoError(t, err)
			got[i] = l
		})
	}
	close(start)
	wg.Wait()

	assert.Equal(t, int32(1), calls.Load())
	for i := range got {
		assert.Same(t, got[0], got[i])
	}
	assert.Equal(t, n, c.entries[key].refs)
}

func TestCacheKeysAreDistinct(t *testing.T) {
	c := NewCache()
	var calls atomic.Int32
	a, _, err := c.acquire(cacheKey{path: "/a"}, countingLoad(&calls))
	require.NoError(t, err)
	b, _, err := c.acquire(cacheKey{path: "/a", gitUrl: "https://example.com/org/repo"}, countingLoad(&calls))
	require.NoError(t, err)

	assert.Equal(t, int32(2), calls.Load())
	assert.NotSame(t, a, b)
}

func TestCacheDropsEntryWithLastRelease(t *testing.T) {
	c := NewCache()
	key := cacheKey{path: "/manifests"}
	var calls atomic.Int32

	first, releaseFirst, err := c.acquire(key, countingLoad(&calls))
	require.NoError(t, err)
	_, releaseSecond, err := c.acquire(key, countingLoad(&calls))
	require.NoError(t, err)

	releaseFirst()
	require.Contains(t, c.entries, key, "an entry still held must stay")
	// Releasing twice must not give back the other holder's reference.
	releaseFirst()
	require.Contains(t, c.entries, key)

	releaseSecond()
	assert.NotContains(t, c.entries, key)

	again, release, err := c.acquire(key, countingLoad(&calls))
	require.NoError(t, err)
	defer release()
	assert.Equal(t, int32(2), calls.Load(), "a manifest connected after its last close is read again")
	assert.NotSame(t, first, again)
}

func TestCacheDoesNotKeepFailedLoads(t *testing.T) {
	c := NewCache()
	key := cacheKey{path: "/missing"}
	boom := errors.New("boom")

	_, _, err := c.acquire(key, func() (*loaded, error) { return nil, boom })
	require.ErrorIs(t, err, boom)
	assert.NotContains(t, c.entries, key)

	var calls atomic.Int32
	_, release, err := c.acquire(key, countingLoad(&calls))
	require.NoError(t, err)
	defer release()
	assert.Equal(t, int32(1), calls.Load())
}

func TestNilCacheLoadsEveryTime(t *testing.T) {
	var c *Cache
	var calls atomic.Int32
	for range 2 {
		_, release, err := c.acquire(cacheKey{path: "/manifests"}, countingLoad(&calls))
		require.NoError(t, err)
		release()
	}
	assert.Equal(t, int32(2), calls.Load())
}

// A connection holds its manifest until it is closed, including the one that
// fails for finding no objects.
func TestConnectionReleasesCacheOnClose(t *testing.T) {
	newAsset := func(namespace string) *inventory.Asset {
		return &inventory.Asset{Connections: []*inventory.Config{{
			Type:    "k8s",
			Options: map[string]string{shared.OPTION_NAMESPACE: namespace},
		}}}
	}
	c := NewCache()

	a, err := NewConnection(1, newAsset(""), WithManifestFile("./testdata/valid/deployment.yaml"), WithCache(c))
	require.NoError(t, err)
	b, err := NewConnection(2, newAsset("default"), WithManifestFile("./testdata/valid/deployment.yaml"), WithCache(c))
	require.NoError(t, err)
	assert.Same(t, a.(*Connection).manifest, b.(*Connection).manifest)
	require.Len(t, c.entries, 1)

	a.(*Connection).Close()
	require.Len(t, c.entries, 1)
	b.(*Connection).Close()
	assert.Empty(t, c.entries)

	// A folder of plain config YAML holds no Kubernetes objects.
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("foo: bar\n"), 0o600))
	_, err = NewConnection(3, newAsset(""), WithManifestFile(dir), WithCache(c))
	require.ErrorIs(t, err, plugin.ErrNoMatch)
	assert.Empty(t, c.entries)
}
