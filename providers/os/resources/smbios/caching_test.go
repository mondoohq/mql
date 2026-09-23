// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package smbios

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers/os/connection/mock"
)

// countingManager records how many times the underlying query would run.
type countingManager struct {
	calls atomic.Int32
	info  *SmBiosInfo
	err   error
	// block, when non-nil, holds Info() until it is closed, so a test can get
	// several callers in flight at once.
	block chan struct{}
}

func (c *countingManager) Name() string { return "counting manager" }

func (c *countingManager) Info() (*SmBiosInfo, error) {
	c.calls.Add(1)
	if c.block != nil {
		<-c.block
	}
	if c.err != nil {
		return nil, c.err
	}
	return c.info, nil
}

// TestCachingManager_QueriesOnceForRepeatedCallers is the point of the type:
// clouddetect fans out to six detectors at once and every one of them asks for
// SMBIOS data. On Windows that query is a PowerShell process; on macOS it is
// two ioreg processes. One caller's worth of work should serve all of them.
func TestCachingManager_QueriesOnceForRepeatedCallers(t *testing.T) {
	inner := &countingManager{info: &SmBiosInfo{SysInfo: SysInfo{Model: "test-model"}}}
	mgr := &cachingManager{inner: inner}

	for i := 0; i < 5; i++ {
		info, err := mgr.Info()
		require.NoError(t, err)
		assert.Equal(t, "test-model", info.SysInfo.Model)
	}

	assert.Equal(t, int32(1), inner.calls.Load(), "the underlying SMBIOS query ran more than once")
}

// TestCachingManager_CollapsesConcurrentCallers covers the shape the cloud
// detectors actually have: six goroutines arriving together, none of which has
// a cached answer to read yet. Without the lock held across the query they all
// start their own.
func TestCachingManager_CollapsesConcurrentCallers(t *testing.T) {
	const callers = 6

	inner := &countingManager{
		info:  &SmBiosInfo{SysInfo: SysInfo{Model: "test-model"}},
		block: make(chan struct{}),
	}
	mgr := &cachingManager{inner: inner}

	var wg sync.WaitGroup
	wg.Add(callers)
	for i := 0; i < callers; i++ {
		go func() {
			defer wg.Done()
			info, err := mgr.Info()
			assert.NoError(t, err)
			assert.NotNil(t, info)
		}()
	}

	// Let the first query finish only once every caller has had a chance to
	// arrive, so this fails if they are not being collapsed.
	close(inner.block)
	wg.Wait()

	assert.Equal(t, int32(1), inner.calls.Load(), "concurrent callers each started their own SMBIOS query")
}

// TestCachingManager_DoesNotCacheFailures keeps a transient failure from
// becoming permanent. A machine that was mid-boot when the first detector
// asked should still report its SMBIOS data to the next caller.
func TestCachingManager_DoesNotCacheFailures(t *testing.T) {
	inner := &countingManager{err: errors.New("smbios query failed")}
	mgr := &cachingManager{inner: inner}

	_, err := mgr.Info()
	require.Error(t, err)

	// The query now succeeds; the manager must not be stuck on the failure.
	inner.err = nil
	inner.info = &SmBiosInfo{SysInfo: SysInfo{Model: "test-model"}}

	info, err := mgr.Info()
	require.NoError(t, err)
	assert.Equal(t, "test-model", info.SysInfo.Model)
	assert.Equal(t, int32(2), inner.calls.Load(), "a failed query was cached instead of retried")
}

// TestCachingManager_KeepsInnerName leaves the manager's identity alone: the
// wrapper is a memo, not a different manager.
func TestCachingManager_KeepsInnerName(t *testing.T) {
	mgr := &cachingManager{inner: &countingManager{}}
	assert.Equal(t, "counting manager", mgr.Name())
}

// TestResolveManager_MemoizesOnEveryPlatform is the regression test for the
// gap this change closes. Only the Windows manager used to memoize Info(), so
// on macOS, Linux and AIX every caller re-ran the query. Resolving against a
// macOS mock and asking twice must hit the connection once.
func TestResolveManager_MemoizesOnEveryPlatform(t *testing.T) {
	resetManagerCache()
	t.Cleanup(resetManagerCache)

	conn, err := mock.New(0, &inventory.Asset{}, mock.WithPath("./testdata/macos.toml"))
	require.NoError(t, err)

	pf := &inventory.Platform{Name: "macos", Family: []string{"darwin", "bsd", "unix", "os"}, Arch: "arm64"}

	mgr, err := ResolveManager(conn, pf)
	require.NoError(t, err)

	first, err := mgr.Info()
	require.NoError(t, err)

	// A second resolve returns the same memoized manager, which is what the
	// cloud detectors and the machine resource each do.
	again, err := ResolveManager(conn, pf)
	require.NoError(t, err)
	second, err := again.Info()
	require.NoError(t, err)

	assert.Same(t, first, second, "the second caller got a freshly queried result instead of the memoized one")
}
