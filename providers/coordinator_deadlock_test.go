// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package providers

import (
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestCoordinatorSchemaLockOrder guards against an ABBA deadlock between
// coordinator.mutex and extensibleSchema.sync. Before LoadSchema stopped
// taking coordinator.mutex this test hung deterministically:
//
//	goroutine B: schema.Lookup(miss) ── holds schema.sync ──▶ unsafeLoadAll
//	             ──▶ coordinator.LoadSchema(name) ── wants coordinator.mutex
//	goroutine A: coordinator.GetRunningProvider(new) ── holds coordinator.mutex
//	             ──▶ unsafeStartProvider ──▶ schema.Add ── wants schema.sync
//
// In a scan this is a dispatcher worker compiling the first policy filter
// that references a not-yet-loaded resource (B) while the main goroutine
// connects a discovered child asset whose provider isn't running yet (A) —
// e.g. a github org scan starting the k8s provider for a manifest found in
// a repo. Once wedged, nothing times out; the job runs to its deadline.
//
// A is played out as its two lock steps rather than by calling
// GetRunningProvider, so the interleaving is controlled instead of raced:
// the test takes coordinator.mutex (what GetRunningProvider does first),
// waits until B provably holds schema.sync, then calls schema.Add under
// that mutex (what unsafeStartProvider does last). unsafeLoadAll calls
// LoadSchema for every provider ListActive returns, and the builtins alone
// are enough for that, so nothing needs to be installed on disk.
func TestCoordinatorSchemaLockOrder(t *testing.T) {
	c := newCoordinator()

	// A, step 1: GetRunningProvider takes coordinator.mutex before it starts
	// the provider and registers its schema.
	c.mutex.Lock()
	defer c.mutex.Unlock()

	// B: a lookup that misses with lastRefreshed < LastProviderInstall runs
	// unsafeLoadAll with schema.sync held.
	bDone := make(chan struct{})
	go func() {
		defer close(bDone)
		c.schema.Lookup("resource.that.does.not.exist")
	}()

	// Wait until B holds schema.sync — TryLock succeeding means it isn't
	// there yet, so give the lock straight back and poll again — or until B
	// has finished, which it can only do if LoadSchema no longer needs
	// coordinator.mutex (the fixed behavior).
	deadline := time.Now().Add(10 * time.Second)
	for {
		select {
		case <-bDone:
		default:
			if !c.schema.sync.TryLock() {
				break
			}
			c.schema.sync.Unlock()
			if time.Now().After(deadline) {
				t.Fatal("schema.Lookup never took schema.sync")
			}
			time.Sleep(time.Millisecond)
			continue
		}
		break
	}

	// A, step 2, still under coordinator.mutex: register the new provider's
	// schema, which needs schema.sync.
	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		c.schema.Add(BuiltinCoreID, builtinProviders[BuiltinCoreID].Runtime.Schema)
	}()

	select {
	case <-aDone:
	case <-time.After(15 * time.Second):
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		for g := range strings.SplitSeq(string(buf[:n]), "\n\n") {
			if strings.Contains(g, "extensibleSchema") || strings.Contains(g, "coordinator)") {
				t.Log(g)
			}
		}
		t.Fatal("deadlock: schema.Add (holding coordinator.mutex) and schema.Lookup (holding schema.sync) never returned")
	}

	select {
	case <-bDone:
	case <-time.After(15 * time.Second):
		t.Fatal("schema.Lookup did not return after schema.Add completed")
	}
}
