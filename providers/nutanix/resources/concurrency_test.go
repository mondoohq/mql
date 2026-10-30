// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/utils/syncx"
)

// fakeResource is a minimal plugin.Resource for exercising the cache helper.
type fakeResource struct{ id string }

func (f *fakeResource) MqlID() string   { return f.id }
func (f *fakeResource) MqlName() string { return "fake" }

// otherResource is a distinct plugin.Resource type used to verify that a cache
// entry of the wrong concrete type is not returned.
type otherResource struct{}

func (o *otherResource) MqlID() string   { return "other" }
func (o *otherResource) MqlName() string { return "other" }

func newTestRuntime() *plugin.Runtime {
	return &plugin.Runtime{Resources: &syncx.Map[plugin.Resource]{}}
}

func TestGuardReturnsValueAndError(t *testing.T) {
	var mu sync.Mutex

	v, err := guard(&mu, func() (int, error) { return 42, nil })
	if err != nil {
		t.Fatalf("guard returned error: %v", err)
	}
	if v != 42 {
		t.Errorf("guard returned %d, want 42", v)
	}

	wantErr := errors.New("boom")
	_, err = guard(&mu, func() (int, error) { return 0, wantErr })
	if !errors.Is(err, wantErr) {
		t.Errorf("guard error = %v, want %v", err, wantErr)
	}

	// guard must release the mutex once fn returns, including on the error path.
	if !mu.TryLock() {
		t.Fatal("guard did not release the mutex")
	}
	mu.Unlock()
}

// TestGuardSerializesConcurrentCalls verifies guard provides mutual exclusion:
// at most one fn runs at a time under a shared mutex. Run with -race to also
// catch unsynchronized access to the value the SDK client would mutate.
func TestGuardSerializesConcurrentCalls(t *testing.T) {
	var mu sync.Mutex
	var inFlight, maxInFlight int32

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			_, _ = guard(&mu, func() (struct{}, error) {
				n := atomic.AddInt32(&inFlight, 1)
				for {
					m := atomic.LoadInt32(&maxInFlight)
					if n <= m || atomic.CompareAndSwapInt32(&maxInFlight, m, n) {
						break
					}
				}
				time.Sleep(time.Millisecond)
				atomic.AddInt32(&inFlight, -1)
				return struct{}{}, nil
			})
		})
	}
	wg.Wait()

	if maxInFlight != 1 {
		t.Fatalf("guard allowed %d concurrent calls, want 1", maxInFlight)
	}
}

func TestCachedResourceHit(t *testing.T) {
	rt := newTestRuntime()
	want := &fakeResource{id: "abc"}
	rt.Resources.Set("nutanix.cluster\x00abc", want)

	got, ok := cachedResource[*fakeResource](rt, "nutanix.cluster", "abc")
	if !ok {
		t.Fatal("cachedResource missed a present entry")
	}
	if got != want {
		t.Errorf("cachedResource returned %p, want %p", got, want)
	}
}

func TestCachedResourceMiss(t *testing.T) {
	rt := newTestRuntime()
	rt.Resources.Set("nutanix.cluster\x00present", &fakeResource{id: "present"})

	// Same id under a different resource name must not collide.
	if _, ok := cachedResource[*fakeResource](rt, "nutanix.host", "present"); ok {
		t.Error("cachedResource returned an entry for the wrong resource name")
	}
	if _, ok := cachedResource[*fakeResource](rt, "nutanix.cluster", "missing"); ok {
		t.Error("cachedResource returned an entry for a missing id")
	}
}

func TestCachedResourceWrongType(t *testing.T) {
	rt := newTestRuntime()
	rt.Resources.Set("nutanix.cluster\x00abc", &otherResource{})

	if _, ok := cachedResource[*fakeResource](rt, "nutanix.cluster", "abc"); ok {
		t.Error("cachedResource returned a cache entry of the wrong concrete type")
	}
}
