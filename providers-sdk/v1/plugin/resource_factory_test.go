// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package plugin

import (
	"errors"
	goruntime "runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/types"
	"go.mondoo.com/mql/utils/syncx"
)

type fakeResource struct {
	id string
}

func (f *fakeResource) MqlID() string   { return f.id }
func (f *fakeResource) MqlName() string { return "fake" }

func testRuntime() *Runtime {
	return &Runtime{Resources: &syncx.Map[Resource]{}}
}

// countingFactory builds a factory whose init resolves every argument set to the
// same resource id, and records how many times init actually ran.
func countingFactory(id string, calls *atomic.Int64, hook func()) ResourceFactory {
	return ResourceFactory{
		Init: func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error) {
			calls.Add(1)
			if hook != nil {
				hook()
			}
			return args, &fakeResource{id: id}, nil
		},
		Create: func(runtime *Runtime, args map[string]*llx.RawData) (Resource, error) {
			return &fakeResource{id: id}, nil
		},
	}
}

// TestResolveResourceRunsInitOnceForConcurrentCallers is the core of the
// change: the second caller must wait on the first flight rather than spend a
// second API call whose result is then discarded.
//
// It is written as a two-goroutine handoff rather than a stress loop so that the
// call count is a deterministic assertion: the first init is held open until we
// have confirmed the second caller is parked, so a second init can only appear
// if the deduplication is genuinely absent.
func TestResolveResourceRunsInitOnceForConcurrentCallers(t *testing.T) {
	runtime := testRuntime()

	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	factory := countingFactory("vol-1", &calls, func() {
		once.Do(func() { close(started) })
		<-release
	})

	args := func() map[string]*llx.RawData {
		return map[string]*llx.RawData{"id": llx.StringData("vol-1")}
	}

	type result struct {
		res Resource
		err error
	}
	firstDone := make(chan result, 1)
	go func() {
		res, err := ResolveResource(runtime, "fake", args(), factory)
		firstDone <- result{res, err}
	}()

	// The first caller is now inside init and owns the flight.
	<-started

	secondDone := make(chan result, 1)
	go func() {
		res, err := ResolveResource(runtime, "fake", args(), factory)
		secondDone <- result{res, err}
	}()

	select {
	case <-secondDone:
		t.Fatal("the second caller resolved while the first was still in init; it ran its own init instead of joining the flight")
	case <-time.After(500 * time.Millisecond):
		// Expected: parked behind the first caller.
	}

	close(release)
	first := <-firstDone
	second := <-secondDone

	require.NoError(t, first.err)
	require.NoError(t, second.err)
	assert.Equal(t, int64(1), calls.Load(), "init must run exactly once for two identical concurrent calls")
	assert.Same(t, first.res, second.res, "both callers must receive the same resource instance")
}

// TestResolveResourceDoesNotMergeDifferentArguments guards the other direction:
// deduplication must never hand one caller another caller's resource.
func TestResolveResourceDoesNotMergeDifferentArguments(t *testing.T) {
	runtime := testRuntime()

	var calls atomic.Int64
	factory := ResourceFactory{
		Init: func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error) {
			calls.Add(1)
			return args, &fakeResource{id: args["id"].Value.(string)}, nil
		},
		Create: func(runtime *Runtime, args map[string]*llx.RawData) (Resource, error) {
			return nil, errors.New("unexpected create")
		},
	}

	a, err := ResolveResource(runtime, "fake", map[string]*llx.RawData{"id": llx.StringData("vol-1")}, factory)
	require.NoError(t, err)
	b, err := ResolveResource(runtime, "fake", map[string]*llx.RawData{"id": llx.StringData("vol-2")}, factory)
	require.NoError(t, err)

	assert.Equal(t, int64(2), calls.Load())
	assert.Equal(t, "vol-1", a.MqlID())
	assert.Equal(t, "vol-2", b.MqlID())
}

// TestResolveResourceSharesFailuresButDoesNotCacheThem pins the error policy:
// everyone waiting on a flight sees the failure, and the next caller gets a
// fresh attempt rather than a memoized error.
func TestResolveResourceSharesFailuresButDoesNotCacheThem(t *testing.T) {
	runtime := testRuntime()

	var calls atomic.Int64
	boom := errors.New("api is down")
	factory := ResourceFactory{
		Init: func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error) {
			if calls.Add(1) == 1 {
				return nil, nil, boom
			}
			return args, &fakeResource{id: "vol-1"}, nil
		},
		Create: func(runtime *Runtime, args map[string]*llx.RawData) (Resource, error) {
			return nil, errors.New("unexpected create")
		},
	}

	args := map[string]*llx.RawData{"id": llx.StringData("vol-1")}

	res, err := ResolveResource(runtime, "fake", args, factory)
	require.ErrorIs(t, err, boom)
	assert.Nil(t, res)

	// The flight is forgotten when it completes, so the retry runs init again.
	res, err = ResolveResource(runtime, "fake", args, factory)
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "vol-1", res.MqlID())
	assert.Equal(t, int64(2), calls.Load())
}

// TestResolveResourceKeepsThePartialResourceOnError preserves a behavior the
// generated code had: some inits report a resource alongside a failure.
func TestResolveResourceKeepsThePartialResourceOnError(t *testing.T) {
	runtime := testRuntime()

	boom := errors.New("partial")
	partial := &fakeResource{id: "vol-1"}
	factory := ResourceFactory{
		Init: func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error) {
			return nil, partial, boom
		},
	}

	res, err := ResolveResource(runtime, "fake", map[string]*llx.RawData{"id": llx.StringData("vol-1")}, factory)
	require.ErrorIs(t, err, boom)
	assert.Same(t, partial, res)
}

// TestResolveResourceFallsThroughToCreate covers the init path that returns no
// resource, only rewritten arguments.
func TestResolveResourceFallsThroughToCreate(t *testing.T) {
	runtime := testRuntime()

	factory := ResourceFactory{
		Init: func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error) {
			args["id"] = llx.StringData("rewritten")
			return args, nil, nil
		},
		Create: func(runtime *Runtime, args map[string]*llx.RawData) (Resource, error) {
			return &fakeResource{id: args["id"].Value.(string)}, nil
		},
	}

	res, err := ResolveResource(runtime, "fake", map[string]*llx.RawData{"id": llx.StringData("original")}, factory)
	require.NoError(t, err)
	assert.Equal(t, "rewritten", res.MqlID())
}

// TestResolveResourceWithoutInitSkipsTheFlight makes sure resources that have no
// init still resolve, and are not routed through the deduplication path.
func TestResolveResourceWithoutInitSkipsTheFlight(t *testing.T) {
	runtime := testRuntime()

	var calls atomic.Int64
	factory := ResourceFactory{
		Create: func(runtime *Runtime, args map[string]*llx.RawData) (Resource, error) {
			calls.Add(1)
			return &fakeResource{id: "vol-1"}, nil
		},
	}

	a, err := ResolveResource(runtime, "fake", nil, factory)
	require.NoError(t, err)
	b, err := ResolveResource(runtime, "fake", nil, factory)
	require.NoError(t, err)

	assert.Equal(t, int64(2), calls.Load())
	assert.Same(t, a, b, "the cache must still collapse both onto one instance")
}

// TestResolveResourceWithUnkeyableArgumentsStillResolves is the safety valve: an
// argument set we cannot compare must fall back to resolving without
// deduplication rather than fail or guess at a key.
func TestResolveResourceWithUnkeyableArgumentsStillResolves(t *testing.T) {
	runtime := testRuntime()

	var calls atomic.Int64
	factory := countingFactory("vol-1", &calls, nil)
	args := map[string]*llx.RawData{
		"filters": llx.ArrayData([]any{"a", "b"}, types.String),
	}

	a, err := ResolveResource(runtime, "fake", args, factory)
	require.NoError(t, err)
	b, err := ResolveResource(runtime, "fake", args, factory)
	require.NoError(t, err)

	assert.Equal(t, int64(2), calls.Load(), "unkeyable arguments must not be deduplicated")
	assert.Same(t, a, b, "the cache must still collapse both onto one instance")
}

// TestResolveResourceNestedResolutionDoesNotDeadlock covers the pattern every
// typed accessor uses: an init that resolves another resource while it runs.
// Distinct flights must never block each other.
func TestResolveResourceNestedResolutionDoesNotDeadlock(t *testing.T) {
	runtime := testRuntime()

	inner := ResourceFactory{
		Init: func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error) {
			return args, &fakeResource{id: "vpc-1"}, nil
		},
	}
	outer := ResourceFactory{
		Init: func(runtime *Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, Resource, error) {
			_, err := ResolveResource(runtime, "fake.vpc", map[string]*llx.RawData{"id": llx.StringData("vpc-1")}, inner)
			if err != nil {
				return nil, nil, err
			}
			return args, &fakeResource{id: "vol-1"}, nil
		},
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := ResolveResource(runtime, "fake", map[string]*llx.RawData{"id": llx.StringData("vol-1")}, outer)
		assert.NoError(t, err)
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a nested resolution of a different resource deadlocked")
	}
}

// TestInstantiateResourceConvergesOnOneInstance is the regression test for the
// check-then-act race the generated code used to carry. A Get followed by a Set
// lets two callers that both miss the Get hand out two different objects for one
// id, which makes every field memoized on the loser invisible to the rest of the
// graph. All callers must end up with the same pointer.
func TestInstantiateResourceConvergesOnOneInstance(t *testing.T) {
	// Sized to the cores actually available so that every caller can be running
	// at the same instant, and repeated because the window a check-then-act pair
	// leaves open is a handful of instructions wide. A single round of this
	// missed the regression roughly nine times out of ten.
	callers := goruntime.GOMAXPROCS(0)
	if callers < 4 {
		callers = 4
	}
	const rounds = 100

	for round := 0; round < rounds; round++ {
		runtime := testRuntime()

		// Each caller announces itself and then spins until all of them have,
		// so they leave Create together rather than being woken one at a time.
		var arrived atomic.Int64
		factory := ResourceFactory{
			Create: func(runtime *Runtime, args map[string]*llx.RawData) (Resource, error) {
				arrived.Add(1)
				for arrived.Load() < int64(callers) {
					goruntime.Gosched()
				}
				// A fresh instance every time, exactly like a real Create.
				return &fakeResource{id: "vol-1"}, nil
			},
		}

		results := make([]Resource, callers)
		var wg sync.WaitGroup
		for i := 0; i < callers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				res, err := InstantiateResource(runtime, "fake", nil, factory)
				assert.NoError(t, err)
				results[i] = res
			}(i)
		}
		wg.Wait()

		for i := 1; i < callers; i++ {
			if results[0] != results[i] {
				t.Fatalf("round %d: caller %d received a different instance for the same id; "+
					"two objects for one cache key means fields memoized on one are invisible to the other", round, i)
			}
		}
	}
}

func TestInitFlightKey(t *testing.T) {
	t.Run("no arguments still yields a key", func(t *testing.T) {
		key, ok := initFlightKey("aws.vpc", nil)
		require.True(t, ok)
		assert.NotEmpty(t, key)
	})

	t.Run("argument order does not matter", func(t *testing.T) {
		a, ok := initFlightKey("aws.vpc", map[string]*llx.RawData{
			"id":     llx.StringData("vpc-1"),
			"region": llx.StringData("us-east-1"),
		})
		require.True(t, ok)
		b, ok := initFlightKey("aws.vpc", map[string]*llx.RawData{
			"region": llx.StringData("us-east-1"),
			"id":     llx.StringData("vpc-1"),
		})
		require.True(t, ok)
		assert.Equal(t, a, b)
	})

	t.Run("distinguishes values that would concatenate alike", func(t *testing.T) {
		// Without length prefixes both of these serialize to "abc".
		a, ok := initFlightKey("fake", map[string]*llx.RawData{"ab": llx.StringData("c")})
		require.True(t, ok)
		b, ok := initFlightKey("fake", map[string]*llx.RawData{"a": llx.StringData("bc")})
		require.True(t, ok)
		assert.NotEqual(t, a, b)
	})

	t.Run("a value cannot forge a separator", func(t *testing.T) {
		a, ok := initFlightKey("fake", map[string]*llx.RawData{"a": llx.StringData("x\x00b\x00y")})
		require.True(t, ok)
		b, ok := initFlightKey("fake", map[string]*llx.RawData{
			"a": llx.StringData("x"),
			"b": llx.StringData("y"),
		})
		require.True(t, ok)
		assert.NotEqual(t, a, b)
	})

	t.Run("the type is part of the key", func(t *testing.T) {
		a, ok := initFlightKey("fake", map[string]*llx.RawData{"v": llx.StringData("1")})
		require.True(t, ok)
		b, ok := initFlightKey("fake", map[string]*llx.RawData{"v": llx.IntData(1)})
		require.True(t, ok)
		assert.NotEqual(t, a, b)
	})

	t.Run("the resource name is part of the key", func(t *testing.T) {
		a, ok := initFlightKey("aws.vpc", map[string]*llx.RawData{"id": llx.StringData("x")})
		require.True(t, ok)
		b, ok := initFlightKey("aws.subnet", map[string]*llx.RawData{"id": llx.StringData("x")})
		require.True(t, ok)
		assert.NotEqual(t, a, b)
	})

	t.Run("null and empty string are distinct", func(t *testing.T) {
		a, ok := initFlightKey("fake", map[string]*llx.RawData{"id": llx.StringData("")})
		require.True(t, ok)
		b, ok := initFlightKey("fake", map[string]*llx.RawData{"id": llx.NilData})
		require.True(t, ok)
		assert.NotEqual(t, a, b)
	})

	t.Run("scalars are keyable", func(t *testing.T) {
		now := time.Now()
		for name, arg := range map[string]*llx.RawData{
			"string": llx.StringData("x"),
			"int":    llx.IntData(7),
			"float":  llx.FloatData(1.5),
			"bool":   llx.BoolData(true),
			"time":   llx.TimeData(now),
			"nil":    llx.NilData,
		} {
			_, ok := initFlightKey("fake", map[string]*llx.RawData{"v": arg})
			assert.Truef(t, ok, "%s should be keyable", name)
		}
	})

	t.Run("non-scalars refuse rather than guess", func(t *testing.T) {
		for name, arg := range map[string]*llx.RawData{
			"array":    llx.ArrayData([]any{"a"}, types.String),
			"map":      llx.MapData(map[string]any{"a": "b"}, types.String),
			"resource": llx.ResourceData(&fakeResource{id: "x"}, "fake"),
		} {
			_, ok := initFlightKey("fake", map[string]*llx.RawData{"v": arg})
			assert.Falsef(t, ok, "%s should not be keyable", name)
		}
	})

	t.Run("an argument carrying an error refuses", func(t *testing.T) {
		_, ok := initFlightKey("fake", map[string]*llx.RawData{
			"v": {Type: types.String, Error: errors.New("broken")},
		})
		assert.False(t, ok)
	})

	t.Run("a nil argument refuses", func(t *testing.T) {
		_, ok := initFlightKey("fake", map[string]*llx.RawData{"v": nil})
		assert.False(t, ok)
	})
}

// TestInheritedRuntimesShareOneFlight covers the child-connection case. A child
// runtime that inherits its parent's resource cache must resolve through the
// same flights, because the two scopes have to agree: sibling assets scanned in
// parallel share one cache, so without shared flights they each run the same
// init and then race to publish into it.
func TestInheritedRuntimesShareOneFlight(t *testing.T) {
	parent := testRuntime()
	child := testRuntime()
	child.InheritResourceCacheFrom(parent)

	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	factory := countingFactory("vpc-1", &calls, func() {
		once.Do(func() { close(started) })
		<-release
	})

	args := func() map[string]*llx.RawData {
		return map[string]*llx.RawData{"id": llx.StringData("vpc-1")}
	}

	type result struct {
		res Resource
		err error
	}
	parentDone := make(chan result, 1)
	go func() {
		res, err := ResolveResource(parent, "fake", args(), factory)
		parentDone <- result{res, err}
	}()
	<-started

	childDone := make(chan result, 1)
	go func() {
		res, err := ResolveResource(child, "fake", args(), factory)
		childDone <- result{res, err}
	}()

	select {
	case <-childDone:
		t.Fatal("the child resolved while the parent was still in init; the two are not sharing flights")
	case <-time.After(500 * time.Millisecond):
	}

	close(release)
	p := <-parentDone
	c := <-childDone

	require.NoError(t, p.err)
	require.NoError(t, c.err)
	assert.Equal(t, int64(1), calls.Load(), "a parent and its child must run init once between them")
	assert.Same(t, p.res, c.res)
}

// TestUnrelatedRuntimesDoNotShareFlights is the other half: two connections that
// do not share a resource cache must not deduplicate against each other. They
// may be pointed at different accounts, where the same arguments mean different
// resources.
func TestUnrelatedRuntimesDoNotShareFlights(t *testing.T) {
	a := testRuntime()
	b := testRuntime()

	var calls atomic.Int64
	started := make(chan struct{})
	release := make(chan struct{})
	// Only the first init parks. A second one must be free to finish, which is
	// exactly what we are asserting can happen.
	var first atomic.Bool
	factory := countingFactory("vpc-1", &calls, func() {
		if first.CompareAndSwap(false, true) {
			close(started)
			<-release
		}
	})

	args := func() map[string]*llx.RawData {
		return map[string]*llx.RawData{"id": llx.StringData("vpc-1")}
	}

	aDone := make(chan struct{})
	go func() {
		defer close(aDone)
		_, _ = ResolveResource(a, "fake", args(), factory)
	}()
	<-started

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, err := ResolveResource(b, "fake", args(), factory)
		assert.NoError(t, err)
	}()

	select {
	case <-done:
		// Expected: b runs its own init rather than waiting on a's.
	case <-time.After(2 * time.Second):
		t.Fatal("an unrelated runtime waited on another connection's flight")
	}
	close(release)
	<-aDone
	assert.Equal(t, int64(2), calls.Load())
}
