// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/inventory"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
)

type blockedRuntime struct {
	staticRuntime
	schema       *resources.Schema
	phase        string
	entered      chan struct{}
	release      chan struct{}
	returned     chan struct{}
	unregistered chan struct{}
	unregister   sync.Once
}

func newBlockedRuntime(phase string) *blockedRuntime {
	return &blockedRuntime{
		schema: &resources.Schema{Resources: map[string]*resources.ResourceInfo{
			"probe": {Id: "probe", Name: "probe", Global: true, Fields: map[string]*resources.Field{
				"value": {Name: "value", Type: "bool"},
			}},
		}},
		phase: phase, entered: make(chan struct{}), release: make(chan struct{}),
		returned: make(chan struct{}), unregistered: make(chan struct{}),
	}
}

func (r *blockedRuntime) Schema() resources.ResourcesSchema { return r.schema }
func (r *blockedRuntime) Unregister(string) error {
	r.unregister.Do(func() { close(r.unregistered) })
	return nil
}
func (r *blockedRuntime) wait(ctx context.Context) error {
	close(r.entered)
	defer close(r.returned)
	select {
	case <-r.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (r *blockedRuntime) CreateResource(string, map[string]*llx.Primitive) (llx.Resource, error) {
	if r.phase == "create" {
		if err := r.wait(context.Background()); err != nil {
			return nil, err
		}
	}
	return &llx.MockResource{Name: "probe", ID: "one"}, nil
}
func (r *blockedRuntime) WatchAndUpdate(_ llx.Resource, _, _ string, callback func(any, error)) error {
	if err := r.wait(context.Background()); err != nil {
		return err
	}
	callback(true, nil)
	return nil
}

type cancellableRuntime struct {
	*blockedRuntime
	ctx context.Context
}

func (r *cancellableRuntime) WithContext(ctx context.Context) llx.Runtime {
	return &cancellableRuntime{blockedRuntime: r.blockedRuntime, ctx: ctx}
}
func (r *cancellableRuntime) CreateResource(name string, args map[string]*llx.Primitive) (llx.Resource, error) {
	if r.phase == "create" {
		if err := r.wait(r.ctx); err != nil {
			return nil, err
		}
		return &llx.MockResource{Name: "probe", ID: "one"}, nil
	}
	return r.blockedRuntime.CreateResource(name, args)
}
func (r *cancellableRuntime) WatchAndUpdate(_ llx.Resource, _, _ string, callback func(any, error)) error {
	if err := r.wait(r.ctx); err != nil {
		return err
	}
	callback(true, nil)
	return nil
}

func compileProbe(t *testing.T, runtime llx.Runtime) *llx.CodeBundle {
	t.Helper()
	bundle, err := mqlc.Compile("probe.value", nil, mqlc.NewConfig(runtime.Schema(), mql.DefaultFeatures))
	require.NoError(t, err)
	return bundle
}

func awaitSignal(t *testing.T, signal <-chan struct{}) {
	t.Helper()
	select {
	case <-signal:
	case <-time.After(5 * time.Second):
		t.Fatal("blocked operation did not reach the expected state")
	}
}

func TestExecutionManagerDeadlineIncludesSynchronousProviderCalls(t *testing.T) {
	for _, phase := range []string{"create", "field"} {
		t.Run(phase, func(t *testing.T) {
			blocked := newBlockedRuntime(phase)
			runtime := &cancellableRuntime{blockedRuntime: blocked}
			bundle := compileProbe(t, runtime)
			results := make(chan *llx.RawResult, 16)
			em := newExecutionManager(runtime.Schema(), runtime, nil, results, 100*time.Millisecond)
			defer em.Stop()
			done := make(chan error, 1)
			go func() { done <- em.executeCodeBundle(bundle, nil, "") }()
			awaitSignal(t, blocked.entered)
			select {
			case err := <-done:
				require.ErrorIs(t, err, errQueryTimeout)
			case <-time.After(5 * time.Second):
				t.Fatal("query deadline did not bound the synchronous provider call")
			}
			awaitSignal(t, blocked.returned)
			select {
			case result := <-results:
				t.Fatalf("timed-out call reported a result: %+v", result)
			default:
			}
		})
	}
}

func TestExecutionManagerDiscardsLateLegacyResults(t *testing.T) {
	runtime := newBlockedRuntime("field")
	bundle := compileProbe(t, runtime)
	results := make(chan *llx.RawResult, 16)
	em := newExecutionManager(runtime.Schema(), runtime, nil, results, 100*time.Millisecond)
	defer em.Stop()
	t.Cleanup(func() { close(runtime.release) })
	done := make(chan error, 1)
	go func() { done <- em.executeCodeBundle(bundle, nil, "") }()
	awaitSignal(t, runtime.entered)
	select {
	case err := <-done:
		require.ErrorIs(t, err, errQueryTimeout)
	case <-time.After(5 * time.Second):
		t.Fatal("legacy provider prevented the query deadline")
	}
	runtime.release <- struct{}{}
	awaitSignal(t, runtime.unregistered)
	select {
	case result := <-results:
		t.Fatalf("late result escaped the completed query: %+v", result)
	default:
	}
}

func TestExecutionManagerStopCancelsProviderCall(t *testing.T) {
	blocked := newBlockedRuntime("field")
	runtime := &cancellableRuntime{blockedRuntime: blocked}
	bundle := compileProbe(t, runtime)
	queue := make(chan runQueueItem, 1)
	em := newExecutionManager(runtime.Schema(), runtime, queue, make(chan *llx.RawResult, 16), time.Hour)
	em.Start()
	queue <- runQueueItem{codeBundle: bundle}
	awaitSignal(t, blocked.entered)
	stopped := make(chan struct{})
	go func() { em.Stop(); close(stopped) }()
	awaitSignal(t, stopped)
	awaitSignal(t, blocked.returned)
}

func TestExecutionManagerPropertyErrorDeliveryHonorsCancellation(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "stop"}[stopped], func(t *testing.T) {
			bundle := compileStatic(t, "true")
			// No consumer can accept the property error. The manager must
			// publish a fatal execution error instead of dropping it silently.
			em := newExecutionManager(emptySchema, staticRuntime{}, nil, make(chan *llx.RawResult), 20*time.Millisecond)
			defer em.Stop()
			want := errQueryTimeout
			if stopped {
				em.Stop()
				want = context.Canceled
			}
			require.ErrorIs(t, em.executeCodeBundle(bundle, nil, "property failed"), want)
		})
	}
}

type asynchronousRuntime struct{ *blockedRuntime }

func (asynchronousRuntime) WatchAndUpdate(_ llx.Resource, _, _ string, callback func(any, error)) error {
	go callback(true, nil)
	return nil
}

// unexpectedChecksumRuntime changes the VM's callback checksum after the
// manager captures its expected checksums, before the worker builds the VM.
// This injects an invalid asynchronous result without mutating running code.
type unexpectedChecksumRuntime struct {
	asynchronousRuntime
	bundle        *llx.CodeBundle
	callbackPanic chan any
}

func (r *unexpectedChecksumRuntime) WithContext(context.Context) llx.Runtime {
	ref := r.bundle.CodeV2.Blocks[0].Entrypoints[0]
	r.bundle.CodeV2.Checksums[ref] = "unexpected-checksum"
	return r
}

func (r *unexpectedChecksumRuntime) WatchAndUpdate(_ llx.Resource, _, _ string, callback func(any, error)) error {
	go func() {
		defer func() { r.callbackPanic <- recover() }()
		callback(true, nil)
	}()
	return nil
}

func TestExecutionManagerRejectsUnexpectedAsynchronousChecksum(t *testing.T) {
	runtime := &unexpectedChecksumRuntime{
		asynchronousRuntime: asynchronousRuntime{newBlockedRuntime("")},
		callbackPanic:       make(chan any, 1),
	}
	bundle := compileProbe(t, runtime)
	runtime.bundle = bundle
	expected := CodepointChecksums(bundle)
	results := make(chan *llx.RawResult, 16)
	em := newExecutionManager(runtime.Schema(), runtime, nil, results, time.Hour)
	t.Cleanup(func() {
		em.Stop()
		awaitSignal(t, runtime.unregistered)
	})
	done := make(chan error, 1)
	go func() { done <- em.executeCodeBundle(bundle, nil, "") }()
	select {
	case recovered := <-runtime.callbackPanic:
		require.Nil(t, recovered, "a provider callback must not panic outside the worker's recovery")
	case <-time.After(5 * time.Second):
		t.Fatal("asynchronous callback did not return")
	}
	select {
	case err := <-done:
		require.ErrorContains(t, err, `unexpected datapoint checksum "unexpected-checksum"`)
	case <-time.After(5 * time.Second):
		t.Fatal("invalid checksum waited for the query deadline instead of failing execution")
	}
	for len(results) > 0 {
		result := <-results
		require.Contains(t, expected, result.CodeID, "an unknown checksum must not reach the graph")
	}
}

type blockedUnregisterRuntime struct{ asynchronousRuntime }

func (r blockedUnregisterRuntime) Unregister(string) error {
	r.unregister.Do(func() {
		close(r.entered)
		<-r.release
		close(r.returned)
	})
	return nil
}

func TestExecutionManagerUnregisterCannotBlockDeadlineOrStop(t *testing.T) {
	for _, stopped := range []bool{false, true} {
		t.Run(map[bool]string{false: "deadline", true: "stop"}[stopped], func(t *testing.T) {
			runtime := blockedUnregisterRuntime{asynchronousRuntime{newBlockedRuntime("")}}
			bundle := compileProbe(t, runtime)
			queue := make(chan runQueueItem, 1)
			timeout := time.Second
			if stopped {
				timeout = time.Hour
			}
			em := newExecutionManager(runtime.Schema(), runtime, queue, make(chan *llx.RawResult, 16), timeout)
			t.Cleanup(func() {
				close(runtime.release)
				em.Stop()
				awaitSignal(t, runtime.returned)
			})
			em.Start()
			queue <- runQueueItem{codeBundle: bundle}
			awaitSignal(t, runtime.entered)
			if stopped {
				stopDone := make(chan struct{})
				go func() { em.Stop(); close(stopDone) }()
				awaitSignal(t, stopDone)
			} else {
				select {
				case err := <-em.Err():
					require.ErrorIs(t, err, errQueryTimeout)
				case <-time.After(5 * time.Second):
					t.Fatal("blocked Unregister prevented the query deadline")
				}
			}
			select {
			case <-runtime.returned:
				t.Fatal("cleanup was not held open while the manager returned")
			default:
			}
		})
	}
}

func TestExecutionManagerWaitsForAsynchronousResultDelivery(t *testing.T) {
	runtime := asynchronousRuntime{newBlockedRuntime("")}
	bundle := compileProbe(t, runtime)
	count := len(CodepointChecksums(bundle))
	require.Positive(t, count)
	// Hold exactly the final handoff. Marking the last datapoint complete
	// before sending it would let the manager cancel this still-blocked send
	// and return success while the graph is missing a required result.
	results := make(chan *llx.RawResult, count-1)
	em := newExecutionManager(runtime.Schema(), runtime, nil, results, 20*time.Millisecond)
	defer em.Stop()
	require.ErrorIs(t, em.executeCodeBundle(bundle, nil, ""), errQueryTimeout)
	awaitSignal(t, runtime.unregistered)
}

func TestExecutionManagerRecoversPanic(t *testing.T) {
	runQueue := make(chan runQueueItem, 1)
	resultChan := make(chan *llx.RawResult, 1)
	em := newExecutionManager(nil, nil, runQueue, resultChan, time.Second)
	em.Start()

	// A nil code bundle panics inside executeCodeBundle. The manager must
	// recover and surface it as an unrecoverable error instead of crashing.
	runQueue <- runQueueItem{}

	select {
	case err := <-em.Err():
		require.ErrorContains(t, err, "panic during query execution")
	case <-time.After(5 * time.Second):
		t.Fatal("expected the execution manager to report the panic as an error")
	}

	em.Stop()
}

var emptySchema = &resources.Schema{Resources: map[string]*resources.ResourceInfo{}}

// staticRuntime runs queries that need no resources.
type staticRuntime struct{}

func (staticRuntime) AssetMRN() string                  { return "" }
func (staticRuntime) Unregister(string) error           { return nil }
func (staticRuntime) Schema() resources.ResourcesSchema { return emptySchema }
func (staticRuntime) Close()                            {}
func (staticRuntime) Recording() llx.Recording          { return nil }
func (staticRuntime) SetRecording(llx.Recording) error  { return nil }
func (staticRuntime) AssetUpdated(*inventory.Asset)     {}
func (staticRuntime) CreateResource(string, map[string]*llx.Primitive) (llx.Resource, error) {
	return nil, errors.New("no resources")
}
func (staticRuntime) CloneResource(llx.Resource, string, []string, map[string]*llx.Primitive) (llx.Resource, error) {
	return nil, errors.New("no resources")
}
func (staticRuntime) WatchAndUpdate(llx.Resource, string, string, func(any, error)) error {
	return errors.New("no resources")
}

func compileStatic(t *testing.T, query string) *llx.CodeBundle {
	t.Helper()
	bundle, err := mqlc.Compile(query, nil, mqlc.NewConfig(emptySchema, mql.DefaultFeatures))
	require.NoError(t, err)
	return bundle
}

// A query that panics while it runs fails with the panic as its error, and the
// next query still runs: one broken query must not drop every other result.
func TestExecutionManagerPanicFailsOnlyThatQuery(t *testing.T) {
	resetReportedPanicSites(t)
	// `true && true` with its right operand swapped for a string: the bool &&
	// bool builtin asserts a bool and panics, as a bug in a builtin would.
	broken := compileStatic(t, "true && true")
	var patched bool
	for _, c := range broken.CodeV2.Blocks[0].Chunks {
		if c.Function != nil && strings.HasPrefix(c.Id, "&&") {
			c.Function.Args[0] = llx.StringPrimitive("not a bool")
			patched = true
		}
	}
	require.True(t, patched, "no && chunk to break")
	good := compileStatic(t, "true && false")

	runQueue := make(chan runQueueItem, 2)
	resultChan := make(chan *llx.RawResult, 16)
	em := newExecutionManager(emptySchema, staticRuntime{}, runQueue, resultChan, 5*time.Second)
	em.Start()
	defer em.Stop()

	runQueue <- runQueueItem{codeBundle: broken}
	runQueue <- runQueueItem{codeBundle: good}

	want := map[string]bool{}
	for _, c := range CodepointChecksums(broken) {
		want[c] = true
	}
	for _, c := range CodepointChecksums(good) {
		want[c] = true
	}
	brokenEntry := broken.CodeV2.Checksums[broken.CodeV2.Blocks[0].Entrypoints[0]]
	goodEntry := good.CodeV2.Checksums[good.CodeV2.Blocks[0].Entrypoints[0]]

	got := map[string]*llx.RawResult{}
	deadline := time.After(5 * time.Second)
	for len(got) < len(want) {
		select {
		case rr := <-resultChan:
			got[rr.CodeID] = rr
		case err := <-em.Err():
			t.Fatalf("a panic in one query stopped the execution manager: %v", err)
		case <-deadline:
			t.Fatalf("timed out with %d of %d results", len(got), len(want))
		}
	}

	require.NotNil(t, got[brokenEntry])
	require.ErrorContains(t, got[brokenEntry].Data.Error, "panic during query execution")
	require.NotNil(t, got[goodEntry])
	require.NoError(t, got[goodEntry].Data.Error)
	require.Equal(t, false, got[goodEntry].Data.Value)

	// The report names the builtin that panicked, not the runtime or the
	// execution manager.
	var site string
	for _, s := range reportedSites() {
		if strings.HasPrefix(s, "go.mondoo.com/mql/llx.") {
			site = s
		}
	}
	require.NotEmpty(t, site, "no llx panic site among %v", reportedSites())
}

// recoveredSite runs fn and returns the panic site seen by its recover.
func recoveredSite(fn func()) (site string) {
	defer func() {
		if recover() != nil {
			site = panicSite()
		}
	}()
	fn()
	return "no panic"
}

func panicsOnTypeAssertion(v any) { _ = v.(bool) }

func panicsOnIndex(i int) { _ = []int{}[i] }

func TestPanicSite(t *testing.T) {
	// A runtime-raised panic is attributed to the code that caused it, not to
	// runtime.panicdottypeE or runtime.panicIndex.
	site := recoveredSite(func() { panicsOnTypeAssertion("not a bool") })
	require.Contains(t, site, "internal.panicsOnTypeAssertion ")
	require.Contains(t, site, "execution_manager_test.go:")

	require.Contains(t, recoveredSite(func() { panicsOnIndex(1) }), "internal.panicsOnIndex ")
	require.Contains(t, recoveredSite(func() { panic("explicit") }), "internal.TestPanicSite.func")

	// The same site from two different callers is one site, so one report.
	require.Equal(t,
		recoveredSite(func() { panicsOnTypeAssertion(1) }),
		recoveredSite(func() { panicsOnTypeAssertion("x") }))

	require.Equal(t, "unknown", panicSite())
}

// resetReportedPanicSites starts a test with no panic sites reported and
// clears the ones it reports, so tests that read reportedPanicSites don't see
// each other's sites (or their own from an earlier -count run).
func resetReportedPanicSites(t *testing.T) {
	reportedPanicSites.Clear()
	t.Cleanup(reportedPanicSites.Clear)
}

func reportedSites() []string {
	var sites []string
	reportedPanicSites.Range(func(k, _ any) bool {
		sites = append(sites, k.(string))
		return true
	})
	return sites
}

func TestReportPanicOncePerSite(t *testing.T) {
	resetReportedPanicSites(t)
	report := func(fn func()) {
		defer func() { _ = reportPanic(nil, recover()) }()
		fn()
	}

	report(func() { panicsOnTypeAssertion(1) })
	require.Len(t, reportedSites(), 1)
	// Same site, different value and caller: already reported.
	report(func() { panicsOnTypeAssertion("x") })
	require.Len(t, reportedSites(), 1)
	// Another site is reported.
	report(func() { panicsOnIndex(1) })
	require.Len(t, reportedSites(), 2)
}
