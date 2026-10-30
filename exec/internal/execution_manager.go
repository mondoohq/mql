// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/mqlc"
	"go.mondoo.com/mql/providers-sdk/v1/resources"
	"go.mondoo.com/mql/providers-sdk/v1/upstream/health"
)

type executionManager struct {
	schema  resources.ResourcesSchema
	runtime llx.Runtime
	// runQueue is the channel the execution manager will read
	// items that need to be run from
	runQueue chan runQueueItem
	// resultChan is the channel the execution manager will write
	// results to
	resultChan chan *llx.RawResult
	// errChan is used to signal an unrecoverable error. The execution
	// manager writes to this channel
	errChan chan error
	// timeout covers starting a query, synchronous provider calls and waiting
	// for its remaining results.
	timeout time.Duration
	// stopChan is a channel that is closed when a stop is requested
	stopChan chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	stopOnce sync.Once
	wg       sync.WaitGroup
}

type runQueueItem struct {
	codeBundle *llx.CodeBundle
	props      map[string]*llx.Result
}

func newExecutionManager(schema resources.ResourcesSchema, runtime llx.Runtime, runQueue chan runQueueItem,
	resultChan chan *llx.RawResult, timeout time.Duration,
) *executionManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &executionManager{
		runQueue:   runQueue,
		schema:     schema,
		runtime:    runtime,
		resultChan: resultChan,
		errChan:    make(chan error, 1),
		stopChan:   make(chan struct{}),
		ctx:        ctx,
		cancel:     cancel,
		timeout:    timeout,
	}
}

func (em *executionManager) Start() {
	em.wg.Go(func() {
		// current is the code bundle being executed; the deferred panic
		// handler snapshots it at crash time so the report carries WHICH
		// query was running, not just where the engine died. The recover
		// stays at the goroutine top so the stacktrace points at the
		// panic site. Instead of crashing the process, the panic is
		// reported upstream and surfaced as an unrecoverable execution
		// error, mirroring the executeCodeBundle error path below.
		//
		// A panic while a query runs is handled in executeCodeBundle, which
		// fails that query only. This handler is for panics outside of it.
		var current *llx.CodeBundle
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			err := reportPanic(current, r)
			select {
			case em.errChan <- err:
			default:
			}
		}()
		for {
			// Prioritize stopChan
			select {
			case <-em.stopChan:
				return
			default:
			}

			select {
			case item, ok := <-em.runQueue:
				if !ok {
					return
				}
				props := make(map[string]*llx.Primitive)
				errMsg := ""
				for k, r := range item.props {
					if r.Error != "" {
						// This case is tricky to handle. If we cannot run the query at
						// all, its unclear what to report for the datapoint. If we
						// report them in, then another query can't report them, at least
						// with the way things are right now. If we don't report them,
						// things will wait around for datapoint results that will never
						// arrive.
						errMsg = "property " + k + " errored: " + r.Error
						break
					}
					props[k] = r.Data
				}

				current = item.codeBundle
				err := em.executeCodeBundle(item.codeBundle, props, errMsg)
				current = nil
				if err != nil {
					// an error is returned if we cannot execute a query. This happens
					// if the lumi runtime doesn't report back expected data, there is
					// a problem with the lumi runtime, or the query is somehow invalid.
					// We need to give up here because the underlying runtime is in a bad
					// state and/or we will not be able to report certain datapoints and
					// we cannot be confident about which ones
					select {
					case em.errChan <- err:
					default:
					}
					return
				}
			case <-em.stopChan:
				return
			}
		}
	})
}

func (em *executionManager) Err() chan error {
	return em.errChan
}

func (em *executionManager) Stop() {
	em.stopOnce.Do(func() {
		em.cancel()
		close(em.stopChan)
	})
	em.wg.Wait()
}

// reportedPanicSites holds the panic sites already reported upstream by this
// process. A panic in one query no longer stops the asset, so the same bug can
// fire once per query on every asset; it is reported once per site.
var reportedPanicSites sync.Map

// reportPanic reports a recovered panic upstream and in the log, with the query
// that was running when there is one, and returns it as an error. It must be
// called from the deferred function that recovered, so the stack still shows
// the panic site. Only the first panic at a site is reported upstream and logs
// its stack; later ones log the site and the query.
func reportPanic(codeBundle *llx.CodeBundle, r any) error {
	var tags map[string]string
	if codeBundle != nil {
		tags = health.QueryPanicTags(codeBundle.CodeV2.GetId(), codeBundle.Source)
	}
	site := panicSite()
	if _, seen := reportedPanicSites.LoadOrStore(site, struct{}{}); seen {
		log.Error().
			Str("site", site).
			Interface("tags", tags).
			Msgf("recovered from panic during query execution: %v", r)
		return fmt.Errorf("panic during query execution: %v", r)
	}

	stack := debug.Stack()
	health.ReportRecoveredPanic("mql", mql.Version, mql.Build, r, stack, tags)
	log.Error().
		Str("site", site).
		Str("stacktrace", string(stack)).
		Msgf("recovered from panic during query execution: %v", r)
	return fmt.Errorf("panic during query execution: %v", r)
}

// panicSite returns the function and line that panicked, as "func file:line":
// the first frame below runtime.gopanic that is not in the runtime itself
// (runtime.panicdottypeE, runtime.panicIndex, runtime.sigpanic, ...). It must
// be called while the panic is being recovered. Returns "unknown" when no
// panic is on the stack.
func panicSite() string {
	pcs := make([]uintptr, 64)
	frames := runtime.CallersFrames(pcs[:runtime.Callers(2, pcs)])
	inPanic := false
	for {
		frame, more := frames.Next()
		if inPanic && !strings.HasPrefix(frame.Function, "runtime.") {
			return fmt.Sprintf("%s %s:%d", frame.Function, frame.File, frame.Line)
		}
		if frame.Function == "runtime.gopanic" {
			inPanic = true
		}
		if !more {
			return "unknown"
		}
	}
}

func (em *executionManager) executeCodeBundle(codeBundle *llx.CodeBundle, props map[string]*llx.Primitive, errMsg string) error {
	// Start the budget before Run: provider calls made while starting a query
	// are synchronous, so starting a timer afterwards cannot bound them.
	ctx, cancel := context.WithTimeout(em.ctx, em.timeout)
	defer cancel()
	wg := NewWaitGroup()
	checksums := map[string]struct{}{}
	var resultMu sync.Mutex
	var resultErr error
	finished := false

	sendResult := func(rr *llx.RawResult) {
		resultMu.Lock()
		defer resultMu.Unlock()
		if finished || ctx.Err() != nil {
			return
		}
		log.Trace().Str("codeID", rr.CodeID).Msg("received result from executor")
		// Callbacks can run on provider goroutines, outside the worker's
		// recovery. Fail execution without panicking or forwarding an unknown
		// checksum to the graph, and wake the manager without waiting for its
		// deadline or a potentially blocked Unregister.
		if _, ok := checksums[rr.CodeID]; !ok {
			resultErr = fmt.Errorf("unexpected datapoint checksum %q", rr.CodeID)
			log.Error().Err(resultErr).Msg("invalid result from executor")
			cancel()
			return
		}
		select {
		case em.resultChan <- rr:
			wg.Done(rr.CodeID)
		case <-ctx.Done():
		}
	}

	// Find the list of things we must wait for before execution of this codebundle is considered done
	for _, checksum := range CodepointChecksums(codeBundle) {
		if _, ok := checksums[checksum]; !ok {
			checksums[checksum] = struct{}{}
			// We must use a synchronization primitive because the llx.Run callback
			// is not guaranteed to happen in a single thread
			wg.Add(checksum)
			if errMsg != "" {
				// TODO: this is not entirely correct when looking at things as a whole.
				// Its possible that another query executing will produce a non error.
				// However, datapoint nodes take the first data that was reported. This
				// issue exists in general for any query that errors
				sendResult(&llx.RawResult{
					CodeID: checksum,
					Data: &llx.RawData{
						Error: errors.New(errMsg),
					},
				})
			}
		}
	}

	if errMsg != "" {
		// Property failures still have to deliver their datapoints. A deadline
		// while the result channel is full must fail the execution; returning
		// success would leave the graph waiting for the dropped datapoints.
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return errQueryTimeout
		}
		return ctx.Err()
	}

	codeID := codeBundle.CodeV2.GetId()
	log.Debug().Str("qrid", codeID).Msg("starting query execution")
	defer func() {
		log.Debug().Str("qrid", codeID).Msg("finished query execution")
	}()

	runtime := em.runtime
	if contextual, ok := runtime.(llx.ContextRuntime); ok {
		runtime = contextual.WithContext(ctx)
	}

	// The worker owns the executor, including unregistering it. Older in-process
	// runtimes cannot be forcibly interrupted; if one eventually returns, its
	// late callbacks are discarded and it still unregisters its own watchers.
	// Unregister stays in this worker so blocked cleanup cannot prevent the
	// manager from returning on the deadline or Stop.
	type executionResult struct {
		err      error
		panicErr error
	}
	run := func() (out executionResult) {
		defer func() {
			if r := recover(); r != nil {
				out.panicErr = reportPanic(codeBundle, r)
			}
		}()
		x, err := llx.NewExecutorV2WithSkew(codeBundle.CodeV2, runtime, props, sendResult,
			skewPolicyFor(codeBundle, runtime))
		if err != nil {
			out.err = err
			return
		}
		defer func() {
			if err := x.Unregister(); err != nil && out.err == nil {
				out.err = err
			}
		}()
		out.err = x.RunWithContext(ctx)
		if out.err == nil {
			wg.Wait()
		}
		return
	}
	done := make(chan executionResult, 1)
	go func() { done <- run() }()

	var out executionResult
	select {
	case out = <-done:
	case <-ctx.Done():
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		log.Error().Dur("timeout", em.timeout).Str("qrid", codeID).Msg("execution timed out")
		out.err = errQueryTimeout
	} else if ctx.Err() != nil {
		out.err = ctx.Err()
	}
	// Release any callback blocked on a full result channel before closing the
	// gate. No worker is allowed to report a successful result after this point.
	cancel()
	resultMu.Lock()
	finished = true
	if resultErr != nil {
		// Preserve the callback failure rather than its cancellation side
		// effect, including when the worker completed at the same time.
		out.err = resultErr
	}
	unreported := wg.Decommission()
	resultMu.Unlock()
	if len(unreported) > 0 {
		log.Warn().Strs("missing", unreported).Str("qrid", codeID).Msg("unreported datapoints")
	}
	if out.panicErr != nil {
		// A recovered panic fails this query's remaining datapoints and allows
		// the next query to run. A deadline, like other fatal execution errors,
		// returns through Err instead so the graph cannot finish successfully
		// before it observes that error.
		for _, checksum := range unreported {
			select {
			case em.resultChan <- &llx.RawResult{CodeID: checksum, Data: &llx.RawData{Error: out.panicErr}}:
			case <-em.stopChan:
				return out.err
			}
		}
	}
	return out.err
}

var errQueryTimeout = errors.New("query execution timed out")

// skewPolicyFor compares what a bundle says it needs against what this build
// has, and returns a policy naming every provider the reader is behind on
// (ADR 040 parts 1 and 4).
//
// This is the one place that knows both halves: the bundle carries the versions
// it was compiled against, and the runtime's schema carries the versions that
// are loaded. It returns nil when the reader satisfies everything, and for any
// bundle compiled before provenance existed - an absent requirement is absent
// information, not permission to start dropping fields.
func skewPolicyFor(codeBundle *llx.CodeBundle, runtime llx.Runtime) *llx.SkewPolicy {
	if codeBundle == nil || runtime == nil {
		return nil
	}
	schema := runtime.Schema()
	if schema == nil {
		return nil
	}

	unmet := mqlc.UnmetRequirements(codeBundle, schema.AllProviderVersions())
	if len(unmet) == 0 {
		return nil
	}

	reasons := make(map[string]string, len(unmet))
	for _, req := range unmet {
		// A provider the reader cannot name a version for is excluded, even
		// though UnmetRequirements reports it. Reporting it is right - content
		// needing a provider you do not have genuinely cannot run - but
		// degrading on it is not: not knowing a version is not evidence of
		// skew, and treating it as evidence would silently drop fields whenever
		// provenance is merely absent, which is every bundle and every schema
		// that predates it. Dropping a field needs proof the field could not
		// have existed here, and only a known-older version is that proof.
		if req.Installed == "" {
			continue
		}
		reasons[req.Provider] = req.Error()
	}
	if len(reasons) == 0 {
		return nil
	}
	log.Debug().Interface("providers", reasons).
		Msg("bundle was compiled against newer providers than this build has")
	return llx.NewSkewPolicy(reasons)
}
