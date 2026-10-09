// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package internal

import (
	"errors"
	"fmt"
	"runtime/debug"
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
	// timeout is the amount of time the executor will wait for a query
	// to return all the results after
	timeout time.Duration
	// stopChan is a channel that is closed when a stop is requested
	stopChan chan struct{}
	wg       sync.WaitGroup
}

type runQueueItem struct {
	codeBundle *llx.CodeBundle
	props      map[string]*llx.Result
}

func newExecutionManager(schema resources.ResourcesSchema, runtime llx.Runtime, runQueue chan runQueueItem,
	resultChan chan *llx.RawResult, timeout time.Duration,
) *executionManager {
	return &executionManager{
		runQueue:   runQueue,
		schema:     schema,
		runtime:    runtime,
		resultChan: resultChan,
		errChan:    make(chan error, 1),
		stopChan:   make(chan struct{}),
		timeout:    timeout,
	}
}

func (em *executionManager) Start() {
	em.wg.Add(1)
	go func() {
		defer em.wg.Done()
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
	}()
}

func (em *executionManager) Err() chan error {
	return em.errChan
}

func (em *executionManager) Stop() {
	close(em.stopChan)
	em.wg.Wait()
}

// reportPanic reports a recovered panic upstream and in the log, with the query
// that was running when there is one, and returns it as an error.
func reportPanic(codeBundle *llx.CodeBundle, r any) error {
	var tags map[string]string
	if codeBundle != nil {
		tags = health.QueryPanicTags(codeBundle.CodeV2.GetId(), codeBundle.Source)
	}
	// The stack is taken in the deferred handler, so it still shows the panic
	// site.
	stack := debug.Stack()
	health.ReportRecoveredPanic("mql", mql.Version, mql.Build, r, stack, tags)
	log.Error().
		Str("stacktrace", string(stack)).
		Msgf("recovered from panic during query execution: %v", r)
	return fmt.Errorf("panic during query execution: %v", r)
}

func (em *executionManager) executeCodeBundle(codeBundle *llx.CodeBundle, props map[string]*llx.Primitive, errMsg string) (rerr error) {
	wg := NewWaitGroup()

	sendResult := func(rr *llx.RawResult) {
		log.Trace().Str("codeID", rr.CodeID).Msg("received result from executor")
		wg.Done(rr.CodeID)
		select {
		case em.resultChan <- rr:
		case <-em.stopChan:
		}
	}

	checksums := map[string]struct{}{}
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
		return nil
	}

	var executor iExecutor
	var err error

	codeID := codeBundle.CodeV2.GetId()
	log.Debug().Str("qrid", codeID).Msg("starting query execution")
	defer func() {
		log.Debug().Str("qrid", codeID).Msg("finished query execution")
	}()

	// A panic while this query runs fails this query only: every datapoint it
	// has not reported gets the panic as its error, and the manager goes on
	// with the next query. Giving up on the whole run instead would drop the
	// results of every other query on the asset. The executor is unregistered,
	// so nothing it registered calls back afterwards.
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		perr := reportPanic(codeBundle, r)
		if executor != nil {
			if err := executor.Unregister(); err != nil {
				log.Warn().Err(err).Str("qrid", codeID).Msg("failed to unregister the executor of a query that panicked")
			}
		}
		for _, checksum := range wg.Decommission() {
			sendResult(&llx.RawResult{
				CodeID: checksum,
				Data:   &llx.RawData{Error: perr},
			})
		}
		rerr = nil
	}()

	// TODO(jaym): sendResult may not be correct. We may need to fill in the
	// checksum
	x, err := llx.NewExecutorV2WithSkew(codeBundle.CodeV2, em.runtime, props, sendResult,
		skewPolicyFor(codeBundle, em.runtime))
	if err == nil {
		executor = x
		err = x.Run()
	}

	if err != nil {
		return err
	}

	execDoneChan := make(chan struct{})
	go func() {
		wg.Wait()
		close(execDoneChan)
	}()

	var errOut error

	timer := time.NewTimer(em.timeout)
	defer timer.Stop()
	select {
	case <-timer.C:
		log.Error().Dur("timeout", em.timeout).Str("qrid", codeID).Msg("execution timed out")
		errOut = errQueryTimeout
	case <-execDoneChan:
	}

	unreported := wg.Decommission()
	if len(unreported) > 0 {
		log.Warn().Strs("missing", unreported).Str("qrid", codeID).Msg("unreported datapoints")
	}

	if err := executor.Unregister(); err != nil {
		return err
	}

	return errOut
}

var errQueryTimeout = errors.New("query execution timed out")

type iExecutor interface {
	Unregister() error
}

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
