// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	abstractions "github.com/microsoft/kiota-abstractions-go"
	"github.com/microsoft/kiota-abstractions-go/serialization"
	msgraphgocore "github.com/microsoftgraph/msgraph-sdk-go-core"
	"github.com/rs/zerolog/log"
)

// batchItemRequest pairs a caller-defined key with the Graph request to issue
// for it. The key is how the caller correlates a batched response back to the
// item it asked for (typically a user, group, or service principal id).
type batchItemRequest struct {
	key     string
	reqInfo *abstractions.RequestInformation
}

// batchResult holds the per-key outcome of a batched Graph request. A failure
// on a single item (e.g. a 403 on one user) is recorded in errs without
// failing the whole batch, mirroring the per-resource error handling the
// provider already uses for serial calls.
type batchResult[T serialization.Parsable] struct {
	results  map[string]T
	errs     map[string]error
	statuses map[string]int32
}

// batchChunkSize is the number of sub-requests sent in one $batch call. Graph
// caps a payload at 20; 19 matches the SDK's own BatchRequestCollection.
const batchChunkSize = 19

// batchMaxConcurrency is the most $batch calls batchEach keeps in flight. A
// per-user sub-request can take over a second, so a field over every member
// of a large tenant takes hours one chunk at a time. But Graph throttles per
// app and tenant: with four calls in flight a tenant's per-user endpoint
// answered nearly every sub-request with 429, which made the walk far slower
// than one call at a time. batchEach starts here and drops to one call on the
// first throttled sub-request (see batchPacer).
const batchMaxConcurrency = 2

// batchRampUpChunks is how many chunks in a row must come back without a
// throttled sub-request before batchEach allows one more call in flight.
const batchRampUpChunks = 50

// batchMaxRetries is how often batchEach resends a sub-request that Graph
// throttled or could not serve (see batchStatusIsTransient) before recording
// it as failed. The SDK's retry handler only sees the $batch call itself,
// which succeeds even when sub-requests inside it were throttled, so those
// would otherwise surface as errors on single users.
const batchMaxRetries = 5

// batchMaxRetryWait caps how long batchEach pauses after throttling.
const batchMaxRetryWait = time.Minute

// batchRetryBackoff is the pause after a throttled chunk when Graph sent no
// Retry-After; it doubles while chunks keep coming back throttled. A variable
// so tests can shorten it.
var batchRetryBackoff = time.Second

// batchProgressEvery is how many chunks pass between progress log lines.
const batchProgressEvery = 500

// batchGet issues every request in reqs against the Microsoft Graph $batch
// endpoint and returns, per caller key, the deserialized response of type T.
//
// This collapses an N-call N+1 pattern into ceil(N/19) HTTP round-trips, up
// to batchMaxConcurrency of them in flight.
//
// The adapter selects the service root, so v1.0 and beta requests must not be
// mixed in one call -- pass the matching client's adapter for each.
//
// Every result is held until the call returns. A fetch over every user of a
// large tenant should use batchEach instead, which hands each result over as
// its chunk arrives.
func batchGet[T serialization.Parsable](
	ctx context.Context,
	adapter abstractions.RequestAdapter,
	reqs []batchItemRequest,
	constructor serialization.ParsableFactory,
) (batchResult[T], error) {
	out := batchResult[T]{results: make(map[string]T, len(reqs))}
	keys := make([]string, len(reqs))
	byKey := make(map[string]*abstractions.RequestInformation, len(reqs))
	for i, r := range reqs {
		keys[i] = r.key
		byKey[r.key] = r.reqInfo
	}
	var err error
	out.errs, out.statuses, err = batchEach(ctx, adapter, keys,
		func(key string) (*abstractions.RequestInformation, error) { return byKey[key], nil },
		constructor,
		func(key string, val T) error {
			out.results[key] = val
			return nil
		})
	return out, err
}

// batchEach issues one Graph request per key through the $batch endpoint,
// batchChunkSize keys per call, and passes each successful sub-response to
// each as its chunk returns.
//
// It replaces the SDK's BatchRequestCollection for large fetches. That
// collection builds every request up front and keeps every chunk's response
// until the last one returns, so a per-user field on a large tenant held
// gigabytes and the scan was OOM-killed. Here build runs per chunk, and a
// chunk's raw responses are dropped once each has seen them; at most
// batchMaxConcurrency chunks are in flight, so memory grows only by what each
// keeps.
//
// Chunks may complete in any order. build, each, and every write to errs and
// statuses run on the calling goroutine, so neither needs locking.
//
// A failed sub-request, or an error returned by each, is recorded under its
// key in errs and does not stop the fetch; statuses holds every key's last
// status code. An error from build or from sending a chunk ends the fetch.
//
// A sub-request that Graph throttled or could not serve goes back into the
// queue and is sent again, up to batchMaxRetries times; only then is it
// recorded in errs. A throttled chunk also slows the whole fetch down: see
// batchPacer.
func batchEach[T serialization.Parsable](
	ctx context.Context,
	adapter abstractions.RequestAdapter,
	keys []string,
	build func(key string) (*abstractions.RequestInformation, error),
	constructor serialization.ParsableFactory,
	each func(key string, val T) error,
) (errs map[string]error, statuses map[string]int32, err error) {
	errs = map[string]error{}
	statuses = make(map[string]int32, len(keys))

	type chunkResult struct {
		// the SDK assigns each step a generated id; map it back to the caller key
		idToKey map[string]string
		resp    msgraphgocore.BatchResponse
		err     error
	}
	// Send reads the SDK's error-mapping registry, a singleton created lazily
	// behind an unlocked nil check, so the first concurrent Sends race on its
	// creation. Create it here, before any chunk is sent; after that it is
	// only read.
	msgraphgocore.GetErrorFactoryFromRegistry(msgraphgocore.BatchRequestErrorRegistryKey)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	results := make(chan chunkResult)

	// keys still to send; throttled keys are appended again
	queue := append([]string(nil), keys...)
	next := 0
	attempts := map[string]int{}
	pacer := newBatchPacer(batchMaxConcurrency)
	inFlight := 0
	var chunks, throttled, pauses int
	var paused time.Duration
	start := time.Now()

	for {
		for err == nil && inFlight < pacer.limit && next < len(queue) && pacer.ready(time.Now()) {
			chunk := queue[next:min(next+batchChunkSize, len(queue))]
			next += len(chunk)
			batch := msgraphgocore.NewBatchRequest(adapter)
			idToKey := make(map[string]string, len(chunk))
			for _, key := range chunk {
				reqInfo, buildErr := build(key)
				if buildErr != nil {
					err = transformError(buildErr)
					break
				}
				item, addErr := batch.AddBatchRequestStep(*reqInfo)
				if addErr != nil {
					err = addErr
					break
				}
				idToKey[*item.GetId()] = key
			}
			if err != nil {
				cancel()
				break
			}
			inFlight++
			go func() {
				resp, sendErr := batch.Send(ctx, adapter)
				if sendErr != nil {
					sendErr = transformError(sendErr)
				}
				results <- chunkResult{idToKey: idToKey, resp: resp, err: sendErr}
			}()
		}

		if inFlight == 0 {
			if err != nil || next == len(queue) {
				break
			}
			// throttled with nothing in flight: wait out the pause
			wait := time.Until(pacer.pausedUntil)
			paused += wait
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return errs, statuses, ctx.Err()
			}
			continue
		}

		res := <-results
		inFlight--
		if err != nil {
			// the fetch already failed; drain what is still in flight
			continue
		}
		if res.err != nil {
			err = res.err
			cancel()
			continue
		}
		retry, retryAfter := handleBatchChunk(res.resp, res.idToKey, constructor, each, errs, statuses)
		chunks++
		for _, key := range retry {
			attempts[key]++
			if attempts[key] > batchMaxRetries {
				errs[key] = fmt.Errorf("batch request failed with status %d", statuses[key])
				continue
			}
			queue = append(queue, key)
		}
		if len(retry) > 0 {
			throttled += len(retry)
			pauses++
		}
		pacer.observe(time.Now(), len(retry) > 0, retryAfter)
		if chunks%batchProgressEvery == 0 {
			log.Debug().Int("keys", len(keys)).Int("sent", next).Int("queued", len(queue)-next).
				Int("throttled", throttled).Int("concurrency", pacer.limit).Dur("elapsed", time.Since(start)).
				Msg("ms365> batch progress")
		}
	}

	if throttled > 0 || chunks >= batchProgressEvery {
		log.Debug().Int("keys", len(keys)).Int("chunks", chunks).Int("throttled", throttled).
			Int("pauses", pauses).Dur("paused", paused).Dur("elapsed", time.Since(start)).
			Msg("ms365> batch done")
	}
	return errs, statuses, err
}

// batchPacer decides how many $batch calls may be in flight and when the next
// one may be sent. A chunk with a throttled sub-request drops the limit to one
// call and pauses sending for the Retry-After Graph asked for, or for a
// backoff that doubles while chunks keep coming back throttled.
// batchRampUpChunks clean chunks in a row raise the limit by one, up to max.
//
// Resending everything Graph throttled straight away keeps the app throttled:
// a tenant then let through a few hundred users per ten minutes. Slowing down
// as soon as Graph pushes back costs a pause instead.
type batchPacer struct {
	max, limit  int
	clean       int // chunks in a row without throttling
	throttled   int // chunks in a row with throttling
	pausedUntil time.Time
}

func newBatchPacer(maxInFlight int) *batchPacer {
	return &batchPacer{max: maxInFlight, limit: maxInFlight}
}

// ready reports whether a chunk may be sent at now.
func (p *batchPacer) ready(now time.Time) bool {
	return !now.Before(p.pausedUntil)
}

// observe records a chunk that came back at now; throttled is whether any of
// its sub-requests were, and retryAfter the longest Retry-After they asked for.
func (p *batchPacer) observe(now time.Time, throttled bool, retryAfter time.Duration) {
	if !throttled {
		p.throttled = 0
		p.clean++
		if p.clean >= batchRampUpChunks && p.limit < p.max {
			p.limit++
			p.clean = 0
		}
		return
	}
	p.clean = 0
	p.limit = 1
	wait := retryAfter
	if wait == 0 {
		wait = batchRetryBackoff << min(p.throttled, 6)
	}
	p.throttled++
	if until := now.Add(min(wait, batchMaxRetryWait)); until.After(p.pausedUntil) {
		p.pausedUntil = until
	}
}

// handleBatchChunk passes each successful sub-response of one $batch call to
// each and records the outcome of every sub-request in errs and statuses. It
// returns the keys whose sub-request should be sent again, and the longest
// Retry-After their sub-responses asked for.
func handleBatchChunk[T serialization.Parsable](
	resp msgraphgocore.BatchResponse,
	idToKey map[string]string,
	constructor serialization.ParsableFactory,
	each func(key string, val T) error,
	errs map[string]error,
	statuses map[string]int32,
) (retry []string, retryAfter time.Duration) {
	statusCodes := resp.GetStatusCodes()
	for id, key := range idToKey {
		code, hasCode := statusCodes[id]
		if hasCode {
			statuses[key] = code
		}
		if hasCode && batchStatusIsTransient(code) {
			retry = append(retry, key)
			retryAfter = max(retryAfter, batchRetryAfter(resp.GetResponseById(id)))
			continue
		}
		// A non-2xx sub-response carries an error body, not a T. The kiota core
		// helper GetBatchResponseById panics trying to deserialize that body as
		// T (e.g. a 403 when the app lacks AuditLog.Read.All for signInActivity).
		// Skip the parse when we already know the sub-request failed...
		if hasCode && (code < 200 || code >= 300) {
			errs[key] = fmt.Errorf("batch request failed with status %d", code)
			continue
		}
		// A no-content success has no body to deserialize. GetBatchResponseById
		// dereferences it anyway and panics, which the recover below would turn
		// into a per-item error -- but this is not a failure. Graph answers 204
		// for a sub-request whose target has no value for the selected property
		// (for example signInActivity on a user who has never signed in), so
		// leave the key out of both results and errs and let the field read
		// null.
		if hasCode && batchStatusHasNoBody(code) {
			continue
		}
		// ...and recover defensively around the parse itself, since the helper
		// can still panic on malformed/error bodies the status map does not flag.
		val, err := safeGetBatchResponseByID[T](resp, id, constructor)
		if err != nil {
			errs[key] = transformError(err)
			continue
		}
		if err := each(key, val); err != nil {
			errs[key] = err
		}
	}
	return retry, retryAfter
}

// batchStatusIsTransient reports whether a sub-request failed in a way that
// resending it can fix: Graph throttled it, or the service was briefly
// unavailable.
func batchStatusIsTransient(code int32) bool {
	return code == http.StatusTooManyRequests || code == http.StatusServiceUnavailable || code == http.StatusGatewayTimeout
}

// batchRetryAfter reads the Retry-After header, in seconds, of a throttled
// sub-response. It returns 0 when there is none.
func batchRetryAfter(item msgraphgocore.BatchItem) time.Duration {
	if item == nil {
		return 0
	}
	for name, value := range item.GetHeaders() {
		if !strings.EqualFold(name, "Retry-After") {
			continue
		}
		if secs, err := strconv.Atoi(strings.TrimSpace(value)); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 0
}

// batchStatusHasNoBody reports whether a successful batch sub-response status
// carries no body, so there is nothing for the caller to deserialize.
//
// This has to be checked separately from the non-2xx guard because these codes
// ARE successes: they fall inside the 2xx range and would otherwise reach the
// parse, which panics on the absent body.
func batchStatusHasNoBody(code int32) bool {
	return code == http.StatusNoContent || code == http.StatusResetContent
}

// safeGetBatchResponseByID wraps msgraphgocore.GetBatchResponseById, which can
// panic (rather than return an error) when a batch sub-response holds an error
// body that does not deserialize into T -- e.g. a 403 error object parsed as a
// User. Recovering keeps one failed sub-request from crashing the whole batched
// query; the caller records it as a per-item error like any other failure.
func safeGetBatchResponseByID[T serialization.Parsable](
	resp msgraphgocore.BatchResponse,
	id string,
	constructor serialization.ParsableFactory,
) (val T, err error) {
	defer func() {
		if r := recover(); r != nil {
			var zero T
			val = zero
			err = fmt.Errorf("batch sub-response %q could not be parsed (recovered panic): %v", id, r)
			// Surface the recovered panic so it is not lost during debugging --
			// the status-code guard handles the expected non-2xx case, so a panic
			// reaching here means an unexpected/malformed body the SDK mishandled.
			log.Warn().Str("id", id).Msgf("recovered panic parsing batch sub-response: %v", r)
		}
	}()
	return msgraphgocore.GetBatchResponseById[T](resp, id, constructor)
}
