// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"net/http"

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

// batchGet issues every request in reqs against the Microsoft Graph $batch
// endpoint and returns, per caller key, the deserialized response of type T.
//
// This collapses an N-call N+1 pattern into ceil(N/19) HTTP round-trips, sent
// sequentially. Concurrency across chunks is intentionally left out here
// (tracked separately).
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
// each before the next chunk is sent.
//
// It replaces the SDK's BatchRequestCollection for large fetches. That
// collection builds every request up front and keeps every chunk's response
// until the last one returns, so a per-user field on a large tenant held
// gigabytes and the scan was OOM-killed. Here build runs per chunk,
// and a chunk's raw responses are dropped once each has seen them, so memory
// grows only by what each keeps.
//
// A failed sub-request, or an error returned by each, is recorded under its
// key in errs and does not stop the fetch; statuses holds every sub-response's
// status code. An error from build or from sending a chunk ends the fetch.
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
	for start := 0; start < len(keys); start += batchChunkSize {
		chunk := keys[start:min(start+batchChunkSize, len(keys))]
		batch := msgraphgocore.NewBatchRequest(adapter)
		// the SDK assigns each step a generated id; map it back to the caller key
		idToKey := make(map[string]string, len(chunk))
		for _, key := range chunk {
			reqInfo, err := build(key)
			if err != nil {
				return errs, statuses, transformError(err)
			}
			item, err := batch.AddBatchRequestStep(*reqInfo)
			if err != nil {
				return errs, statuses, err
			}
			idToKey[*item.GetId()] = key
		}

		resp, err := batch.Send(ctx, adapter)
		if err != nil {
			return errs, statuses, transformError(err)
		}

		statusCodes := resp.GetStatusCodes()
		for id, key := range idToKey {
			code, hasCode := statusCodes[id]
			if hasCode {
				statuses[key] = code
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
	}
	return errs, statuses, nil
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
