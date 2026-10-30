// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"runtime/debug"
	"sync"

	"github.com/cockroachdb/errors"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers/aws/connection"
)

// regionalConcurrency bounds how many regions one lister queries at a time.
const regionalConcurrency = 5

// perRegion runs fn once for every region in scope and returns the results
// concatenated.
//
// It owns the decisions that a hand-rolled region fan-out otherwise makes over
// and over, differently each time:
//
//   - Errors are classified centrally. A region where the service is absent or
//     was never enabled contributes nothing and is not an error; a region the
//     caller may not read contributes nothing and is recorded as a coverage gap;
//     anything else is a real failure.
//   - Partial results survive. One unreachable region no longer discards the
//     data collected from every other region, though a run where every region
//     failed still returns the error rather than an empty list.
//   - A panic inside fn fails that one region instead of taking down the scan.
//
// service is the AWS service id used for error classification and gap
// reporting, for example "ecr" or "macie2".
func perRegion[T any](conn *connection.AwsConnection, service string,
	fn func(ctx context.Context, region string) ([]T, error),
) ([]T, error) {
	regions, err := conn.Regions()
	if err != nil {
		return nil, err
	}
	return forRegions(conn, service, regions, fn)
}

// forRegions is perRegion over an explicit region list, for the few listers
// that scope themselves more narrowly than the connection does.
func forRegions[T any](conn *connection.AwsConnection, service string, regions []string,
	fn func(ctx context.Context, region string) ([]T, error),
) ([]T, error) {
	type outcome struct {
		items []T
		err   error
	}
	outcomes := make([]outcome, len(regions))

	// TODO: thread the caller's context through here once the plugin runtime
	// hands one to resource accessors, so a cancelled scan stops in flight.
	ctx := context.Background()

	sem := make(chan struct{}, regionalConcurrency)
	var wg sync.WaitGroup
	for i := range regions {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			outcomes[i].items, outcomes[i].err = callRegion(ctx, regions[i], fn)
		}(i)
	}
	wg.Wait()

	res := []T{}
	var (
		firstErr error
		failed   int
	)
	for i := range outcomes {
		region := regions[i]
		if err := outcomes[i].err; err != nil {
			switch classifyError(service, err) {
			case dispositionEmpty:
				// Nothing here to report, and that is the honest answer.
			case dispositionUnreadable:
				conn.RecordGap(serviceName(service), region, connection.GapDenied)
			default:
				conn.RecordGap(serviceName(service), region, connection.GapFailed)
				failed++
				if firstErr == nil {
					firstErr = errors.Wrapf(err, "%s in %s", service, region)
				}
			}
			continue
		}
		res = append(res, outcomes[i].items...)
	}

	// Every region failing means the caller learned nothing, so report it.
	// Otherwise keep what was collected: discarding twenty good regions because
	// one was throttled loses far more than it protects.
	if failed > 0 && failed == len(regions) {
		return nil, firstErr
	}
	if failed > 0 {
		log.Warn().
			Str("service", service).
			Int("failedRegions", failed).
			Int("totalRegions", len(regions)).
			Err(firstErr).
			Msg("some regions could not be read; returning partial results")
	}
	return res, nil
}

// callRegion invokes fn, converting a panic into an error for that region.
//
// Resource accessors run in the executor's goroutines, where an unrecovered
// panic takes down the whole scan rather than the one query that caused it. A
// bad type assertion in one region's mapping code should cost that region, not
// every other result the run had already collected.
func callRegion[T any](ctx context.Context, region string,
	fn func(ctx context.Context, region string) ([]T, error),
) (items []T, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Str("region", region).
				Interface("panic", r).
				Str("stack", string(debug.Stack())).
				Msg("recovered panic while collecting region")
			items = nil
			err = fmt.Errorf("panic while collecting region %s: %v", region, r)
		}
	}()
	return fn(ctx, region)
}
