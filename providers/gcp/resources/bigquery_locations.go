// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"fmt"
	"strings"
	"sync"

	"github.com/rs/zerolog/log"
	"google.golang.org/grpc/codes"
)

// bigqueryLocations is every location BigQuery serves, named as the API names
// them: the two multi-regions, the single regions, and the BigQuery Omni
// locations that sit in AWS and Azure.
//
// The set has to be enumerated because neither API this drives accepts a
// wildcard parent. `projects/<p>/locations/-/reservations`,
// `.../capacityCommitments` and `.../reservations:searchAllAssignments` are all
// rejected with INVALID_ARGUMENT, and there is no project-wide list endpoint
// for connections either, so a caller has to name each location it wants.
//
// This list previously came from the project's own dataset locations, on the
// assumption that a region holding no dataset holds no reservation or
// connection. That assumption is wrong in both directions that matter. Slot
// capacity is routinely bought in a region where the project holds no dataset,
// because queries may run against datasets in another project, and a connection
// to Cloud SQL, Spanner, or an Omni region needs no dataset at all. A project
// with no datasets therefore reported nothing at all while the API held both.
//
// Sourced from https://docs.cloud.google.com/bigquery/docs/locations. It needs
// updating as Google adds locations, and a location missing from here is
// invisible rather than reported, which is why the list lives in one place with
// this note attached to it.
var bigqueryLocations = []string{
	// multi-regions
	"US",
	"EU",

	// Americas
	"northamerica-northeast1",
	"northamerica-northeast2",
	"northamerica-south1",
	"southamerica-east1",
	"southamerica-west1",
	"us-central1",
	"us-central2",
	"us-east1",
	"us-east4",
	"us-east5",
	"us-south1",
	"us-west1",
	"us-west2",
	"us-west3",
	"us-west4",

	// Asia Pacific
	"asia-east1",
	"asia-east2",
	"asia-northeast1",
	"asia-northeast2",
	"asia-northeast3",
	"asia-south1",
	"asia-south2",
	"asia-southeast1",
	"asia-southeast2",
	"asia-southeast3",
	"australia-southeast1",
	"australia-southeast2",

	// Europe
	"europe-central2",
	"europe-north1",
	"europe-north2",
	"europe-southwest1",
	"europe-west1",
	"europe-west2",
	"europe-west3",
	"europe-west4",
	"europe-west6",
	"europe-west8",
	"europe-west9",
	"europe-west10",
	"europe-west12",

	// Middle East and Africa
	"africa-south1",
	"me-central1",
	"me-central2",
	"me-west1",

	// BigQuery Omni
	"aws-ap-northeast-2",
	"aws-ap-southeast-2",
	"aws-eu-central-1",
	"aws-eu-west-1",
	"aws-us-east-1",
	"aws-us-west-2",
	"azure-eastus2",
}

// bigqueryLocationConcurrency bounds how many locations are in flight at once.
// The whole list is queried on every call, so it is the difference between one
// slow round trip and fifty of them, but an unbounded fan-out would open a
// connection per location and is not worth the burst.
const bigqueryLocationConcurrency = 10

// bigqueryLocationUnsupported reports whether err means the location itself
// does not apply: BigQuery is not offered there, the project cannot reach it,
// or the parent path names nothing.
//
// It deliberately does not reuse isSkippable, which folds PermissionDenied in
// with "nothing here". Permission for these APIs is granted per project rather
// than per location, so a denial answers every location identically, and
// classifying it as "nothing here" is exactly how a fan-out ends up reporting
// an empty list for a project nobody was allowed to read.
func bigqueryLocationUnsupported(err error) bool {
	if err == nil {
		return false
	}
	if s, ok := grpcStatusOf(err); ok {
		switch s.Code() {
		case codes.NotFound, codes.Unimplemented, codes.InvalidArgument, codes.FailedPrecondition:
			return true
		}
	}
	return false
}

// listBigqueryLocations calls list once per BigQuery location and concatenates
// what comes back.
//
// How a failure is handled is the point of this helper, because the bug it
// replaces was a silent empty list:
//
//   - The API not being enabled on the project means there is genuinely nothing
//     to find in any location, so it degrades to an empty result.
//   - A location that does not apply is skipped. Most of the list is expected
//     to answer this way for any given project.
//   - Anything else, a permission denial above all, is a failure. If no
//     location succeeded, the failure is returned rather than an empty list:
//     "we were not allowed to look" must not arrive looking like "there is
//     nothing here", or every assertion over the result passes vacuously.
//   - If some locations succeeded and others failed, the partial result is
//     returned and the failures are logged, because failing the whole field
//     over one unreachable location would hide the reservations that were read.
func listBigqueryLocations(list func(location string) ([]any, error)) ([]any, error) {
	type failure struct {
		location string
		err      error
	}

	var (
		mu        sync.Mutex
		out       []any
		succeeded int
		failures  []failure
	)

	sem := make(chan struct{}, bigqueryLocationConcurrency)
	wg := sync.WaitGroup{}
	for _, location := range bigqueryLocations {
		wg.Add(1)
		go func(location string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			res, err := list(location)

			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				succeeded++
				out = append(out, res...)
			case isServiceDisabled(err):
				// The API is off for the whole project. Every location says so,
				// and none of them is a failure to report.
			case bigqueryLocationUnsupported(err):
				log.Debug().Err(err).Str("location", location).Msg("skipping BigQuery location")
			default:
				failures = append(failures, failure{location: location, err: err})
			}
		}(location)
	}
	wg.Wait()

	if len(failures) == 0 {
		return out, nil
	}

	locations := make([]string, 0, len(failures))
	for _, f := range failures {
		locations = append(locations, f.location)
	}
	if succeeded == 0 {
		return nil, fmt.Errorf("could not read any BigQuery location (%s): %w",
			strings.Join(locations, ", "), failures[0].err)
	}
	log.Warn().Err(failures[0].err).Str("locations", strings.Join(locations, ", ")).
		Msg("could not read every BigQuery location, results are partial")
	return out, nil
}
