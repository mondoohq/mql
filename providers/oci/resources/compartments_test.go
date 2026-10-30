// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
)

func TestOciCompartmentInaccessible(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		// OCI deliberately collapses "not found" and "not authorized" into one
		// response so callers cannot probe for resources they cannot see, so
		// both mean the same thing at compartment granularity.
		{"403 not authorized", fakeServiceError{status: 403, code: "NotAuthorizedOrNotFound"}, true},
		{"404 not authorized or not found", fakeServiceError{status: 404, code: "NotAuthorizedOrNotFound"}, true},

		// A 404 that is not the authorization denial is an absent endpoint,
		// not a compartment the caller cannot read. Matching on the code
		// rather than the status is what lets this run before
		// ociRegionServiceUnavailable without swallowing undeployed regions.
		{"404 plain not found", fakeServiceError{status: 404, code: "NotFound"}, false},

		// A bad credential is tenancy-wide, not per-compartment, and must not
		// be mistaken for a compartment the caller merely lacks read on.
		{"401 not authenticated", fakeServiceError{status: 401, code: "NotAuthenticated"}, false},

		// Transient and server-side faults are real: skipping them per
		// compartment would silently drop resources that do exist.
		{"429 too many requests", fakeServiceError{status: 429, code: "TooManyRequests"}, false},
		{"500 internal", fakeServiceError{status: 500, code: "InternalServerError"}, false},
		{"400 bad request", fakeServiceError{status: 400, code: "InvalidParameter"}, false},

		// Transport errors carry no HTTP status and are not a compartment
		// permission signal.
		{"plain error", errors.New("boom"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ociCompartmentInaccessible(tt.err))
		})
	}
}

func TestOciRegionsByID(t *testing.T) {
	iad := &mqlOciRegion{}
	iad.Id.Data = "us-ashburn-1"
	iad.Id.State = plugin.StateIsSet
	phx := &mqlOciRegion{}
	phx.Id.Data = "us-phoenix-1"
	phx.Id.State = plugin.StateIsSet

	t.Run("indexes every region by its id", func(t *testing.T) {
		got, err := ociRegionsByID([]any{iad, phx})
		require.NoError(t, err)
		assert.Len(t, got, 2)
		assert.Same(t, iad, got["us-ashburn-1"])
		assert.Same(t, phx, got["us-phoenix-1"])
	})

	t.Run("no regions", func(t *testing.T) {
		got, err := ociRegionsByID(nil)
		require.NoError(t, err)
		assert.Empty(t, got)
	})

	t.Run("a non-region element is an error, not a silent gap", func(t *testing.T) {
		// A compartment lister only receives the region as a string and looks
		// the resource up in this map, so a dropped entry would surface much
		// later as a missing region field rather than here.
		_, err := ociRegionsByID([]any{iad, "us-phoenix-1"})
		require.Error(t, err)
	})
}

func TestOciDedupeByID(t *testing.T) {
	zone := func(id string) *mqlOciDnsZone {
		z := &mqlOciDnsZone{}
		z.__id = id
		return z
	}

	t.Run("no items", func(t *testing.T) {
		assert.Empty(t, ociDedupeByID(nil))
	})

	t.Run("distinct resources are all kept", func(t *testing.T) {
		a, b := zone("oci.dns.zone/a"), zone("oci.dns.zone/b")
		assert.Equal(t, []any{a, b}, ociDedupeByID([]any{a, b}))
	})

	t.Run("a global zone seen once per region collapses to one", func(t *testing.T) {
		// CreateResource returns the cached instance for an id it has already
		// built, so the region fan-out yields the same pointer N times rather
		// than N distinct rows. Without this, zones.length multiplies by the
		// number of subscribed regions.
		a := zone("oci.dns.zone/a")
		assert.Equal(t, []any{a}, ociDedupeByID([]any{a, a, a}))
	})

	t.Run("order of first appearance is preserved", func(t *testing.T) {
		a, b, c := zone("oci.dns.zone/a"), zone("oci.dns.zone/b"), zone("oci.dns.zone/c")
		assert.Equal(t, []any{a, b, c}, ociDedupeByID([]any{a, b, a, c, b}))
	})

	t.Run("a non-resource element passes through untouched", func(t *testing.T) {
		// Nothing in the provider does this today, but dropping an element the
		// helper does not recognise would be a silent data loss of its own.
		assert.Equal(t, []any{"raw", "raw"}, ociDedupeByID([]any{"raw", "raw"}))
	})
}

func TestOciCollectCompartmentJobs(t *testing.T) {
	ok := func(items ...any) *jobpool.Job {
		return jobpool.NewJob(func() (jobpool.JobResult, error) {
			return jobpool.JobResult(items), nil
		})
	}
	// A compartment the caller cannot read. Normal in OCI, where policies are
	// routinely scoped per compartment.
	denied := func() *jobpool.Job {
		return jobpool.NewJob(func() (jobpool.JobResult, error) {
			return nil, fakeServiceError{status: 403, code: "NotAuthorizedOrNotFound"}
		})
	}
	// A region where the service is not deployed at all. Deliberately NOT
	// NotAuthorizedOrNotFound: that code is OCI's authorization denial, and
	// using it here is what previously let an entirely-denied tenancy be
	// mistaken for a set of undeployed regions.
	unavailable := func() *jobpool.Job {
		return jobpool.NewJob(func() (jobpool.JobResult, error) {
			return nil, fakeServiceError{status: 404, code: "NotFound"}
		})
	}
	// The shape OCI actually returns when a policy does not grant read on a
	// compartment. Same status as an absent endpoint, different code.
	denied404 := func() *jobpool.Job {
		return jobpool.NewJob(func() (jobpool.JobResult, error) {
			return nil, fakeServiceError{status: 404, code: "NotAuthorizedOrNotFound"}
		})
	}
	throttled := func() *jobpool.Job {
		return jobpool.NewJob(func() (jobpool.JobResult, error) {
			return nil, fakeServiceError{status: 429, code: "TooManyRequests"}
		})
	}

	t.Run("all compartments succeed", func(t *testing.T) {
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{ok("a"), ok("b", "c")}, ociScopeAllCompartments.concurrency())
		require.NoError(t, err)
		assert.ElementsMatch(t, []any{"a", "b", "c"}, res)
	})

	t.Run("a denied compartment does not discard the readable ones", func(t *testing.T) {
		// The whole point of the fan-out: a scanning principal with read on
		// some compartments is correctly configured, not broken.
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{ok("a"), denied(), ok("b")}, ociScopeAllCompartments.concurrency())
		require.NoError(t, err)
		assert.ElementsMatch(t, []any{"a", "b"}, res)
	})

	t.Run("every compartment denied is an error, not an empty tenancy", func(t *testing.T) {
		// The failure this guard exists for: an under-scoped token must not
		// render as a clean scan of a tenancy with nothing in it.
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{denied(), denied()}, ociScopeAllCompartments.concurrency())
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "NotAuthorizedOrNotFound")
	})

	t.Run("every compartment denied with a 404 is an error, not an empty tenancy", func(t *testing.T) {
		// OCI answers an authorization failure with 404
		// NotAuthorizedOrNotFound, not 403. Classifying that as an absent
		// regional endpoint made an under-scoped token return a clean, empty
		// scan of the whole tenancy - the exact outcome the denied counter
		// exists to prevent.
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{denied404(), denied404()}, ociScopeAllCompartments.concurrency())
		require.Error(t, err)
		assert.Nil(t, res)
		assert.Contains(t, err.Error(), "NotAuthorizedOrNotFound")
	})

	t.Run("a 404-denied compartment does not discard the readable ones", func(t *testing.T) {
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{ok("a"), denied404(), ok("b")}, ociScopeAllCompartments.concurrency())
		require.NoError(t, err)
		assert.ElementsMatch(t, []any{"a", "b"}, res)
	})

	t.Run("an undeployed region does not rescue an all-denied run", func(t *testing.T) {
		// The two 404s differ only by code. The denial still has to win, or a
		// single undeployed region would push a broken token back onto the
		// success path.
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{unavailable(), denied404()}, ociScopeAllCompartments.concurrency())
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("a readable but empty compartment counts as success", func(t *testing.T) {
		// Distinguishes "read everything, found nothing" from "could not read".
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{ok(), denied()}, ociScopeAllCompartments.concurrency())
		require.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("an unavailable region is skipped without counting as denied", func(t *testing.T) {
		// A service with no endpoint in a region is an expected absence, so it
		// must not push an otherwise all-denied run into the success path.
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{unavailable(), denied()}, ociScopeAllCompartments.concurrency())
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("every region unavailable is an empty result, not an error", func(t *testing.T) {
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{unavailable(), unavailable()}, ociScopeAllCompartments.concurrency())
		require.NoError(t, err)
		assert.Empty(t, res)
	})

	t.Run("a throttled compartment is reported", func(t *testing.T) {
		// Silently dropping a 429 would under-report resources that exist.
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{ok("a"), throttled()}, ociScopeAllCompartments.concurrency())
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("a hard error wins over partial success", func(t *testing.T) {
		res, err := ociJoinCompartmentJobs([]*jobpool.Job{ok("a"), denied(), throttled()}, ociScopeAllCompartments.concurrency())
		require.Error(t, err)
		assert.Nil(t, res)
	})

	t.Run("no jobs", func(t *testing.T) {
		res, err := ociJoinCompartmentJobs(nil, ociScopeAllCompartments.concurrency())
		require.NoError(t, err)
		assert.Empty(t, res)
	})
}
