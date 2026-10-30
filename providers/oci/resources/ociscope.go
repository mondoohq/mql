// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/jobpool"
	"go.mondoo.com/mql/providers/oci/connection"
)

// Almost every OCI list API answers for exactly one compartment in one region,
// so a lister has to be fanned out over both. This is the one place that does
// that fanning out.
//
// It replaces two separate idioms. One walked the compartment tree; the other
// passed the tenancy OCID as the compartment and so listed only the tenancy
// root, which returns nothing at all for any tenancy that organizes its
// resources into child compartments - the normal way to run OCI. Both compiled,
// both returned a plausible list, and nothing at the call site distinguished
// them: the difference was a `conn.TenantID()` buried in a request struct.
//
// Naming the scope is the point. A lister now has to say which set of
// compartments it means, so the root-only choice is a visible, greppable token
// instead of an accident.

// ociScope selects the compartments a lister is fanned out over.
type ociScope int

const (
	// ociScopeTenancyRoot lists the tenancy root compartment only.
	//
	// This is what the older listers did implicitly. It is correct for a
	// genuinely tenancy-wide API, and wrong for anything a customer can place in
	// a child compartment - which is most things.
	//
	// The bulk migration is done. What still carries this scope is one of three
	// things, and only the last is a defect:
	//
	//   - the request sets a compartmentIdInSubtree flag itself, so one call
	//     from the root already covers the tree (Cloud Guard, Data Safe,
	//     Logging, Monitoring);
	//   - the service really is tenancy-scoped (Zero Trust Packet Routing);
	//   - the lister ignores the compartment it is handed and asks about
	//     conn.TenantID() instead. Those cannot simply be re-scoped: under the
	//     compartment scope they would ask the root once per compartment and,
	//     since ociJoinCompartmentJobs concatenates without deduplicating,
	//     return the root's resources N times while still never reading a child
	//     compartment. Fixing one means threading the compartmentID argument
	//     through first. TestCompartmentScopedListersUseTheirCompartment fails
	//     the build if one is re-scoped without that.
	ociScopeTenancyRoot ociScope = iota

	// ociScopeAllCompartments walks the tenancy root plus every active
	// compartment beneath it.
	//
	// Needed because most OCI list APIs have no `compartmentIdInSubtree` flag.
	// The few services that do offer one (Cloud Guard, Data Safe, Monitoring)
	// set it on the request and use ociScopeSubtree instead.
	ociScopeAllCompartments

	// ociScopeSubtree asks the tenancy root once per region, for a request
	// that sets its own compartmentIdInSubtree flag and so answers for the
	// whole tree.
	//
	// The root is asked even when a compartment filter excludes it, because
	// the filter selects where resources live, not where the question is
	// asked: under ociScopeTenancyRoot a filter naming one child compartment
	// skipped the call and returned nothing at all. The lister has to drop
	// the items of compartments the filter does not admit itself, with
	// ociCompartmentAdmitter, since only it can read an item's compartment.
	//
	// Logging documents such a flag too but ignores it (a log group in a
	// child compartment is not returned from the root), so it uses
	// ociScopeAllCompartments.
	ociScopeSubtree
)

// ociListerConcurrency bounds how many (region, compartment) list calls run at
// once, per scope.
//
// The compartment scope multiplies the request count by the size of the
// compartment tree, so it is deliberately higher while still staying well inside
// OCI's per-tenancy rate limits. The two values are kept distinct rather than
// unified because changing either changes how a scan behaves under throttling.
func (s ociScope) concurrency() int {
	if s == ociScopeAllCompartments {
		return 10
	}
	return 5
}

// ociLister lists resources of a single type inside one compartment in one
// region, returning the already-constructed MQL resources.
//
// The region arrives as its key rather than as the oci.region resource because
// that is all most listers need - they hand it to a client constructor. The few
// that set a typed `region` field index the collection with ociRegionsByID.
type ociLister func(ctx context.Context, region string, compartmentID string) ([]any, error)

// ociCollect fans a lister out over every (region, compartment) pair the scope
// selects and joins the results.
func ociCollect(runtime *plugin.Runtime, scope ociScope, list ociLister) ([]any, error) {
	conn := runtime.Connection.(*connection.OciConnection)
	ctx := context.Background()

	regions, err := ociRegionsFor(runtime)
	if err != nil {
		return nil, err
	}

	// Already narrowed by the region filters: ociRegionsFor is the one source
	// every fan-out draws from, so the filter is applied there rather than at
	// each of the places a job list gets built.
	regionIDs, err := ociRegionIDs(regions)
	if err != nil {
		return nil, err
	}

	compartmentIDs, err := scope.compartmentIDs(ctx, conn)
	if err != nil {
		return nil, err
	}

	jobs := make([]*jobpool.Job, 0, len(regionIDs)*len(compartmentIDs))
	for _, regionID := range regionIDs {
		for _, compartmentID := range compartmentIDs {
			jobs = append(jobs, jobpool.NewJob(func() (jobpool.JobResult, error) {
				items, err := list(ctx, regionID, compartmentID)
				if err != nil {
					return nil, err
				}
				return jobpool.JobResult(items), nil
			}))
		}
	}

	return scope.join(jobs)
}

// ociRegionIDs extracts the region keys from the resolved region collection.
func ociRegionIDs(regions []any) ([]string, error) {
	ids := make([]string, 0, len(regions))
	for _, raw := range regions {
		region, ok := raw.(*mqlOciRegion)
		if !ok {
			return nil, errors.New("invalid region type")
		}
		ids = append(ids, region.Id.Data)
	}
	return ids, nil
}

// compartmentIDs resolves the scope to the compartments to ask, after the
// compartment filters have been applied.
//
// The filter applies under both scopes. The tenancy root is a compartment like
// any other, so a scan told to look at one child compartment must not fall back
// to reporting the root's contents - under the root scope that would be a
// different set of resources presented as if it were the requested one.
func (s ociScope) compartmentIDs(ctx context.Context, conn *connection.OciConnection) ([]string, error) {
	if s == ociScopeTenancyRoot {
		return conn.SelectTenancyRoot(ctx), nil
	}
	if s == ociScopeSubtree {
		return []string{conn.TenantID()}, nil
	}

	compartments, err := conn.GetCompartments(ctx)
	if err != nil {
		return nil, err
	}
	return conn.Filters.SelectCompartments(compartments), nil
}

// join collects the fan-out under the scope's error policy.
//
// The two policies are NOT interchangeable, which is why the scope carries its
// own rather than sharing one. Under the root scope a 404 carrying
// NotAuthorizedOrNotFound is read as an absent regional endpoint and skipped;
// under the compartment scope the same error is a per-compartment denial, which
// is counted and tolerated unless every compartment refuses. Swapping them would
// change what a tenancy-wide IAM gap returns - today an empty list, under the
// compartment policy an error. That is arguably the better answer, but it is a
// different answer, so the choice stays with the scope until it is made
// deliberately.
func (s ociScope) join(jobs []*jobpool.Job) ([]any, error) {
	if s == ociScopeAllCompartments {
		return ociJoinCompartmentJobs(jobs, s.concurrency())
	}
	return ociJoinRegionJobs(jobs, s.concurrency())
}

// ociJoinRegionJobs returns the union of the jobs that succeeded, skipping only
// the regions where the service genuinely has no endpoint.
//
// The distinction matters in both directions. Failing the whole collection when
// any region errors turned one unsubscribed or undeployed region into a
// tenancy-wide failure. But skipping every error is just as wrong the other way:
// a 403 from an IAM gap, a 429 throttle or a 500 would silently under-report
// resources, and an authoritative-looking short list is worse than an error in an
// inventory tool.
//
// So ociRegionServiceUnavailable decides. An absent endpoint is expected and is
// skipped; anything else is reported, joined across regions so a broken token
// names every region it affected.
func ociJoinRegionJobs(jobs []*jobpool.Job, concurrency int) ([]any, error) {
	if len(jobs) == 0 {
		return []any{}, nil
	}

	poolOfJobs := jobpool.CreatePool(jobs, concurrency)
	poolOfJobs.Run()

	res := []any{}
	var hardErr error
	for i := range poolOfJobs.Jobs {
		job := poolOfJobs.Jobs[i]
		if job.Err != nil {
			if ociRegionServiceUnavailable(job.Err) {
				log.Debug().Err(job.Err).Msg("skipping oci region where the service is unavailable")
				continue
			}
			hardErr = errors.Join(hardErr, job.Err)
			continue
		}
		items, ok := job.Result.([]any)
		if !ok {
			continue
		}
		res = append(res, items...)
	}

	if hardErr != nil {
		return nil, hardErr
	}
	return res, nil
}

// ociJoinCompartmentJobs joins a compartment fan-out.
//
// Error handling has to distinguish three cases that all surface as an error
// from a single job:
//
//   - The service has no endpoint in this region. Expected; skipped, matching
//     ociJoinRegionJobs.
//   - The caller cannot read this one compartment. Also expected: OCI policies
//     are routinely written per-compartment, so a scanning principal that can
//     read ten of fifty compartments is correctly configured, not broken. The
//     compartment is skipped and counted.
//   - Anything else (throttling, 5xx, malformed request) is a real fault and is
//     returned, because silently dropping it would under-report resources.
//
// The one case that must not be swallowed is *every* compartment refusing
// access. That is an under-scoped token, and reporting it as an empty tenancy
// would turn a broken credential into a clean scan.
func ociJoinCompartmentJobs(jobs []*jobpool.Job, concurrency int) ([]any, error) {
	if len(jobs) == 0 {
		return []any{}, nil
	}

	poolOfJobs := jobpool.CreatePool(jobs, concurrency)
	poolOfJobs.Run()

	res := []any{}
	var (
		hardErr   error
		deniedErr error
		denied    int
		succeeded int
	)
	for i := range poolOfJobs.Jobs {
		job := poolOfJobs.Jobs[i]
		if job.Err != nil {
			// Order matters. OCI answers an authorization failure with 404
			// NotAuthorizedOrNotFound, and ociRegionServiceUnavailable treats
			// any 404 as an absent regional endpoint - so asking it first
			// consumed every denial before it could be counted, and the
			// all-denied guard below could never fire. The denial test is
			// narrower (it matches on the error code, not just the status), so
			// it goes first and the region test keeps the rest.
			if ociCompartmentInaccessible(job.Err) {
				denied++
				if deniedErr == nil {
					deniedErr = job.Err
				}
				continue
			}
			if ociRegionServiceUnavailable(job.Err) {
				log.Debug().Err(job.Err).Msg("skipping oci region where the service is unavailable")
				continue
			}
			hardErr = errors.Join(hardErr, job.Err)
			continue
		}

		succeeded++
		items, ok := job.Result.([]any)
		if !ok {
			continue
		}
		res = append(res, items...)
	}

	if hardErr != nil {
		return nil, hardErr
	}

	if succeeded == 0 && denied > 0 {
		return nil, deniedErr
	}

	if denied > 0 {
		// Visible rather than silent: the result is a partial view of the
		// tenancy and the operator should know how partial.
		log.Warn().
			Int("compartments_denied", denied).
			Int("compartments_read", succeeded).
			Msg("oci: listed a partial view of the tenancy, some compartments were not readable")
	}

	return res, nil
}

// ociCompartmentAdmitter returns whether the compartment filters admit a
// compartment, for listers that receive resources of many compartments from
// one call (ociScopeSubtree). Without a compartment filter every compartment
// is admitted and the tree is not read.
func ociCompartmentAdmitter(ctx context.Context, conn *connection.OciConnection) (func(compartmentID string) bool, error) {
	if !conn.Filters.HasCompartments() {
		return func(string) bool { return true }, nil
	}
	compartments, err := conn.GetCompartments(ctx)
	if err != nil {
		return nil, err
	}
	return ociAdmitted(conn.Filters, compartments), nil
}

// ociAdmitted is the set of compartments the filters admit, as a predicate.
func ociAdmitted(filters connection.DiscoveryFilters, compartments []identity.Compartment) func(compartmentID string) bool {
	admitted := map[string]bool{}
	for _, id := range filters.SelectCompartments(compartments) {
		admitted[id] = true
	}
	return func(compartmentID string) bool { return admitted[compartmentID] }
}

// ociGlobalLister lists resources of a global (home region) service inside
// one compartment.
type ociGlobalLister func(ctx context.Context, compartmentID string) ([]any, error)

// ociCollectGlobal fans a lister out over every compartment the filters
// admit, without a region dimension: for identity-plane resources such as
// policies that live in any compartment but are served the same from every
// region, so a region fan-out would return each one once per region.
func ociCollectGlobal(runtime *plugin.Runtime, list ociGlobalLister) ([]any, error) {
	conn := runtime.Connection.(*connection.OciConnection)
	ctx := context.Background()
	compartmentIDs, err := ociScopeAllCompartments.compartmentIDs(ctx, conn)
	if err != nil {
		return nil, err
	}
	jobs := make([]*jobpool.Job, 0, len(compartmentIDs))
	for _, compartmentID := range compartmentIDs {
		jobs = append(jobs, jobpool.NewJob(func() (jobpool.JobResult, error) {
			items, err := list(ctx, compartmentID)
			if err != nil {
				return nil, err
			}
			return jobpool.JobResult(items), nil
		}))
	}
	return ociJoinCompartmentJobs(jobs, ociScopeAllCompartments.concurrency())
}

// ociKeepAdmitted drops the resources of compartments the compartment filters
// do not admit, from a collection one subtree call returned for the whole
// tenancy (ociScopeSubtree, or a lister that sets the subtree flag itself). A
// resource that does not record its compartment is kept: dropping it would
// hide a resource on the strength of a filter nobody could apply to it.
func ociKeepAdmitted(runtime *plugin.Runtime, items []any, err error) ([]any, error) {
	if err != nil {
		return nil, err
	}
	conn := runtime.Connection.(*connection.OciConnection)
	if !conn.Filters.HasCompartments() {
		return items, nil
	}
	admit, err := ociCompartmentAdmitter(context.Background(), conn)
	if err != nil {
		return nil, err
	}
	return ociFilterAdmitted(items, admit), nil
}

// ociFilterAdmitted keeps the items whose compartment is admitted, and those
// that do not record one.
func ociFilterAdmitted(items []any, admit func(compartmentID string) bool) []any {
	out := make([]any, 0, len(items))
	for _, item := range items {
		if g, ok := item.(ociCompartmentGetter); ok && !admit(g.compartmentIDValue()) {
			continue
		}
		out = append(out, item)
	}
	return out
}
