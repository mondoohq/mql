// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"
	"errors"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"
)

// The tenancy-shaped reads every lister depends on before it can fan out: which
// tenancy this is, which compartments it contains, and which regions it is
// subscribed to.

func (c *OciConnection) TenantID() string {
	return c.tenancyOcid
}

// ConfiguredRegion returns the region the configuration provider is pointed at.
//
// Tenancy-wide services answer the same from any region, so a lister that does
// not fan out needs one region to build a client against rather than a choice
// between them. This is that region: whatever the profile, environment or
// principal the connection was built from already named.
func (c *OciConnection) ConfiguredRegion() (string, error) {
	return c.config.Region()
}

func (c *OciConnection) Tenant(ctx context.Context) (*identity.Tenancy, error) {
	oClient, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}

	resp, err := oClient.GetTenancy(ctx, identity.GetTenancyRequest{
		TenancyId: &c.tenancyOcid,
	})
	if err != nil {
		return nil, err
	}
	return &resp.Tenancy, nil
}

// compartmentFetchRetryAfter is how long a failed tenancy tree fetch is held
// before the next caller tries again.
//
// Long enough that a throttled scan retries a handful of times rather than
// once per resource, short enough that a transient failure early on does not
// decide the compartment of everything read afterwards.
const compartmentFetchRetryAfter = 30 * time.Second

// GetCompartments returns the tenancy root plus every active compartment
// beneath it.
//
// The result is memoized for the lifetime of the connection. A dozen listers
// fan out over the compartment tree, and each one asking for it separately
// meant walking the same paginated ListCompartments a dozen times per scan.
//
// A failure is held only for compartmentFetchRetryAfter rather than for the
// life of the connection: an Identity call that fails on a throttle should be
// retried rather than turning one bad moment into a scan with no compartments
// at all. But it is held, because the callers are no longer only the dozen
// listers. Every resource that reports its compartment reaches this, so an
// uncached failure would answer a throttle by walking the paginated listing
// again for each of them - hundreds of retries of the call that was already
// being rate limited, on top of the direct read each one then falls back to.
func (c *OciConnection) GetCompartments(ctx context.Context) ([]identity.Compartment, error) {
	c.compartmentLock.Lock()
	defer c.compartmentLock.Unlock()
	if c.compartmentsDone {
		return c.compartmentList, nil
	}
	if c.compartmentFetchBlocked(time.Now()) {
		return nil, c.compartmentFetchErr
	}

	compartments, err := c.fetchCompartments(ctx)
	if err != nil {
		c.compartmentFetchErr = err
		c.compartmentFetchAt = time.Now()
		return nil, err
	}

	c.compartmentFetchErr = nil
	c.compartmentList = compartments
	c.compartmentsDone = true
	return compartments, nil
}

// compartmentFetchBlocked reports whether a recorded tree fetch failure is
// recent enough to be reused instead of retried. The caller holds
// compartmentLock.
func (c *OciConnection) compartmentFetchBlocked(now time.Time) bool {
	if c.compartmentFetchErr == nil {
		return false
	}
	return now.Sub(c.compartmentFetchAt) < compartmentFetchRetryAfter
}

// fetchCompartments reads the tenancy root and walks the paginated listing of
// every active compartment beneath it. Callers go through GetCompartments,
// which owns the memoizing and the retry window.
func (c *OciConnection) fetchCompartments(ctx context.Context) ([]identity.Compartment, error) {
	oClient, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}

	compartments := make([]identity.Compartment, 0)

	req := identity.GetCompartmentRequest{
		CompartmentId: &c.tenancyOcid,
	}

	resp, err := oClient.GetCompartment(ctx, req)
	if err != nil {
		return nil, err
	}
	compartments = append(compartments, resp.Compartment)

	var page *string
	for {
		request := identity.ListCompartmentsRequest{
			CompartmentId:          new(c.tenancyOcid),
			CompartmentIdInSubtree: new(true),
			LifecycleState:         identity.CompartmentLifecycleStateActive,
			Page:                   page,
		}

		response, err := oClient.ListCompartments(ctx, request)
		if err != nil {
			return nil, errors.Join(errors.New("failed to list compartments in tenancy: "+c.tenancyOcid), err)
		}

		for i := range response.Items {
			compartments = append(compartments, response.Items[i])
		}

		page = response.OpcNextPage
		if response.OpcNextPage == nil {
			break
		}
	}

	return compartments, nil
}

// CompartmentByID returns the compartment with the given OCID out of the
// memoized tenancy tree, or nil when the tree does not contain it.
//
// Almost every resource in the provider reports the compartment it lives in,
// and resolving that through the Identity API is one GetCompartment call per
// resource: five hundred instances in five compartments cost five hundred
// calls. The tree those five compartments come from is already fetched once per
// connection, walks the whole subtree, and cannot change mid-scan, so the
// answer is nearly always sitting in it.
//
// A nil result is not an error. An OCID outside this tenancy, or one belonging
// to a compartment deleted since the listing, legitimately misses; the caller
// falls back to the direct read for those.
func (c *OciConnection) CompartmentByID(ctx context.Context, id string) (*identity.Compartment, error) {
	if id == "" {
		return nil, nil
	}

	// Taken before the lock: GetCompartments locks for itself, and it is a
	// no-op once the tree has been fetched.
	if _, err := c.GetCompartments(ctx); err != nil {
		return nil, err
	}

	c.compartmentLock.Lock()
	defer c.compartmentLock.Unlock()
	if c.compartmentIndex == nil {
		c.compartmentIndex = compartmentIndexByID(c.compartmentList)
	}

	compartment, ok := c.compartmentIndex[id]
	if !ok {
		return nil, nil
	}
	// A copy, so a caller cannot reach into the memoized tree.
	return &compartment, nil
}

// compartmentIndexByID keys a compartment list by OCID, skipping entries
// without one. The first entry wins, which matters only if the tenancy root
// were to repeat in the listing.
func compartmentIndexByID(compartments []identity.Compartment) map[string]identity.Compartment {
	index := make(map[string]identity.Compartment, len(compartments))
	for i := range compartments {
		id := compartments[i].Id
		if id == nil || *id == "" {
			continue
		}
		if _, seen := index[*id]; seen {
			continue
		}
		index[*id] = compartments[i]
	}
	return index
}

// AccessibleCompartmentIDs returns the OCIDs of the compartments beneath the
// tenancy that the caller holds INSPECT on, directly or through a
// subcompartment.
//
// This is a second walk of ListCompartments, and it has to be. The listing
// fills in isAccessible only when it is asked for the accessible subset, and
// asking for that subset also drops every compartment outside it - so the walk
// that enumerates the tree cannot be the one that reports the flag, and the
// walk that reports the flag cannot enumerate the tree. Running both and
// intersecting them is what turns "the caller can see this compartment exists"
// and "the caller can look inside it" into two separate answers.
//
// It is memoized and taken lazily, so a scan that never asks about
// accessibility never pays for it. A failure is returned rather than cached as
// an empty set: reporting every compartment as inaccessible because Identity
// was throttled would be a fabricated verdict, not a missing one.
func (c *OciConnection) AccessibleCompartmentIDs(ctx context.Context) (map[string]struct{}, error) {
	c.accessibleLock.Lock()
	defer c.accessibleLock.Unlock()
	if c.accessibleDone {
		return c.accessibleIDs, nil
	}

	oClient, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}

	ids := map[string]struct{}{}
	var page *string
	for {
		response, err := oClient.ListCompartments(ctx, identity.ListCompartmentsRequest{
			CompartmentId:          new(c.tenancyOcid),
			CompartmentIdInSubtree: new(true),
			AccessLevel:            identity.ListCompartmentsAccessLevelAccessible,
			LifecycleState:         identity.CompartmentLifecycleStateActive,
			Page:                   page,
		})
		if err != nil {
			return nil, errors.Join(errors.New("failed to list accessible compartments in tenancy: "+c.tenancyOcid), err)
		}

		for i := range response.Items {
			id := response.Items[i].Id
			if id == nil || *id == "" {
				continue
			}
			ids[*id] = struct{}{}
		}

		page = response.OpcNextPage
		if page == nil {
			break
		}
	}

	c.accessibleIDs = ids
	c.accessibleDone = true
	return ids, nil
}

func (c *OciConnection) GetRegions(ctx context.Context) ([]identity.RegionSubscription, error) {
	oClient, err := c.IdentityClient()
	if err != nil {
		return nil, err
	}

	request := identity.ListRegionSubscriptionsRequest{
		TenancyId: new(c.tenancyOcid),
	}

	response, err := oClient.ListRegionSubscriptions(ctx, request)
	if err != nil {
		return nil, err
	}

	regions := make([]identity.RegionSubscription, 0)
	for _, region := range response.Items {
		if region.Status != identity.RegionSubscriptionStatusReady {
			continue
		}
		regions = append(regions, region)
	}

	return regions, nil
}
