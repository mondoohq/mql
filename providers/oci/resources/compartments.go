// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"errors"

	"github.com/oracle/oci-go-sdk/v65/common"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
)

// Compartment-shaped helpers used by listers. The fan-out itself lives in
// ociscope.go.

// ociRegionsByID indexes an oci.regions collection by region key so a lister,
// which receives the region as a string, can still set a typed oci.region field
// on the resources it builds.
func ociRegionsByID(regions []any) (map[string]*mqlOciRegion, error) {
	res := make(map[string]*mqlOciRegion, len(regions))
	for _, region := range regions {
		regionResource, ok := region.(*mqlOciRegion)
		if !ok {
			return nil, errors.New("invalid region type")
		}
		res[regionResource.Id.Data] = regionResource
	}
	return res, nil
}

// ociDedupeByID drops repeated resources from a fan-out result.
//
// The compartment scope queries every (region, compartment) pair, which is right
// for a regional service but over-counts a global one: OCI's public DNS is served
// from every regional endpoint, so each global zone comes back once per
// subscribed region. Because CreateResource returns the cached instance for an id
// it has already seen, those repeats are the same resource appearing several
// times rather than distinct rows, and a length or a where() over the collection
// silently multiplies by the region count.
func ociDedupeByID(items []any) []any {
	res := make([]any, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		resource, ok := item.(plugin.Resource)
		if !ok {
			res = append(res, item)
			continue
		}
		id := resource.MqlID()
		if _, dup := seen[id]; dup {
			continue
		}
		seen[id] = struct{}{}
		res = append(res, item)
	}
	return res
}

// ociNotAuthorizedOrNotFound is the error code OCI returns when the caller is
// not permitted to see a resource. The service deliberately reports it for a
// resource that does not exist as well, so that a caller cannot probe for the
// existence of things it has no access to.
const ociNotAuthorizedOrNotFound = "NotAuthorizedOrNotFound"

// ociCompartmentInaccessible reports whether an error means "you cannot see
// into this particular compartment" rather than a tenancy-wide fault.
//
// A 403 is unambiguous. A 404 is not: it is both OCI's authorization denial
// (carrying NotAuthorizedOrNotFound) and what a region with no endpoint for
// the service returns. Matching the code rather than the bare status keeps the
// two apart, which is what lets the caller test this before
// ociRegionServiceUnavailable and still skip genuinely undeployed regions.
//
// Treating a denial as skippable is safe only because the caller checks that
// at least one compartment did succeed.
func ociCompartmentInaccessible(err error) bool {
	svcErr, ok := common.IsServiceError(err)
	if !ok {
		return false
	}
	switch svcErr.GetHTTPStatusCode() {
	case 403:
		return true
	case 404:
		return svcErr.GetCode() == ociNotAuthorizedOrNotFound
	default:
		return false
	}
}
