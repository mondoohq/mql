// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"

	"github.com/oracle/oci-go-sdk/v65/common"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
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

// children lists the compartments directly beneath this one, read from the
// tenancy tree the connection already holds.
func (o *mqlOciCompartment) children() ([]any, error) {
	conn, ok := o.MqlRuntime.Connection.(*connection.OciConnection)
	if !ok {
		return nil, errors.New("oci.compartment requires an oci connection")
	}
	all, err := conn.GetCompartments(context.Background())
	if err != nil {
		return nil, err
	}
	res := []any{}
	for i := range all {
		c := all[i]
		if ociCompartmentParent(stringValue(c.Id), stringValue(c.CompartmentId)) != o.Id.Data {
			continue
		}
		child, err := CreateResource(o.MqlRuntime, "oci.compartment", ociCompartmentArgs(c))
		if err != nil {
			return nil, err
		}
		res = append(res, child)
	}
	return res, nil
}

// policies lists the policies defined in this compartment.
func (o *mqlOciCompartment) policies() ([]any, error) {
	items, err := ociServiceCollection(o.MqlRuntime, "oci.identity", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciIdentity).GetPolicies()
	})
	if err != nil {
		return nil, err
	}
	res := []any{}
	for _, raw := range items {
		if p, ok := raw.(*mqlOciIdentityPolicy); ok && p.cacheCompartmentID == o.Id.Data {
			res = append(res, p)
		}
	}
	return res, nil
}

// securityZone resolves the security zone governing the compartment: its own,
// or the nearest ancestor's.
func (o *mqlOciCompartment) securityZone() (*mqlOciCloudGuardSecurityZone, error) {
	items, err := ociServiceCollection(o.MqlRuntime, "oci.cloudGuard", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCloudGuard).GetSecurityZones()
	})
	if err != nil {
		return nil, err
	}
	byCompartment := map[string]any{}
	for _, raw := range items {
		if z, ok := raw.(*mqlOciCloudGuardSecurityZone); ok && z.cacheCompartmentID != "" {
			byCompartment[z.cacheCompartmentID] = z
		}
	}
	zone, err := ociNearestByCompartment(o.Id.Data, byCompartment, o.compartmentParentOf())
	if err != nil {
		return nil, err
	}
	if zone == nil {
		o.SecurityZone.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return zone.(*mqlOciCloudGuardSecurityZone), nil
}

// cloudGuardTarget resolves the Cloud Guard target monitoring the
// compartment: its own, or the nearest ancestor's.
func (o *mqlOciCompartment) cloudGuardTarget() (*mqlOciCloudGuardTarget, error) {
	items, err := ociServiceCollection(o.MqlRuntime, "oci.cloudGuard", func(r plugin.Resource) *plugin.TValue[[]any] {
		return r.(*mqlOciCloudGuard).GetTargets()
	})
	if err != nil {
		return nil, err
	}
	target, err := ociNearestByCompartment(o.Id.Data, ociCloudGuardTargetsByCompartment(items), o.compartmentParentOf())
	if err != nil {
		return nil, err
	}
	if target == nil {
		o.CloudGuardTarget.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	return target.(*mqlOciCloudGuardTarget), nil
}

// compartmentParentOf returns a lookup of a compartment's parent OCID from
// the tenancy tree, "" for the root or an OCID the tree does not hold.
func (o *mqlOciCompartment) compartmentParentOf() func(string) (string, error) {
	lookup := ociCompartmentLookup(o.MqlRuntime)
	return func(id string) (string, error) {
		if lookup == nil {
			return "", nil
		}
		c, err := lookup(id)
		if err != nil || c == nil {
			return "", err
		}
		return ociCompartmentParent(id, stringValue(c.CompartmentId)), nil
	}
}

// ociNearestByCompartment walks from a compartment up through its ancestors
// and returns the first entry keyed by one of them, or nil when none is. The
// walk stops at the root or at a compartment seen before, so a malformed tree
// cannot loop.
func ociNearestByCompartment(start string, byCompartment map[string]any, parentOf func(string) (string, error)) (any, error) {
	seen := map[string]bool{}
	for id := start; id != "" && !seen[id]; {
		if item, ok := byCompartment[id]; ok {
			return item, nil
		}
		seen[id] = true
		parent, err := parentOf(id)
		if err != nil {
			return nil, err
		}
		id = parent
	}
	return nil, nil
}

// ociCloudGuardTargetsByCompartment indexes Cloud Guard targets by the
// compartment they monitor. When a compartment carries both its own
// COMPARTMENT target and the SECURITY_ZONE target of a zone on it, the
// COMPARTMENT target is the one reported.
func ociCloudGuardTargetsByCompartment(items []any) map[string]any {
	res := map[string]any{}
	for _, raw := range items {
		t, ok := raw.(*mqlOciCloudGuardTarget)
		if !ok {
			continue
		}
		id := ociCloudGuardTargetCompartmentID(t.TargetResourceType.Data, t.TargetResourceId.Data)
		if id == "" {
			continue
		}
		if existing, ok := res[id].(*mqlOciCloudGuardTarget); ok && existing.TargetResourceType.Data == "COMPARTMENT" {
			continue
		}
		res[id] = t
	}
	return res
}
