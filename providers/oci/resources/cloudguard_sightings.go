// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/cloudguard"
	"github.com/oracle/oci-go-sdk/v65/common"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

// A problem says a resource is configured badly. A sighting says something
// was observed doing it. Cloud Guard's detection side was modelled here
// before its observation side, so questions about who did what and from
// where had no answer at all.

// ociCloudGuardSightingWindow is how far back the sighting listing reaches.
//
// Left unset, the service applies a window of its own, so the scope of the
// answer would be whatever that default currently is rather than what this
// code says. 90 days matches the window ociCloudGuardProblemWindow uses for
// problems, so the two halves of the service cover a comparable span and a
// sighting can still be lined up against the problem it produced.
const ociCloudGuardSightingWindow = 90 * 24 * time.Hour

// ociCloudGuardSightingChildID keys a record that hangs off one sighting.
//
// Impacted resources and endpoints carry their own identifiers, but those are
// only documented as unique within the sighting. Two sightings reporting the
// same compromised host with the same record id would collide, and
// CreateResource answers a repeated id with the cached first instance - so
// the second sighting would report the first one's timestamps, and a query
// asking when a host was touched would get the wrong answer with nothing to
// indicate it.
func ociCloudGuardSightingChildID(sightingID, recordID string) string {
	return sightingID + "/" + recordID
}

type mqlOciCloudGuardSightingInternal struct {
	ociCompartmentRef
	cacheProblemID string
}

type mqlOciCloudGuardSightingImpactedResourceInternal struct {
	ociCompartmentRef
}

func (o *mqlOciCloudGuardSighting) id() (string, error) {
	return "oci.cloudGuard.sighting/" + o.Id.Data, nil
}

func (o *mqlOciCloudGuardSighting) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

func (o *mqlOciCloudGuardSightingImpactedResource) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// sightings is one subtree call for the whole tenancy, narrowed to the
// compartments the filters admit.
func (o *mqlOciCloudGuard) sightings() ([]any, error) {
	items, err := o.listSightings()
	return ociKeepAdmitted(o.MqlRuntime, items, err)
}

// listSightings lists the activity Cloud Guard has correlated across the tenancy.
func (o *mqlOciCloudGuard) listSightings() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	serviceRegion, err := o.getServiceRegion()
	if err != nil {
		return nil, err
	}

	client, err := conn.CloudGuardClient(serviceRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	since := common.SDKTime{Time: time.Now().UTC().Add(-ociCloudGuardSightingWindow)}
	sightings, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.SightingSummary, *string, error) {
		response, err := client.ListSightings(ctx, cloudguard.ListSightingsRequest{
			CompartmentId: common.String(conn.TenantID()),
			// Sightings are recorded against resources in sub-compartments, so
			// without the subtree flag the tenancy root reports almost none.
			CompartmentIdInSubtree: common.Bool(true),
			// Required with the subtree flag rather than optional: Cloud Guard
			// answers 400 when one is sent without the other. ACCESSIBLE
			// degrades to the compartments the caller can read instead of
			// failing on the first one it cannot.
			AccessLevel:                          cloudguard.ListSightingsAccessLevelAccessible,
			TimeLastDetectedGreaterThanOrEqualTo: &since,
			Page:                                 page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(sightings))
	for i := range sightings {
		sighting := sightings[i]

		mqlSighting, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.sighting", stringValue(sighting.CompartmentId), map[string]*llx.RawData{
			"id":                      llx.StringDataPtr(sighting.Id),
			"detectorRuleId":          llx.StringDataPtr(sighting.DetectorRuleId),
			"classificationStatus":    llx.StringData(string(sighting.ClassificationStatus)),
			"sightingType":            llx.StringDataPtr(sighting.SightingType),
			"sightingTypeDisplayName": llx.StringDataPtr(sighting.SightingTypeDisplayName),
			"tacticName":              llx.StringDataPtr(sighting.TacticName),
			"techniqueName":           llx.StringDataPtr(sighting.TechniqueName),
			// Ptr rather than a default: a sighting the service did not score
			// must not read as a score of zero, which is the lowest possible
			// grade and would rank it below every real one.
			"sightingScore":      llx.IntDataPtr(intPtrToInt64(sighting.SightingScore)),
			"severity":           llx.StringData(string(sighting.Severity)),
			"confidence":         llx.StringData(string(sighting.Confidence)),
			"actorPrincipalId":   llx.StringDataPtr(sighting.ActorPrincipalId),
			"actorPrincipalName": llx.StringDataPtr(sighting.ActorPrincipalName),
			"actorPrincipalType": llx.StringDataPtr(sighting.ActorPrincipalType),
			"regions":            llx.ArrayData(stringsToAny(sighting.Regions), types.String),
			"firstDetected":      sdkTimeData(sighting.TimeFirstDetected),
			"lastDetected":       sdkTimeData(sighting.TimeLastDetected),
			"firstOccurred":      sdkTimeData(sighting.TimeFirstOccurred),
			"lastOccurred":       sdkTimeData(sighting.TimeLastOccurred),
		})
		if err != nil {
			return nil, err
		}
		mqlSighting.(*mqlOciCloudGuardSighting).cacheProblemID = stringValue(sighting.ProblemId)
		res = append(res, mqlSighting)
	}

	return res, nil
}

// problem resolves the problem the sighting produced, when it produced one.
//
// Matched against the already-fetched problem listing rather than through a
// per-sighting lookup. A sighting whose problem falls outside the problem
// window, or that never raised one, resolves to null.
func (o *mqlOciCloudGuardSighting) problem() (*mqlOciCloudGuardProblem, error) {
	if o.cacheProblemID == "" {
		o.Problem.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	obj, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	problems := obj.(*mqlOciCloudGuard).GetProblems()
	if problems.Error != nil {
		return nil, problems.Error
	}

	for _, raw := range problems.Data {
		p, ok := raw.(*mqlOciCloudGuardProblem)
		if ok && p.Id.Data == o.cacheProblemID {
			return p, nil
		}
	}

	o.Problem.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}

// sightingClient builds a Cloud Guard client for the reporting region, which
// is where every sighting sub-listing is served from.
func (o *mqlOciCloudGuardSighting) sightingClient() (*cloudguard.CloudGuardClient, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	obj, err := CreateResource(o.MqlRuntime, "oci.cloudGuard", nil)
	if err != nil {
		return nil, err
	}
	serviceRegion, err := obj.(*mqlOciCloudGuard).getServiceRegion()
	if err != nil {
		return nil, err
	}
	return conn.CloudGuardClient(serviceRegion)
}

// impactedResources lists what the observed activity actually reached.
//
// One call per sighting, which is why it is a field rather than part of the
// sighting listing: a tenancy with hundreds of sightings pays for this only
// when a query asks for it.
func (o *mqlOciCloudGuardSighting) impactedResources() ([]any, error) {
	client, err := o.sightingClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.SightingImpactedResourceSummary, *string, error) {
		response, err := client.ListSightingImpactedResources(ctx, cloudguard.ListSightingImpactedResourcesRequest{
			SightingId: common.String(o.Id.Data),
			Page:       page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		item := items[i]

		mqlItem, err := createOciResourceInCompartment(o.MqlRuntime, "oci.cloudGuard.sighting.impactedResource", stringValue(item.CompartmentId), map[string]*llx.RawData{
			"__id":          llx.StringData(ociCloudGuardSightingChildID(o.Id.Data, stringValue(item.Id))),
			"id":            llx.StringDataPtr(item.Id),
			"resourceId":    llx.StringDataPtr(item.ResourceId),
			"resourceName":  llx.StringDataPtr(item.ResourceName),
			"resourceType":  llx.StringDataPtr(item.ResourceType),
			"region":        llx.StringDataPtr(item.Region),
			"identified":    sdkTimeData(item.TimeIdentified),
			"firstDetected": sdkTimeData(item.TimeFirstDetected),
			"lastDetected":  sdkTimeData(item.TimeLastDetected),
			"firstOccurred": sdkTimeData(item.TimeFirstOccurred),
			"lastOccurred":  sdkTimeData(item.TimeLastOccurred),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlItem)
	}

	return res, nil
}

// endpoints lists the source addresses the observed activity came from.
func (o *mqlOciCloudGuardSighting) endpoints() ([]any, error) {
	client, err := o.sightingClient()
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]cloudguard.SightingEndpointSummary, *string, error) {
		response, err := client.ListSightingEndpoints(ctx, cloudguard.ListSightingEndpointsRequest{
			SightingId: common.String(o.Id.Data),
			Page:       page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		if ociCloudGuardNotSubscribed(err) {
			return []any{}, nil
		}
		return nil, err
	}

	res := make([]any, 0, len(items))
	for i := range items {
		item := items[i]

		mqlItem, err := CreateResource(o.MqlRuntime, "oci.cloudGuard.sighting.endpoint", map[string]*llx.RawData{
			"__id":                 llx.StringData(ociCloudGuardSightingChildID(o.Id.Data, stringValue(item.Id))),
			"id":                   llx.StringDataPtr(item.Id),
			"ipAddress":            llx.StringDataPtr(item.IpAddress),
			"ipAddressType":        llx.StringDataPtr(item.IpAddressType),
			"ipClassificationType": llx.StringDataPtr(item.IpClassificationType),
			"country":              llx.StringDataPtr(item.Country),
			// Ptr rather than a default: 0,0 is a real point in the Gulf of
			// Guinea, so an address the service could not place must read null
			// instead of being mapped to a coastline nobody was near.
			"latitude":      llx.FloatDataPtr(item.Latitude),
			"longitude":     llx.FloatDataPtr(item.Longitude),
			"asnNumber":     llx.StringDataPtr(item.AsnNumber),
			"regions":       llx.ArrayData(stringsToAny(item.Regions), types.String),
			"services":      llx.ArrayData(stringsToAny(item.Services), types.String),
			"firstDetected": sdkTimeData(item.TimeFirstDetected),
			"lastDetected":  sdkTimeData(item.TimeLastDetected),
			"firstOccurred": sdkTimeData(item.TimeFirstOccurred),
			"lastOccurred":  sdkTimeData(item.TimeLastOccurred),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlItem)
	}

	return res, nil
}
