// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/oracle/oci-go-sdk/v65/dns"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOciDns) id() (string, error) {
	return "oci.dns", nil
}

// ociDnsZoneScopes are the two scopes a zone can live in.
//
// The Zones API scopes its listing, and omitting the parameter does not return
// the union: private zones - the ones resolving inside a VCN - are only
// returned when PRIVATE is asked for explicitly. Listing one scope would report
// a tenancy's internal DNS as absent, so both are queried and merged.
var ociDnsZoneScopes = []dns.ListZonesScopeEnum{
	dns.ListZonesScopeGlobal,
	dns.ListZonesScopePrivate,
}

func (o *mqlOciDns) zones() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Deduplicated: a global zone is returned by every regional DNS
	// endpoint, so the region fan-out sees it once per subscribed region.
	items, err := ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.DnsClient(region)
			if err != nil {
				return nil, err
			}

			zones := []dns.ZoneSummary{}
			for _, scope := range ociDnsZoneScopes {
				perScope, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]dns.ZoneSummary, *string, error) {
					response, err := client.ListZones(ctx, dns.ListZonesRequest{
						CompartmentId: new(compartmentID),
						Scope:         scope,
						Page:          page,
					})
					if err != nil {
						return nil, nil, err
					}
					return response.Items, response.OpcNextPage, nil
				})
				if err != nil {
					return nil, err
				}
				zones = append(zones, perScope...)
			}

			return o.newZones(region, zones)
		})
	if err != nil {
		return nil, err
	}
	return ociDedupeByID(items), nil
}

func (o *mqlOciDns) newZones(region string, zones []dns.ZoneSummary) ([]any, error) {
	res := make([]any, 0, len(zones))
	for i := range zones {
		zone := zones[i]

		var dnssecKeyVersions map[string]any
		if zone.DnssecConfig != nil {
			var err error
			dnssecKeyVersions, err = convert.JsonToDict(zone.DnssecConfig)
			if err != nil {
				return nil, err
			}
		}

		kskVersions, zskVersions, err := o.newDnssecKeyVersions(stringValue(zone.Id), zone.DnssecConfig)
		if err != nil {
			return nil, err
		}

		mqlZone, err := CreateResource(o.MqlRuntime, "oci.dns.zone", map[string]*llx.RawData{
			"id":                llx.StringDataPtr(zone.Id),
			"name":              llx.StringDataPtr(zone.Name),
			"zoneType":          llx.StringData(string(zone.ZoneType)),
			"scope":             llx.StringData(string(zone.Scope)),
			"resolutionMode":    llx.StringData(string(zone.ResolutionMode)),
			"dnssecState":       llx.StringData(string(zone.DnssecState)),
			"dnssecKeyVersions": llx.DictData(dnssecKeyVersions),
			"kskVersions":       llx.ArrayData(kskVersions, types.Resource("oci.dns.zone.dnssecKeyVersion")),
			"zskVersions":       llx.ArrayData(zskVersions, types.Resource("oci.dns.zone.dnssecKeyVersion")),
			"isProtected":       llx.BoolData(boolValue(zone.IsProtected)),
			"serial":            llx.IntDataDefault(zone.Serial, 0),
			"version":           llx.StringDataPtr(zone.Version),
			"viewId":            llx.StringDataPtr(zone.ViewId),
			"state":             llx.StringData(string(zone.LifecycleState)),
			"created":           sdkTimeData(zone.TimeCreated),
			"freeformTags":      llx.MapData(strMapToAny(zone.FreeformTags), types.String),
			"definedTags":       llx.MapData(definedTagsToAny(zone.DefinedTags), types.Any),
		})
		if err != nil {
			return nil, err
		}
		mqlZoneTyped := mqlZone.(*mqlOciDnsZone)
		mqlZoneTyped.cacheCompartmentID = stringValue(zone.CompartmentId)
		mqlZoneTyped.cacheRegion = region
		mqlZoneTyped.cacheScope = zone.Scope
		res = append(res, mqlZoneTyped)
	}

	return res, nil
}

// newDnssecKeyVersions builds the key-signing and zone-signing key version
// resources for one zone. Both are the same shape apart from the DS records,
// which only a key-signing key carries.
func (o *mqlOciDns) newDnssecKeyVersions(zoneID string, config *dns.DnssecConfig) (ksks []any, zsks []any, err error) {
	ksks = []any{}
	zsks = []any{}
	if config == nil {
		return ksks, zsks, nil
	}

	for i := range config.KskDnssecKeyVersions {
		mqlKsk, err := CreateResource(o.MqlRuntime, "oci.dns.zone.dnssecKeyVersion",
			ociKskKeyVersionArgs(zoneID, config.KskDnssecKeyVersions[i]))
		if err != nil {
			return nil, nil, err
		}
		ksks = append(ksks, mqlKsk)
	}

	for i := range config.ZskDnssecKeyVersions {
		mqlZsk, err := CreateResource(o.MqlRuntime, "oci.dns.zone.dnssecKeyVersion",
			ociZskKeyVersionArgs(zoneID, config.ZskDnssecKeyVersions[i]))
		if err != nil {
			return nil, nil, err
		}
		zsks = append(zsks, mqlZsk)
	}

	return ksks, zsks, nil
}

// ociKskKeyVersionArgs maps one key-signing key version.
//
// Every lifecycle timestamp is optional, and an absent one has to stay null:
// the zero time would read as 1 January year 1, which an "activated before X"
// or "expired before now" audit would count as a real date and act on.
func ociKskKeyVersionArgs(zoneID string, k dns.KskDnssecKeyVersion) map[string]*llx.RawData {
	dsData := make([]any, 0, len(k.DsData))
	for _, ds := range k.DsData {
		dsData = append(dsData, map[string]any{
			"rdata":      stringValue(ds.Rdata),
			"digestType": string(ds.DigestType),
		})
	}

	return map[string]*llx.RawData{
		"__id":            llx.StringData(zoneID + "/ksk/" + stringValue(k.Uuid)),
		"algorithm":       llx.StringData(string(k.Algorithm)),
		"lengthInBytes":   llx.IntDataPtr(intPtrToInt64(k.LengthInBytes)),
		"keyTag":          llx.IntDataPtr(intPtrToInt64(k.KeyTag)),
		"created":         sdkTimeData(k.TimeCreated),
		"timePublished":   sdkTimeData(k.TimePublished),
		"timeActivated":   sdkTimeData(k.TimeActivated),
		"timeInactivated": sdkTimeData(k.TimeInactivated),
		"timeUnpublished": sdkTimeData(k.TimeUnpublished),
		"timeExpired":     sdkTimeData(k.TimeExpired),
		"timePromoted":    sdkTimeData(k.TimePromoted),
		"predecessorUuid": llx.StringDataPtr(k.PredecessorDnssecKeyVersionUuid),
		"successorUuid":   llx.StringDataPtr(k.SuccessorDnssecKeyVersionUuid),
		"dsData":          llx.ArrayData(dsData, types.Dict),
	}
}

// ociZskKeyVersionArgs maps one zone-signing key version. It is the key-signing
// shape without the DS records, which only a key-signing key publishes.
func ociZskKeyVersionArgs(zoneID string, z dns.ZskDnssecKeyVersion) map[string]*llx.RawData {
	return map[string]*llx.RawData{
		"__id":            llx.StringData(zoneID + "/zsk/" + stringValue(z.Uuid)),
		"algorithm":       llx.StringData(string(z.Algorithm)),
		"lengthInBytes":   llx.IntDataPtr(intPtrToInt64(z.LengthInBytes)),
		"keyTag":          llx.IntDataPtr(intPtrToInt64(z.KeyTag)),
		"created":         sdkTimeData(z.TimeCreated),
		"timePublished":   sdkTimeData(z.TimePublished),
		"timeActivated":   sdkTimeData(z.TimeActivated),
		"timeInactivated": sdkTimeData(z.TimeInactivated),
		"timeUnpublished": sdkTimeData(z.TimeUnpublished),
		"timeExpired":     sdkTimeData(z.TimeExpired),
		"timePromoted":    sdkTimeData(z.TimePromoted),
		"predecessorUuid": llx.StringDataPtr(z.PredecessorDnssecKeyVersionUuid),
		"successorUuid":   llx.StringDataPtr(z.SuccessorDnssecKeyVersionUuid),
		// A zone-signing key publishes no DS records; the chain of trust runs
		// through the key-signing key.
		"dsData": llx.ArrayData([]any{}, types.Dict),
	}
}

func (o *mqlOciDns) steeringPolicies() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	// Deduplicated: a global steering policy is returned by every regional DNS
	// endpoint, so the region fan-out sees it once per subscribed region.
	items, err := ociCollect(o.MqlRuntime, ociScopeAllCompartments,
		func(ctx context.Context, region string, compartmentID string) ([]any, error) {
			client, err := conn.DnsClient(region)
			if err != nil {
				return nil, err
			}

			// Unlike zones, steering policies exist only globally: the listing
			// rejects any other scope with "query param scope must be one of
			// [GLOBAL]", so asking for PRIVATE fails the whole call.
			policies, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]dns.SteeringPolicySummary, *string, error) {
				response, err := client.ListSteeringPolicies(ctx, dns.ListSteeringPoliciesRequest{
					CompartmentId: new(compartmentID),
					Scope:         dns.ListSteeringPoliciesScopeGlobal,
					Page:          page,
				})
				if err != nil {
					return nil, nil, err
				}
				return response.Items, response.OpcNextPage, nil
			})
			if err != nil {
				return nil, err
			}

			res := make([]any, 0, len(policies))
			for i := range policies {
				policy := policies[i]

				mqlPolicy, err := CreateResource(o.MqlRuntime, "oci.dns.steeringPolicy", map[string]*llx.RawData{
					"id":                   llx.StringDataPtr(policy.Id),
					"name":                 llx.StringDataPtr(policy.DisplayName),
					"template":             llx.StringData(string(policy.Template)),
					"ttl":                  llx.IntDataDefault(policy.Ttl, 0),
					"healthCheckMonitorId": llx.StringDataPtr(policy.HealthCheckMonitorId),
					"state":                llx.StringData(string(policy.LifecycleState)),
					"created":              sdkTimeData(policy.TimeCreated),
					"freeformTags":         llx.MapData(strMapToAny(policy.FreeformTags), types.String),
					"definedTags":          llx.MapData(definedTagsToAny(policy.DefinedTags), types.Any),
				})
				if err != nil {
					return nil, err
				}
				mqlPolicyTyped := mqlPolicy.(*mqlOciDnsSteeringPolicy)
				mqlPolicyTyped.cacheCompartmentID = stringValue(policy.CompartmentId)
				res = append(res, mqlPolicyTyped)
			}

			return res, nil
		})
	if err != nil {
		return nil, err
	}
	return ociDedupeByID(items), nil
}

type mqlOciDnsZoneInternal struct {
	cacheCompartmentID string
	cacheRegion        string
	cacheScope         dns.ScopeEnum
}

func (o *mqlOciDnsZone) id() (string, error) {
	return "oci.dns.zone/" + o.Id.Data, nil
}

func (o *mqlOciDnsZone) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}

// records fetches the zone's resource records on demand.
//
// This is a per-zone call, so it stays computed rather than being prefetched
// with the listing: a query that only asks which zones have DNSSEC disabled
// should not pull every record in the tenancy to answer it.
func (o *mqlOciDnsZone) records() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	client, err := conn.DnsClient(o.cacheRegion)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	records, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]dns.Record, *string, error) {
		response, err := client.GetZoneRecords(ctx, dns.GetZoneRecordsRequest{
			ZoneNameOrId: new(o.Id.Data),
			// A private zone is only addressable within its scope, and the
			// service rejects the request without it.
			Scope: dns.GetZoneRecordsScopeEnum(o.cacheScope),
			Page:  page,
		})
		if err != nil {
			return nil, nil, err
		}
		return response.Items, response.OpcNextPage, nil
	})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(records))
	for i := range records {
		record := records[i]

		// recordHash uniquely identifies a record within a zone. Records have
		// no OCID, and domain+type is not unique because a name can carry
		// several values of the same type.
		key := stringValue(record.RecordHash)
		if key == "" {
			key = stringValue(record.Domain) + "/" + stringValue(record.Rtype) + "/" + stringValue(record.Rdata)
		}

		mqlRecord, err := CreateResource(o.MqlRuntime, "oci.dns.record", map[string]*llx.RawData{
			"__id":         llx.StringData(o.Id.Data + "/record/" + key),
			"domain":       llx.StringDataPtr(record.Domain),
			"rtype":        llx.StringDataPtr(record.Rtype),
			"rdata":        llx.StringDataPtr(record.Rdata),
			"ttl":          llx.IntDataDefault(record.Ttl, 0),
			"isProtected":  llx.BoolData(boolValue(record.IsProtected)),
			"rrsetVersion": llx.StringDataPtr(record.RrsetVersion),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRecord)
	}

	return res, nil
}

type mqlOciDnsSteeringPolicyInternal struct {
	cacheCompartmentID string
}

func (o *mqlOciDnsSteeringPolicy) id() (string, error) {
	return "oci.dns.steeringPolicy/" + o.Id.Data, nil
}

func (o *mqlOciDnsSteeringPolicy) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}
