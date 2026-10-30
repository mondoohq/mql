// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"maps"
	"time"

	"github.com/oracle/oci-go-sdk/v65/audit"
	"github.com/oracle/oci-go-sdk/v65/identity"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
	"go.mondoo.com/mql/types"
)

func (o *mqlOci) id() (string, error) {
	return "oci", nil
}

func (o *mqlOci) regions() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	regions, err := conn.GetRegions(context.Background())
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range regions {
		region := regions[i]

		homeRegion := false
		if region.IsHomeRegion != nil {
			homeRegion = *region.IsHomeRegion
		}

		mqlRegion, err := CreateResource(o.MqlRuntime, "oci.region", map[string]*llx.RawData{
			"id":           llx.StringDataPtr(region.RegionKey),
			"name":         llx.StringDataPtr(region.RegionName),
			"isHomeRegion": llx.BoolData(homeRegion),
			"status":       llx.StringData(string(region.Status)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlRegion)
	}

	return res, nil
}

func (o *mqlOciRegion) id() (string, error) {
	return "oci.region/" + o.Id.Data, nil
}

func (o *mqlOci) compartments() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	compartments, err := conn.GetCompartments(context.Background())
	if err != nil {
		return nil, err
	}

	res := []any{}
	for i := range compartments {
		mqlCompartment, err := CreateResource(o.MqlRuntime, "oci.compartment", ociCompartmentArgs(compartments[i]))
		if err != nil {
			return nil, err
		}
		res = append(res, mqlCompartment)
	}

	return res, nil
}

// ociCompartmentArgs builds the MQL fields for a compartment.
//
// Both the lister and initOciCompartment create oci.compartment, so a field
// added to one and forgotten in the other ships unset rather than null, which
// crosses the plugin boundary as a primitive with no type information. Building
// both from here makes the two impossible to drift apart.
func ociCompartmentArgs(compartment identity.Compartment) map[string]*llx.RawData {
	var created *time.Time
	if compartment.TimeCreated != nil {
		created = &compartment.TimeCreated.Time
	}

	return map[string]*llx.RawData{
		"id":          llx.StringDataPtr(compartment.Id),
		"name":        llx.StringDataPtr(compartment.Name),
		"description": llx.StringDataPtr(compartment.Description),
		"created":     llx.TimeDataPtr(created),
		"state":       llx.StringData(string(compartment.LifecycleState)),
		// Absent means the record was never asked the question, which is the
		// case for the tenancy root: it is read with GetCompartment rather
		// than as part of the subtree listing. A default false there would
		// report the root as walled off from its own owner, so it stays null.
		"isAccessible": llx.BoolDataPtr(compartment.IsAccessible),
		"freeformTags": llx.MapData(strMapToAny(compartment.FreeformTags), types.String),
		"definedTags":  llx.MapData(definedTagsToAny(compartment.DefinedTags), types.Any),
	}
}

// ociCompartmentUnreadable marks every field except id explicitly null, for a
// compartment the caller may see by OCID but not read.
//
// The field list is derived from ociCompartmentArgs rather than written out, so
// a field added there is nulled here without a second edit.
func ociCompartmentUnreadable(args map[string]*llx.RawData) {
	for name := range ociCompartmentArgs(identity.Compartment{}) {
		if name == "id" {
			continue
		}
		args[name] = llx.NilData
	}
}

func (o *mqlOciCompartment) id() (string, error) {
	return "oci.compartment/" + o.Id.Data, nil
}

// parent resolves the compartment this one sits directly beneath.
//
// The parent OCID is not part of the schema, so rather than caching it on every
// compartment it is read back from the tenancy tree the connection already
// holds. The tree is fetched once per connection and covers every compartment
// the lister produced, so the whole hierarchy resolves without a single extra
// call.
func (o *mqlOciCompartment) parent() (*mqlOciCompartment, error) {
	parentID, err := o.parentCompartmentID()
	if err != nil {
		return nil, err
	}

	parentID = ociCompartmentParent(o.Id.Data, parentID)
	if parentID == "" {
		o.Parent.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	return resolveOciCompartment(o.MqlRuntime, parentID, &o.Parent)
}

// ociCompartmentParent reports the OCID a compartment's parent field should
// resolve, given the compartment's own OCID and the parent the service
// reported for it.
//
// The tenancy root names itself as its own parent. It is the top of the tree,
// so the honest answer is that it has none - and resolving it would make a walk
// up the hierarchy loop forever rather than terminate at the root.
func ociCompartmentParent(self, reported string) string {
	if reported == "" || reported == self {
		return ""
	}
	return reported
}

// parentCompartmentID reports the OCID of the compartment this one sits under,
// or "" when there is none to report.
func (o *mqlOciCompartment) parentCompartmentID() (string, error) {
	id := o.Id.Data
	if id == "" {
		return "", nil
	}

	if lookup := ociCompartmentLookup(o.MqlRuntime); lookup != nil {
		compartment, err := lookup(id)
		if err != nil {
			// The tree could not be read at all. That is not an answer about
			// this compartment, so fall through to the direct read.
			log.Debug().Err(err).Str("compartment", id).
				Msg("oci compartment tree unavailable, reading parent directly")
		} else if compartment != nil {
			return stringValue(compartment.CompartmentId), nil
		}
	}

	conn, ok := o.MqlRuntime.Connection.(*connection.OciConnection)
	if !ok {
		return "", errors.New("oci.compartment requires an oci connection")
	}
	client, err := conn.IdentityClient()
	if err != nil {
		return "", err
	}
	resp, err := client.GetCompartment(context.Background(), identity.GetCompartmentRequest{
		CompartmentId: new(id),
	})
	if err != nil {
		if ociCompartmentInaccessible(err) {
			// A compartment reached by OCID from outside this tenancy, or one
			// deleted since it was listed. Its parent is unreadable rather
			// than absent, and null is the only way the field can say so.
			log.Debug().Err(err).Str("compartment", id).
				Msg("oci compartment parent not readable")
			return "", nil
		}
		return "", err
	}
	return stringValue(resp.Compartment.CompartmentId), nil
}

// isAccessible reports whether the caller may inspect resources in the
// compartment.
//
// The flag cannot be read off the compartment record the lister already holds:
// ListCompartments fills it in only when asked for the accessible subset, and
// that request also drops every compartment outside the subset, so the walk
// that enumerates the tree comes back with it absent on every entry. The
// answer is the intersection instead - present in the tree, present in the
// accessible listing - which the connection resolves once and memoizes.
func (o *mqlOciCompartment) isAccessible() (bool, error) {
	conn, ok := o.MqlRuntime.Connection.(*connection.OciConnection)
	if !ok {
		return false, errors.New("oci.compartment requires an oci connection")
	}

	// Reported rather than answered false. A throttled or denied Identity call
	// says nothing about this compartment, and "the caller cannot look inside"
	// is far too strong a thing to invent from a failed request.
	accessible, err := conn.AccessibleCompartmentIDs(context.Background())
	if err != nil {
		return false, err
	}

	// The accessible listing enumerates the subtree beneath the tenancy and so
	// never contains the root itself. The root's own record does carry the
	// flag, because it is read with GetCompartment rather than listed.
	if o.Id.Data == conn.TenantID() {
		return o.rootAccessible()
	}

	_, ok = accessible[o.Id.Data]
	return ok, nil
}

// rootAccessible reports the tenancy root's own accessibility, which comes
// from the direct read the tree fetch makes for it rather than from the
// subtree listing.
func (o *mqlOciCompartment) rootAccessible() (bool, error) {
	lookup := ociCompartmentLookup(o.MqlRuntime)
	if lookup == nil {
		o.IsAccessible.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	compartment, err := lookup(o.Id.Data)
	if err != nil {
		return false, err
	}
	if compartment == nil || compartment.IsAccessible == nil {
		o.IsAccessible.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return *compartment.IsAccessible, nil
}

func initOciCompartment(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 2 {
		return args, nil, nil
	}
	if args["id"] == nil || args["id"].Value == nil {
		return args, nil, nil
	}
	id, ok := args["id"].Value.(string)
	if !ok || id == "" {
		return args, nil, nil
	}

	// Checked rather than asserted: an init runs inside the executor's
	// goroutines, where a failed bare assertion ends the scan instead of the
	// field.
	conn, ok := runtime.Connection.(*connection.OciConnection)
	if !ok {
		return nil, nil, errors.New("oci.compartment requires an oci connection")
	}
	client, err := conn.IdentityClient()
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.GetCompartment(context.Background(), identity.GetCompartmentRequest{
		CompartmentId: new(id),
	})
	if err != nil {
		// Keep the resource identifiable by id when the caller can't read its
		// details (cross-tenancy / IAM denial), but set the remaining fields
		// explicitly null. Leaving them unset sends a primitive with no type
		// information across the plugin boundary, which surfaces client-side as
		// an unattributed coercion warning rather than a readable null.
		ociCompartmentUnreadable(args)
		return args, nil, nil
	}

	maps.Copy(args, ociCompartmentArgs(resp.Compartment))
	return args, nil, nil
}

func (o *mqlOciTenancy) id() (string, error) {
	return "oci.tenancy", nil
}

func initOciTenancy(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	conn := runtime.Connection.(*connection.OciConnection)

	tenancy, err := conn.Tenant(context.Background())
	if err != nil {
		return nil, nil, err
	}

	args["id"] = llx.StringDataPtr(tenancy.Id)
	args["name"] = llx.StringDataPtr(tenancy.Name)
	args["description"] = llx.StringDataPtr(tenancy.Description)
	args["freeformTags"] = llx.MapData(strMapToAny(tenancy.FreeformTags), types.String)
	args["definedTags"] = llx.MapData(definedTagsToAny(tenancy.DefinedTags), types.Any)

	return args, nil, nil
}

func (o *mqlOciTenancy) retentionPeriod() (*time.Time, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)

	ctx := context.Background()
	tenancy, err := conn.Tenant(ctx)
	if err != nil {
		return nil, err
	}

	if tenancy.HomeRegionKey == nil {
		return nil, errors.New("no home region set")
	}

	client, err := conn.AuditClient(*tenancy.HomeRegionKey)
	if err != nil {
		return nil, err
	}
	response, err := client.GetConfiguration(ctx, audit.GetConfigurationRequest{
		CompartmentId: tenancy.Id,
	})
	if err != nil {
		return nil, err
	}

	// retention period is in days
	if response.Configuration.RetentionPeriodDays == nil {
		return nil, nil
	}

	days := time.Duration(*response.Configuration.RetentionPeriodDays) * 24 * time.Hour

	ts := llx.DurationToTime(int64(days.Seconds()))
	return &ts, nil
}
