// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"time"

	"github.com/oracle/oci-go-sdk/v65/identity"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/oci/connection"
)

// tagDefaults lists the tag defaults of every compartment the filters admit.
// ListTagDefaults answers for one compartment and does not include the
// defaults a compartment inherits from its parents, so each compartment is
// asked about itself. IAM is global, so there is no region dimension.
func (o *mqlOciIdentity) tagDefaults() ([]any, error) {
	return ociCollectGlobal(o.MqlRuntime, func(ctx context.Context, compartmentID string) ([]any, error) {
		return tagDefaultsIn(ctx, o.MqlRuntime, compartmentID)
	})
}

// tagDefaults lists the tag defaults of the root compartment, which apply to
// the whole tenancy. They are the tenancy's own configuration, so they are
// read whatever the compartment filters select, as retentionPeriod is: a scan
// narrowed to one compartment is still governed by them.
func (o *mqlOciTenancy) tagDefaults() ([]any, error) {
	conn := o.MqlRuntime.Connection.(*connection.OciConnection)
	return tagDefaultsIn(context.Background(), o.MqlRuntime, conn.TenantID())
}

// tagDefaultsIn lists the tag defaults defined in one compartment.
func tagDefaultsIn(ctx context.Context, runtime *plugin.Runtime, compartmentID string) ([]any, error) {
	conn := runtime.Connection.(*connection.OciConnection)
	svc, err := conn.IdentityClient()
	if err != nil {
		return nil, err
	}

	items, err := ociPaginate(ctx, func(ctx context.Context, page *string) ([]identity.TagDefaultSummary, *string, error) {
		response, err := svc.ListTagDefaults(ctx, identity.ListTagDefaultsRequest{
			CompartmentId: new(compartmentID),
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

	res := make([]any, 0, len(items))
	for i := range items {
		args, compartment := tagDefaultArgs(items[i])
		mqlTagDefault, err := createOciResourceInCompartment(runtime, "oci.identity.tagDefault", compartment, args)
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTagDefault)
	}
	return res, nil
}

// tagDefaultArgs maps a tag default to the resource's fields and returns the
// compartment it belongs to.
func tagDefaultArgs(td identity.TagDefaultSummary) (map[string]*llx.RawData, string) {
	var created *time.Time
	if td.TimeCreated != nil {
		created = &td.TimeCreated.Time
	}

	return map[string]*llx.RawData{
		"id":                llx.StringDataPtr(td.Id),
		"tagNamespaceId":    llx.StringDataPtr(td.TagNamespaceId),
		"tagDefinitionId":   llx.StringDataPtr(td.TagDefinitionId),
		"tagDefinitionName": llx.StringDataPtr(td.TagDefinitionName),
		"value":             llx.StringDataPtr(td.Value),
		"isRequired":        llx.BoolDataPtr(td.IsRequired),
		"state":             llx.StringData(string(td.LifecycleState)),
		"created":           llx.TimeDataPtr(created),
	}, stringValue(td.CompartmentId)
}

type mqlOciIdentityTagDefaultInternal struct {
	ociCompartmentRef
}

func (o *mqlOciIdentityTagDefault) id() (string, error) {
	return "oci.identity.tagDefault/" + o.Id.Data, nil
}

func (o *mqlOciIdentityTagDefault) compartment() (*mqlOciCompartment, error) {
	return resolveOciCompartment(o.MqlRuntime, o.cacheCompartmentID, &o.Compartment)
}
