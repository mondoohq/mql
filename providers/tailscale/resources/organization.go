// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/tailscale/connection"
	tsclient "tailscale.com/client/tailscale/v2"
)

// organizationTailnetsScope is the OAuth scope the list endpoint requires.
const organizationTailnetsScope = "tailnets:read"

// classifyOrganizationTailnetsError turns a 403 from the organization
// tailnets endpoint into a Forbidden error naming the scope it needs. The
// endpoint only answers OAuth clients holding that scope, so a 403 is a
// refusal of the credential, not an absence of tailnets. Anything else is
// returned unchanged.
func classifyOrganizationTailnetsError(err error) error {
	if connection.APIStatusCode(err) == 403 {
		return llx.Forbidden(err, llx.WithPermissions(organizationTailnetsScope))
	}
	return err
}

// organizationTailnets lists the tailnets of the organization that owns the
// connected tailnet. The SDK requests the endpoint's first page, which holds up
// to 100 tailnets, and does not expose the pagination cursor.
func (t *mqlTailscale) organizationTailnets() ([]any, error) {
	conn := t.MqlRuntime.Connection.(*connection.TailscaleConnection)

	tailnets, err := conn.Client().Tailnets().List(context.Background())
	if err != nil {
		return nil, classifyOrganizationTailnetsError(err)
	}

	resources := make([]any, 0, len(tailnets))
	for i := range tailnets {
		resource, err := createTailscaleOrganizationTailnetResource(t.MqlRuntime, &tailnets[i])
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, nil
}

func createTailscaleOrganizationTailnetResource(runtime *plugin.Runtime, tn *tsclient.Tailnet) (plugin.Resource, error) {
	return CreateResource(runtime, "tailscale.organizationTailnet", map[string]*llx.RawData{
		"__id":        llx.StringData("tailscale/organizationTailnet/" + tn.ID),
		"id":          llx.StringData(tn.ID),
		"displayName": llx.StringData(tn.DisplayName),
		"orgId":       llx.StringData(tn.OrgID),
		"dnsName":     llx.StringData(tn.DNSName),
		"createdAt":   llx.TimeDataPtr(optionalTimeValue(tn.CreatedAt)),
	})
}
