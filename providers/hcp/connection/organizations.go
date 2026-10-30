// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package connection

import (
	"context"

	org_service "github.com/hashicorp/hcp-sdk-go/clients/cloud-resource-manager/stable/2019-12-10/client/organization_service"
)

// firstOrganizationID returns the id of the first organization the service
// principal can access, used to anchor the connection when no --org-id was
// given.
func (c *HcpConnection) firstOrganizationID(ctx context.Context) (string, error) {
	client := org_service.New(c.transport, nil)
	params := org_service.NewOrganizationServiceListParams()
	params.SetContext(ctx)
	resp, err := client.OrganizationServiceList(params, nil)
	if err != nil {
		return "", err
	}
	if resp.Payload == nil || len(resp.Payload.Organizations) == 0 {
		return "", nil
	}
	return resp.Payload.Organizations[0].ID, nil
}
