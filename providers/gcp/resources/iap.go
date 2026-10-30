// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strconv"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	iap "cloud.google.com/go/iap/apiv1"
	"cloud.google.com/go/iap/apiv1/iappb"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) iap() (*mqlGcpProjectIapService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.iapService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectIapService), nil
}

func (g *mqlGcpProjectIapService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/iapService", g.ProjectId.Data), nil
}

// iamPolicy returns the IAM bindings on the project-wide IAP web resource,
// which governs who is allowed to pass through Identity-Aware Proxy to the
// project's IAP-secured web resources.
func (g *mqlGcpProjectIapService) iamPolicy() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(iap.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iap.NewIdentityAwareProxyAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	resource := fmt.Sprintf("projects/%s/iap_web", projectId)
	policy, err := client.GetIamPolicy(ctx, &iampb.GetIamPolicyRequest{Resource: resource, Options: &iampb.GetPolicyOptions{RequestedPolicyVersion: 3}})
	if err != nil {
		return nil, err
	}

	res := make([]any, 0, len(policy.Bindings))
	// Index-suffixed, matching every other IAM binding creator in the provider.
	// An IAM v3 policy may carry several bindings for the same role that differ
	// only by condition -- and this call asks for version 3 -- so keying on the
	// role alone silently collapses them onto the first one.
	for i, b := range policy.Bindings {
		mqlBinding, err := CreateResource(g.MqlRuntime, "gcp.resourcemanager.binding", map[string]*llx.RawData{
			"id":                   llx.StringData(resource + "-" + strconv.Itoa(i)),
			"role":                 llx.StringData(b.Role),
			"members":              llx.ArrayData(convert.SliceAnyToInterface(b.Members), types.String),
			"conditionTitle":       llx.StringData(b.GetCondition().GetTitle()),
			"conditionExpression":  llx.StringData(b.GetCondition().GetExpression()),
			"conditionDescription": llx.StringData(b.GetCondition().GetDescription()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBinding)
	}
	return res, nil
}

func (g *mqlGcpProjectIapService) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

// settings returns the access and application settings for the project-wide
// iap_web resource, including the reauth policy used to audit whether
// IAP-fronted apps require periodic re-authentication.
func (g *mqlGcpProjectIapService) settings() (any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(iap.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iap.NewIdentityAwareProxyAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	settings, err := client.GetIapSettings(ctx, &iappb.GetIapSettingsRequest{
		Name: fmt.Sprintf("projects/%s/iap_web", projectId),
	})
	if err != nil {
		return nil, err
	}
	return protoToDict(settings)
}

func (g *mqlGcpProjectIapService) brands() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(iap.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iap.NewIdentityAwareProxyOAuthClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// ListBrands is not paginated — returns all brands at once
	resp, err := client.ListBrands(ctx, &iappb.ListBrandsRequest{
		Parent: fmt.Sprintf("projects/%s", projectId),
	})
	if err != nil {
		return nil, err
	}

	var res []any
	for _, brand := range resp.Brands {
		mqlBrand, err := CreateResource(g.MqlRuntime, "gcp.project.iapService.brand", map[string]*llx.RawData{
			"projectId":        llx.StringData(projectId),
			"name":             llx.StringData(brand.Name),
			"applicationTitle": llx.StringData(brand.ApplicationTitle),
			"supportEmail":     llx.StringData(brand.SupportEmail),
			"orgInternalOnly":  llx.BoolData(brand.OrgInternalOnly),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlBrand)
	}

	return res, nil
}

func (g *mqlGcpProjectIapServiceBrand) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/iapService.brand/%s", g.ProjectId.Data, g.Name.Data), nil
}

func (g *mqlGcpProjectIapServiceIdentityAwareProxyClient) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// clients lists the OAuth clients registered under this brand. The client
// secret is intentionally not exposed; only the identity (name, displayName)
// is surfaced for credential-hygiene audits.
func (g *mqlGcpProjectIapServiceBrand) clients() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	brandName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(iap.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iap.NewIdentityAwareProxyOAuthClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListIdentityAwareProxyClients(ctx, &iappb.ListIdentityAwareProxyClientsRequest{
		Parent: brandName,
	})

	var res []any
	for {
		c, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		mqlClient, err := CreateResource(g.MqlRuntime, "gcp.project.iapService.identityAwareProxyClient", map[string]*llx.RawData{
			"name":        llx.StringData(c.GetName()),
			"displayName": llx.StringData(c.GetDisplayName()),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlClient)
	}
	return res, nil
}

func (g *mqlGcpProjectIapService) tunnelDestGroups() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(iap.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := iap.NewIdentityAwareProxyAdminClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListTunnelDestGroups(ctx, &iappb.ListTunnelDestGroupsRequest{
		Parent: fmt.Sprintf("projects/%s/iap_tunnel/locations/-", projectId),
	})

	var res []any
	for {
		group, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		cidrs := make([]any, len(group.Cidrs))
		for i, c := range group.Cidrs {
			cidrs[i] = c
		}
		fqdns := make([]any, len(group.Fqdns))
		for i, f := range group.Fqdns {
			fqdns[i] = f
		}

		mqlGroup, err := CreateResource(g.MqlRuntime, "gcp.project.iapService.tunnelDestGroup", map[string]*llx.RawData{
			"projectId": llx.StringData(projectId),
			"name":      llx.StringData(group.Name),
			"cidrs":     llx.ArrayData(cidrs, types.String),
			"fqdns":     llx.ArrayData(fqdns, types.String),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGroup)
	}

	return res, nil
}

func (g *mqlGcpProjectIapServiceTunnelDestGroup) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return fmt.Sprintf("gcp.project/%s/iapService.tunnelDestGroup/%s", g.ProjectId.Data, g.Name.Data), nil
}
