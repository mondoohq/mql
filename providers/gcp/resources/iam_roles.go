// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"
	"strings"

	admin "cloud.google.com/go/iam/admin/apiv1"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
	adminpb "google.golang.org/genproto/googleapis/iam/admin/v1"
)

func (g *mqlGcpProjectIamService) roles() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}

	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(admin.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	adminSvc, err := admin.NewIamClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer adminSvc.Close()

	var roles []any
	it := adminSvc.ListRolesIter(ctx, &adminpb.ListRolesRequest{
		Parent:      fmt.Sprintf("projects/%s", projectId),
		View:        adminpb.RoleView_FULL,
		ShowDeleted: true,
	})
	for {
		r, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		permissions := make([]any, 0, len(r.IncludedPermissions))
		for _, p := range r.IncludedPermissions {
			permissions = append(permissions, p)
		}

		mqlRole, err := CreateResource(g.MqlRuntime, "gcp.project.iamService.role", map[string]*llx.RawData{
			"projectId":           llx.StringData(projectId),
			"name":                llx.StringData(r.Name),
			"title":               llx.StringData(r.Title),
			"description":         llx.StringData(r.Description),
			"stage":               llx.StringData(r.Stage.String()),
			"includedPermissions": llx.ArrayData(permissions, types.String),
			"deleted":             llx.BoolData(r.Deleted),
		})
		if err != nil {
			return nil, err
		}
		roles = append(roles, mqlRole)
	}
	return roles, nil
}

func (g *mqlGcpProjectIamServiceRole) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpOrganizationRole) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// serviceAccountImpersonationPermissions are the IAM permissions that let a
// principal act as a service account and thereby escalate privilege.
var serviceAccountImpersonationPermissions = map[string]struct{}{
	"iam.serviceAccounts.actAs":              {},
	"iam.serviceAccounts.getAccessToken":     {},
	"iam.serviceAccounts.signBlob":           {},
	"iam.serviceAccounts.signJwt":            {},
	"iam.serviceAccounts.getOpenIdToken":     {},
	"iam.serviceAccounts.implicitDelegation": {},
}

func roleGrantsIamPolicyManagement(perms *plugin.TValue[[]any]) (bool, error) {
	if perms.Error != nil {
		return false, perms.Error
	}
	for _, p := range perms.Data {
		if s, ok := p.(string); ok && strings.HasSuffix(s, ".setIamPolicy") {
			return true, nil
		}
	}
	return false, nil
}

func roleGrantsServiceAccountImpersonation(perms *plugin.TValue[[]any]) (bool, error) {
	if perms.Error != nil {
		return false, perms.Error
	}
	for _, p := range perms.Data {
		if s, ok := p.(string); ok {
			if _, found := serviceAccountImpersonationPermissions[s]; found {
				return true, nil
			}
		}
	}
	return false, nil
}

func (g *mqlGcpProjectIamServiceRole) grantsIamPolicyManagement() (bool, error) {
	return roleGrantsIamPolicyManagement(&g.IncludedPermissions)
}

func (g *mqlGcpProjectIamServiceRole) grantsServiceAccountImpersonation() (bool, error) {
	return roleGrantsServiceAccountImpersonation(&g.IncludedPermissions)
}

func (g *mqlGcpOrganizationRole) grantsIamPolicyManagement() (bool, error) {
	return roleGrantsIamPolicyManagement(&g.IncludedPermissions)
}

func (g *mqlGcpOrganizationRole) grantsServiceAccountImpersonation() (bool, error) {
	return roleGrantsServiceAccountImpersonation(&g.IncludedPermissions)
}

func (g *mqlGcpOrganization) customRoles() ([]any, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	// g.Id.Data is already in "organizations/{id}" format
	orgParent := g.Id.Data
	orgNumericId := strings.TrimPrefix(orgParent, "organizations/")

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(admin.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	adminSvc, err := admin.NewIamClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer adminSvc.Close()

	var roles []any
	it := adminSvc.ListRolesIter(ctx, &adminpb.ListRolesRequest{
		Parent:      orgParent,
		View:        adminpb.RoleView_FULL,
		ShowDeleted: true,
	})
	for {
		r, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		permissions := make([]any, 0, len(r.IncludedPermissions))
		for _, p := range r.IncludedPermissions {
			permissions = append(permissions, p)
		}

		mqlRole, err := CreateResource(g.MqlRuntime, "gcp.organization.role", map[string]*llx.RawData{
			"organizationId":      llx.StringData(orgNumericId),
			"name":                llx.StringData(r.Name),
			"title":               llx.StringData(r.Title),
			"description":         llx.StringData(r.Description),
			"stage":               llx.StringData(r.Stage.String()),
			"includedPermissions": llx.ArrayData(permissions, types.String),
			"deleted":             llx.BoolData(r.Deleted),
		})
		if err != nil {
			return nil, err
		}
		roles = append(roles, mqlRole)
	}
	return roles, nil
}
