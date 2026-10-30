// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	pam "cloud.google.com/go/privilegedaccessmanager/apiv1"
	"cloud.google.com/go/privilegedaccessmanager/apiv1/privilegedaccessmanagerpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	googleoauth "golang.org/x/oauth2/google"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectPrivilegedAccessManagerServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) privilegedAccessManager() (*mqlGcpProjectPrivilegedAccessManagerService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.privilegedAccessManagerService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_pam)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectPrivilegedAccessManagerService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_pam).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectPrivilegedAccessManagerService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	if args == nil {
		args = make(map[string]*llx.RawData)
	}
	args["projectId"] = llx.StringData(conn.ResourceID())
	return args, nil, nil
}

func (g *mqlGcpProjectPrivilegedAccessManagerService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.privilegedAccessManagerService", g.ProjectId.Data), nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectPrivilegedAccessManagerService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_pam)
}

func (g *mqlGcpProjectPrivilegedAccessManagerServiceEntitlement) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectPrivilegedAccessManagerServiceGrant) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// pamCredentials returns credentials scoped for the Privileged Access Manager
// API.
//
// Only the credentials are shared, not the client: the permissions extractor
// tracks client variables per function, so a helper that returned the client
// would hide pam.NewClient from every caller and silently drop their permissions
// from the manifest. Each lister constructs the client itself for that reason.
func (g *mqlGcpProjectPrivilegedAccessManagerService) pamCredentials() (*googleoauth.Credentials, error) {
	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return conn.Credentials(pam.DefaultAuthScopes()...)
}

// entitlements lists the project's entitlements.
//
// Entitlements attached to a resource-manager container live under the global
// location; the regional locations carry entitlements for regional resources,
// which are not addressable from a project-scoped listing.
func (g *mqlGcpProjectPrivilegedAccessManagerService) entitlements() ([]any, error) {
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

	creds, err := g.pamCredentials()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := pam.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListEntitlements(ctx, &privilegedaccessmanagerpb.ListEntitlementsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global", projectId),
	})

	res := []any{}
	for {
		e, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				// break rather than discard: keep the entitlements already returned.
				log.Warn().Err(err).Str("project", projectId).Msg("could not list all Privileged Access Manager entitlements")
				break
			}
			return nil, err
		}

		eligibleUsers, err := protoToDictSlice(e.GetEligibleUsers())
		if err != nil {
			return nil, err
		}
		approvalWorkflow, err := protoToDict(e.GetApprovalWorkflow())
		if err != nil {
			return nil, err
		}
		privilegedAccess, err := protoToDict(e.GetPrivilegedAccess())
		if err != nil {
			return nil, err
		}
		requesterJustificationConfig, err := protoToDict(e.GetRequesterJustificationConfig())
		if err != nil {
			return nil, err
		}
		additionalNotificationTargets, err := protoToDict(e.GetAdditionalNotificationTargets())
		if err != nil {
			return nil, err
		}

		maxRequestDuration := ""
		if e.GetMaxRequestDuration() != nil {
			maxRequestDuration = e.GetMaxRequestDuration().AsDuration().String()
		}

		grantedRoles, grantedResource := pamGrantedAccess(e.GetPrivilegedAccess())

		mqlEntitlement, err := CreateResource(g.MqlRuntime, "gcp.project.privilegedAccessManagerService.entitlement", map[string]*llx.RawData{
			"name":                          llx.StringData(e.GetName()),
			"state":                         llx.StringData(e.GetState().String()),
			"eligiblePrincipals":            llx.ArrayData(pamEligiblePrincipals(e.GetEligibleUsers()), types.String),
			"grantedRoles":                  llx.ArrayData(grantedRoles, types.String),
			"grantedResource":               llx.StringData(grantedResource),
			"requiresApproval":              llx.BoolData(e.GetApprovalWorkflow() != nil),
			"eligibleUsers":                 llx.ArrayData(eligibleUsers, types.Dict),
			"approvalWorkflow":              llx.DictData(approvalWorkflow),
			"privilegedAccess":              llx.DictData(privilegedAccess),
			"maxRequestDuration":            llx.StringData(maxRequestDuration),
			"requesterJustificationConfig":  llx.DictData(requesterJustificationConfig),
			"additionalNotificationTargets": llx.DictData(additionalNotificationTargets),
			"etag":                          llx.StringData(e.GetEtag()),
			"createTime":                    llx.TimeDataPtr(timestampAsTimePtr(e.GetCreateTime())),
			"updateTime":                    llx.TimeDataPtr(timestampAsTimePtr(e.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlEntitlement)
	}

	return res, nil
}

// pamEligiblePrincipals flattens the eligible-user access control entries into
// the member list an IAM audit compares against.
func pamEligiblePrincipals(entries []*privilegedaccessmanagerpb.AccessControlEntry) []any {
	seen := map[string]struct{}{}
	for _, entry := range entries {
		for _, p := range entry.GetPrincipals() {
			if p != "" {
				seen[p] = struct{}{}
			}
		}
	}
	return sortedAnySet(seen)
}

// pamGrantedAccess extracts the roles an elevation confers and the resource they
// are applied to. Only the IAM access form carries roles; other forms return no
// roles rather than a misleading empty-but-set answer.
func pamGrantedAccess(access *privilegedaccessmanagerpb.PrivilegedAccess) (roles []any, resource string) {
	iamAccess := access.GetGcpIamAccess()
	if iamAccess == nil {
		return []any{}, ""
	}
	seen := map[string]struct{}{}
	for _, rb := range iamAccess.GetRoleBindings() {
		if r := rb.GetRole(); r != "" {
			seen[r] = struct{}{}
		}
	}
	return sortedAnySet(seen), iamAccess.GetResource()
}

// grants lists the elevations requested against the project's entitlements, the
// record of privilege actually taken.
func (g *mqlGcpProjectPrivilegedAccessManagerService) grants() ([]any, error) {
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

	creds, err := g.pamCredentials()
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	client, err := pam.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	// A grant is a child of an entitlement, and ListGrants takes an entitlement
	// parent. The "-" wildcard collects grants across every entitlement in the
	// location, so one call covers the project.
	it := client.ListGrants(ctx, &privilegedaccessmanagerpb.ListGrantsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/global/entitlements/-", projectId),
	})

	res := []any{}
	for {
		grant, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			if isSkippable(err) {
				// break rather than discard: keep the grants already returned.
				log.Warn().Err(err).Str("project", projectId).Msg("could not list all Privileged Access Manager grants")
				break
			}
			return nil, err
		}

		justification, err := protoToDict(grant.GetJustification())
		if err != nil {
			return nil, err
		}
		timeline, err := protoToDict(grant.GetTimeline())
		if err != nil {
			return nil, err
		}
		privilegedAccess, err := protoToDict(grant.GetPrivilegedAccess())
		if err != nil {
			return nil, err
		}
		auditTrail, err := protoToDict(grant.GetAuditTrail())
		if err != nil {
			return nil, err
		}

		requestedDuration := ""
		if grant.GetRequestedDuration() != nil {
			requestedDuration = grant.GetRequestedDuration().AsDuration().String()
		}

		mqlGrant, err := CreateResource(g.MqlRuntime, "gcp.project.privilegedAccessManagerService.grant", map[string]*llx.RawData{
			"name":                      llx.StringData(grant.GetName()),
			"requester":                 llx.StringData(grant.GetRequester()),
			"requestedDuration":         llx.StringData(requestedDuration),
			"state":                     llx.StringData(grant.GetState().String()),
			"externallyModified":        llx.BoolData(grant.GetExternallyModified()),
			"justification":             llx.DictData(justification),
			"timeline":                  llx.DictData(timeline),
			"privilegedAccess":          llx.DictData(privilegedAccess),
			"auditTrail":                llx.DictData(auditTrail),
			"additionalEmailRecipients": llx.ArrayData(convert.SliceAnyToInterface(grant.GetAdditionalEmailRecipients()), types.String),
			"createTime":                llx.TimeDataPtr(timestampAsTimePtr(grant.GetCreateTime())),
			"updateTime":                llx.TimeDataPtr(timestampAsTimePtr(grant.GetUpdateTime())),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlGrant)
	}

	return res, nil
}
