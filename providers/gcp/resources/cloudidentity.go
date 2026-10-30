// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	cloudidentity "google.golang.org/api/cloudidentity/v1"
	"google.golang.org/api/option"
)

func (g *mqlGcpCloudIdentityGroup) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpCloudIdentityMembership) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpCloudIdentityGroupSecuritySettings) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpCloudIdentityGroup) securitySettings() (*mqlGcpCloudIdentityGroupSecuritySettings, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	groupName := g.Name.Data
	if groupName == "" {
		g.SecuritySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		g.SecuritySettings.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	client, err := conn.Client(cloudidentity.CloudIdentityGroupsReadonlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	cloudIdentitySvc, err := cloudidentity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	// read_mask selects which settings the API returns; member_restriction is
	// the only member-governance surface exposed here.
	settings, err := cloudIdentitySvc.Groups.GetSecuritySettings(groupName + "/securitySettings").
		ReadMask("memberRestriction").Context(ctx).Do()
	if err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("group", groupName).Msg("could not get Cloud Identity group security settings")
			g.SecuritySettings.State = plugin.StateIsSet | plugin.StateIsNull
			return nil, nil
		}
		return nil, err
	}

	query := ""
	evaluationState := ""
	if settings.MemberRestriction != nil {
		query = settings.MemberRestriction.Query
		if settings.MemberRestriction.Evaluation != nil {
			evaluationState = settings.MemberRestriction.Evaluation.State
		}
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.cloudIdentity.group.securitySettings", map[string]*llx.RawData{
		"name":                             llx.StringData(settings.Name),
		"memberRestrictionQuery":           llx.StringData(query),
		"memberRestrictionEvaluationState": llx.StringData(evaluationState),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpCloudIdentityGroupSecuritySettings), nil
}

// cloudIdentityGroups lists the Cloud Identity / Workspace groups for the
// organization. Unlike the project-level accessors there is no serviceusage
// service-enabled pre-check: service enablement is a per-project concept and
// this resource is organization-scoped, so a disabled API instead surfaces as
// a 403/404 that isSkippable handles below.
func (g *mqlGcpOrganization) cloudIdentityGroups() ([]any, error) {
	if g.CustomerId.Error != nil {
		return nil, g.CustomerId.Error
	}
	customerId := g.CustomerId.Data
	if customerId == "" {
		return nil, nil
	}

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil
	}
	client, err := conn.Client(cloudidentity.CloudIdentityGroupsReadonlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	cloudIdentitySvc, err := cloudidentity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	call := cloudIdentitySvc.Groups.List().Parent("customers/" + customerId).View("FULL")
	if err := call.Pages(ctx, func(page *cloudidentity.ListGroupsResponse) error {
		for _, group := range page.Groups {
			email := ""
			if group.GroupKey != nil {
				email = group.GroupKey.Id
			}

			mqlGroup, err := CreateResource(g.MqlRuntime, "gcp.cloudIdentity.group", map[string]*llx.RawData{
				"name":        llx.StringData(group.Name),
				"id":          llx.StringData(parseResourceName(group.Name)),
				"email":       llx.StringData(email),
				"displayName": llx.StringData(group.DisplayName),
				"description": llx.StringData(group.Description),
				"labels":      llx.MapData(convert.MapToInterfaceMap(group.Labels), types.String),
				"created":     llx.TimeDataPtr(parseTime(group.CreateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlGroup)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Msg("could not list Cloud Identity groups")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpCloudIdentityGroup) memberships() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	groupName := g.Name.Data

	conn, ok := g.MqlRuntime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil
	}
	client, err := conn.Client(cloudidentity.CloudIdentityGroupsReadonlyScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	cloudIdentitySvc, err := cloudidentity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	res := []any{}
	call := cloudIdentitySvc.Groups.Memberships.List(groupName).View("FULL")
	if err := call.Pages(ctx, func(page *cloudidentity.ListMembershipsResponse) error {
		for _, m := range page.Memberships {
			memberKey := ""
			if m.PreferredMemberKey != nil {
				memberKey = m.PreferredMemberKey.Id
			}

			roles := make([]any, 0, len(m.Roles))
			for _, role := range m.Roles {
				if role != nil {
					roles = append(roles, role.Name)
				}
			}

			mqlMembership, err := CreateResource(g.MqlRuntime, "gcp.cloudIdentity.membership", map[string]*llx.RawData{
				"name":            llx.StringData(m.Name),
				"memberKey":       llx.StringData(memberKey),
				"type":            llx.StringData(m.Type),
				"roles":           llx.ArrayData(roles, types.String),
				"deliverySetting": llx.StringData(m.DeliverySetting),
				"created":         llx.TimeDataPtr(parseTime(m.CreateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlMembership)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Warn().Err(err).Str("group", groupName).Msg("could not list Cloud Identity group memberships")
			return nil, nil
		}
		return nil, err
	}
	return res, nil
}
