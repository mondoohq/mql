// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"

	iampb "cloud.google.com/go/iam/apiv1/iampb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	agentidentity "google.golang.org/api/agentidentity/v1"
	"google.golang.org/api/option"
	"google.golang.org/genproto/googleapis/type/expr"
)

type mqlGcpProjectAgentIdentityServiceInternal struct {
	serviceGate
	locationsOnce sync.Once
	locations     []string
	locationsErr  error
}

func (g *mqlGcpProject) agentIdentity() (*mqlGcpProjectAgentIdentityService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.agentIdentityService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	serviceEnabled, err := g.isServiceEnabled(service_agentidentity)
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectAgentIdentityService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_agentidentity).Msg("gcp service is not enabled, skipping")
	}
	return svc, nil
}

func initGcpProjectAgentIdentityService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return map[string]*llx.RawData{"projectId": llx.StringData(conn.ResourceID())}, nil, nil
}

func (g *mqlGcpProjectAgentIdentityService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/agentIdentityService", g.ProjectId.Data), nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectAgentIdentityService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_agentidentity)
}

// listLocations returns the project's locations to list in, read once per
// service resource.
func (g *mqlGcpProjectAgentIdentityService) listLocations() ([]string, error) {
	g.locationsOnce.Do(func() {
		conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
		client, err := conn.Client(agentidentity.CloudPlatformScope)
		if err != nil {
			g.locationsErr = err
			return
		}
		ctx := context.Background()
		svc, err := agentidentity.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			g.locationsErr = err
			return
		}
		g.locationsErr = svc.Projects.Locations.List("projects/"+g.ProjectId.Data).Pages(ctx, func(page *agentidentity.ListLocationsResponse) error {
			for _, l := range page.Locations {
				if l != nil && l.Name != "" {
					g.locations = append(g.locations, l.Name)
				}
			}
			return nil
		})
	})
	return g.locations, g.locationsErr
}

// authProviderType names the credential kind an auth provider uses, by the
// API's own field name. Only the kind is read; the parameters hold the API
// key and client secrets, which are never reported.
func authProviderType(p *agentidentity.AuthProviderTypeParams) string {
	switch {
	case p == nil:
		return ""
	case p.ApiKey != nil:
		return "apiKey"
	case p.TwoLeggedOauth != nil:
		return "twoLeggedOauth"
	case p.ThreeLeggedOauth != nil:
		return "threeLeggedOauth"
	case p.ConnectorReferenceAuthProvider != nil:
		return "connectorReferenceAuthProvider"
	case p.GeAuthProvider != nil:
		return "geAuthProvider"
	case p.XaaAuthProvider != nil:
		return "xaaAuthProvider"
	}
	return ""
}

func (g *mqlGcpProjectAgentIdentityService) authProviders() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	locations, err := g.listLocations()
	if err != nil {
		return listRefusal(err, "cannot list agent identity locations", "agentidentity.locations.list")
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(agentidentity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := agentidentity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return listAcrossAgentLocations("authProviders", locations, func(location string) ([]any, error) {
		var items []any
		err := svc.Projects.Locations.AuthProviders.List(location).Pages(ctx, func(page *agentidentity.ListAuthProvidersResponse) error {
			for _, ap := range page.AuthProviders {
				if ap == nil {
					continue
				}
				r, err := CreateResource(g.MqlRuntime, "gcp.project.agentIdentityService.authProvider", map[string]*llx.RawData{
					"name":          llx.StringData(ap.Name),
					"description":   llx.StringData(ap.Description),
					"state":         llx.StringData(ap.State),
					"type":          llx.StringData(authProviderType(ap.AuthProviderTypeParams)),
					"allowedScopes": llx.ArrayData(convert.SliceAnyToInterface(ap.AllowedScopes), types.String),
					"blockedScopes": llx.ArrayData(convert.SliceAnyToInterface(ap.BlockedScopes), types.String),
					"workloadIds":   llx.ArrayData(convert.SliceAnyToInterface(ap.WorkloadIds), types.String),
					"deleted":       llx.BoolData(ap.Deleted),
					"expireTime":    llx.TimeDataPtr(parseTime(ap.ExpireTime)),
					"labels":        llx.MapData(convert.MapToInterfaceMap(ap.Labels), types.String),
					"createdAt":     llx.TimeDataPtr(parseTime(ap.CreateTime)),
					"updatedAt":     llx.TimeDataPtr(parseTime(ap.UpdateTime)),
				})
				if err != nil {
					return err
				}
				items = append(items, r)
			}
			return nil
		})
		if err != nil && isSkippable(err) {
			return nil, nil
		}
		return items, err
	})
}

func (g *mqlGcpProjectAgentIdentityServiceAuthProvider) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectAgentIdentityServiceAuthProvider) iamPolicy() ([]any, error) {
	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	name := g.Name.Data
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(agentidentity.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := agentidentity.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	policy, err := svc.Projects.Locations.AuthProviders.GetIamPolicy(name).
		OptionsRequestedPolicyVersion(3).Context(ctx).Do()
	if err != nil {
		return listRefusal(err, "cannot read agent identity auth provider IAM policy", "agentidentity.authProviders.getIamPolicy")
	}
	return iampbBindingsToMql(g.MqlRuntime, name, agentIdentityBindingsToIampb(policy.Bindings))
}

// public is null when the IAM policy could not be read: a refusal must not
// read as "not public".
func (g *mqlGcpProjectAgentIdentityServiceAuthProvider) public() (bool, error) {
	bindings := g.GetIamPolicy()
	if bindings.Error != nil {
		return false, bindings.Error
	}
	if bindings.Data == nil {
		g.Public.State = plugin.StateIsSet | plugin.StateIsNull
		return false, nil
	}
	return iamPolicyHasPublicMember(bindings.Data)
}

// agentIdentityBindingsToIampb converts the Agent Identity REST bindings to
// the iampb shape the shared binding mapper takes.
func agentIdentityBindingsToIampb(bindings []*agentidentity.Binding) []*iampb.Binding {
	res := make([]*iampb.Binding, 0, len(bindings))
	for _, b := range bindings {
		if b == nil {
			continue
		}
		ib := &iampb.Binding{Role: b.Role, Members: b.Members}
		if c := b.Condition; c != nil {
			ib.Condition = &expr.Expr{Title: c.Title, Expression: c.Expression, Description: c.Description}
		}
		res = append(res, ib)
	}
	return res
}

// resourceNameWithoutProject drops the projects/{project}/ prefix of a
// resource name, so a name carrying the project number matches one carrying
// the project ID.
func resourceNameWithoutProject(name string) string {
	parts := strings.SplitN(name, "/", 3)
	if len(parts) == 3 && parts[0] == "projects" {
		return parts[2]
	}
	return name
}
