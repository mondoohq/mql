// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	agentregistry "google.golang.org/api/agentregistry/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

const (
	service_agentregistry = "agentregistry.googleapis.com"
	service_agentidentity = "agentidentity.googleapis.com"
)

type mqlGcpProjectAgentRegistryServiceInternal struct {
	serviceGate
	locationsOnce sync.Once
	locations     []string
	locationsErr  error
}

func (g *mqlGcpProject) agentRegistry() (*mqlGcpProjectAgentRegistryService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.agentRegistryService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	serviceEnabled, err := g.isServiceEnabled(service_agentregistry)
	if err != nil {
		return nil, err
	}
	svc := res.(*mqlGcpProjectAgentRegistryService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_agentregistry).Msg("gcp service is not enabled, skipping")
	}
	return svc, nil
}

func initGcpProjectAgentRegistryService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}
	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}
	return map[string]*llx.RawData{"projectId": llx.StringData(conn.ResourceID())}, nil, nil
}

func (g *mqlGcpProjectAgentRegistryService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/agentRegistryService", g.ProjectId.Data), nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectAgentRegistryService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_agentregistry)
}

// listLocations returns the project's locations to list in, read once per
// service resource.
func (g *mqlGcpProjectAgentRegistryService) listLocations() ([]string, error) {
	g.locationsOnce.Do(func() {
		conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
		client, err := conn.Client(agentregistry.CloudPlatformScope)
		if err != nil {
			g.locationsErr = err
			return
		}
		ctx := context.Background()
		svc, err := agentregistry.NewService(ctx, option.WithHTTPClient(client))
		if err != nil {
			g.locationsErr = err
			return
		}
		g.locationsErr = svc.Projects.Locations.List("projects/"+g.ProjectId.Data).Pages(ctx, func(page *agentregistry.ListLocationsResponse) error {
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

// listAcrossAgentLocations runs fn for every location and merges the
// results. A location that fails is logged and skipped so the others are
// still reported; the error is returned only when every location failed.
func listAcrossAgentLocations(kind string, locations []string, fn func(location string) ([]any, error)) ([]any, error) {
	res := []any{}
	var firstErr error
	failed := 0
	for _, location := range locations {
		items, err := fn(location)
		if err != nil {
			failed++
			if firstErr == nil {
				firstErr = err
			}
			log.Warn().Err(err).Str("kind", kind).Str("location", location).
				Msg("location listing failed, continuing with the remaining locations")
			continue
		}
		res = append(res, items...)
	}
	if len(locations) > 0 && failed == len(locations) {
		return nil, firstErr
	}
	return res, nil
}

// rawAttributesToDict decodes registry attributes, each a JSON object, into a
// dict. An attribute that does not decode is kept as its raw string.
func rawAttributesToDict(attrs map[string]googleapi.RawMessage) map[string]any {
	res := make(map[string]any, len(attrs))
	for k, raw := range attrs {
		var v any
		if err := json.Unmarshal(raw, &v); err != nil {
			res[k] = string(raw)
			continue
		}
		res[k] = v
	}
	return res
}

// agentRegistryInterfaces maps interface URLs to their protocol binding.
func agentRegistryInterfaces(ifaces []*agentregistry.Interface) map[string]any {
	res := make(map[string]any, len(ifaces))
	for _, i := range ifaces {
		if i == nil || i.Url == "" {
			continue
		}
		res[i.Url] = i.ProtocolBinding
	}
	return res
}

// agentRegistryAgentProtocols returns the protocol types of an agent and the
// URLs of all their interfaces, each listed once in API order.
func agentRegistryAgentProtocols(protocols []*agentregistry.Protocol) ([]string, []string) {
	types, urls := []string{}, []string{}
	seenType, seenUrl := map[string]bool{}, map[string]bool{}
	for _, p := range protocols {
		if p == nil {
			continue
		}
		if p.Type != "" && !seenType[p.Type] {
			seenType[p.Type] = true
			types = append(types, p.Type)
		}
		for _, i := range p.Interfaces {
			if i != nil && i.Url != "" && !seenUrl[i.Url] {
				seenUrl[i.Url] = true
				urls = append(urls, i.Url)
			}
		}
	}
	return types, urls
}

func (g *mqlGcpProjectAgentRegistryService) agents() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	locations, err := g.listLocations()
	if err != nil {
		return listRefusal(err, "cannot list agent registry locations", "agentregistry.locations.list")
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(agentregistry.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := agentregistry.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return listAcrossAgentLocations("agents", locations, func(location string) ([]any, error) {
		var items []any
		err := svc.Projects.Locations.Agents.List(location).Pages(ctx, func(page *agentregistry.ListAgentsResponse) error {
			for _, a := range page.Agents {
				if a == nil {
					continue
				}
				protocols, urls := agentRegistryAgentProtocols(a.Protocols)
				skills := make([]any, 0, len(a.Skills))
				for _, s := range a.Skills {
					if s != nil {
						skills = append(skills, s.Name)
					}
				}
				r, err := CreateResource(g.MqlRuntime, "gcp.project.agentRegistryService.agent", map[string]*llx.RawData{
					"name":        llx.StringData(a.Name),
					"agentId":     llx.StringData(a.AgentId),
					"displayName": llx.StringData(a.DisplayName),
					"description": llx.StringData(a.Description),
					"location":    llx.StringData(a.Location),
					"version":     llx.StringData(a.Version),
					"protocols":   llx.ArrayData(convert.SliceAnyToInterface(protocols), types.String),
					"urls":        llx.ArrayData(convert.SliceAnyToInterface(urls), types.String),
					"skills":      llx.ArrayData(skills, types.String),
					"attributes":  llx.DictData(rawAttributesToDict(a.Attributes)),
					"createdAt":   llx.TimeDataPtr(parseTime(a.CreateTime)),
					"updatedAt":   llx.TimeDataPtr(parseTime(a.UpdateTime)),
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

func (g *mqlGcpProjectAgentRegistryService) mcpServers() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	locations, err := g.listLocations()
	if err != nil {
		return listRefusal(err, "cannot list agent registry locations", "agentregistry.locations.list")
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(agentregistry.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := agentregistry.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return listAcrossAgentLocations("mcpServers", locations, func(location string) ([]any, error) {
		var items []any
		err := svc.Projects.Locations.McpServers.List(location).Pages(ctx, func(page *agentregistry.ListMcpServersResponse) error {
			for _, m := range page.McpServers {
				if m == nil {
					continue
				}
				tools := make([]any, 0, len(m.Tools))
				for _, t := range m.Tools {
					if t != nil {
						tools = append(tools, t.Name)
					}
				}
				r, err := CreateResource(g.MqlRuntime, "gcp.project.agentRegistryService.mcpServer", map[string]*llx.RawData{
					"name":        llx.StringData(m.Name),
					"mcpServerId": llx.StringData(m.McpServerId),
					"displayName": llx.StringData(m.DisplayName),
					"description": llx.StringData(m.Description),
					"interfaces":  llx.MapData(agentRegistryInterfaces(m.Interfaces), types.String),
					"tools":       llx.ArrayData(tools, types.String),
					"attributes":  llx.DictData(rawAttributesToDict(m.Attributes)),
					"createdAt":   llx.TimeDataPtr(parseTime(m.CreateTime)),
					"updatedAt":   llx.TimeDataPtr(parseTime(m.UpdateTime)),
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

func (g *mqlGcpProjectAgentRegistryService) endpoints() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	locations, err := g.listLocations()
	if err != nil {
		return listRefusal(err, "cannot list agent registry locations", "agentregistry.locations.list")
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(agentregistry.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := agentregistry.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return listAcrossAgentLocations("endpoints", locations, func(location string) ([]any, error) {
		var items []any
		err := svc.Projects.Locations.Endpoints.List(location).Pages(ctx, func(page *agentregistry.ListEndpointsResponse) error {
			for _, e := range page.Endpoints {
				if e == nil {
					continue
				}
				r, err := CreateResource(g.MqlRuntime, "gcp.project.agentRegistryService.endpoint", map[string]*llx.RawData{
					"name":        llx.StringData(e.Name),
					"endpointId":  llx.StringData(e.EndpointId),
					"displayName": llx.StringData(e.DisplayName),
					"description": llx.StringData(e.Description),
					"interfaces":  llx.MapData(agentRegistryInterfaces(e.Interfaces), types.String),
					"attributes":  llx.DictData(rawAttributesToDict(e.Attributes)),
					"createdAt":   llx.TimeDataPtr(parseTime(e.CreateTime)),
					"updatedAt":   llx.TimeDataPtr(parseTime(e.UpdateTime)),
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

type mqlGcpProjectAgentRegistryServiceBindingInternal struct {
	cacheAuthProvider string
}

func (g *mqlGcpProjectAgentRegistryService) bindings() ([]any, error) {
	enabled, err := g.isEnabled()
	if err != nil {
		return nil, err
	}
	if !enabled {
		return nil, nil
	}
	locations, err := g.listLocations()
	if err != nil {
		return listRefusal(err, "cannot list agent registry locations", "agentregistry.locations.list")
	}
	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(agentregistry.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	ctx := context.Background()
	svc, err := agentregistry.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}
	return listAcrossAgentLocations("bindings", locations, func(location string) ([]any, error) {
		var items []any
		err := svc.Projects.Locations.Bindings.List(location).Pages(ctx, func(page *agentregistry.ListBindingsResponse) error {
			for _, b := range page.Bindings {
				if b == nil {
					continue
				}
				var source, target string
				if b.Source != nil {
					source = b.Source.Identifier
				}
				if b.Target != nil {
					target = b.Target.Identifier
				}
				var scopes []string
				var authProvider string
				if apb := b.AuthProviderBinding; apb != nil {
					scopes = apb.Scopes
					authProvider = apb.AuthProvider
				}
				r, err := CreateResource(g.MqlRuntime, "gcp.project.agentRegistryService.binding", map[string]*llx.RawData{
					"name":        llx.StringData(b.Name),
					"displayName": llx.StringData(b.DisplayName),
					"description": llx.StringData(b.Description),
					"source":      llx.StringData(source),
					"target":      llx.StringData(target),
					"scopes":      llx.ArrayData(convert.SliceAnyToInterface(scopes), types.String),
					"createdAt":   llx.TimeDataPtr(parseTime(b.CreateTime)),
					"updatedAt":   llx.TimeDataPtr(parseTime(b.UpdateTime)),
				})
				if err != nil {
					return err
				}
				r.(*mqlGcpProjectAgentRegistryServiceBinding).cacheAuthProvider = authProvider
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

func (g *mqlGcpProjectAgentRegistryServiceAgent) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectAgentRegistryServiceMcpServer) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectAgentRegistryServiceEndpoint) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectAgentRegistryServiceBinding) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

// authProvider resolves the binding's auth provider from the owning
// project's listed providers. A name that is not listed (a deleted provider)
// reads as null.
func (g *mqlGcpProjectAgentRegistryServiceBinding) authProvider() (*mqlGcpProjectAgentIdentityServiceAuthProvider, error) {
	name := g.cacheAuthProvider
	project := projectFromResourceName(name)
	if name == "" || project == "" {
		g.AuthProvider.State = plugin.StateIsSet | plugin.StateIsNull
		return nil, nil
	}
	svc, err := NewResource(g.MqlRuntime, "gcp.project.agentIdentityService", map[string]*llx.RawData{
		"projectId": llx.StringData(project),
	})
	if err != nil {
		return nil, err
	}
	providers := svc.(*mqlGcpProjectAgentIdentityService).GetAuthProviders()
	if providers.Error != nil {
		return nil, providers.Error
	}
	want := resourceNameWithoutProject(name)
	for _, p := range providers.Data {
		ap := p.(*mqlGcpProjectAgentIdentityServiceAuthProvider)
		if resourceNameWithoutProject(ap.Name.Data) == want {
			return ap, nil
		}
	}
	g.AuthProvider.State = plugin.StateIsSet | plugin.StateIsNull
	return nil, nil
}
