// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/apigateway/v1"
	"google.golang.org/api/option"
)

type mqlGcpProjectApiGatewayServiceApiConfigInternal struct {
	cacheGatewayServiceAccount string
}

func newApiGatewayService(conn *connection.GcpConnection) (*apigateway.Service, error) {
	client, err := conn.Client(apigateway.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	return apigateway.NewService(context.Background(), option.WithHTTPClient(client))
}

func (g *mqlGcpProject) apiGateway() (*mqlGcpProjectApiGatewayService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.apiGatewayService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectApiGatewayService), nil
}

func (g *mqlGcpProjectApiGatewayService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/apiGatewayService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectApiGatewayService) apis() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newApiGatewayService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	parent := fmt.Sprintf("projects/%s/locations/global", projectId)
	req := svc.Projects.Locations.Apis.List(parent)
	if err := req.Pages(ctx, func(page *apigateway.ApigatewayListApisResponse) error {
		for _, a := range page.Apis {
			mqlApi, err := CreateResource(g.MqlRuntime, "gcp.project.apiGatewayService.api", map[string]*llx.RawData{
				"projectId":      llx.StringData(projectId),
				"name":           llx.StringData(a.Name),
				"displayName":    llx.StringData(a.DisplayName),
				"managedService": llx.StringData(a.ManagedService),
				"state":          llx.StringData(a.State),
				"createTime":     llx.TimeDataPtr(parseTime(a.CreateTime)),
				"updateTime":     llx.TimeDataPtr(parseTime(a.UpdateTime)),
				"labels":         llx.MapData(convert.MapToInterfaceMap(a.Labels), types.String),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlApi)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectApiGatewayService) gateways() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newApiGatewayService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	// "-" as the location lists gateways across all regions.
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	req := svc.Projects.Locations.Gateways.List(parent)
	if err := req.Pages(ctx, func(page *apigateway.ApigatewayListGatewaysResponse) error {
		for _, gw := range page.Gateways {
			mqlGateway, err := CreateResource(g.MqlRuntime, "gcp.project.apiGatewayService.gateway", map[string]*llx.RawData{
				"projectId":       llx.StringData(projectId),
				"name":            llx.StringData(gw.Name),
				"displayName":     llx.StringData(gw.DisplayName),
				"apiConfig":       llx.StringData(gw.ApiConfig),
				"state":           llx.StringData(gw.State),
				"defaultHostname": llx.StringData(gw.DefaultHostname),
				"createTime":      llx.TimeDataPtr(parseTime(gw.CreateTime)),
				"updateTime":      llx.TimeDataPtr(parseTime(gw.UpdateTime)),
				"labels":          llx.MapData(convert.MapToInterfaceMap(gw.Labels), types.String),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlGateway)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectApiGatewayServiceApi) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectApiGatewayServiceApi) configs() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Name.Error != nil {
		return nil, g.Name.Error
	}
	apiName := g.Name.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newApiGatewayService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	req := svc.Projects.Locations.Apis.Configs.List(apiName)
	if err := req.Pages(ctx, func(page *apigateway.ApigatewayListApiConfigsResponse) error {
		for _, c := range page.ApiConfigs {
			openapiDocuments, err := apiGatewayConvertOpenApiDocuments(c.OpenapiDocuments)
			if err != nil {
				return err
			}

			mqlConfig, err := CreateResource(g.MqlRuntime, "gcp.project.apiGatewayService.apiConfig", map[string]*llx.RawData{
				"projectId":        llx.StringData(projectId),
				"name":             llx.StringData(c.Name),
				"displayName":      llx.StringData(c.DisplayName),
				"state":            llx.StringData(c.State),
				"serviceConfigId":  llx.StringData(c.ServiceConfigId),
				"createTime":       llx.TimeDataPtr(parseTime(c.CreateTime)),
				"updateTime":       llx.TimeDataPtr(parseTime(c.UpdateTime)),
				"labels":           llx.MapData(convert.MapToInterfaceMap(c.Labels), types.String),
				"openapiDocuments": llx.ArrayData(openapiDocuments, types.Dict),
			})
			if err != nil {
				return err
			}
			mqlRef := mqlConfig.(*mqlGcpProjectApiGatewayServiceApiConfig)
			mqlRef.cacheGatewayServiceAccount = c.GatewayServiceAccount
			res = append(res, mqlConfig)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectApiGatewayServiceApiConfig) serviceAccount() (*mqlGcpProjectIamServiceServiceAccount, error) {
	sa, err := resolveServiceAccountRef(g.MqlRuntime, g.cacheGatewayServiceAccount, g.ProjectId.Data)
	if err != nil {
		return nil, err
	}
	if sa == nil {
		g.ServiceAccount.State = plugin.StateIsSet | plugin.StateIsNull
	}
	return sa, nil
}

func (g *mqlGcpProjectApiGatewayServiceApiConfig) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectApiGatewayServiceGateway) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func apiGatewayConvertOpenApiDocuments(docs []*apigateway.ApigatewayApiConfigOpenApiDocument) ([]any, error) {
	res := make([]any, 0, len(docs))
	for _, d := range docs {
		if d == nil {
			continue
		}
		var path, contents string
		if d.Document != nil {
			path = d.Document.Path
			contents = d.Document.Contents
		}
		dict, err := convert.JsonToDict(struct {
			Path     string `json:"path"`
			Contents string `json:"contents"`
		}{
			Path:     path,
			Contents: contents,
		})
		if err != nil {
			return nil, err
		}
		res = append(res, dict)
	}
	return res, nil
}
