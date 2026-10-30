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
	"google.golang.org/api/appengine/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
)

func newAppEngineService(conn *connection.GcpConnection) (*appengine.APIService, error) {
	client, err := conn.Client(appengine.CloudPlatformReadOnlyScope)
	if err != nil {
		return nil, err
	}
	return appengine.NewService(context.Background(), option.WithHTTPClient(client))
}

func (g *mqlGcpProject) appEngine() (*mqlGcpProjectAppEngineService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.appEngineService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectAppEngineService), nil
}

func (g *mqlGcpProjectAppEngineService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/appEngineService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectAppEngineService) application() (*mqlGcpProjectAppEngineServiceApplication, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newAppEngineService(conn)
	if err != nil {
		return nil, err
	}

	app, err := svc.Apps.Get(projectId).Do()
	if err != nil {
		// App Engine returns 404 when the project has no application and 403
		// when the API is disabled; treat both as "no application" so a
		// project-wide scan doesn't fail on the common no-app case.
		if gerr, ok := err.(*googleapi.Error); ok && (gerr.Code == 403 || gerr.Code == 404) {
			g.Application.State = plugin.StateIsNull | plugin.StateIsSet
			return nil, nil
		}
		return nil, err
	}

	featureSettings, err := appEngineConvertFeatureSettings(app.FeatureSettings)
	if err != nil {
		return nil, err
	}
	iapSettings, err := appEngineConvertIap(app.Iap)
	if err != nil {
		return nil, err
	}

	res, err := CreateResource(g.MqlRuntime, "gcp.project.appEngineService.application", map[string]*llx.RawData{
		"projectId":               llx.StringData(projectId),
		"id":                      llx.StringData(app.Id),
		"locationId":              llx.StringData(app.LocationId),
		"servingStatus":           llx.StringData(app.ServingStatus),
		"defaultHostname":         llx.StringData(app.DefaultHostname),
		"defaultCookieExpiration": llx.StringData(app.DefaultCookieExpiration),
		"codeBucket":              llx.StringData(app.CodeBucket),
		"defaultBucket":           llx.StringData(app.DefaultBucket),
		"gcrDomain":               llx.StringData(app.GcrDomain),
		"databaseType":            llx.StringData(app.DatabaseType),
		"authDomain":              llx.StringData(app.AuthDomain),
		"featureSettings":         llx.DictData(featureSettings),
		"iap":                     llx.DictData(iapSettings),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectAppEngineServiceApplication), nil
}

func (g *mqlGcpProjectAppEngineService) services() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newAppEngineService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	req := svc.Apps.Services.List(projectId)
	if err := req.Pages(ctx, func(page *appengine.ListServicesResponse) error {
		for _, s := range page.Services {
			split, err := appEngineConvertSplit(s.Split)
			if err != nil {
				return err
			}

			mqlService, err := CreateResource(g.MqlRuntime, "gcp.project.appEngineService.service", map[string]*llx.RawData{
				"projectId": llx.StringData(projectId),
				"id":        llx.StringData(s.Id),
				"name":      llx.StringData(s.Name),
				"labels":    llx.MapData(convert.MapToInterfaceMap(s.Labels), types.String),
				"split":     llx.DictData(split),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlService)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectAppEngineService) firewallRules() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newAppEngineService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	req := svc.Apps.Firewall.IngressRules.List(projectId)
	if err := req.Pages(ctx, func(page *appengine.ListIngressRulesResponse) error {
		for _, rule := range page.IngressRules {
			mqlRule, err := CreateResource(g.MqlRuntime, "gcp.project.appEngineService.firewallRule", map[string]*llx.RawData{
				"__id":        llx.StringData(fmt.Sprintf("gcp.project/%s/appEngineService.firewallRule/%d", projectId, rule.Priority)),
				"projectId":   llx.StringData(projectId),
				"priority":    llx.IntData(rule.Priority),
				"action":      llx.StringData(rule.Action),
				"sourceRange": llx.StringData(rule.SourceRange),
				"description": llx.StringData(rule.Description),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlRule)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectAppEngineServiceService) versions() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	serviceId := g.Id.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newAppEngineService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	// The FULL view is required for the response to include handlers,
	// libraries, and other detail omitted by the default BASIC view.
	req := svc.Apps.Services.Versions.List(projectId, serviceId).View("FULL")
	if err := req.Pages(ctx, func(page *appengine.ListVersionsResponse) error {
		for _, v := range page.Versions {
			vpcConnector, err := appEngineConvertVpcConnector(v.VpcAccessConnector)
			if err != nil {
				return err
			}
			handlers, err := appEngineConvertHandlers(v.Handlers)
			if err != nil {
				return err
			}

			mqlVersion, err := CreateResource(g.MqlRuntime, "gcp.project.appEngineService.version", map[string]*llx.RawData{
				"projectId":                llx.StringData(projectId),
				"serviceId":                llx.StringData(serviceId),
				"id":                       llx.StringData(v.Id),
				"name":                     llx.StringData(v.Name),
				"servingStatus":            llx.StringData(v.ServingStatus),
				"runtime":                  llx.StringData(v.Runtime),
				"env":                      llx.StringData(v.Env),
				"createTime":               llx.TimeDataPtr(parseTime(v.CreateTime)),
				"runtimeApiVersion":        llx.StringData(v.RuntimeApiVersion),
				"vpcAccessConnector":       llx.DictData(vpcConnector),
				"handlers":                 llx.ArrayData(handlers, types.Dict),
				"inboundServices":          llx.ArrayData(convert.SliceAnyToInterface(v.InboundServices), types.String),
				"appEngineBundledServices": llx.ArrayData(convert.SliceAnyToInterface(v.AppEngineBundledServices), types.String),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlVersion)
		}
		return nil
	}); err != nil {
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectAppEngineServiceApplication) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/appEngineService.application", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectAppEngineServiceService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/appEngineService.service/%s", g.ProjectId.Data, g.Id.Data), nil
}

func (g *mqlGcpProjectAppEngineServiceVersion) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/appEngineService.version/%s/%s", g.ProjectId.Data, g.ServiceId.Data, g.Id.Data), nil
}

func appEngineConvertFeatureSettings(fs *appengine.FeatureSettings) (map[string]any, error) {
	if fs == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		SplitHealthChecks       bool `json:"splitHealthChecks"`
		UseContainerOptimizedOs bool `json:"useContainerOptimizedOs"`
	}{
		SplitHealthChecks:       fs.SplitHealthChecks,
		UseContainerOptimizedOs: fs.UseContainerOptimizedOs,
	})
}

func appEngineConvertIap(iap *appengine.IdentityAwareProxy) (map[string]any, error) {
	if iap == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		Enabled                  bool   `json:"enabled"`
		Oauth2ClientId           string `json:"oauth2ClientId"`
		Oauth2ClientSecretSha256 string `json:"oauth2ClientSecretSha256"`
	}{
		Enabled:                  iap.Enabled,
		Oauth2ClientId:           iap.Oauth2ClientId,
		Oauth2ClientSecretSha256: iap.Oauth2ClientSecretSha256,
	})
}

func appEngineConvertSplit(s *appengine.TrafficSplit) (map[string]any, error) {
	if s == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		ShardBy     string             `json:"shardBy"`
		Allocations map[string]float64 `json:"allocations"`
	}{
		ShardBy:     s.ShardBy,
		Allocations: s.Allocations,
	})
}

func appEngineConvertHandlers(handlers []*appengine.UrlMap) ([]any, error) {
	res := make([]any, 0, len(handlers))
	for _, h := range handlers {
		if h == nil {
			continue
		}
		d, err := convert.JsonToDict(h)
		if err != nil {
			return nil, err
		}
		res = append(res, d)
	}
	return res, nil
}

func appEngineConvertVpcConnector(vc *appengine.VpcAccessConnector) (map[string]any, error) {
	if vc == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		Name          string `json:"name"`
		EgressSetting string `json:"egressSetting"`
	}{
		Name:          vc.Name,
		EgressSetting: vc.EgressSetting,
	})
}
