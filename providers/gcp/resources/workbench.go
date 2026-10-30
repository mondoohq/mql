// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	notebooksv1 "google.golang.org/api/notebooks/v1"
	notebooksv2 "google.golang.org/api/notebooks/v2"
	"google.golang.org/api/option"
)

func newWorkbenchService(conn *connection.GcpConnection) (*notebooksv2.Service, error) {
	client, err := conn.Client(notebooksv2.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	return notebooksv2.NewService(context.Background(), option.WithHTTPClient(client))
}

func newNotebooksService(conn *connection.GcpConnection) (*notebooksv1.Service, error) {
	client, err := conn.Client(notebooksv1.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	return notebooksv1.NewService(context.Background(), option.WithHTTPClient(client))
}

func (g *mqlGcpProject) workbench() (*mqlGcpProjectWorkbenchService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.workbenchService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectWorkbenchService), nil
}

func (g *mqlGcpProject) notebooks() (*mqlGcpProjectNotebooksService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.notebooksService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectNotebooksService), nil
}

func (g *mqlGcpProjectWorkbenchService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/workbenchService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectNotebooksService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/notebooksService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectWorkbenchServiceInstance) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectNotebooksServiceInstance) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectWorkbenchService) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newWorkbenchService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	req := svc.Projects.Locations.Instances.List(parent)
	if err := req.Pages(ctx, func(page *notebooksv2.ListInstancesResponse) error {
		for _, i := range page.Instances {
			gceSetup, err := convert.JsonToDict(i.GceSetup)
			if err != nil {
				return err
			}

			disablePublicIp := false
			if i.GceSetup != nil {
				disablePublicIp = i.GceSetup.DisablePublicIp
			}

			mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.workbenchService.instance", map[string]*llx.RawData{
				"projectId":                llx.StringData(projectId),
				"name":                     llx.StringData(i.Name),
				"state":                    llx.StringData(i.State),
				"healthState":              llx.StringData(i.HealthState),
				"proxyUri":                 llx.StringData(i.ProxyUri),
				"creator":                  llx.StringData(i.Creator),
				"instanceOwners":           llx.ArrayData(convert.SliceAnyToInterface(i.InstanceOwners), types.String),
				"disableProxyAccess":       llx.BoolData(i.DisableProxyAccess),
				"enableDeletionProtection": llx.BoolData(i.EnableDeletionProtection),
				"enableThirdPartyIdentity": llx.BoolData(i.EnableThirdPartyIdentity),
				"labels":                   llx.MapData(convert.MapToInterfaceMap(i.Labels), types.String),
				"gceSetup":                 llx.DictData(gceSetup),
				"disablePublicIp":          llx.BoolData(disablePublicIp),
				"createTime":               llx.TimeDataPtr(parseTime(i.CreateTime)),
				"updateTime":               llx.TimeDataPtr(parseTime(i.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlInstance)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Debug().Str("project", projectId).Msg("vertex ai workbench api is not enabled, skipping")
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}

func (g *mqlGcpProjectNotebooksService) instances() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newNotebooksService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	var res []any
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	req := svc.Projects.Locations.Instances.List(parent)
	if err := req.Pages(ctx, func(page *notebooksv1.ListInstancesResponse) error {
		for _, i := range page.Instances {
			mqlInstance, err := CreateResource(g.MqlRuntime, "gcp.project.notebooksService.instance", map[string]*llx.RawData{
				"projectId":      llx.StringData(projectId),
				"name":           llx.StringData(i.Name),
				"state":          llx.StringData(i.State),
				"machineType":    llx.StringData(i.MachineType),
				"noPublicIp":     llx.BoolData(i.NoPublicIp),
				"noProxyAccess":  llx.BoolData(i.NoProxyAccess),
				"network":        llx.StringData(i.Network),
				"subnet":         llx.StringData(i.Subnet),
				"serviceAccount": llx.StringData(i.ServiceAccount),
				"proxyUri":       llx.StringData(i.ProxyUri),
				"creator":        llx.StringData(i.Creator),
				"labels":         llx.MapData(convert.MapToInterfaceMap(i.Labels), types.String),
				"createTime":     llx.TimeDataPtr(parseTime(i.CreateTime)),
				"updateTime":     llx.TimeDataPtr(parseTime(i.UpdateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlInstance)
		}
		return nil
	}); err != nil {
		if isSkippable(err) {
			log.Debug().Str("project", projectId).Msg("notebooks api is not enabled, skipping")
			return []any{}, nil
		}
		return nil, err
	}

	return res, nil
}
