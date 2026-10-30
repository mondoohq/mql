// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/option"
	"google.golang.org/api/workstations/v1"
)

func newWorkstationsService(conn *connection.GcpConnection) (*workstations.Service, error) {
	client, err := conn.Client(workstations.CloudPlatformScope)
	if err != nil {
		return nil, err
	}
	return workstations.NewService(context.Background(), option.WithHTTPClient(client))
}

func (g *mqlGcpProject) workstations() (*mqlGcpProjectWorkstationsService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.workstationsService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectWorkstationsService), nil
}

func (g *mqlGcpProjectWorkstationsService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/workstationsService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectWorkstationsService) clusters() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	svc, err := newWorkstationsService(conn)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	parent := fmt.Sprintf("projects/%s/locations/-", projectId)
	var res []any
	req := svc.Projects.Locations.WorkstationClusters.List(parent)
	if err := req.Pages(ctx, func(page *workstations.ListWorkstationClustersResponse) error {
		for _, c := range page.WorkstationClusters {
			privateClusterConfig, err := workstationsConvertPrivateClusterConfig(c.PrivateClusterConfig)
			if err != nil {
				return err
			}

			mqlCluster, err := CreateResource(g.MqlRuntime, "gcp.project.workstationsService.cluster", map[string]*llx.RawData{
				"projectId":            llx.StringData(projectId),
				"name":                 llx.StringData(c.Name),
				"displayName":          llx.StringData(c.DisplayName),
				"uid":                  llx.StringData(c.Uid),
				"network":              llx.StringData(c.Network),
				"subnetwork":           llx.StringData(c.Subnetwork),
				"controlPlaneIp":       llx.StringData(c.ControlPlaneIp),
				"degraded":             llx.BoolData(c.Degraded),
				"reconciling":          llx.BoolData(c.Reconciling),
				"createTime":           llx.TimeDataPtr(parseTime(c.CreateTime)),
				"updateTime":           llx.TimeDataPtr(parseTime(c.UpdateTime)),
				"labels":               llx.MapData(convert.MapToInterfaceMap(c.Labels), types.String),
				"annotations":          llx.MapData(convert.MapToInterfaceMap(c.Annotations), types.String),
				"privateClusterConfig": llx.DictData(privateClusterConfig),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlCluster)
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

func (g *mqlGcpProjectWorkstationsServiceCluster) id() (string, error) {
	if g.Name.Error != nil {
		return "", g.Name.Error
	}
	return g.Name.Data, nil
}

func workstationsConvertPrivateClusterConfig(pcc *workstations.PrivateClusterConfig) (map[string]any, error) {
	if pcc == nil {
		return nil, nil
	}
	return convert.JsonToDict(struct {
		EnablePrivateEndpoint bool     `json:"enablePrivateEndpoint"`
		ClusterHostname       string   `json:"clusterHostname"`
		ServiceAttachmentUri  string   `json:"serviceAttachmentUri"`
		AllowedProjects       []string `json:"allowedProjects"`
	}{
		EnablePrivateEndpoint: pcc.EnablePrivateEndpoint,
		ClusterHostname:       pcc.ClusterHostname,
		ServiceAttachmentUri:  pcc.ServiceAttachmentUri,
		AllowedProjects:       pcc.AllowedProjects,
	})
}
