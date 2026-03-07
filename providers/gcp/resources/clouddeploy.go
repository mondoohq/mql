// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	deploy "cloud.google.com/go/deploy/apiv1"
	"cloud.google.com/go/deploy/apiv1/deploypb"
	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) cloudDeploy() (*mqlGcpProjectCloudDeployService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.cloudDeployService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectCloudDeployService), nil
}

func (g *mqlGcpProjectCloudDeployService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/cloudDeployService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectCloudDeployService) deliveryPipelines() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(deploy.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := deploy.NewCloudDeployClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListDeliveryPipelines(ctx, &deploypb.ListDeliveryPipelinesRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		p, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		serialPipeline, err := protoToDict(p.GetSerialPipeline())
		if err != nil {
			return nil, err
		}
		condition, err := protoToDict(p.GetCondition())
		if err != nil {
			return nil, err
		}

		mqlPipeline, err := CreateResource(g.MqlRuntime, "gcp.project.cloudDeployService.deliveryPipeline", map[string]*llx.RawData{
			"projectId":      llx.StringData(projectId),
			"name":           llx.StringData(p.Name),
			"uid":            llx.StringData(p.Uid),
			"description":    llx.StringData(p.Description),
			"annotations":    llx.MapData(convert.MapToInterfaceMap(p.Annotations), types.String),
			"labels":         llx.MapData(convert.MapToInterfaceMap(p.Labels), types.String),
			"createTime":     llx.TimeDataPtr(timestampAsTimePtr(p.CreateTime)),
			"updateTime":     llx.TimeDataPtr(timestampAsTimePtr(p.UpdateTime)),
			"suspended":      llx.BoolData(p.Suspended),
			"serialPipeline": llx.DictData(serialPipeline),
			"condition":      llx.DictData(condition),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlPipeline)
	}
	return res, nil
}

func (g *mqlGcpProjectCloudDeployServiceDeliveryPipeline) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectCloudDeployService) targets() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(deploy.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := deploy.NewCloudDeployClient(ctx, option.WithCredentials(creds))
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListTargets(ctx, &deploypb.ListTargetsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		t, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		gke, err := protoToDict(t.GetGke())
		if err != nil {
			return nil, err
		}
		run, err := protoToDict(t.GetRun())
		if err != nil {
			return nil, err
		}
		customTarget, err := protoToDict(t.GetCustomTarget())
		if err != nil {
			return nil, err
		}
		executionConfigs := make([]any, 0, len(t.ExecutionConfigs))
		for _, ec := range t.ExecutionConfigs {
			d, err := protoToDict(ec)
			if err != nil {
				return nil, err
			}
			executionConfigs = append(executionConfigs, d)
		}

		mqlTarget, err := CreateResource(g.MqlRuntime, "gcp.project.cloudDeployService.target", map[string]*llx.RawData{
			"projectId":       llx.StringData(projectId),
			"name":            llx.StringData(t.Name),
			"uid":             llx.StringData(t.Uid),
			"description":     llx.StringData(t.Description),
			"annotations":     llx.MapData(convert.MapToInterfaceMap(t.Annotations), types.String),
			"labels":          llx.MapData(convert.MapToInterfaceMap(t.Labels), types.String),
			"createTime":      llx.TimeDataPtr(timestampAsTimePtr(t.CreateTime)),
			"updateTime":      llx.TimeDataPtr(timestampAsTimePtr(t.UpdateTime)),
			"requireApproval": llx.BoolData(t.RequireApproval),
			"gke":             llx.DictData(gke),
			"run":             llx.DictData(run),
			"customTarget":    llx.DictData(customTarget),
			"executionConfigs": llx.ArrayData(executionConfigs, types.Dict),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlTarget)
	}
	return res, nil
}

func (g *mqlGcpProjectCloudDeployServiceTarget) id() (string, error) {
	return g.Name.Data, g.Name.Error
}
