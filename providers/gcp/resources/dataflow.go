// Copyright (c) Mondoo, Inc.
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"fmt"

	"go.mondoo.com/mql/v13/llx"
	"go.mondoo.com/mql/v13/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/v13/providers/gcp/connection"
	"go.mondoo.com/mql/v13/types"
	"google.golang.org/api/dataflow/v1b3"
	"google.golang.org/api/option"
)

func (g *mqlGcpProject) dataflow() (*mqlGcpProjectDataflowService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	res, err := CreateResource(g.MqlRuntime, "gcp.project.dataflowService", map[string]*llx.RawData{
		"projectId": llx.StringData(g.Id.Data),
	})
	if err != nil {
		return nil, err
	}
	return res.(*mqlGcpProjectDataflowService), nil
}

func (g *mqlGcpProjectDataflowService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("gcp.project/%s/dataflowService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectDataflowService) jobs() ([]any, error) {
	if g.ProjectId.Error != nil {
		return nil, g.ProjectId.Error
	}
	projectId := g.ProjectId.Data

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	client, err := conn.Client(dataflow.CloudPlatformScope)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	svc, err := dataflow.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, err
	}

	var res []any
	// Use aggregated list to get jobs across all locations
	call := svc.Projects.Jobs.Aggregated(projectId)
	if err := call.Pages(ctx, func(page *dataflow.ListJobsResponse) error {
		for _, job := range page.Jobs {
			env, _ := convert.JsonToDict(job.Environment)
			pipelineDesc, _ := convert.JsonToDict(job.PipelineDescription)

			mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.dataflowService.job", map[string]*llx.RawData{
				"projectId":           llx.StringData(projectId),
				"id":                  llx.StringData(job.Id),
				"name":                llx.StringData(job.Name),
				"type":                llx.StringData(job.Type),
				"currentState":        llx.StringData(job.CurrentState),
				"createTime":          llx.TimeDataPtr(parseTime(job.CreateTime)),
				"location":            llx.StringData(job.Location),
				"labels":              llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
				"environment":         llx.DictData(env),
				"pipelineDescription": llx.DictData(pipelineDesc),
				"currentStateTime":    llx.TimeDataPtr(parseTime(job.CurrentStateTime)),
			})
			if err != nil {
				return err
			}
			res = append(res, mqlJob)
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return res, nil
}

func (g *mqlGcpProjectDataflowServiceJob) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	if g.Id.Error != nil {
		return "", g.Id.Error
	}
	return fmt.Sprintf("gcp.project/%s/dataflowService.job/%s", g.ProjectId.Data, g.Id.Data), nil
}
