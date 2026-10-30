// Copyright Mondoo, Inc. 2024, 2026
// SPDX-License-Identifier: BUSL-1.1

package resources

import (
	"context"
	"errors"
	"fmt"

	batch "cloud.google.com/go/batch/apiv1"
	"cloud.google.com/go/batch/apiv1/batchpb"
	"github.com/rs/zerolog/log"
	"go.mondoo.com/mql/llx"
	"go.mondoo.com/mql/providers-sdk/v1/plugin"
	"go.mondoo.com/mql/providers-sdk/v1/util/convert"
	"go.mondoo.com/mql/providers/gcp/connection"
	"go.mondoo.com/mql/types"
	"google.golang.org/api/iterator"
	"google.golang.org/api/option"
)

type mqlGcpProjectBatchServiceInternal struct {
	serviceGate
}

func (g *mqlGcpProject) batch() (*mqlGcpProjectBatchService, error) {
	if g.Id.Error != nil {
		return nil, g.Id.Error
	}
	projectId := g.Id.Data

	res, err := CreateResource(g.MqlRuntime, "gcp.project.batchService", map[string]*llx.RawData{
		"projectId": llx.StringData(projectId),
	})
	if err != nil {
		return nil, err
	}

	serviceEnabled, err := g.isServiceEnabled(service_batch)
	if err != nil {
		return nil, err
	}

	svc := res.(*mqlGcpProjectBatchService)
	svc.recordEnabled(serviceEnabled)
	if !serviceEnabled {
		log.Debug().Str("service", service_batch).Msg("gcp service is not enabled, skipping")
	}

	return svc, nil
}

func initGcpProjectBatchService(runtime *plugin.Runtime, args map[string]*llx.RawData) (map[string]*llx.RawData, plugin.Resource, error) {
	if len(args) > 0 {
		return args, nil, nil
	}

	conn, ok := runtime.Connection.(*connection.GcpConnection)
	if !ok {
		return nil, nil, errors.New("invalid connection provided, it is not a GCP connection")
	}

	projectId := conn.ResourceID()
	args["projectId"] = llx.StringData(projectId)

	return args, nil, nil
}

func (g *mqlGcpProjectBatchService) id() (string, error) {
	if g.ProjectId.Error != nil {
		return "", g.ProjectId.Error
	}
	return fmt.Sprintf("%s/gcp.project.batchService", g.ProjectId.Data), nil
}

func (g *mqlGcpProjectBatchServiceJob) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBatchServiceJobTaskGroup) id() (string, error) {
	return g.Name.Data, g.Name.Error
}

func (g *mqlGcpProjectBatchService) jobs() ([]any, error) {
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

	conn := g.MqlRuntime.Connection.(*connection.GcpConnection)
	creds, err := conn.Credentials(batch.DefaultAuthScopes()...)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
	client, err := batch.NewClient(ctx, option.WithCredentials(creds), connection.GRPCClientTraceOption())
	if err != nil {
		return nil, err
	}
	defer client.Close()

	it := client.ListJobs(ctx, &batchpb.ListJobsRequest{
		Parent: fmt.Sprintf("projects/%s/locations/-", projectId),
	})

	var res []any
	for {
		job, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			if isSkippable(err) {
				log.Warn().Err(err).Msg("could not list Batch jobs")
				break
			}
			return nil, err
		}

		taskGroups := make([]any, 0, len(job.TaskGroups))
		for _, tg := range job.TaskGroups {
			taskSpec, err := protoToDict(tg.TaskSpec)
			if err != nil {
				return nil, err
			}
			mqlTG, err := CreateResource(g.MqlRuntime, "gcp.project.batchService.job.taskGroup", map[string]*llx.RawData{
				"name":             llx.StringData(tg.Name),
				"taskSpec":         llx.DictData(taskSpec),
				"taskCount":        llx.IntData(tg.TaskCount),
				"parallelism":      llx.IntData(tg.Parallelism),
				"schedulingPolicy": llx.StringData(tg.SchedulingPolicy.String()),
				"taskCountPerNode": llx.IntData(tg.TaskCountPerNode),
				"requireHostsFile": llx.BoolData(tg.RequireHostsFile),
				"permissiveSsh":    llx.BoolData(tg.PermissiveSsh),
			})
			if err != nil {
				return nil, err
			}
			taskGroups = append(taskGroups, mqlTG)
		}

		allocationPolicy, err := protoToDict(job.AllocationPolicy)
		if err != nil {
			return nil, err
		}

		status, err := protoToDict(job.Status)
		if err != nil {
			return nil, err
		}

		logsPolicy, err := protoToDict(job.LogsPolicy)
		if err != nil {
			return nil, err
		}

		mqlJob, err := CreateResource(g.MqlRuntime, "gcp.project.batchService.job", map[string]*llx.RawData{
			"name":             llx.StringData(job.Name),
			"uid":              llx.StringData(job.Uid),
			"priority":         llx.IntData(job.Priority),
			"taskGroups":       llx.ArrayData(taskGroups, types.Resource("gcp.project.batchService.job.taskGroup")),
			"allocationPolicy": llx.DictData(allocationPolicy),
			"status":           llx.DictData(status),
			"labels":           llx.MapData(convert.MapToInterfaceMap(job.Labels), types.String),
			"logsPolicy":       llx.DictData(logsPolicy),
			"created":          llx.TimeDataPtr(timestampAsTimePtr(job.CreateTime)),
			"updated":          llx.TimeDataPtr(timestampAsTimePtr(job.UpdateTime)),
		})
		if err != nil {
			return nil, err
		}
		res = append(res, mqlJob)
	}

	return res, nil
}

// isEnabled reports whether the API is enabled on this project.
func (g *mqlGcpProjectBatchService) isEnabled() (bool, error) {
	return g.resolveEnabled(g.MqlRuntime, g.ProjectId, service_batch)
}
